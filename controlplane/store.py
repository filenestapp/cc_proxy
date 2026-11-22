"""SQLite store for the control plane (schema v2): hosts, egress IPs, password users bound to IP + port, devices.

Model
  host      an exit node: public address, Reality keys, a port range for user entry ports, an agent token
  egress IP belongs to one host
  user      username + password; bound to one egress IP and one entry port on that IP's host
  device    created when a user signs in from a computer; holds the VLESS credential and a subscription token

Every mutation bumps a global config version (shown on /healthz). Configs themselves are served with a hash
ETag, so a change that does not touch a given config costs its consumers nothing.

Configs are rendered by egress/gen.py from a per-host inventory, so the file-based flow and the control plane
share one renderer.
"""
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
import uuid as uuidlib

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "egress"))
import gen  # noqa: E402
from alerts import validate_settings as validate_alerts  # noqa: E402
from x25519 import reality_keypair  # noqa: E402

SCHEMA_VERSION = 2
DEFAULT_COOLDOWN = 7 * 24 * 3600
DEFAULT_MAX_DEVICES = 5
PBKDF2_ITERATIONS = 200_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS hosts (
  name TEXT PRIMARY KEY,
  public_host TEXT NOT NULL,
  port_min INTEGER NOT NULL,
  port_max INTEGER NOT NULL,
  reality_private TEXT NOT NULL,
  reality_public TEXT NOT NULL,
  short_id TEXT NOT NULL,
  server_name TEXT NOT NULL,
  handshake_server TEXT NOT NULL,
  handshake_port INTEGER NOT NULL DEFAULT 443,
  block_private INTEGER NOT NULL DEFAULT 1,
  block_cidrs TEXT NOT NULL DEFAULT '["169.254.169.254/32"]',
  agent_token_hash TEXT NOT NULL UNIQUE,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS egress_ips (
  ip TEXT PRIMARY KEY,
  host TEXT NOT NULL REFERENCES hosts(name),
  banned INTEGER NOT NULL DEFAULT 0,
  cooldown_until REAL NOT NULL DEFAULT 0,
  note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY,
  password_hash TEXT NOT NULL,
  mode TEXT NOT NULL DEFAULT 'exclusive' CHECK (mode IN ('exclusive', 'shared')),
  egress_ip TEXT REFERENCES egress_ips(ip),
  port INTEGER,
  max_devices INTEGER NOT NULL DEFAULT 5,
  created_at REAL NOT NULL,
  CHECK ((egress_ip IS NULL) = (port IS NULL))
);
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY,
  user_name TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
  name TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT '',
  uuid TEXT NOT NULL UNIQUE,
  token_hash TEXT NOT NULL UNIQUE,
  revoked_at REAL,
  last_seen REAL,
  created_at REAL NOT NULL,
  UNIQUE (user_name, name)
);
"""


class Conflict(Exception):
    """The request contradicts current state (409)."""


class NotFound(Exception):
    pass


class AuthError(Exception):
    """Wrong username or password (401)."""


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), digest.hex())


def check_password(password, stored):
    try:
        _, iterations, salt, digest = stored.split("$")
        expected = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iterations))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected.hex(), digest)


# A fixed hash to compare against when the user does not exist, so timing does not reveal valid usernames.
_DUMMY_HASH = hash_password("x", salt=b"\0" * 16)


def render(obj):
    """Canonical bytes of a served config; config_etag() is computed over exactly these bytes."""
    return (json.dumps(obj, indent=2) + "\n").encode()


def config_etag(obj):
    return hashlib.sha256(render(obj)).hexdigest()[:20]


def check_name(kind, name):
    if not isinstance(name, str) or not name or len(name) > 64 or any(c in name for c in "/ \t\n"):
        raise Conflict("%s name must be 1-64 characters without '/' or spaces" % kind)


def check_password_policy(password):
    if not isinstance(password, str) or len(password) < 8:
        raise Conflict("password must be at least 8 characters")


class Store:
    def __init__(self, path, clock=time.time):
        self.clock = clock
        self.lock = threading.RLock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        self.db.execute("PRAGMA journal_mode = WAL")
        old = self.db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'").fetchone()
        if old:
            row = self.db.execute("SELECT value FROM settings WHERE key = 'schema'").fetchone()
            if not row or json.loads(row["value"]) != SCHEMA_VERSION:
                raise RuntimeError("database was created by an older control plane (schema v1); "
                                   "start from a new database")
        self.db.executescript(SCHEMA)
        self._set("schema", SCHEMA_VERSION)

    # -- helpers -----------------------------------------------------------------------------------------

    def _tx(self):
        return _Tx(self)

    def _get(self, key, default=None):
        row = self.db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else default

    def _set(self, key, value):
        self.db.execute("INSERT INTO settings(key, value) VALUES(?, ?) "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, json.dumps(value)))

    def _bump(self):
        self._set("version", self._get("version", 0) + 1)

    def version(self):
        with self.lock:
            return self._get("version", 0)

    def setting(self, key, default=None):
        with self.lock:
            return self._get(key, default)

    def _ip_status(self, row):
        if row["banned"]:
            return "banned"
        if row["cooldown_until"] > self.clock():
            return "cooldown"
        return "available"

    def _host(self, name):
        row = self.db.execute("SELECT * FROM hosts WHERE name = ?", (name,)).fetchone()
        if not row:
            raise NotFound("host %s" % name)
        return row

    def _user(self, name):
        row = self.db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()
        if not row:
            raise NotFound("user %s" % name)
        return row

    def _holders(self, ip):
        return self.db.execute("SELECT name, mode FROM users WHERE egress_ip = ?", (ip,)).fetchall()

    def _host_of_ip(self, ip):
        row = self.db.execute("SELECT host FROM egress_ips WHERE ip = ?", (ip,)).fetchone()
        return row["host"] if row else None

    def _release(self, user_row):
        ip = user_row["egress_ip"]
        if not ip:
            return None
        self.db.execute("UPDATE users SET egress_ip = NULL, port = NULL WHERE name = ?", (user_row["name"],))
        if not self._holders(ip):
            # Last holder gone: the IP rests before anyone else gets it.
            until = self.clock() + self._get("cooldown_seconds", DEFAULT_COOLDOWN)
            self.db.execute("UPDATE egress_ips SET cooldown_until = ? WHERE ip = ?", (until, ip))
        return ip

    # -- global settings ---------------------------------------------------------------------------------

    def configure(self, client_policy=None, cooldown_seconds=None, monitor=None, alerts=None):
        with self._tx():
            if client_policy is not None:
                if not isinstance(client_policy, dict):
                    raise Conflict("client_policy must be an object")
                self._set("client_policy", client_policy)
            if cooldown_seconds is not None:
                self._set("cooldown_seconds", int(cooldown_seconds))
            if monitor is not None:
                if not isinstance(monitor, dict) or not isinstance(monitor.get("egress_targets", []), list) \
                        or not isinstance(monitor.get("entries", []), list):
                    raise Conflict("monitor must be an object with list fields egress_targets and entries")
                self._set("monitor", monitor)
            if alerts is not None:
                try:
                    validate_alerts(alerts)
                except ValueError as e:
                    raise Conflict(str(e))
                self._set("alerts", alerts)
            self._bump()

    # -- hosts -------------------------------------------------------------------------------------------

    def add_host(self, name, public_host, server_name, handshake_server=None, handshake_port=443,
                 port_min=20000, port_max=29999, block_private=True, block_cidrs=None):
        """Register an exit node. Generates its Reality keys; returns the agent token (shown once)."""
        check_name("host", name)
        if not public_host:
            raise Conflict("public_host is required")
        if not server_name:
            raise Conflict("server_name (the Reality camouflage SNI) is required")
        if not (1 <= int(port_min) <= int(port_max) <= 65535):
            raise Conflict("port range must satisfy 1 <= port_min <= port_max <= 65535")
        private, public = reality_keypair()
        token = secrets.token_urlsafe(32)
        with self._tx():
            try:
                self.db.execute(
                    "INSERT INTO hosts(name, public_host, port_min, port_max, reality_private, reality_public, "
                    "short_id, server_name, handshake_server, handshake_port, block_private, block_cidrs, "
                    "agent_token_hash, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (name, public_host, int(port_min), int(port_max), private, public, secrets.token_hex(8),
                     server_name, handshake_server or server_name, int(handshake_port), int(bool(block_private)),
                     json.dumps(block_cidrs if block_cidrs is not None else ["169.254.169.254/32"]),
                     hash_token(token), self.clock()))
            except sqlite3.IntegrityError:
                raise Conflict("host %s exists" % name)
            self._bump()
        return token

    def update_host(self, name, **fields):
        allowed = {"public_host", "server_name", "handshake_server", "handshake_port", "port_min", "port_max",
                   "block_private", "block_cidrs"}
        bad = set(fields) - allowed
        if bad:
            raise Conflict("cannot update %s" % ", ".join(sorted(bad)))
        with self._tx():
            host = dict(self._host(name))
            host.update(fields)
            if not (1 <= int(host["port_min"]) <= int(host["port_max"]) <= 65535):
                raise Conflict("port range must satisfy 1 <= port_min <= port_max <= 65535")
            outside = self.db.execute(
                "SELECT u.name, u.port FROM users u JOIN egress_ips e ON u.egress_ip = e.ip "
                "WHERE e.host = ? AND (u.port < ? OR u.port > ?)",
                (name, int(host["port_min"]), int(host["port_max"]))).fetchall()
            if outside:
                raise Conflict("users outside the new port range: %s" % ", ".join(
                    "%s:%d" % (r["name"], r["port"]) for r in outside))
            for k, v in fields.items():
                self.db.execute("UPDATE hosts SET %s = ? WHERE name = ?" % k,
                                (json.dumps(v) if k == "block_cidrs" else v, name))
            self._bump()

    def rotate_agent_token(self, name):
        token = secrets.token_urlsafe(32)
        with self._tx():
            self._host(name)
            self.db.execute("UPDATE hosts SET agent_token_hash = ? WHERE name = ?", (hash_token(token), name))
            self._bump()
        return token

    def delete_host(self, name):
        with self._tx():
            self._host(name)
            held = self.db.execute("SELECT u.name FROM users u JOIN egress_ips e ON u.egress_ip = e.ip "
                                   "WHERE e.host = ?", (name,)).fetchall()
            if held:
                raise Conflict("host %s still serves users: %s" % (name, ", ".join(r["name"] for r in held)))
            self.db.execute("DELETE FROM egress_ips WHERE host = ?", (name,))
            self.db.execute("DELETE FROM hosts WHERE name = ?", (name,))
            self._bump()

    def list_hosts(self):
        with self.lock:
            out = []
            for h in self.db.execute("SELECT * FROM hosts ORDER BY name"):
                out.append({
                    "name": h["name"], "public_host": h["public_host"],
                    "port_range": [h["port_min"], h["port_max"]],
                    "server_name": h["server_name"], "reality_public_key": h["reality_public"],
                    "ips": self.db.execute("SELECT COUNT(*) FROM egress_ips WHERE host = ?",
                                           (h["name"],)).fetchone()[0],
                    "users": self.db.execute("SELECT COUNT(*) FROM users u JOIN egress_ips e ON u.egress_ip = e.ip "
                                             "WHERE e.host = ?", (h["name"],)).fetchone()[0],
                })
            return out

    def host_for_agent_token(self, token):
        with self.lock:
            row = self.db.execute("SELECT name FROM hosts WHERE agent_token_hash = ?", (hash_token(token),)).fetchone()
            return row["name"] if row else None

    # -- egress IPs --------------------------------------------------------------------------------------

    def add_ips(self, host, ips):
        added = []
        with self._tx():
            self._host(host)
            for ip in ips:
                ip = str(ipaddress.IPv4Address(ip))
                other = self._host_of_ip(ip)
                if other and other != host:
                    raise Conflict("ip %s already belongs to host %s" % (ip, other))
                cur = self.db.execute("INSERT OR IGNORE INTO egress_ips(ip, host) VALUES(?, ?)", (ip, host))
                if cur.rowcount:
                    added.append(ip)
            self._bump()
        return added

    def list_ips(self, host=None):
        with self.lock:
            q, args = "SELECT * FROM egress_ips", ()
            if host:
                q, args = q + " WHERE host = ?", (host,)
            out = []
            for row in self.db.execute(q, args):
                holders = self.db.execute("SELECT name, port FROM users WHERE egress_ip = ? ORDER BY name",
                                          (row["ip"],)).fetchall()
                out.append({
                    "ip": row["ip"], "host": row["host"],
                    "status": "assigned" if holders else self._ip_status(row),
                    "users": [h["name"] for h in holders],
                    "ports": {h["name"]: h["port"] for h in holders},
                    "cooldown_until": row["cooldown_until"] or None,
                    "note": row["note"],
                })
            out.sort(key=lambda e: ipaddress.IPv4Address(e["ip"]))
            return out

    def ban_ip(self, ip, note=""):
        """Mark an IP as blocked by targets: its holders lose it (and their ports), and it is never reused."""
        with self._tx():
            if not self._host_of_ip(ip):
                raise NotFound("ip %s" % ip)
            released = [h["name"] for h in self._holders(ip)]
            self.db.execute("UPDATE users SET egress_ip = NULL, port = NULL WHERE egress_ip = ?", (ip,))
            self.db.execute("UPDATE egress_ips SET banned = 1, note = ? WHERE ip = ?", (note, ip))
            self._bump()
        return released

    def delete_ip(self, ip):
        """Take an unassigned IP out of the pool. (The agent does not unplumb it from the interface.)"""
        with self._tx():
            if not self._host_of_ip(ip):
                raise NotFound("ip %s" % ip)
            holders = [h["name"] for h in self._holders(ip)]
            if holders:
                raise Conflict("ip %s is held by %s; release it first" % (ip, ", ".join(holders)))
            self.db.execute("DELETE FROM egress_ips WHERE ip = ?", (ip,))
            self._bump()

    def settings(self):
        with self.lock:
            return {
                "client_policy": self._get("client_policy", {}),
                "cooldown_seconds": self._get("cooldown_seconds", DEFAULT_COOLDOWN),
                "monitor": self._get("monitor", {"egress_targets": [], "entries": []}),
                "alerts": self._get("alerts", {}),
            }

    def make_available(self, ip):
        """Admin override: end a cooldown or lift a ban."""
        with self._tx():
            cur = self.db.execute("UPDATE egress_ips SET banned = 0, cooldown_until = 0 WHERE ip = ?", (ip,))
            if not cur.rowcount:
                raise NotFound("ip %s" % ip)
            self._bump()

    # -- users -------------------------------------------------------------------------------------------

    def add_user(self, name, password, mode="exclusive", max_devices=DEFAULT_MAX_DEVICES):
        check_name("user", name)
        check_password_policy(password)
        if mode not in ("exclusive", "shared"):
            raise Conflict("mode must be exclusive or shared")
        if int(max_devices) < 1:
            raise Conflict("max_devices must be at least 1")
        pw = hash_password(password)
        with self._tx():
            try:
                self.db.execute("INSERT INTO users(name, password_hash, mode, max_devices, created_at) "
                                "VALUES(?, ?, ?, ?, ?)", (name, pw, mode, int(max_devices), self.clock()))
            except sqlite3.IntegrityError:
                raise Conflict("user %s exists" % name)
            self._bump()

    def set_password(self, name, password, revoke_devices=False):
        check_password_policy(password)
        pw = hash_password(password)
        with self._tx():
            self._user(name)
            self.db.execute("UPDATE users SET password_hash = ? WHERE name = ?", (pw, name))
            if revoke_devices:
                self.db.execute("UPDATE devices SET revoked_at = ? WHERE user_name = ? AND revoked_at IS NULL",
                                (self.clock(), name))
            self._bump()

    def set_max_devices(self, name, max_devices):
        if int(max_devices) < 1:
            raise Conflict("max_devices must be at least 1")
        with self._tx():
            self._user(name)
            self.db.execute("UPDATE users SET max_devices = ? WHERE name = ?", (int(max_devices), name))
            self._bump()

    def delete_user(self, name):
        with self._tx():
            self._release(self._user(name))
            self.db.execute("DELETE FROM users WHERE name = ?", (name,))
            self._bump()

    def list_users(self):
        with self.lock:
            users = []
            for u in self.db.execute("SELECT * FROM users ORDER BY name"):
                devices = [{
                    "name": d["name"], "platform": d["platform"], "revoked": d["revoked_at"] is not None,
                    "last_seen": d["last_seen"],
                } for d in self.db.execute("SELECT * FROM devices WHERE user_name = ? ORDER BY name", (u["name"],))]
                users.append({
                    "name": u["name"], "mode": u["mode"], "egress_ip": u["egress_ip"], "port": u["port"],
                    "host": self._host_of_ip(u["egress_ip"]) if u["egress_ip"] else None,
                    "max_devices": u["max_devices"], "devices": devices,
                })
            return users

    def assign(self, name, ip=None, port=None, host=None):
        """Bind a user to an egress IP and an entry port on that IP's host.

        Without ip, take the lowest free IP (on `host` if given). Without port, take the lowest free port in
        the host's range. Returns (ip, port)."""
        with self._tx():
            user = self._user(name)
            if user["egress_ip"]:
                raise Conflict("user %s already holds %s:%s; use reassign to move it" % (name, user["egress_ip"], user["port"]))
            ip, port = self._choose(user, ip, port, host)
            self.db.execute("UPDATE users SET egress_ip = ?, port = ? WHERE name = ?", (ip, port, name))
            self._bump()
            return ip, port

    def reassign(self, name, ip=None, port=None, host=None):
        """Move a bound user to another IP / port in one transaction (review finding CC-05).

        A subscription sees either the old or the new binding, never an unassigned user. Without ip, take the lowest
        free IP other than the current one (on `host` if given). The old IP goes into cooldown when nobody else
        holds it. If the new target is not acceptable nothing changes."""
        with self._tx():
            user = self._user(name)
            old_ip = user["egress_ip"]
            if not old_ip:
                raise Conflict("user %s holds no egress IP; use assign" % name)
            new_ip, new_port = self._choose(user, ip, port, host, moving=True)
            if (new_ip, new_port) == (old_ip, user["port"]):
                return new_ip, new_port
            self.db.execute("UPDATE users SET egress_ip = ?, port = ? WHERE name = ?", (new_ip, new_port, name))
            if new_ip != old_ip and not self._holders(old_ip):
                until = self.clock() + self._get("cooldown_seconds", DEFAULT_COOLDOWN)
                self.db.execute("UPDATE egress_ips SET cooldown_until = ? WHERE ip = ?", (until, old_ip))
            self._bump()
            return new_ip, new_port

    def _choose(self, user, ip, port, host, moving=False):
        """Validate (or pick) the IP and port for `user`. When moving, the user's own current binding does not count
        as taken, and an automatic pick avoids the current IP. Caller holds the transaction."""
        name = user["name"]
        others = lambda rows: [r for r in rows if r["name"] != name]  # noqa: E731
        if ip is None:
            ip = self._pick_free_ip(host, exclude=user["egress_ip"] if moving else None)
        row = self.db.execute("SELECT * FROM egress_ips WHERE ip = ?", (ip,)).fetchone()
        if not row:
            raise NotFound("ip %s" % ip)
        if host and row["host"] != host:
            raise Conflict("ip %s belongs to host %s, not %s" % (ip, row["host"], host))
        holders = others(self._holders(ip))
        if row["banned"]:
            raise Conflict("ip %s is banned" % ip)
        staying = moving and ip == user["egress_ip"]
        if not holders and not staying and self._ip_status(row) != "available":
            raise Conflict("ip %s is %s" % (ip, self._ip_status(row)))
        if holders and (user["mode"] != "shared" or any(h["mode"] != "shared" for h in holders)):
            raise Conflict("ip %s is held by %s; sharing needs mode=shared on every holder"
                           % (ip, ", ".join(h["name"] for h in holders)))
        h = self._host(row["host"])
        used = {p: n for p, n in self._used_ports(row["host"]).items() if n != name}
        if port is None:
            if moving and user["port"] and self._host_of_ip(user["egress_ip"]) == h["name"] and user["port"] not in used:
                port = user["port"]  # same host: keep the entry port the client already uses
            else:
                port = next((p for p in range(h["port_min"], h["port_max"] + 1) if p not in used), None)
            if port is None:
                raise Conflict("no free port left in %d-%d on host %s" % (h["port_min"], h["port_max"], h["name"]))
        else:
            port = int(port)
            if not h["port_min"] <= port <= h["port_max"]:
                raise Conflict("port %d is outside host %s's range %d-%d" % (port, h["name"], h["port_min"], h["port_max"]))
            if port in used:
                raise Conflict("port %d on host %s is used by %s" % (port, h["name"], used[port]))
        return ip, port

    def _used_ports(self, host):
        return {r["port"]: r["name"] for r in self.db.execute(
            "SELECT u.name, u.port FROM users u JOIN egress_ips e ON u.egress_ip = e.ip WHERE e.host = ?", (host,))}

    def _pick_free_ip(self, host=None, exclude=None):
        q, args = "SELECT * FROM egress_ips", ()
        if host:
            self._host(host)
            q, args = q + " WHERE host = ?", (host,)
        free = [r["ip"] for r in self.db.execute(q, args)
                if r["ip"] != exclude and self._ip_status(r) == "available" and not self._holders(r["ip"])]
        if not free:
            raise Conflict("no free egress IP" + (" on host %s" % host if host else ""))
        return min(free, key=ipaddress.IPv4Address)

    def release(self, name):
        with self._tx():
            ip = self._release(self._user(name))
            if ip is None:
                raise Conflict("user %s holds no egress IP" % name)
            self._bump()
            return ip

    # -- devices and sign-in -----------------------------------------------------------------------------

    def _new_device(self, user, device_name, platform):
        """Create a device, or rotate the token of an existing one with the same name (signing in again on the
        same computer). Returns the new token. Caller holds the transaction."""
        check_name("device", device_name)
        token = secrets.token_urlsafe(32)
        existing = self.db.execute("SELECT * FROM devices WHERE user_name = ? AND name = ?",
                                   (user["name"], device_name)).fetchone()
        if existing and existing["revoked_at"] is None:
            self.db.execute("UPDATE devices SET token_hash = ?, platform = ?, last_seen = ? WHERE id = ?",
                            (hash_token(token), platform, self.clock(), existing["id"]))
            return token
        active = self.db.execute("SELECT COUNT(*) FROM devices WHERE user_name = ? AND revoked_at IS NULL",
                                 (user["name"],)).fetchone()[0]
        if active >= user["max_devices"]:
            raise Conflict("device limit reached (%d); sign out on another device or ask the admin"
                           % user["max_devices"])
        if existing:  # a revoked device signing in again gets a fresh credential
            self.db.execute("DELETE FROM devices WHERE id = ?", (existing["id"],))
        self.db.execute(
            "INSERT INTO devices(user_name, name, platform, uuid, token_hash, created_at, last_seen) "
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (user["name"], device_name, platform, str(uuidlib.uuid4()), hash_token(token), self.clock(), self.clock()))
        return token

    def login(self, username, password, device_name, platform=""):
        """Password sign-in from a client. Returns (token, user summary)."""
        with self.lock:
            row = self.db.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchone()
        if not check_password(password or "", row["password_hash"] if row else _DUMMY_HASH) or not row:
            raise AuthError("wrong username or password")
        verified = row["password_hash"]
        with self._tx():
            user = self._user(username)
            # The (slow) check above ran outside the lock. If the password changed since, that check is stale
            # (review finding CC-06): a reset with device revocation must not be undone by an in-flight sign-in.
            if user["password_hash"] != verified:
                raise AuthError("wrong username or password")
            token = self._new_device(user, device_name, str(platform)[:32])
            self._bump()
        return token, self.user_summary(username)

    def add_device(self, user_name, device_name, platform=""):
        """Admin-created device (no password needed). Returns its token, shown once."""
        with self._tx():
            token = self._new_device(self._user(user_name), device_name, platform)
            self._bump()
        return token

    def revoke_device(self, user_name, device_name):
        with self._tx():
            cur = self.db.execute("UPDATE devices SET revoked_at = ? WHERE user_name = ? AND name = ? "
                                  "AND revoked_at IS NULL", (self.clock(), user_name, device_name))
            if not cur.rowcount:
                raise NotFound("active device %s of %s" % (device_name, user_name))
            self._bump()

    def device_for_token(self, token):
        """The active device a subscription token belongs to, or None. Records last_seen."""
        with self.lock:
            row = self.db.execute("SELECT * FROM devices WHERE token_hash = ? AND revoked_at IS NULL",
                                  (hash_token(token),)).fetchone()
            if row:
                self.db.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (self.clock(), row["id"]))
            return row

    def user_summary(self, name):
        with self.lock:
            u = self._user(name)
            out = {"user": u["name"], "egress_ip": u["egress_ip"], "entry": None}
            if u["egress_ip"]:
                h = self._host(self._host_of_ip(u["egress_ip"]))
                out["host"] = h["name"]
                out["entry"] = {"host": h["public_host"], "port": u["port"]}
            return out

    # -- rendering ---------------------------------------------------------------------------------------

    def inventory(self, host):
        """One host's state in the inventory format of egress/gen.py: every user bound to an IP of this host,
        each with its own entry port."""
        with self.lock:
            h = self._host(host)
            inv = {
                "server": {
                    "public_host": h["public_host"],
                    "block_private": bool(h["block_private"]),
                    "block_cidrs": json.loads(h["block_cidrs"]),
                    "reality": {
                        "private_key": h["reality_private"], "public_key": h["reality_public"],
                        "short_id": h["short_id"], "server_name": h["server_name"],
                        "handshake_server": h["handshake_server"], "handshake_port": h["handshake_port"],
                    },
                },
                "client_policy": self._get("client_policy", {}),
                "egress_ips": [],
                "users": [],
            }
            for row in self.db.execute("SELECT * FROM egress_ips WHERE host = ?", (host,)):
                status = self._ip_status(row)
                if self._holders(row["ip"]) and status == "cooldown":
                    status = "available"  # held IPs are never in cooldown; cooldown starts on release
                inv["egress_ips"].append({"ip": row["ip"], "status": status})
            for u in self.db.execute("SELECT u.* FROM users u JOIN egress_ips e ON u.egress_ip = e.ip "
                                     "WHERE e.host = ? ORDER BY u.name", (host,)):
                inv["users"].append({
                    "name": u["name"], "mode": u["mode"], "egress_ip": u["egress_ip"], "port": u["port"],
                    "devices": [{"name": d["name"], "uuid": d["uuid"], "revoked": d["revoked_at"] is not None}
                                for d in self.db.execute("SELECT * FROM devices WHERE user_name = ? ORDER BY name",
                                                         (u["name"],))],
                })
            gen.validate(inv)
            return inv

    def server_config(self, host):
        return gen.build_server(self.inventory(host))

    def client_config(self, device_row, mode):
        with self.lock:
            user = self._user(device_row["user_name"])
            if not user["egress_ip"]:
                raise Conflict("no exit IP is assigned to %s yet; ask the admin" % user["name"])
            inv = self.inventory(self._host_of_ip(user["egress_ip"]))
        return gen.build_client(inv, device_row["name"], mode=mode, user_name=device_row["user_name"])


class _Tx:
    """Serialise writers and wrap them in one SQLite transaction."""

    def __init__(self, store):
        self.store = store

    def __enter__(self):
        self.store.lock.acquire()
        self.store.db.execute("BEGIN IMMEDIATE")

    def __exit__(self, exc_type, exc, tb):
        try:
            self.store.db.execute("ROLLBACK" if exc_type else "COMMIT")
        finally:
            self.store.lock.release()
        return False
