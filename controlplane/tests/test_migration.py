"""Exercise the SQLite v2 cutover, including legacy credentials and config ETags."""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import time
from urllib.request import Request, urlopen

import test_controlplane as tc
import gen

AGENT = "legacy-agent-token"
DEVICE = "legacy-device-token"
COOKIE = "legacy-session-token"
UUID = "c05010b4-88d9-481f-8874-11fdd4a0fa83"
PASSWORD = "legacy-password"

# Only legacy columns are needed by the importer. This fixture predates agents.apply_error and agents.apply_state.
SQLITE_V2 = """
CREATE TABLE settings(key, value);
CREATE TABLE hosts(name, public_host, port_min, port_max, reality_private, reality_public, short_id,
    server_name, handshake_server, handshake_port, block_private, block_cidrs, agent_token_hash, created_at);
CREATE TABLE egress_ips(ip, host, banned, cooldown_until, note);
CREATE TABLE users(name, password_hash, mode, egress_ip, port, max_devices, created_at);
CREATE TABLE devices(id, user_name, name, platform, uuid, token_hash, revoked_at, last_seen, created_at);
CREATE TABLE admins(name, password_hash, created_at, last_login);
CREATE TABLE admin_sessions(token_hash, admin, csrf, created_at, expires_at, address);
CREATE TABLE audit(id, at, actor, action, target, detail, address);
CREATE TABLE agents(name, last_seen, config_etag, singbox_running);
CREATE TABLE probes(id, kind, subject, source, target, ok, latency_ms, detail, at);
CREATE TABLE alerts(id, key, rule, subject, severity, summary, state, started_at, fired_at,
    resolved_at, notify, notified_at, notify_error);
"""


def token_hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def config_bytes(cfg):
    return (json.dumps(cfg, indent=2) + "\n").encode()


def etag(body):
    return '"' + hashlib.sha256(body).hexdigest()[:20] + '"'


class MigrationTest(tc.ServerFixture):
    def setUp(self):
        self.create_schema()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.sqlite = Path(tmp.name) / "v2.db"
        self.inventory = {
            "server": {
                "public_host": "203.0.113.2",
                "block_private": True,
                "block_cidrs": ["169.254.169.254/32"],
                "reality": {
                    "private_key": "old-private-key", "public_key": "old-public-key", "short_id": "1a2b",
                    "server_name": "www.example.com", "handshake_server": "www.example.com", "handshake_port": 443,
                },
            },
            "client_policy": {"domain_suffix": ["target.example"], "process_name": ["Terminal"], "direct_dns": "local"},
            "egress_ips": [{"ip": "203.0.113.3", "status": "available"}],
            "users": [{"name": "alice", "egress_ip": "203.0.113.3", "port": 20004,
                       "devices": [{"name": "desk&<>", "uuid": UUID}]}],
        }
        now = time.time()
        salt = b"0123456789abcdef"
        digest = hashlib.pbkdf2_hmac("sha256", PASSWORD.encode(), salt, 200_000)
        pw = f"pbkdf2_sha256$200000${salt.hex()}${digest.hex()}"
        with closing(sqlite3.connect(self.sqlite)) as db, db:
            db.executescript(SQLITE_V2)
            db.executemany("INSERT INTO settings VALUES (?,?)", (
                ("schema", "2"), ("version", "42"), ("client_policy", json.dumps(self.inventory["client_policy"])),
            ))
            host = self.inventory["server"]
            reality = host["reality"]
            db.execute("INSERT INTO hosts VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       ("hk", host["public_host"], 20000, 20009, reality["private_key"], reality["public_key"],
                        reality["short_id"], reality["server_name"], reality["handshake_server"], 443, 1,
                        json.dumps(host["block_cidrs"]), token_hash(AGENT), now))
            db.execute("INSERT INTO egress_ips VALUES ('203.0.113.3', 'hk', 0, 0, '')")
            db.execute("INSERT INTO users VALUES ('alice', ?, 'exclusive', '203.0.113.3', 20004, 5, ?)", (pw, now))
            db.execute("INSERT INTO devices VALUES (99,'alice','desk&<>','macos',?,?,NULL,?,?)",
                       (UUID, token_hash(DEVICE), now, now))
            db.execute("INSERT INTO admins VALUES ('root',?,?,?)", (pw, now, now))
            db.execute("INSERT INTO admin_sessions VALUES (?,'root','old-csrf',?,?,'192.0.2.1')",
                       (token_hash(COOKIE), now, now + 3600))
            db.execute("INSERT INTO audit VALUES (25,?,'root','legacy change','','tab\t line\n slash\\','192.0.2.1')", (now,))
            db.execute("INSERT INTO agents VALUES ('hk',?,?,1)", (now, etag(config_bytes(gen.build_server(self.inventory))).strip('"')))
            db.execute("INSERT INTO probes VALUES (33,'egress','203.0.113.3','hk','https://target.example',1,23.5,'',?)", (now,))
            db.execute("INSERT INTO alerts VALUES (17,'test','test','hk','warning','old alert','resolved',?,NULL,?,NULL,?,NULL)",
                       (now, now, now))

    def migrate(self):
        return subprocess.run([str(tc.server_binary()), "migrate-sqlite", str(self.sqlite)],
                              env=dict(os.environ, DATABASE_URL=self.dsn), capture_output=True, text=True)

    def test_snapshot_preserves_credentials_config_and_history(self):
        before = self.sqlite.read_bytes()
        result = self.migrate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sqlite.read_bytes(), before)
        self.start_server()
        self.assertEqual(self.req("GET", "/healthz")[2]["version"], 42)
        self.assertEqual(self.req("GET", "/admin/session", headers={"Cookie": "cp_session=" + COOKIE})[2]["csrf"], "old-csrf")
        configs = [("/agent/server-config", AGENT, gen.build_server(self.inventory))]
        configs.extend(("/v1/config?mode=" + mode, DEVICE, gen.build_client(self.inventory, "desk&<>", mode=mode))
                       for mode in ("proxy", "domain", "app"))
        for path, token, cfg in configs:
            with self.subTest(path=path):
                expected = config_bytes(cfg)
                with urlopen(Request(self.base + path, headers={"Authorization": "Bearer " + token}), timeout=5) as resp:
                    self.assertEqual(resp.read(), expected)
                    self.assertEqual(resp.headers["ETag"], etag(expected))
                self.assertEqual(self.req("GET", path, token, headers={"If-None-Match": etag(expected)})[0], 304)
        topo = self.admin("GET", "/admin/topology")[1]
        self.assertTrue(topo["agents"][0]["in_sync"])
        self.assertIsNone(topo["agents"][0]["apply_error"])
        self.assertIsNone(topo["agents"][0]["apply_state"])
        self.assertEqual(topo["ips"][0]["probes"][0]["latency_ms"], 23.5)
        self.assertEqual(self.admin("GET", "/admin/audit")[1][0]["detail"], "tab\t line\n slash\\")
        self.assertEqual(self.admin("GET", "/admin/alerts?all=1")[1][0]["id"], 17)
        self.assertEqual(self.login(password=PASSWORD, device="new")[0], 200)
        self.assertEqual(self.sql(f"SELECT max(id) FROM {self.schema}.devices").strip(), "100")
        self.assertEqual(self.req("POST", "/admin/session", body={"username": "root", "password": PASSWORD})[0], 200)
        result = self.migrate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not empty", result.stderr)

    def test_failed_import_rolls_back_and_can_be_retried(self):
        with closing(sqlite3.connect(self.sqlite)) as db, db:
            db.execute("UPDATE users SET egress_ip = '192.0.2.98'")
        result = self.migrate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("copy SQLite table users", result.stderr)
        self.assertEqual(self.sql(f"SELECT count(*) FROM {self.schema}.hosts").strip(), "0")
        self.assertEqual(self.sql(f"SELECT count(*) FROM {self.schema}.settings").strip(), "1")
        with closing(sqlite3.connect(self.sqlite)) as db, db:
            db.execute("UPDATE users SET egress_ip = '203.0.113.3'")
            db.execute("ALTER TABLE agents ADD COLUMN apply_error TEXT")
            db.execute("ALTER TABLE agents ADD COLUMN apply_state TEXT")
            db.execute("UPDATE agents SET apply_error = 'Checking configuration', apply_state = 'pending'")
        result = self.migrate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.sql(f"SELECT apply_state FROM {self.schema}.agents").strip(), "pending")
