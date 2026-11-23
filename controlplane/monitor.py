"""Health data for the dashboard: agent heartbeats, per-IP egress probes, entry latency from vantage points.

None of this is configuration: writes here never bump the config version, so probes cannot trigger reloads.

Settings key "monitor" (PUT /admin/settings {"monitor": ...}):
  egress_targets  URLs the agent fetches from every egress IP, e.g. ["https://www.example.com/"]
  entries         extra entry points to measure, [{"name", "host", "port"}]. Every exit host is always
                  included under its own name, measured on the lowest entry port in use there
"""
import ipaddress
import time

from store import config_etag

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
  name TEXT PRIMARY KEY,
  last_seen REAL NOT NULL,
  config_etag TEXT,
  singbox_running INTEGER          -- NULL when the agent cannot tell
);
CREATE TABLE IF NOT EXISTS probes (
  id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('egress', 'entry')),
  subject TEXT NOT NULL,      -- egress IP, or entry name
  source TEXT NOT NULL,       -- agent name, or vantage name
  target TEXT NOT NULL,       -- URL, or host:port
  ok INTEGER NOT NULL,
  latency_ms REAL,
  detail TEXT NOT NULL DEFAULT '',
  at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS probes_lookup ON probes(kind, subject, source, target, at);
"""

RETENTION = 7 * 24 * 3600
HISTORY = 20          # results per (subject, source, target) kept for the success-rate bar
MAX_RESULTS = 2000    # per report, to bound a misbehaving reporter
APPLY_STATES = ("confirmed", "pending", "failed", "unknown")


class Monitor:
    def __init__(self, store, clock=None):
        self.store = store
        self.clock = clock or store.clock
        with store.lock:
            store.db.executescript(SCHEMA)
            cols = [r[1] for r in store.db.execute("PRAGMA table_info(agents)")]
            if "apply_error" not in cols:  # added after the first v2 databases
                store.db.execute("ALTER TABLE agents ADD COLUMN apply_error TEXT")
            if "apply_state" not in cols:
                store.db.execute("ALTER TABLE agents ADD COLUMN apply_state TEXT")

    # -- settings ----------------------------------------------------------------------------------------

    def egress_targets(self):
        return (self.store.setting("monitor") or {}).get("egress_targets", [])

    def entries(self):
        out = []
        with self.store.lock:
            for h in self.store.db.execute("SELECT name, public_host FROM hosts ORDER BY name"):
                row = self.store.db.execute(
                    "SELECT MIN(u.port) FROM users u JOIN egress_ips e ON u.egress_ip = e.ip WHERE e.host = ?",
                    (h["name"],)).fetchone()
                if row[0]:  # nothing listens on a host without users
                    out.append({"name": h["name"], "host": h["public_host"], "port": row[0], "kind": "host"})
        out += [dict(e, kind="extra") for e in (self.store.setting("monitor") or {}).get("entries", [])]
        return out

    # -- reports -----------------------------------------------------------------------------------------

    def heartbeat(self, agent, config_etag_value, singbox_running, apply_error=None, apply_state=None):
        """config_etag_value is the version sing-box confirmed running; apply_state is the state of the version the
        agent installed after it (confirmed, pending, failed, unknown); apply_error says why it is not running."""
        if apply_state not in APPLY_STATES:
            apply_state = None
        with self.store.lock:
            self.store.db.execute(
                "INSERT INTO agents(name, last_seen, config_etag, singbox_running, apply_error, apply_state) "
                "VALUES(?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(name) DO UPDATE SET last_seen = excluded.last_seen, config_etag = excluded.config_etag, "
                "singbox_running = excluded.singbox_running, apply_error = excluded.apply_error, "
                "apply_state = excluded.apply_state",
                (agent, self.clock(), (config_etag_value or "").strip('"') or None,
                 None if singbox_running is None else int(bool(singbox_running)),
                 str(apply_error)[:300] if apply_error else None, apply_state))

    def record(self, kind, source, results):
        """results: [{"subject", "target", "ok", "latency_ms"?, "detail"?}]"""
        if not isinstance(results, list) or len(results) > MAX_RESULTS:
            raise ValueError("results must be a list of at most %d items" % MAX_RESULTS)
        rows = []
        for r in results:
            try:
                subject, target = str(r["subject"]), str(r["target"])
                if kind == "egress":
                    subject = str(ipaddress.IPv4Address(subject))
                latency = r.get("latency_ms")
                rows.append((kind, subject, str(source), target, int(bool(r["ok"])),
                             float(latency) if latency is not None else None, str(r.get("detail", ""))[:200],
                             self.clock()))
            except (KeyError, TypeError, AttributeError) as e:
                raise ValueError("bad probe result %r: %s" % (r, e))
        with self.store.lock:
            self.store.db.executemany(
                "INSERT INTO probes(kind, subject, source, target, ok, latency_ms, detail, at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?)", rows)
            self.store.db.execute("DELETE FROM probes WHERE at < ?", (self.clock() - RETENTION,))
        return len(rows)

    # -- dashboard ---------------------------------------------------------------------------------------

    def _series(self, kind, subject):
        """Latest HISTORY results per (source, target) for one subject, newest first."""
        rows = self.store.db.execute(
            "SELECT * FROM probes WHERE kind = ? AND subject = ? ORDER BY at DESC", (kind, subject)).fetchall()
        series = {}
        for r in rows:
            key = (r["source"], r["target"])
            if len(series.setdefault(key, [])) < HISTORY:
                series[key].append(r)
        out = []
        for (source, target), items in sorted(series.items()):
            last = items[0]
            out.append({
                "source": source, "target": target, "ok": bool(last["ok"]),
                "latency_ms": last["latency_ms"], "detail": last["detail"], "at": last["at"],
                "history": [bool(i["ok"]) for i in reversed(items)],
            })
        return out

    def topology(self):
        store = self.store
        now = self.clock()
        hosts = store.list_hosts()
        current = {}
        for h in hosts:
            try:
                current[h["name"]] = config_etag(store.server_config(h["name"]))
            except Exception:  # an invalid host inventory must not take the dashboard down
                current[h["name"]] = None
        with store.lock:
            agents = [{
                "name": a["name"], "last_seen": a["last_seen"], "age": now - a["last_seen"],
                "config_etag": a["config_etag"],
                # Same ETag is not enough when the agent says the installed generation is not proved yet (it may
                # be re-proving the same content after another version ran). Legacy agents send no apply_state.
                "in_sync": a["config_etag"] == current.get(a["name"]) and a["apply_state"] in (None, "confirmed"),
                "singbox_running": None if a["singbox_running"] is None else bool(a["singbox_running"]),
                "apply_error": a["apply_error"], "apply_state": a["apply_state"],
            } for a in store.db.execute("SELECT * FROM agents WHERE name IN (SELECT name FROM hosts) ORDER BY name")]
            entries = []
            for e in self.entries():
                probes = self._series("entry", e["name"])
                ok = [p for p in probes if p["ok"] and p["latency_ms"] is not None]
                best = min(ok, key=lambda p: p["latency_ms"]) if ok else None
                entries.append(dict(e, probes=probes, best=best))
            users = {u["name"]: u for u in store.list_users()}
            ips = []
            for ip in store.list_ips():
                holders = [users[n] for n in ip["users"] if n in users]
                ips.append(dict(
                    ip,
                    devices=sum(1 for u in holders for d in u["devices"] if not d["revoked"]),
                    probes=self._series("egress", ip["ip"]),
                ))
        return {
            "now": now, "version": store.version(), "server_config_etags": current, "hosts": hosts,
            "egress_targets": self.egress_targets(), "agents": agents, "entries": entries, "ips": ips,
        }
