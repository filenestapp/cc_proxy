"""Alerting: evaluate rules over the dashboard topology, track alert state, notify webhooks on fire and resolve.

Rules (thresholds under settings "alerts"):
  egress_probe_failing  an egress IP failed its last `consecutive_failures` probes of a target.
                        critical when users hold the IP, warning otherwise (a blocked spare should not be
                        handed out). Banned IPs are skipped: banning is the operator's answer to this alert.
  entry_unreachable     a vantage point failed its last `consecutive_failures` connects to an entry (warning;
                        critical when every vantage reporting on that entry is failing).
  agent_stale           no heartbeat for `agent_stale_seconds` (critical).
  singbox_down          the agent reports sing-box not running (critical).
  agent_out_of_sync     the agent's installed config differs from the current one for `out_of_sync_seconds`
                        (warning). The agent settles before installing, so this needs a grace period.

An alert is pending while its condition holds but its `for` time has not passed, firing after that, and resolved
once the condition clears. A notification is queued on firing and on resolving (and every `repeat_seconds`
while firing, if set). Delivery is retried on each evaluation until every webhook accepts it, so a webhook can
see the same notification twice after a partial failure.

Settings "alerts":
  webhooks              [{"url", "format": "generic"|"slack"|"feishu"|"dingtalk"|"wecom"}]
  consecutive_failures  3
  agent_stale_seconds   120
  out_of_sync_seconds   300
  repeat_seconds        0 (no reminders)
  eval_interval         15
"""
import json
import sys
import threading
import time
import urllib.request

DEFAULTS = {
    "webhooks": [], "consecutive_failures": 3, "agent_stale_seconds": 120, "out_of_sync_seconds": 300,
    "repeat_seconds": 0, "eval_interval": 15,
}
FORMATS = ("generic", "slack", "feishu", "dingtalk", "wecom")
HISTORY_DAYS = 30

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY,
  key TEXT NOT NULL,              -- rule/subject/...; at most one pending or firing row per key
  rule TEXT NOT NULL,
  subject TEXT NOT NULL,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending', 'firing', 'resolved')),
  started_at REAL NOT NULL,
  fired_at REAL,
  resolved_at REAL,
  notify TEXT,                    -- queued notification: 'firing' or 'resolved'
  notified_at REAL,
  notify_error TEXT
);
CREATE INDEX IF NOT EXISTS alerts_active ON alerts(key, state);
"""


def validate_settings(cfg):
    if not isinstance(cfg, dict):
        raise ValueError("alerts must be an object")
    unknown = set(cfg) - set(DEFAULTS)
    if unknown:
        raise ValueError("unknown alerts settings: %s" % ", ".join(sorted(unknown)))
    for hook in cfg.get("webhooks", []):
        if not isinstance(hook, dict) or not str(hook.get("url", "")).startswith(("http://", "https://")):
            raise ValueError("each webhook needs an http(s) url")
        if hook.get("format", "generic") not in FORMATS:
            raise ValueError("webhook format must be one of %s" % ", ".join(FORMATS))
    for key in DEFAULTS:
        if key != "webhooks" and key in cfg and (not isinstance(cfg[key], (int, float)) or cfg[key] < 0):
            raise ValueError("alerts.%s must be a non-negative number" % key)
    if cfg.get("consecutive_failures", 3) < 1:
        raise ValueError("alerts.consecutive_failures must be at least 1")


def message(alert, status):
    if status == "resolved":
        return "[Resolved] %s" % alert["summary"]  # the condition cleared: recovered, or e.g. the IP was banned
    return "[%s] %s" % ("Critical" if alert["severity"] == "critical" else "Warning", alert["summary"])


def payload(fmt, alert, status):
    text = message(alert, status)
    if fmt == "slack":
        return {"text": text}
    if fmt == "feishu":
        return {"msg_type": "text", "content": {"text": text}}
    if fmt in ("dingtalk", "wecom"):
        return {"msgtype": "text", "text": {"content": text}}
    return {
        "status": status, "rule": alert["rule"], "subject": alert["subject"], "severity": alert["severity"],
        "summary": alert["summary"], "text": text, "started_at": alert["started_at"],
        "fired_at": alert["fired_at"], "resolved_at": alert["resolved_at"],
    }


def post_json(url, body, timeout=5):
    req = urllib.request.Request(url, data=json.dumps(body, ensure_ascii=False).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        if resp.status >= 300:
            raise OSError("HTTP %d" % resp.status)


class Alerter:
    def __init__(self, store, monitor, clock=None, send=post_json, log=None):
        self.store = store
        self.monitor = monitor
        self.clock = clock or store.clock
        self.send = send
        self.log = log or (lambda m: print(m, file=sys.stderr, flush=True))
        with store.lock:
            store.db.executescript(SCHEMA)

    def settings(self):
        return dict(DEFAULTS, **(self.store.setting("alerts") or {}))

    # -- rules -------------------------------------------------------------------------------------------

    def conditions(self, topo, cfg):
        """Everything that is wrong right now: {key: (rule, subject, severity, summary, for_seconds)}."""
        k = int(cfg["consecutive_failures"])
        out = {}

        def failing(series):
            return len(series["history"]) >= k and not any(series["history"][-k:])

        for ip in topo["ips"]:
            if ip["status"] == "banned":
                continue
            for p in ip["probes"]:
                if not failing(p):
                    continue
                users = ip["users"]
                sev = "critical" if users else "warning"
                who = " (affected users: %s)" % ", ".join(users) if users else " (unassigned)"
                out["egress_probe_failing/%s/%s" % (ip["ip"], p["target"])] = (
                    "egress_probe_failing", ip["ip"], sev,
                    "Egress IP %s failed to reach %s %d times in a row%s%s. If the target confirmed a ban, run cpctl ban %s."
                    % (ip["ip"], p["target"], k, ": " + p["detail"] if p["detail"] else "", who, ip["ip"]), 0)

        for e in topo["entries"]:
            bad = [p for p in e["probes"] if failing(p)]
            all_bad = bad and len(bad) == len(e["probes"])
            for p in bad:
                out["entry_unreachable/%s/%s" % (e["name"], p["source"])] = (
                    "entry_unreachable", e["name"], "critical" if all_bad else "warning",
                    "Entry %s (%s:%s) was unreachable from %s %d times in a row%s%s."
                    % (e["name"], e["host"], e["port"], p["source"], k, ": " + p["detail"] if p["detail"] else "",
                       ". All probe locations failed" if all_bad else ""), 0)

        for a in topo["agents"]:
            if a["age"] > cfg["agent_stale_seconds"]:
                out["agent_stale/%s" % a["name"]] = (
                    "agent_stale", a["name"], "critical",
                    "Egress host %s has missed heartbeats for %d seconds." % (a["name"], a["age"]), 0)
                continue  # a silent agent's other fields are stale too
            if a["singbox_running"] is False:
                out["singbox_down/%s" % a["name"]] = (
                    "singbox_down", a["name"], "critical", "sing-box is stopped on egress host %s." % a["name"], 0)
            if not a["in_sync"] and topo["server_config_etags"].get(a["name"]):
                out["agent_out_of_sync/%s" % a["name"]] = (
                    "agent_out_of_sync", a["name"], "warning",
                    "The configuration on egress host %s is out of sync." % a["name"], cfg["out_of_sync_seconds"])
        return out

    # -- state machine -----------------------------------------------------------------------------------

    def evaluate(self):
        """One evaluation round: update alert states, then deliver queued notifications."""
        cfg = self.settings()
        now = self.clock()
        conds = self.conditions(self.monitor.topology(), cfg)
        db = self.store.db
        with self.store.lock:
            active = {r["key"]: r for r in db.execute("SELECT * FROM alerts WHERE state != 'resolved'")}
            for key, row in active.items():
                if key in conds:
                    continue
                if row["state"] == "pending":
                    db.execute("DELETE FROM alerts WHERE id = ?", (row["id"],))
                else:
                    db.execute("UPDATE alerts SET state = 'resolved', resolved_at = ?, notify = 'resolved' "
                               "WHERE id = ?", (now, row["id"]))
            for key, (rule, subject, severity, summary, for_seconds) in conds.items():
                row = active.get(key)
                if row is None:
                    state = "firing" if for_seconds <= 0 else "pending"
                    db.execute(
                        "INSERT INTO alerts(key, rule, subject, severity, summary, state, started_at, fired_at, notify) "
                        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (key, rule, subject, severity, summary, state, now,
                         now if state == "firing" else None, "firing" if state == "firing" else None))
                    continue
                db.execute("UPDATE alerts SET severity = ?, summary = ? WHERE id = ?", (severity, summary, row["id"]))
                if row["state"] == "pending" and now - row["started_at"] >= for_seconds:
                    db.execute("UPDATE alerts SET state = 'firing', fired_at = ?, notify = 'firing' WHERE id = ?",
                               (now, row["id"]))
                elif (row["state"] == "firing" and cfg["repeat_seconds"] and row["notified_at"]
                      and now - row["notified_at"] >= cfg["repeat_seconds"] and row["notify"] is None):
                    db.execute("UPDATE alerts SET notify = 'firing' WHERE id = ?", (row["id"],))
            db.execute("DELETE FROM alerts WHERE state = 'resolved' AND resolved_at < ?", (now - HISTORY_DAYS * 86400,))
            queued = [dict(r) for r in db.execute("SELECT * FROM alerts WHERE notify IS NOT NULL ORDER BY id")]
        self.deliver(queued, cfg["webhooks"])

    def deliver(self, queued, webhooks):
        for alert in queued:
            status = alert["notify"]
            errors = []
            for hook in webhooks:
                try:
                    self.send(hook["url"], payload(hook.get("format", "generic"), alert, status))
                except (OSError, ValueError) as e:
                    errors.append("%s: %s" % (hook["url"], e))
            with self.store.lock:
                if errors:
                    self.store.db.execute("UPDATE alerts SET notify_error = ? WHERE id = ?",
                                          ("; ".join(errors)[:500], alert["id"]))
                    self.log("alert %s: delivery failed, will retry: %s" % (alert["key"], "; ".join(errors)))
                else:
                    self.store.db.execute(
                        "UPDATE alerts SET notify = NULL, notified_at = ?, notify_error = NULL WHERE id = ?",
                        (self.clock(), alert["id"]))
                    self.log("alert %s %s: %s" % (alert["key"], status, alert["summary"]))

    def list(self, include_resolved=False, limit=200):
        with self.store.lock:
            where = "" if include_resolved else "WHERE state = 'firing'"
            rows = self.store.db.execute(
                "SELECT * FROM alerts %s ORDER BY CASE state WHEN 'firing' THEN 0 WHEN 'pending' THEN 1 ELSE 2 END, "
                "CASE severity WHEN 'critical' THEN 0 ELSE 1 END, started_at DESC LIMIT ?" % where, (limit,))
            return [dict(r) for r in rows]

    def run_forever(self, stop=None):
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                self.evaluate()
            except Exception as e:  # keep alerting alive; a bad round must not kill the thread
                self.log("alert evaluation failed: %r" % e)
            stop.wait(self.settings()["eval_interval"] or 15)

    def start(self):
        stop = threading.Event()
        threading.Thread(target=self.run_forever, args=(stop,), daemon=True, name="alerter").start()
        return stop
