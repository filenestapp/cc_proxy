"""Phase 3 of the control-plane e2e: the dashboard data reflects reality. Retries for up to 40 s while
probes come in. Uses CP_URL and CP_ADMIN_TOKEN."""
import json
import os
import sys
import time
import urllib.request

TARGET = "http://target.test:8080/strict"


def topology():
    req = urllib.request.Request(os.environ["CP_URL"] + "/admin/topology",
                                 headers={"Authorization": "Bearer " + os.environ["CP_ADMIN_TOKEN"]})
    return json.load(urllib.request.urlopen(req, timeout=5))


def checks(t):
    out = []
    agents = {a["name"]: a for a in t["agents"]}
    for host in ("hk-1", "jp-1"):
        a = agents.get(host)
        out.append(("agent %s heartbeat fresh" % host, a and a["age"] < 10, a and round(a["age"], 1)))
        out.append(("agent %s config in sync" % host, a and a["in_sync"], a and a["config_etag"]))
        out.append(("agent %s reports sing-box running" % host, a and a["singbox_running"] is True,
                    a and a["singbox_running"]))

    entries = {e["name"]: e for e in t["entries"]}
    for host in ("hk-1", "jp-1"):
        best = entries.get(host, {}).get("best") or {}
        out.append(("entry %s reachable from user-lan" % host, best.get("source") == "user-lan", best.get("latency_ms")))
    b = entries.get("backup", {})
    bp = b.get("probes") or [{}]
    out.append(("entry backup (closed port) reported down", bp[0].get("ok") is False, bp[0].get("detail")))

    ips = {i["ip"]: i for i in t["ips"]}
    for ip, want_ok in (("10.99.0.3", True), ("10.99.0.4", True), ("10.99.0.5", True),
                        ("10.99.0.6", False), ("10.99.0.13", True), ("10.99.0.14", True)):
        probes = {p["target"]: p for p in ips.get(ip, {}).get("probes", [])}
        p = probes.get(TARGET)
        if want_ok:
            good = p is not None and p["ok"] and p["latency_ms"] is not None
        else:
            good = p is not None and not p["ok"] and p["detail"] == "HTTP 403"
        out.append(("%s probe %s" % (ip, "ok" if want_ok else "fails with 403"), good,
                    p and (p["detail"], p["latency_ms"])))
    c = ips.get("10.99.0.5", {})
    out.append(("shared IP card lists both users and ports",
                c.get("users") == ["carol", "dave"] and len(set((c.get("ports") or {}).values())) == 2, c.get("ports")))
    hosts = {i["ip"]: i["host"] for i in t["ips"]}
    out.append(("IPs grouped under their hosts",
                (hosts.get("10.99.0.3"), hosts.get("10.99.0.13")) == ("hk-1", "jp-1"), (hosts.get("10.99.0.3"), hosts.get("10.99.0.13"))))
    return out


deadline = time.time() + 40
while True:
    results = checks(topology())
    if all(ok for _, ok, _ in results) or time.time() > deadline:
        break
    time.sleep(2)
for name, ok, got in results:
    print("%-4s %-44s %s" % ("PASS" if ok else "FAIL", name, got))
failed = sum(not ok for _, ok, _ in results)
print("topology: %d failure(s)" % failed)
sys.exit(1 if failed else 0)
