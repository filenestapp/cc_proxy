#!/usr/bin/env python3
"""Usage e2e driver (started by run-e2e.sh). Talks to the control plane over TLS as an administrator and as
devices, starts containers with docker compose, generates traffic inside the client containers and checks the
admin usage report against the payload bytes each device actually moved.

Phases
  1  provisioning: hk-1 (current agent) and jp-1 (previous agent release); alice (two devices) and bob share one
     egress IPv4 on hk-1; carol is on jp-1
  2  attribution: concurrent short-lived and long transfers from three devices on the shared IP, exact per device
  3  collector retries: the control plane is down while traffic flows; it arrives once after it is back
  4  reload: a configuration change reloads sing-box while a connection is live; the cut is reported, later
     traffic counts from zero
  5  agent restart: the exit container restarts; earlier traffic is not counted again, new traffic is
  6  compatibility: the previous agent keeps its exit in sync and the console marks its usage unavailable
  7  recreated account: alice is deleted right after alice/win moved traffic and is recreated with the same names
     on the same IP; within the same hour the old traffic stays with the deleted device and the new device counts
     only its own. Both identities exist in that hour, so this holds only with the credential hashes the agent
     proves from the running config: name-only reports would leave the bytes unresolved and fail the last check
"""
import json
import os
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
CP = "https://127.0.0.1:18444"
ADMIN = os.environ["CP_ADMIN_TOKEN"]
CTX = ssl.create_default_context(cafile=os.path.join(OUT, "tls", "ca.pem"))
SGT = timezone(timedelta(hours=8))
DEVICES = [("alice", "mac"), ("alice", "win"), ("bob", "phone"), ("carol", "laptop")]
TAIL_LIMIT = 64 << 10  # bytes a cut connection may lose: its last 250 ms at the stream's rate, with headroom

failures = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else "  -- " + detail), flush=True)
    if not ok:
        failures.append(name)


def call(method, path, body=None, token=ADMIN):
    req = urllib.request.Request(CP + path, data=json.dumps(body).encode() if body is not None else None, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=15, context=CTX) as resp:
            data = resp.read()
            return resp.status, json.loads(data) if data[:1] in (b"{", b"[") else data
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except (urllib.error.URLError, ConnectionError, OSError) as e:
        return 0, str(e)  # the control plane is down or restarting


def must(method, path, body=None, token=ADMIN):
    status, out = call(method, path, body, token)
    if status >= 300:
        raise SystemExit("%s %s: HTTP %d %s" % (method, path, status, out))
    return out


def compose(*args, env=None):
    cmd = ["docker", "compose", "-f", os.path.join(HERE, "compose.yaml")] + list(args)
    return subprocess.run(cmd, check=True, capture_output=True, text=True, env=dict(os.environ, **(env or {}))).stdout


def gen(device, *args):
    out = compose("exec", "-T", "client-" + device, "python3", "/app/gen.py", *map(str, args))
    return json.loads(out.strip().splitlines()[-1])


def try_gen(device, *args):
    try:
        return gen(device, *args)
    except subprocess.CalledProcessError:
        return None  # the tunnel is not up yet


def wait_for(what, fn, timeout=90):
    deadline = time.time() + timeout
    while True:
        value = fn()
        if value:
            return value
        if time.time() > deadline:
            raise SystemExit("timed out waiting for " + what)
        time.sleep(1)


def report_rows():
    """Per-device sums over today and yesterday in Singapore, so a run across midnight still adds up."""
    today = datetime.now(SGT).date()
    rows = {}
    for day in (today - timedelta(days=1), today):
        report = must("GET", "/admin/usage?period=day&date=" + day.isoformat())
        for r in report["rows"]:
            key = (r["user"], r["device"]) + (("deleted",) if r["device_state"] == "deleted" else ())
            acc = rows.setdefault(key, {"upload": 0, "download": 0, "total": 0, "cut": 0, "statuses": set(),
                                        "reasons": set(), "state": r["device_state"]})
            acc["upload"] += r["upload"]
            acc["download"] += r["download"]
            acc["total"] += r["total"]
            acc["cut"] += r["cut_connections"]
            if r["status"] != "unavailable" or day == today:  # yesterday's empty day is not this run's status
                acc["statuses"].add(r["status"])
            acc["reasons"].update(r["reasons"])
    return rows, report


def settle(expected, label, timeout=90):
    """Waits until the report shows exactly the expected bytes, then one more report cycle to rule out repeats."""
    def matches():
        rows, _ = report_rows()
        return all(rows.get(k, {}).get("upload") == v[0] and rows.get(k, {}).get("download") == v[1]
                   for k, v in expected.items())
    deadline = time.time() + timeout
    while time.time() < deadline and not matches():
        time.sleep(2)
    time.sleep(22)  # two more usage reports (--usage-interval 10)
    rows, report = report_rows()
    for key, (up, down) in expected.items():
        got = rows.get(key, {})
        check("%s: %s/%s upload %d download %d" % (label, key[0], key[1], up, down),
              got.get("upload") == up and got.get("download") == down and got.get("total") == up + down,
              "report shows %s" % {k: got.get(k) for k in ("upload", "download", "total")})
    return rows, report


def topology_agent(name):
    for agent in must("GET", "/admin/topology")["agents"]:
        if agent["name"] == name:
            return agent
    return {}


def collector(host):
    for c in must("GET", "/admin/usage")["collectors"]:
        if c["host"] == host:
            return c
    return {}


def main():
    print("== phase 1: provisioning")
    block = ["10.99.1.20/32", "169.254.169.254/32"]
    hk = must("POST", "/admin/hosts", {"name": "hk-1", "public_host": "10.88.1.2", "server_name": "decoy.test",
                                       "handshake_server": "10.99.1.20", "port_min": 20000, "port_max": 20099,
                                       "block_private": False, "block_cidrs": block})["agent_token"]
    jp = must("POST", "/admin/hosts", {"name": "jp-1", "public_host": "10.88.1.3", "server_name": "decoy.test",
                                       "handshake_server": "10.99.1.20", "port_min": 30000, "port_max": 30099,
                                       "block_private": False, "block_cidrs": block})["agent_token"]
    must("POST", "/admin/hosts/hk-1/ips", {"ips": ["10.99.1.2"]})
    must("POST", "/admin/hosts/jp-1/ips", {"ips": ["10.99.1.12"]})
    for user, mode in (("alice", "shared"), ("bob", "shared"), ("carol", "exclusive")):
        must("POST", "/admin/users", {"name": user, "mode": mode, "password": "pw-%s-0123" % user})
    must("POST", "/admin/users/alice/assign", {"ip": "10.99.1.2"})
    must("POST", "/admin/users/bob/assign", {"ip": "10.99.1.2"})
    must("POST", "/admin/users/carol/assign", {"host": "jp-1"})
    compose("--profile", "exits", "up", "-d", "exit-hk", "exit-jp", env={"HK_TOKEN": hk, "JP_TOKEN": jp})

    os.makedirs(os.path.join(OUT, "clients"), exist_ok=True)
    for user, device in DEVICES:
        login = must("POST", "/v1/login", {"username": user, "password": "pw-%s-0123" % user, "device": device}, token="")
        fetch = lambda: call("GET", "/v1/config?mode=proxy", token=login["token"])
        config = wait_for("a client config for %s/%s" % (user, device), lambda: (lambda r: r[1] if r[0] == 200 else None)(fetch()))
        with open(os.path.join(OUT, "clients", "%s-%s.json" % (user, device)), "w") as f:
            json.dump(config, f)
    compose("--profile", "clients", "up", "-d", *["client-%s-%s" % d for d in DEVICES])

    wait_for("hk-1 to confirm its config", lambda: topology_agent("hk-1").get("apply_state") == "confirmed")
    wait_for("jp-1 (previous agent) to confirm its config", lambda: topology_agent("jp-1").get("apply_state") == "confirmed")
    wait_for("usage collection on hk-1", lambda: collector("hk-1").get("status") == "collecting", timeout=60)
    print("hk-1 collector:", {k: collector("hk-1").get(k) for k in ("status", "agent_version", "singbox_version")})
    # Clients reach their exits (a sized transfer through each tunnel before measuring).
    for user, device in DEVICES:
        wait_for("a tunnel for %s/%s" % (user, device), lambda: try_gen("%s-%s" % (user, device), "short", 1, 1, 1), timeout=60)
    expected = {}

    def add(key, result):
        up, down = expected.get(key, (0, 0))
        expected[key] = (up + result["up"], down + result["down"])

    # The warm-up transfers count too.
    for user, device in DEVICES:
        add((user, device), {"up": len(b"u 1 d 1\n") + 1, "down": 1})

    print("== phase 2: attribution on a shared egress IPv4")
    results = {}

    def run(name, *args):
        results[name] = gen(*args)

    threads = [threading.Thread(target=run, args=("mac", "alice-mac", "short", 40, 1000, 50000)),
               threading.Thread(target=run, args=("win", "alice-win", "parallel", 10, 7000, 3000)),
               threading.Thread(target=run, args=("phone", "bob-phone", "parallel", 1, 2_000_000, 5_000_000)),
               threading.Thread(target=run, args=("laptop", "carol-laptop", "short", 5, 100, 100))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    print("generated:", results)
    add(("alice", "mac"), results["mac"])
    add(("alice", "win"), results["win"])
    add(("bob", "phone"), results["phone"])
    hk_expected = {k: v for k, v in expected.items() if k[0] != "carol"}
    rows, report = settle(hk_expected, "attribution")
    check("carol on the previous agent is not measured", rows.get(("carol", "laptop"), {}).get("statuses") == {"unavailable"},
          str(rows.get(("carol", "laptop"))))
    check("measured devices are complete or show why not",
          all(rows[k]["statuses"] <= {"complete", "incomplete"} for k in hk_expected))

    print("== phase 3: control plane outage, collector retries")
    compose("stop", "cp")
    outage = gen("alice-mac", "short", 10, 3000, 30000)
    time.sleep(25)  # at least two failed usage reports
    compose("start", "cp")
    wait_for("the control plane", lambda: call("GET", "/healthz", token="")[0] == 200)
    add(("alice", "mac"), outage)
    settle(hk_expected | {("alice", "mac"): expected[("alice", "mac")]}, "after outage")

    print("== phase 4: reload while a connection is live")
    before = report_rows()[0]
    stream = {}
    t = threading.Thread(target=lambda: stream.update(gen("alice-mac", "stream", 30)))
    t.start()
    time.sleep(4)
    must("POST", "/admin/users/bob/devices", {"name": "tablet"})  # changes hk-1's config: the agent reloads sing-box
    t.join()
    print("stream:", stream)
    check("the reload cut the live connection", stream.get("cut") is True, str(stream))
    after_reload = gen("alice-mac", "short", 5, 2000, 2000)
    wait_for("the reload to be reported", lambda: report_rows()[0][("alice", "mac")]["cut"] >= 1, timeout=60)
    time.sleep(22)
    rows = report_rows()[0]
    got = rows[("alice", "mac")]
    stream_up = got["upload"] - before[("alice", "mac")]["upload"] - after_reload["up"]
    stream_down = got["download"] - before[("alice", "mac")]["download"] - after_reload["down"]
    check("cut connection counted up to its last update (upload %d of %d)" % (stream_up, stream["up"]),
          stream["up"] - TAIL_LIMIT <= stream_up <= stream["up"])
    check("cut connection counted up to its last update (download %d of %d)" % (stream_down, stream["down"]),
          stream["down"] - TAIL_LIMIT <= stream_down <= stream["down"])
    check("the cut is reported on alice/mac", got["cut"] >= 1 and "incomplete" in got["statuses"] and
          any("reload" in r for r in got["reasons"]), str(got))
    check("traffic after the reload counts from zero, nothing doubled",
          rows[("alice", "win")]["upload"] == expected[("alice", "win")][0] and
          rows[("bob", "phone")]["upload"] == expected[("bob", "phone")][0])
    expected[("alice", "mac")] = (got["upload"], got["download"])

    print("== phase 5: exit container restart")
    compose("--profile", "exits", "restart", "exit-hk", env={"HK_TOKEN": hk, "JP_TOKEN": jp})
    wait_for("hk-1 to confirm again", lambda: topology_agent("hk-1").get("apply_state") == "confirmed")
    wait_for("usage collection again", lambda: collector("hk-1").get("status") == "collecting", timeout=60)
    wait_for("the alice/win tunnel again", lambda: try_gen("alice-win", "short", 1, 10, 10), timeout=60)
    add(("alice", "win"), {"up": len(b"u 10 d 10\n") + 10, "down": 10})
    add(("alice", "win"), gen("alice-win", "short", 3, 4000, 4000))
    rows, _ = settle({k: v for k, v in expected.items() if k[0] != "carol"}, "after restart")

    print("== phase 6: compatibility")
    jp_agent = topology_agent("jp-1")
    check("the previous agent release still syncs its exit", jp_agent.get("apply_state") == "confirmed", str(jp_agent))
    jp_usage = collector("jp-1")
    check("the console marks jp-1 usage collection unavailable",
          jp_usage.get("status") == "unavailable" and "does not report usage" in jp_usage.get("note", ""), str(jp_usage))

    print("== phase 7: account deleted and recreated with the same names within the hour")
    old_win = gen("alice-win", "short", 5, 1111, 2222)
    must("DELETE", "/admin/users/alice")  # before the agent's next usage report, which arrives after this
    must("POST", "/admin/users", {"name": "alice", "mode": "shared", "password": "pw-alice-0123"})
    must("POST", "/admin/users/alice/assign", {"ip": "10.99.1.2"})
    login = must("POST", "/v1/login", {"username": "alice", "password": "pw-alice-0123", "device": "win"}, token="")
    fetch = lambda: call("GET", "/v1/config?mode=proxy", token=login["token"])
    config = wait_for("the recreated device's config", lambda: (lambda r: r[1] if r[0] == 200 else None)(fetch()))
    with open(os.path.join(OUT, "clients", "alice-win.json"), "w") as f:
        json.dump(config, f)
    compose("--profile", "clients", "restart", "client-alice-win")
    wait_for("the recreated device's tunnel", lambda: try_gen("alice-win", "short", 1, 5, 5), timeout=90)
    new_win = gen("alice-win", "short", 3, 333, 444)
    names = compose("exec", "-T", "exit-hk", "sh", "-c", "grep -o '\"name\": \"alice/[^\"]*\"' /etc/sing-box/config.json")
    print("exit config names:", " ".join(names.split()), "| old phase:", old_win, "| new phase:", new_win)
    check("the server config keeps its <user>/<device> names", '"name": "alice/win"' in names, names)
    for device in ("mac", "win"):
        expected[("alice", device, "deleted")] = expected.pop(("alice", device))
    add(("alice", "win", "deleted"), old_win)
    expected[("alice", "win")] = (len(b"u 5 d 5\n") + 5 + new_win["up"], 5 + new_win["down"])
    rows, report = settle({k: v for k, v in expected.items() if k[0] != "carol"}, "recreated account")
    check("nothing was left unresolved or rejected", not any(h["unresolved_upload"] or h["rejected_upload"]
                                                             for h in report["hosts"]), str(report["hosts"]))

    rows, report = report_rows()
    print("\nfinal report (today and yesterday, Asia/Singapore):")
    for key, r in sorted(rows.items()):
        user, device = key[0], key[1] + (" (deleted)" if len(key) == 3 else "")
        print("  %-6s %-17s %-8s up %10d  down %10d  total %10d  %s %s" % (user, device, r["state"], r["upload"],
              r["download"], r["total"], "/".join(sorted(r["statuses"])), "; ".join(sorted(r["reasons"]))))
    print("collectors:", [(c["host"], c["status"], c["note"]) for c in report["collectors"]])
    print("\n%d check(s) failed" % len(failures) if failures else "\nall checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
