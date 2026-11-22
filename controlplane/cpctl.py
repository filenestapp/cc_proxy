#!/usr/bin/env python3
"""Admin CLI for the control plane. Reads CP_URL (default http://127.0.0.1:8443) and CP_ADMIN_TOKEN.

Hosts and IPs
  cpctl.py hosts
  cpctl.py host-add NAME PUBLIC_HOST SNI [--handshake H] [--ports 20000-29999]
                    [--allow-private] [--block-cidr CIDR]...     prints the agent token once
  cpctl.py host-del NAME
  cpctl.py host-token NAME                    rotate the agent token
  cpctl.py ip-add HOST IP...
  cpctl.py ips [HOST]
  cpctl.py ban IP [NOTE...]
  cpctl.py ip-available IP                    end cooldown / lift ban
Users
  cpctl.py users
  cpctl.py user-add NAME [--password P] [--shared] [--max-devices N]   generates a password if none is given
  cpctl.py passwd NAME [--password P] [--revoke-devices]
  cpctl.py user-del NAME
  cpctl.py assign NAME [IP] [--port N] [--host H]    omit IP/port to take the lowest free ones
  cpctl.py reassign NAME [IP] [--port N] [--host H]  move a bound user in one step (clients stay connected)
  cpctl.py release NAME
  cpctl.py device-add USER DEVICE             headless device; prints its token once
  cpctl.py revoke USER DEVICE
Alerts
  cpctl.py alerts [--all]
  cpctl.py alert-test
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def call(method, path, body=None):
    url = os.environ.get("CP_URL", "http://127.0.0.1:8443").rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", "Bearer " + os.environ.get("CP_ADMIN_TOKEN", ""))
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error")
        except ValueError:
            msg = e.reason
        sys.exit("error %d: %s" % (e.code, msg))


def q(s):
    return urllib.parse.quote(s, safe="")


def show(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main(argv):
    p = argparse.ArgumentParser(prog="cpctl.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hosts")
    a = sub.add_parser("host-add")
    a.add_argument("name"); a.add_argument("public_host"); a.add_argument("server_name")
    a.add_argument("--handshake"); a.add_argument("--ports")
    a.add_argument("--allow-private", action="store_true", help="let users reach private addresses (testing)")
    a.add_argument("--block-cidr", action="append", help="destinations to refuse (repeatable)")
    sub.add_parser("host-del").add_argument("name")
    sub.add_parser("host-token").add_argument("name")
    a = sub.add_parser("ip-add"); a.add_argument("host"); a.add_argument("ips", nargs="+")
    sub.add_parser("ips").add_argument("host", nargs="?")
    a = sub.add_parser("ban"); a.add_argument("ip"); a.add_argument("note", nargs="*")
    sub.add_parser("ip-available").add_argument("ip")
    sub.add_parser("users")
    a = sub.add_parser("user-add")
    a.add_argument("name"); a.add_argument("--password"); a.add_argument("--shared", action="store_true")
    a.add_argument("--max-devices", type=int)
    a = sub.add_parser("passwd")
    a.add_argument("name"); a.add_argument("--password"); a.add_argument("--revoke-devices", action="store_true")
    sub.add_parser("user-del").add_argument("name")
    a = sub.add_parser("assign")
    a.add_argument("name"); a.add_argument("ip", nargs="?"); a.add_argument("--port", type=int); a.add_argument("--host")
    a = sub.add_parser("reassign")
    a.add_argument("name"); a.add_argument("ip", nargs="?"); a.add_argument("--port", type=int); a.add_argument("--host")
    sub.add_parser("release").add_argument("name")
    a = sub.add_parser("device-add"); a.add_argument("user"); a.add_argument("device")
    a = sub.add_parser("revoke"); a.add_argument("user"); a.add_argument("device")
    sub.add_parser("alerts").add_argument("--all", action="store_true")
    sub.add_parser("alert-test")
    args = p.parse_args(argv)
    c = args.cmd

    if c == "hosts":
        for h in call("GET", "/admin/hosts"):
            print("%-12s %-18s ports %d-%d  ips %-3d users %-3d sni %s" % (
                h["name"], h["public_host"], h["port_range"][0], h["port_range"][1], h["ips"], h["users"],
                h["server_name"]))
    elif c == "host-add":
        body = {"name": args.name, "public_host": args.public_host, "server_name": args.server_name}
        if args.handshake:
            body["handshake_server"] = args.handshake
        if args.ports:
            lo, _, hi = args.ports.partition("-")
            body.update(port_min=int(lo), port_max=int(hi or lo))
        if args.allow_private:
            body["block_private"] = False
        if args.block_cidr:
            body["block_cidrs"] = args.block_cidr
        show(call("POST", "/admin/hosts", body))
    elif c == "host-del":
        show(call("DELETE", "/admin/hosts/" + q(args.name)))
    elif c == "host-token":
        show(call("POST", "/admin/hosts/%s/rotate-token" % q(args.name)))
    elif c == "ip-add":
        show(call("POST", "/admin/hosts/%s/ips" % q(args.host), {"ips": args.ips}))
    elif c == "ips":
        for e in call("GET", "/admin/ips" + ("?host=" + q(args.host) if args.host else "")):
            holders = ",".join("%s:%d" % (u, e["ports"][u]) for u in e["users"]) or "-"
            print("%-16s %-10s %-9s %s %s" % (e["ip"], e["host"], e["status"], holders, e["note"]))
    elif c == "ban":
        show(call("POST", "/admin/ips/%s/ban" % q(args.ip), {"note": " ".join(args.note)}))
    elif c == "ip-available":
        show(call("POST", "/admin/ips/%s/available" % q(args.ip)))
    elif c == "users":
        for u in call("GET", "/admin/users"):
            entry = "%s:%d" % (u["egress_ip"], u["port"]) if u["egress_ip"] else "-"
            devs = ", ".join(d["name"] + (" (revoked)" if d["revoked"] else "") for d in u["devices"]) or "-"
            print("%-14s %-9s %-10s %-22s devices %d/%d: %s" % (
                u["name"], u["mode"], u["host"] or "-", entry,
                sum(not d["revoked"] for d in u["devices"]), u["max_devices"], devs))
    elif c == "user-add":
        body = {"name": args.name, "mode": "shared" if args.shared else "exclusive"}
        if args.password:
            body["password"] = args.password
        if args.max_devices:
            body["max_devices"] = args.max_devices
        show(call("POST", "/admin/users", body))
    elif c == "passwd":
        body = {"revoke_devices": args.revoke_devices}
        if args.password:
            body["password"] = args.password
        show(call("POST", "/admin/users/%s/password" % q(args.name), body))
    elif c == "user-del":
        show(call("DELETE", "/admin/users/" + q(args.name)))
    elif c == "assign":
        body = {k: v for k, v in (("ip", args.ip), ("port", args.port), ("host", args.host)) if v is not None}
        show(call("POST", "/admin/users/%s/assign" % q(args.name), body))
    elif c == "reassign":
        body = {k: v for k, v in (("ip", args.ip), ("port", args.port), ("host", args.host)) if v is not None}
        show(call("POST", "/admin/users/%s/reassign" % q(args.name), body))
    elif c == "release":
        show(call("POST", "/admin/users/%s/release" % q(args.name)))
    elif c == "device-add":
        show(call("POST", "/admin/users/%s/devices" % q(args.user), {"name": args.device}))
    elif c == "revoke":
        show(call("POST", "/admin/users/%s/devices/%s/revoke" % (q(args.user), q(args.device))))
    elif c == "alerts":
        for al in call("GET", "/admin/alerts" + ("?all=1" if args.all else "")):
            print("%-8s %-8s %-22s %s" % (al["state"], al["severity"], al["rule"], al["summary"]))
    elif c == "alert-test":
        show(call("POST", "/admin/alerts/test"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
