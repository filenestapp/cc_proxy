#!/usr/bin/env python3
"""Vantage-point prober: measure TCP connect latency from here to every entry point and report it.

Run one per network you care about (for example one per ISP and region your users are on); --vantage names it
on the dashboard.

  CP_PROBE_TOKEN=... prober.py --cp https://cp.example:8443 --vantage sh-telecom [--interval 30] [--once]
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.request

from probes import tcp_probe


def call(args, ctx, token, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(args.cp.rstrip("/") + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
        return json.loads(resp.read())


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cp", required=True)
    p.add_argument("--vantage", required=True)
    p.add_argument("--cafile")
    p.add_argument("--interval", type=float, default=30)
    p.add_argument("--once", action="store_true")
    args = p.parse_args(argv)
    token = os.environ.get("CP_PROBE_TOKEN") or sys.exit("set CP_PROBE_TOKEN")
    ctx = ssl.create_default_context(cafile=args.cafile) if args.cafile else None

    while True:
        try:
            entries = call(args, ctx, token, "GET", "/probe/targets")["entries"]
            results = []
            for e in entries:
                r = tcp_probe(e["host"], e["port"])
                results.append(dict(r, subject=e["name"], target="%s:%s" % (e["host"], e["port"])))
            call(args, ctx, token, "POST", "/probe/report", {"vantage": args.vantage, "results": results})
            print(time.strftime("%H:%M:%S ") + ", ".join(
                "%s %s" % (r["subject"], "%.0fms" % r["latency_ms"] if r["ok"] else "unreachable") for r in results),
                flush=True)
        except (OSError, ValueError, KeyError) as e:
            print("probe round failed: %s" % e, file=sys.stderr, flush=True)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
