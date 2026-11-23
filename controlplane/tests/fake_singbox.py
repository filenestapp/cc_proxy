#!/usr/bin/env python3
"""Fake sing-box for agent tests. Behaves like sing-box where the agent can observe it:

  check -c FILE     exit 1 when FILE contains REJECT_ME
                    (CRASH_ME passes the check, but a running process that loads it exits with status 3, as
                    sing-box does when a checked config fails at start: the old instance is already closed)
  run -c FILE ...   load FILE and serve its experimental.clash_api like sing-box: GET /proxies lists the loaded
                    config's outbounds by tag, only with "Authorization: Bearer <secret of the loaded config>"
                    (401 otherwise). SIGHUP reloads FILE.

Flag files next to FILE change what a reload does (checked when the SIGHUP arrives):
  stubborn    stay alive and keep serving the previously loaded config (the old revision)
  crash       exit with status 3 (also at start: a config that kills sing-box)
  silent      reload, but stop answering on the API (no evidence either way)
  slow        read FILE at once but switch to it only SLOW_SECONDS later (longer than the tests' confirm
              timeout): the old configuration keeps answering meanwhile, as a slow reload would
Checked on every request:
  noauth      answer without checking the secret, like a sing-box whose config has no API secret (legacy)
A missing FILE at start is not an error: a service can be started before the agent's first config.
"""
import http.server
import json
import os
import signal
import sys
import threading
import time


SLOW_SECONDS = 2.5


def load(text):
    config = json.loads(text)
    api = config["experimental"]["clash_api"]
    host, port = api["external_controller"].rsplit(":", 1)
    tags = [o.get("tag", "") for o in config.get("outbounds", [])]
    return (host.strip("[]"), int(port)), api["secret"], tags


def main(argv):
    cmd, path = argv[0], argv[argv.index("-c") + 1]
    if cmd == "check":
        with open(path) as f:
            sys.exit(1 if "REJECT_ME" in f.read() else 0)
    if cmd != "run":
        sys.exit(2)

    state = {"secret": None, "silent": False, "tags": []}
    flag = lambda name: os.path.exists(os.path.join(os.path.dirname(os.path.abspath(path)), name))

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if state["silent"]:
                self.connection.close()  # the agent sees a dropped connection, i.e. no answer
                return
            ok = flag("noauth") or (state["secret"] is not None
                                    and self.headers.get("Authorization") == "Bearer " + state["secret"])
            ok = ok and self.path == "/proxies"
            proxies = {t: {"type": "Reject", "name": t} for t in state["tags"]}
            body = json.dumps({"proxies": proxies} if ok else {"message": "Unauthorized"}).encode()
            self.send_response(200 if ok else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = None

    def reload(text=None):
        nonlocal server
        if text is None:
            if not os.path.exists(path):
                return
            with open(path) as f:
                text = f.read()
        if "CRASH_ME" in text:
            sys.exit(3)
        address, secret, tags = load(text)
        if server is None:
            server = http.server.ThreadingHTTPServer(address, Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        state["secret"], state["tags"] = secret, tags

    hup = threading.Event()
    signal.signal(signal.SIGHUP, lambda *_: hup.set())
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    open(os.path.join(os.path.dirname(os.path.abspath(path)), "fake.ready"), "w").close()  # signals handled now
    if os.path.exists(path) and flag("crash"):
        sys.exit(3)
    reload()
    while True:
        if hup.wait(0.05):
            hup.clear()
            if flag("crash"):
                sys.exit(3)
            if flag("stubborn"):
                continue
            state["silent"] = flag("silent")
            if flag("slow"):
                with open(path) as f:
                    text = f.read()
                time.sleep(SLOW_SECONDS)
                reload(text)
                continue
            reload()
        time.sleep(0.01)


if __name__ == "__main__":
    main(sys.argv[1:])
