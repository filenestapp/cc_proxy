#!/usr/bin/env python3
"""Fake sing-box for agent tests. Behaves like sing-box where the agent can observe it:

  check -c FILE     exit 1 when FILE contains REJECT_ME
  run -c FILE ...   load FILE and serve its experimental.clash_api like sing-box: GET /version answers 200 only
                    with "Authorization: Bearer <secret of the loaded config>", 401 otherwise. SIGHUP reloads FILE.

Flag files next to FILE change what a reload does (checked when the SIGHUP arrives):
  stubborn    stay alive and keep serving the previously loaded config (the old revision)
  crash       exit with status 3 (also at start: a config that kills sing-box)
  silent      reload, but stop answering on the API (no evidence either way)
A missing FILE at start is not an error: a service can be started before the agent's first config.
"""
import http.server
import json
import os
import signal
import sys
import threading
import time


def load(path):
    with open(path) as f:
        api = json.load(f)["experimental"]["clash_api"]
    host, port = api["external_controller"].rsplit(":", 1)
    return (host, int(port)), api["secret"]


def main(argv):
    cmd, path = argv[0], argv[argv.index("-c") + 1]
    if cmd == "check":
        with open(path) as f:
            sys.exit(1 if "REJECT_ME" in f.read() else 0)
    if cmd != "run":
        sys.exit(2)

    state = {"secret": None, "silent": False}
    flag = lambda name: os.path.exists(os.path.join(os.path.dirname(os.path.abspath(path)), name))

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if state["silent"]:
                self.connection.close()  # the agent sees a dropped connection, i.e. no answer
                return
            ok = state["secret"] is not None and self.headers.get("Authorization") == "Bearer " + state["secret"]
            body = json.dumps({"version": "fake"} if ok else {"message": "Unauthorized"}).encode()
            self.send_response(200 if ok else 401)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    server = None

    def reload():
        nonlocal server
        if not os.path.exists(path):
            return
        address, secret = load(path)
        if server is None:
            server = http.server.ThreadingHTTPServer(address, Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
        state["secret"] = secret

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
            reload()
        time.sleep(0.01)


if __name__ == "__main__":
    main(sys.argv[1:])
