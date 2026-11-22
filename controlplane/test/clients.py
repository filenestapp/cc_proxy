"""Test-harness clients (v2): each device signs in with username + password, then keeps its config current the way
the desktop client does: poll /v1/config with If-None-Match and restart sing-box when it changes.

Reads /creds/devices.json: [{"device", "user", "password", "port"}]. The subscribed proxy-mode config listens on
127.0.0.1:2080; the harness rewrites only the listen address and port so the probe container can reach every
device. On 401/409 a running proxy is deliberately left running with its stale config: that is a client which
ignores revocation, so the e2e checks that the server enforces it.
"""
import json
import subprocess
import time
import urllib.error
import urllib.request

CP = "http://10.88.0.5:8443"


def call(method, path, token=None, body=None, etag=None):
    req = urllib.request.Request(CP + path, data=json.dumps(body).encode() if body else None, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if etag:
        req.add_header("If-None-Match", etag)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.headers.get("ETag"), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, None, e.read()


devices = json.load(open("/creds/devices.json"))
state = {}
for d in devices:
    status, _, body = call("POST", "/v1/login", body={"username": d["user"], "password": d["password"],
                                                     "device": d["device"], "platform": "linux"})
    info = json.loads(body)
    if status != 200:
        raise SystemExit("login %s failed: %s %s" % (d["device"], status, info))
    entry = info["entry"]
    print("login %-10s entry %s" % (d["device"], "%s:%s" % (entry["host"], entry["port"]) if entry else "-"), flush=True)
    state[d["device"]] = {"token": info["token"], "etag": None, "proc": None, "entry": entry}

first = True
while True:
    for d in devices:
        st = state[d["device"]]
        status, etag, body = call("GET", "/v1/config?mode=proxy", st["token"], etag=st["etag"])
        if status == 200:
            cfg = json.loads(body)
            out = cfg["outbounds"][0]
            print("config %-10s -> %s:%s" % (d["device"], out["server"], out["server_port"]), flush=True)
            cfg["inbounds"][0].update(listen="0.0.0.0", listen_port=d["port"])
            path = "/tmp/%s.json" % d["device"]
            with open(path, "w") as f:
                json.dump(cfg, f)
            if st["proc"]:
                st["proc"].terminate()
                st["proc"].wait()
            st["proc"] = subprocess.Popen(["sing-box", "run", "-c", path])
            st["etag"] = etag
        elif status in (401, 409) and st["etag"] != status:
            print("config %-10s -> %d %s (keeping whatever runs)" % (d["device"], status, body.decode().strip()),
                  flush=True)
            st["etag"] = status  # remember, so the message is printed once per state
    if first:
        open("/tmp/ready", "w").close()
        first = False
    time.sleep(2)
