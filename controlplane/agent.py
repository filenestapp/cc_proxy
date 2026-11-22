#!/usr/bin/env python3
"""Exit-node agent: keep the local sing-box in step with the control plane.

Every --interval seconds:
  1. fetch /agent/ips and add any missing egress IPs to --iface (egress/deploy/ips.sh up)
  2. fetch /agent/server-config with If-None-Match. A new version is held until no newer one has arrived for
     --settle seconds (or it has waited --max-delay), so a burst of admin changes costs one reload. Then it
     is `sing-box check`ed, swapped in atomically and sing-box reloads. A config that fails the check is not
     installed, and that exact version is not retried.

Every reload drops the connections open at that moment, hence the settle window.

The heartbeat reports the *applied* version: the one sing-box confirmed running (--run: still alive shortly
after start / SIGHUP; --reload-cmd: the command and --status-cmd succeeded). A written config whose reload
failed is retried every cycle, even when the control plane answers 304, and the failure is reported.

Health (for the dashboard): every cycle the agent posts a heartbeat. Every --probe-interval seconds a probe
round starts on its own thread (never overlapping the previous one): each URL in /agent/probe-targets is
fetched from every egress IP, with the connection bound to that IP. Results are buffered (bounded) as they
complete and sent with the next heartbeats, so a slow round never delays heartbeats or config updates.

Reload, one of:
  --run                 start sing-box as a child and send it SIGHUP on change (containers, testing)
  --reload-cmd CMD      run CMD on change, e.g. "systemctl reload sing-box"

  CP_AGENT_TOKEN=... agent.py --cp https://cp.example:8443 --iface eth0 --reload-cmd "systemctl reload sing-box"
"""
import argparse
import collections
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from probes import http_probe

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IPS_SCRIPT = os.path.join(HERE, "..", "egress", "deploy", "ips.sh")
PROBE_WORKERS = 16
PROBE_BUFFER = 4000          # results kept for reporting; the oldest are dropped beyond this
REPORT_MAX = 2000            # results per report (the control plane accepts up to this many)
RELOAD_CONFIRM_SECONDS = 1.5 # --run: sing-box must still be running this long after start / SIGHUP


def log(msg):
    print(time.strftime("%Y-%m-%dT%H:%M:%S ") + msg, file=sys.stderr, flush=True)


class Agent:
    def __init__(self, args):
        self.args = args
        self.token = os.environ.get("CP_AGENT_TOKEN", "")
        if not self.token:
            sys.exit("set CP_AGENT_TOKEN")
        self.ctx = ssl.create_default_context(cafile=args.cafile) if args.cafile else None
        self.applied = None     # version sing-box confirmed running (what the heartbeat reports)
        self.installed = None   # version written to the config file; may still await a successful reload
        self.apply_error = None # why the installed version is not applied yet
        self.pending = None     # newer version waiting for the settle window: {etag, body, first, last}
        self.rejected = None    # version that failed `sing-box check`
        self.child = None
        self.ips = None
        self.clock = time.time
        self.last_probe = None
        self.probe_running = False
        self.probe_buf = collections.deque(maxlen=PROBE_BUFFER)
        self.probe_lock = threading.Lock()

    @property
    def etag(self):
        """The applied version (kept for callers that read agent.etag)."""
        return self.applied

    def get(self, path, etag=None):
        req = urllib.request.Request(self.args.cp.rstrip("/") + path)
        req.add_header("Authorization", "Bearer " + self.token)
        if etag:
            req.add_header("If-None-Match", etag)
        try:
            with urllib.request.urlopen(req, timeout=10, context=self.ctx) as resp:
                return resp.status, resp.headers.get("ETag"), resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 304:
                return 304, etag, b""
            raise

    def post(self, path, obj):
        req = urllib.request.Request(self.args.cp.rstrip("/") + path, data=json.dumps(obj).encode(), method="POST")
        req.add_header("Authorization", "Bearer " + self.token)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10, context=self.ctx) as resp:
            return json.loads(resp.read())

    def singbox_running(self):
        if self.args.run:
            return self.child is not None and self.child.poll() is None
        if self.args.status_cmd:
            return subprocess.run(shlex.split(self.args.status_cmd)).returncode == 0
        return None  # unknown

    def probe_ips(self, on_result=None):
        """One probe round: every target from every egress IP, PROBE_WORKERS at a time. Each result is passed to
        on_result as soon as it completes, so a slow round still reports what it has."""
        targets = json.loads(self.get("/agent/probe-targets")[2])["egress_targets"]
        ips = (self.ips or "").split()
        jobs = [(ip, url) for ip in ips for url in targets]
        results = []
        if not jobs:
            return results
        with ThreadPoolExecutor(max_workers=min(PROBE_WORKERS, len(jobs))) as pool:
            futures = {pool.submit(http_probe, url, ip, self.args.probe_timeout): (ip, url) for ip, url in jobs}
            for fut in as_completed(futures):
                ip, url = futures[fut]
                r = dict(fut.result(), subject=ip, target=url)
                results.append(r)
                if on_result:
                    on_result(r)
        return results

    def _collect(self, result):
        with self.probe_lock:
            self.probe_buf.append(result)

    def maybe_probe(self, background=True):
        """Start a probe round when one is due and none is running. Rounds never overlap or pile up."""
        now = self.clock()
        with self.probe_lock:
            if self.probe_running or (self.last_probe is not None and now - self.last_probe < self.args.probe_interval):
                return False
            self.last_probe = now
            self.probe_running = True

        def run():
            try:
                self.probe_ips(on_result=self._collect)
            except Exception as e:  # a failed round must not stop later rounds
                log("probe round failed: %s" % e)
            finally:
                with self.probe_lock:
                    self.probe_running = False

        if background:
            threading.Thread(target=run, daemon=True, name="probe-round").start()
        else:
            run()
        return True

    def drain_probes(self):
        with self.probe_lock:
            n = min(len(self.probe_buf), REPORT_MAX)
            return [self.probe_buf.popleft() for _ in range(n)]

    def report(self):
        """Heartbeat with whatever probe results completed since the last one. Never waits for a probe round."""
        self.maybe_probe(background=not self.args.once)
        probes = self.drain_probes()
        bad = [p for p in probes if not p["ok"]]
        if bad:
            log("probe failures: " + "; ".join("%s %s %s" % (p["subject"], p["target"], p["detail"]) for p in bad))
        try:
            self.post("/agent/report", {"agent": self.args.name, "config_etag": self.applied,
                                        "apply_error": self.apply_error,
                                        "singbox_running": self.singbox_running(), "probes": probes})
        except (OSError, ValueError):
            with self.probe_lock:  # keep them for the next heartbeat (the deque bound still applies)
                self.probe_buf.extendleft(reversed(probes))
            raise

    def sync_ips(self):
        _, _, body = self.get("/agent/ips")
        ips = body.decode()
        if ips == self.ips:
            return
        path = os.path.join(self.args.state_dir, "ips.txt")
        with open(path, "w") as f:
            f.write(ips)
        if self.args.iface:
            subprocess.run(["sh", self.args.ips_script, "up", self.args.iface, path], check=True)
        self.ips = ips

    def sync_config(self):
        """Poll once; returns True when a new config was installed and sing-box should reload."""
        known = self.pending["etag"] if self.pending else self.installed
        status, etag, body = self.get("/agent/server-config", known)
        now = self.clock()
        if status == 200 and etag == self.installed:
            self.pending = None  # changed and changed back before it settled
        elif status == 200 and etag != self.rejected:
            if self.pending is None:
                self.pending = {"first": now}
                log("version %s seen, settling" % etag)
            self.pending.update(etag=etag, body=body, last=now)
        if self.pending is None:
            return False
        quiet = now - self.pending["last"]
        waited = now - self.pending["first"]
        first_config = self.applied is None  # nothing is serving yet: do not make a fresh node wait
        if not first_config and quiet < self.args.settle and waited < self.args.max_delay:
            return False
        pending, self.pending = self.pending, None
        return self.install(pending["etag"], pending["body"])

    def install(self, etag, body):
        json.loads(body)  # must be JSON before it goes anywhere near sing-box
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(self.args.config)), suffix=".json")
        with os.fdopen(fd, "wb") as f:
            f.write(body)
        os.chmod(tmp, 0o600)
        check = subprocess.run([self.args.singbox, "check", "-c", tmp], capture_output=True, text=True)
        if check.returncode != 0:
            os.unlink(tmp)
            self.rejected = etag
            log("version %s rejected by sing-box check, keeping current config: %s" % (etag, check.stderr.strip()))
            return False
        os.replace(tmp, self.args.config)
        self.installed = etag
        self.apply_error = "installed, not yet reloaded"
        log("wrote config version %s" % etag)
        return True

    def _child_survives(self):
        deadline = time.monotonic() + RELOAD_CONFIRM_SECONDS
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                return False
            time.sleep(0.1)
        return True

    def reload(self):
        """Make sing-box run the installed config. True only when that is confirmed."""
        if self.args.run:
            if self.child is None or self.child.poll() is not None:
                self.child = subprocess.Popen([self.args.singbox, "run", "-c", self.args.config,
                                               "-D", self.args.state_dir])
                log("started sing-box pid %d" % self.child.pid)
            else:
                self.child.send_signal(signal.SIGHUP)
                log("sent SIGHUP to sing-box")
            if not self._child_survives():
                raise OSError("sing-box exited with %s" % self.child.returncode)
            return True
        if self.args.reload_cmd:
            subprocess.run(shlex.split(self.args.reload_cmd), check=True)
            log("ran %s" % self.args.reload_cmd)
            if self.args.status_cmd and subprocess.run(shlex.split(self.args.status_cmd)).returncode != 0:
                raise OSError("sing-box is not running after reload (%s)" % self.args.status_cmd)
            return True
        return True

    def apply(self):
        """Reload until the installed version is confirmed; until then it is not reported as applied."""
        if self.installed is None or self.installed == self.applied:
            return False
        try:
            self.reload()
        except (OSError, subprocess.CalledProcessError) as e:
            self.apply_error = "reload failed: %s" % e
            log("version %s installed but reload failed, will retry: %s" % (self.installed, e))
            return False
        self.applied, self.apply_error = self.installed, None
        log("installed config version %s" % self.applied)
        return True

    def loop(self):
        os.makedirs(self.args.state_dir, exist_ok=True)
        while True:
            try:
                self.sync_ips()
                self.sync_config()
                if not self.apply() and self.args.run and self.child is not None and self.child.poll() is not None:
                    log("sing-box exited with %s, restarting" % self.child.returncode)
                    try:
                        self.reload()
                    except OSError as e:
                        self.apply_error = "restart failed: %s" % e
                        log(self.apply_error)
            except (OSError, ValueError, subprocess.CalledProcessError) as e:
                log("sync failed: %s" % e)
            try:
                self.report()
            except (OSError, ValueError) as e:
                log("report failed: %s" % e)
            if self.args.once:
                return
            time.sleep(self.args.interval)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cp", required=True, help="control plane base URL")
    p.add_argument("--cafile", help="CA bundle for a private control-plane certificate")
    p.add_argument("--iface", help="interface for egress IPs; omit to skip IP management")
    p.add_argument("--ips-script", default=DEFAULT_IPS_SCRIPT)
    p.add_argument("--config", default="/etc/sing-box/config.json")
    p.add_argument("--state-dir", default="/var/lib/egress-agent")
    p.add_argument("--singbox", default="sing-box")
    p.add_argument("--interval", type=float, default=5)
    p.add_argument("--settle", type=float, default=10,
                   help="install a new version only after this many seconds without a newer one (0 = at once)")
    p.add_argument("--max-delay", type=float, default=60,
                   help="install anyway once a pending version has waited this long")
    p.add_argument("--name", default=socket.gethostname(), help="agent name shown on the dashboard")
    p.add_argument("--probe-interval", type=float, default=60)
    p.add_argument("--probe-timeout", type=float, default=10)
    p.add_argument("--status-cmd", help='with --reload-cmd: exit 0 when sing-box is up, '
                                       'e.g. "systemctl is-active --quiet sing-box"')
    p.add_argument("--once", action="store_true", help="sync once and exit")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true", help="supervise sing-box as a child process")
    mode.add_argument("--reload-cmd")
    args = p.parse_args(argv)
    Agent(args).loop()


if __name__ == "__main__":
    main()
