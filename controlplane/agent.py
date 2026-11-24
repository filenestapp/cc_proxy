#!/usr/bin/env python3
"""Exit-node agent: keep the local sing-box in step with the control plane.

Every --interval seconds:
  1. fetch /agent/ips and add any missing egress IPs to --iface (egress/deploy/ips.sh up)
  2. fetch /agent/server-config with If-None-Match. A new version is held until no newer one has arrived for
     --settle seconds (or it has waited --max-delay), so a burst of admin changes costs one reload. Then it
     is `sing-box check`ed, swapped in atomically and sing-box reloads. A config that fails the check is not
     installed, and that exact version is not retried.

Every reload drops the connections open at that moment, hence the settle window.

The heartbeat reports the *applied* version: the one the running sing-box has been seen to load. A live PID, a
successful SIGHUP or reload command, or the file on disk prove nothing about what the process serves, so the agent
asks the process itself:

  * Every installed candidate gets two independent random values: a secret for `experimental.clash_api`
    (listening on --confirm-api, a numeric loopback address) and a marker, the tag of an extra `block` outbound
    that no rule uses. The agent owns that API block; one sent by the control plane is replaced.
  * After start / SIGHUP / --reload-cmd, the agent calls GET /proxies on that API with the candidate's secret, and
    the candidate counts as running only when the answer lists the marker. The marker is never sent, so only a
    process that loaded the candidate can return it: an old sing-box (with or without API authentication) or an
    unrelated listener on the port cannot. Redirects are not followed and the answer is size-bounded.
  * An answer from sing-box without the marker (401 for the new secret, or a list without it) proves the process
    still serves another configuration.

The heartbeat carries apply_state:
  confirmed   the installed version is the applied one
  pending     written, not reloaded yet
  failed      the reload failed, sing-box exited, or the running process still serves another configuration;
              retried every cycle (also after a 304)
  unknown     reloaded, but no usable answer (nothing listening, a redirect, an answer that is not sing-box's),
              so nothing can be said; re-checked every cycle, reloaded again after UNKNOWN_RETRY_SECONDS
Until a candidate is confirmed the previous applied version stays in the heartbeat, with apply_error saying why.

Files: a checked candidate is kept in --state-dir/candidate-config.json and copied to --config only for a reload;
the last confirmed configuration is kept in --state-dir/confirmed-config.json. When a reload fails definitively
(the reload command fails, sing-box exits, or it still serves another configuration) the confirmed configuration
is put back at --config atomically, so a later restart or reboot starts what worked; the candidate stays in the
state directory and is tried again (also after a 304). A sing-box that is still running is left alone. With --run,
if the agent's own sing-box exited, it is started once more on the confirmed configuration, and only a version it
confirms is reported. Such a candidate (it took sing-box down) is retried after FAILED_OUTAGE_RETRY_SECONDS rather
than every cycle. An unknown result keeps the candidate at --config: it may well be running.

systemd deployment (official sing-box package, whose sing-box.service reloads with SIGHUP):

  --reload-cmd "systemctl reload sing-box" --status-cmd "systemctl is-active --quiet sing-box"

and keep --confirm-api (default 127.0.0.1:9095) free on the exit host. The official builds include the Clash API
(`sing-box version` lists with_clash_api) and the block outbound. To check by hand what is running:
  c=/etc/sing-box/config.json
  curl -s -H "Authorization: Bearer $(jq -r .experimental.clash_api.secret $c)" http://127.0.0.1:9095/proxies \
    | jq --arg m "$(jq -r '.outbounds[] | select(.tag | startswith("confirm-")) | .tag' $c)" '.proxies | has($m)'
true means the file on disk is the configuration sing-box is serving; anything else means it is not (reload it).

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
import http.client
import json
import os
import ipaddress
import secrets
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
DEFAULT_CONFIRM_API = "127.0.0.1:9095"
CONFIRM_MAX_BYTES = 4 << 20  # /proxies lists every outbound: about 200 bytes each, so this covers thousands
MARKER_PREFIX = "confirm-"
UNKNOWN_RETRY_SECONDS = 60   # reload again when a reload stayed unconfirmed (API silent) this long
FAILED_OUTAGE_RETRY_SECONDS = 60  # retry a candidate that made sing-box exit only after this long
PREVIOUS = "previous"        # on_disk: the --config found before this process wrote one (never claimed applied)

CONFIRMED, PENDING, FAILED, UNKNOWN = "confirmed", "pending", "failed", "unknown"


class NotLoaded(Exception):
    """The running sing-box demonstrably does not serve the candidate."""


def loopback_api(addr):
    """Check --confirm-api: a numeric loopback IP and a port, "127.0.0.1:9095" or "[::1]:9095". Returns it in the
    form both sing-box and URLs accept. Host names are refused (resolution could lead anywhere), and so is any
    address that is not loopback."""
    host, sep, port = str(addr).rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ip = ipaddress.ip_address(host)
        port = int(port)
    except ValueError:
        raise ValueError("--confirm-api must be a numeric loopback address with a port, e.g. 127.0.0.1:9095")
    if not sep or not ip.is_loopback or not 1 <= port <= 65535:
        raise ValueError("--confirm-api must be a numeric loopback address with a port, e.g. 127.0.0.1:9095")
    return "%s:%d" % ("[%s]" % ip if ip.version == 6 else ip, port)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # urllib then raises HTTPError for the 3xx itself


# Loopback only: no proxy from the environment, no redirects.
_CONFIRM_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


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
        self.apply_state = None # PENDING / FAILED / UNKNOWN while installed != applied
        self.secret = None      # API secret embedded in the installed version (sent when asking)
        self.marker = None      # tag of the installed version's marker outbound (never sent; must come back)
        self.applied_secret = None  # the same two values for the applied (confirmed) version
        self.applied_marker = None
        self.on_disk = None     # generation at --config: a version's marker, PREVIOUS, or None (not written yet)
        self.kept_previous = False  # this process saved the --config it found at start to previous_copy
        self.retry_after = 0.0  # time.monotonic() before which a failed candidate is not retried
        self.confirm_address = loopback_api(args.confirm_api)
        self.confirm_url = "http://" + self.confirm_address
        self.last_reload = None # time.monotonic() of the last reload attempt
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
        req.add_header("User-Agent", "CCProxy-Agent")
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
        req.add_header("User-Agent", "CCProxy-Agent")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10, context=self.ctx) as resp:
            return json.loads(resp.read())

    @property
    def settled(self):
        """The installed generation is the confirmed one. Compared by marker, not ETag: a version staged again with
        the same content as the confirmed one (A -> B -> A) is a new generation and must be proved again, since B
        may be what runs."""
        return self.installed is not None and self.marker == self.applied_marker

    def state(self):
        """What the heartbeat says about the installed version (None before anything was installed)."""
        if self.installed is None:
            return None
        return CONFIRMED if self.settled else self.apply_state

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
                                        "apply_state": self.state(), "apply_error": self.apply_error,
                                        "candidate_etag": None if self.settled else self.installed,
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
        config = json.loads(body)  # must be JSON before it goes anywhere near sing-box
        experimental = config.setdefault("experimental", {}) if isinstance(config, dict) else None
        if not isinstance(experimental, dict):
            raise ValueError("server config is not a JSON object with an object 'experimental'")
        outbounds = config.setdefault("outbounds", [])
        if not isinstance(outbounds, list):
            raise ValueError("server config 'outbounds' is not a list")
        # Per-candidate values (see the module docstring): the secret authorizes the question, the marker is the
        # answer only a sing-box running this file can give. Appended, so the first (default) outbound is unchanged.
        secret, marker = secrets.token_hex(16), MARKER_PREFIX + secrets.token_hex(16)
        experimental["clash_api"] = {"external_controller": self.confirm_address, "secret": secret}
        outbounds.append({"type": "block", "tag": marker})
        tmp = self._write_temp(self.args.state_dir, json.dumps(config, indent=2).encode())
        check = subprocess.run([self.args.singbox, "check", "-c", tmp], capture_output=True, text=True)
        if check.returncode != 0:
            os.unlink(tmp)
            self.rejected = etag
            log("version %s rejected by sing-box check, keeping current config: %s" % (etag, check.stderr.strip()))
            return False
        os.replace(tmp, self.candidate_copy)  # --config is untouched until the reload
        self.installed, self.secret, self.marker = etag, secret, marker
        self.apply_state, self.apply_error, self.retry_after = PENDING, "installed, not yet reloaded", 0.0
        log("wrote config version %s" % etag)
        return True

    @property
    def candidate_copy(self):
        return os.path.join(self.args.state_dir, "candidate-config.json")

    @property
    def confirmed_copy(self):
        return os.path.join(self.args.state_dir, "confirmed-config.json")

    @staticmethod
    def _write_temp(directory, data):
        fd, tmp = tempfile.mkstemp(dir=directory, suffix=".json")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o600)
        return tmp

    def _place(self, src, dst):
        """Atomically make dst a copy of src (temp file in dst's directory, then rename)."""
        with open(src, "rb") as f:
            data = f.read()
        os.replace(self._write_temp(os.path.dirname(os.path.abspath(dst)), data), dst)

    @property
    def previous_copy(self):
        return os.path.join(self.args.state_dir, "previous-config.json")

    def _put_candidate(self):
        """Stage exactly the installed candidate at --config (by its marker: a newer candidate always replaces an
        older, unconfirmed one). The first time this process writes --config, whatever was there before (from an
        earlier run) is kept as the working configuration to fall back to."""
        if self.on_disk == self.marker:
            return
        if self.on_disk is None and self.applied is None and os.path.isfile(self.args.config):
            self._place(self.args.config, self.previous_copy)
            self.kept_previous = True
            log("kept the existing %s as the fallback configuration" % self.args.config)
        self._place(self.candidate_copy, self.args.config)
        self.on_disk = self.marker

    def _restore_working(self):
        """Put the working configuration back at --config: the last confirmed version, or (before this process
        confirmed anything) the --config found at start. False when there is neither."""
        if self.applied is not None:
            src, generation, what = self.confirmed_copy, self.applied_marker, "config version %s" % self.applied
        elif self.kept_previous:
            src, generation, what = self.previous_copy, PREVIOUS, "the configuration found at start"
        else:
            return False
        if self.on_disk != generation:
            self._place(src, self.args.config)
            self.on_disk = generation
            log("restored %s at %s" % (what, self.args.config))
        return True

    def loaded_evidence(self, version="candidate"):
        """Ask the running sing-box whether it serves the installed candidate (or, with version="confirmed", the
        applied version): "loaded" (its outbound list has that version's marker), "other" (sing-box answered
        without it: another configuration is running) or None (no usable answer: unknown)."""
        secret, marker = ((self.secret, self.marker) if version == "candidate"
                          else (self.applied_secret, self.applied_marker))
        req = urllib.request.Request(self.confirm_url + "/proxies")
        req.add_header("Authorization", "Bearer " + (secret or ""))
        try:
            with _CONFIRM_OPENER.open(req, timeout=2) as resp:
                body = resp.read(CONFIRM_MAX_BYTES + 1)
                if resp.status != 200 or len(body) > CONFIRM_MAX_BYTES:
                    return None
            proxies = json.loads(body).get("proxies")
        except urllib.error.HTTPError as e:
            return "other" if e.code in (401, 403) else None  # sing-box refusing this candidate's secret
        except (OSError, ValueError, AttributeError, http.client.HTTPException):
            return None  # includes a truncated or malformed HTTP answer: no usable evidence
        if not isinstance(proxies, dict):
            return None  # not sing-box's answer
        return "loaded" if marker is not None and marker in proxies else "other"

    def await_confirmation(self, version="candidate"):
        """After a start / reload: True once sing-box serves `version`, None if it never answered within
        --confirm-timeout. Raises NotLoaded when it keeps serving another configuration or exits."""
        deadline = time.monotonic() + self.args.confirm_timeout
        while True:
            if self.args.run and self.child.poll() is not None:
                raise NotLoaded("sing-box exited with %s" % self.child.returncode)
            evidence = self.loaded_evidence(version)
            if evidence == "loaded":
                return True
            if time.monotonic() >= deadline:
                break
            time.sleep(0.1)
        if evidence == "other":
            raise NotLoaded("the running sing-box still serves another configuration")
        return None

    def reload(self):
        """Start sing-box or ask it to reload the installed config. Says nothing about whether it did."""
        self.last_reload = time.monotonic()
        if self.args.run:
            if self.child is None or self.child.poll() is not None:
                self.child = subprocess.Popen([self.args.singbox, "run", "-c", self.args.config,
                                               "-D", self.args.state_dir])
                log("started sing-box pid %d" % self.child.pid)
            else:
                self.child.send_signal(signal.SIGHUP)
                log("sent SIGHUP to sing-box")
        elif self.args.reload_cmd:
            subprocess.run(shlex.split(self.args.reload_cmd), check=True)
            log("ran %s" % self.args.reload_cmd)

    def _confirmed(self):
        """sing-box proved it runs the installed candidate. If --config was rolled back meanwhile (a reload that
        looked failed took effect late), that exact candidate goes back first, so a restart keeps it."""
        if self.on_disk != self.marker:
            self._place(self.candidate_copy, self.args.config)
            self.on_disk = self.marker
        self._place(self.candidate_copy, self.confirmed_copy)
        self.applied, self.applied_secret, self.applied_marker = self.installed, self.secret, self.marker
        self.apply_state, self.apply_error = None, None
        log("sing-box confirmed running config version %s" % self.applied)
        return True

    def _fail(self, reason):
        """A definitive failure for the candidate: the working configuration goes back on disk, and with --run an
        exited sing-box is started once on it."""
        self.apply_state, self.apply_error = FAILED, reason
        log("version %s not running, will retry: %s" % (self.installed, reason))
        restored = self._restore_working()
        if self.args.run and self.child is not None and self.child.poll() is not None:
            self.retry_after = time.monotonic() + FAILED_OUTAGE_RETRY_SECONDS
            if restored:
                self._recover()

    def _recover(self):
        """--run: start sing-box on the restored working configuration, once. Only a confirmed version is ever
        reported; the configuration found at start has no version this process could claim."""
        what = "version %s" % self.applied if self.applied is not None else "the configuration found at start"
        try:
            self.reload()
            ok = self.await_confirmation("confirmed") if self.applied is not None else None
        except (OSError, NotLoaded) as e:
            self.apply_error += "; recovery on %s failed: %s" % (what, e)
            log(self.apply_error)
            return
        log("recovery on %s: %s" % (what, "confirmed" if ok else "started, not confirmed"))

    def restart(self):
        """--run: start sing-box again after it exited, and wait for it to confirm what --config holds. Waiting
        also keeps the next cycle from signalling a process that is still starting."""
        if not self.settled and self.on_disk == self.marker:
            version = "candidate"
        elif self.applied is not None and self.on_disk == self.applied_marker:
            version = "confirmed"
        else:
            version = None  # the configuration found at start: started, never claimed
        try:
            self.reload()
            loaded = self.await_confirmation(version) if version else None
        except (OSError, NotLoaded) as e:
            if version == "candidate":
                self._fail("restart failed: %s" % e)
            else:
                self.apply_error = "restart failed: %s" % e
                log(self.apply_error)
            return
        if loaded and version == "candidate":
            self._confirmed()

    def apply(self):
        """Reload until the running sing-box confirms the installed version; only then is it reported applied."""
        if self.installed is None or self.settled:
            return False
        if self.apply_state in (FAILED, UNKNOWN) and self.loaded_evidence() == "loaded":
            return self._confirmed()  # an earlier reload took effect late
        now = time.monotonic()
        if self.apply_state == UNKNOWN and now - self.last_reload < UNKNOWN_RETRY_SECONDS:
            return False
        if self.apply_state == FAILED and now < self.retry_after:
            return False
        self._put_candidate()
        try:
            self.reload()
            loaded = self.await_confirmation()
        except (OSError, subprocess.CalledProcessError, NotLoaded) as e:
            self._fail("reload failed: %s" % e)
            return False
        if not loaded:
            # Inconclusive: the candidate may be running, so it stays at --config.
            self.apply_state = UNKNOWN
            self.apply_error = "reload not confirmed: no answer from sing-box at %s" % self.confirm_address
            log("version %s: %s" % (self.installed, self.apply_error))
            return False
        return self._confirmed()

    def loop(self):
        os.makedirs(self.args.state_dir, exist_ok=True)
        while True:
            try:
                self.sync_ips()
                self.sync_config()
                if not self.apply() and self.args.run and self.child is not None and self.child.poll() is not None:
                    log("sing-box exited with %s, restarting" % self.child.returncode)
                    self.restart()
            except (OSError, ValueError, subprocess.CalledProcessError) as e:
                log("sync failed: %s" % e)
            try:
                self.report()
            except (OSError, ValueError) as e:
                log("report failed: %s" % e)
            if self.args.once:
                return
            time.sleep(self.args.interval)


def _confirm_api_arg(value):
    try:
        loopback_api(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))
    return value


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
                                       'e.g. "systemctl is-active --quiet sing-box" (reported only; it does '
                                       'not confirm a reload)')
    p.add_argument("--confirm-api", default=DEFAULT_CONFIRM_API, type=_confirm_api_arg,
                   help="numeric loopback address:port for the sing-box API the agent uses to confirm what is "
                        "running (default %(default)s)")
    p.add_argument("--confirm-timeout", type=float, default=15,
                   help="seconds to wait for sing-box to confirm a reloaded config")
    p.add_argument("--once", action="store_true", help="sync once and exit")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run", action="store_true", help="supervise sing-box as a child process")
    mode.add_argument("--reload-cmd")
    args = p.parse_args(argv)
    Agent(args).loop()


if __name__ == "__main__":
    main()
