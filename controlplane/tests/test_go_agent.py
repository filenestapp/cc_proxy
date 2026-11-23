"""The compiled Go exit agent (egress/agent) against the real control plane.

The agent runs as its own process, as the installed services run it, with tests/fake_singbox.py as sing-box (it
serves the Clash API confirmation the way sing-box does). Covered: first config confirmed and reported, a change
picked up and confirmed, both with SIGHUP (macOS/Linux --run) and with the restart that Windows uses instead
(--run-reload restart), a rejected version, the token file, and a refused redirect.
"""
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import test_controlplane as tc  # noqa: E402
from test_controlplane import ADMIN  # noqa: E402

AGENT_SRC = os.path.join(HERE, "..", "..", "egress", "agent")
FAKE = os.path.join(HERE, "fake_singbox.py")


def build_agent():
    if not shutil.which("go") or os.name == "nt":
        return None
    out = os.path.join(tempfile.mkdtemp(), "ccproxy-exit-agent")
    subprocess.run(["go", "build", "-o", out, "."], cwd=AGENT_SRC, check=True)
    return out


AGENT = build_agent()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(AGENT, "Go is not available")
class GoAgentTest(tc.ServerFixture):
    def setUp(self):
        super().setUp()
        self.tmp = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.token_file = os.path.join(self.tmp, "agent.token")
        with open(self.token_file, "w") as f:
            f.write(self.hk + "\n")
        os.chmod(self.token_file, 0o600)
        # fake_singbox.py is not executable in the repository; the agent needs an executable sing-box path.
        # CCPROXY_TEST_SINGBOX (the pinned official binary) replaces the fake, as in test_agent_review.
        self.real = os.environ.get("CCPROXY_TEST_SINGBOX")
        self.singbox = os.path.join(self.tmp, "sing-box")
        with open(self.singbox, "w") as f:
            f.write('#!/bin/sh\nexec "%s" "$@"\n' % self.real if self.real else
                    '#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, FAKE))
        os.chmod(self.singbox, 0o755)
        self.proc = None

    def tearDown(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        subprocess.run(["pkill", "-f", os.path.join(self.tmp, "config.json")], capture_output=True)
        super().tearDown()

    def start(self, *extra):
        self.log = open(os.path.join(self.tmp, "agent.log"), "w")
        self.addCleanup(self.log.close)
        self.proc = subprocess.Popen(
            [AGENT, "--cp", self.base, "--token-file", self.token_file, "--config", os.path.join(self.tmp, "config.json"),
             "--state-dir", os.path.join(self.tmp, "state"), "--singbox", self.singbox, "--run", "--interval", "0.2",
             "--settle", "0", "--confirm-api", "127.0.0.1:%d" % free_port(), "--confirm-timeout", "5",
             "--name", "hk-1", *extra],
            stdout=self.log, stderr=subprocess.STDOUT, env={k: v for k, v in os.environ.items() if k != "CP_AGENT_TOKEN"})

    def agent_view(self):
        _, _, topo = self.req("GET", "/admin/topology", ADMIN)
        return next((a for a in topo["agents"] if a["name"] == "hk-1"), None)

    def wait_for(self, check, what, timeout=20):
        deadline = time.monotonic() + timeout
        view = None
        while time.monotonic() < deadline:
            view = self.agent_view()
            if view and check(view):
                return view
            time.sleep(0.1)
        with open(os.path.join(self.tmp, "agent.log")) as f:
            self.fail("%s; last heartbeat %r\nagent log:\n%s" % (what, view, f.read()))

    def confirmed_change(self, *extra):
        self.setup_user()
        self.start(*extra)
        first = self.wait_for(lambda v: v["in_sync"] and v["apply_state"] == "confirmed" and v["singbox_running"],
                              "first config confirmed")
        self.login(device="alice-win")                       # the server config changes
        second = self.wait_for(lambda v: v["in_sync"] and v["config_etag"] != first["config_etag"]
                               and v["apply_state"] == "confirmed", "changed config confirmed")
        self.assertIsNone(second["apply_error"])
        with open(os.path.join(self.tmp, "agent.log")) as f:
            return f.read()

    def test_sighup_reload_is_confirmed_against_the_real_control_plane(self):
        log = self.confirmed_change()
        self.assertIn("sent SIGHUP to sing-box", log)
        self.assertNotIn(self.hk, log)

    def test_windows_style_restart_reload_is_confirmed(self):
        log = self.confirmed_change("--run-reload", "restart")
        self.assertIn("restarted sing-box (pid", log)
        self.assertNotIn("SIGHUP", log)

    def test_rejected_version_keeps_the_confirmed_one(self):
        if self.real:
            self.skipTest("REJECT_ME is a fake sing-box convention")
        self.setup_user()
        self.start()
        first = self.wait_for(lambda v: v["in_sync"] and v["apply_state"] == "confirmed", "first config confirmed")
        self.store.update_host("hk-1", server_name="REJECT_ME")
        time.sleep(1.5)
        view = self.agent_view()
        self.assertEqual(view["config_etag"], first["config_etag"])
        self.assertFalse(view["in_sync"])
        self.assertEqual(view["apply_state"], "confirmed")   # the installed (staged) version is still the confirmed one
        with open(os.path.join(self.tmp, "agent.log")) as f:
            self.assertIn("rejected by sing-box check", f.read())

    def test_plain_http_to_a_remote_control_plane_is_refused(self):
        r = subprocess.run([AGENT, "--cp", "http://cp.example", "--token-file", self.token_file, "--run", "--once"],
                           capture_output=True, text=True, timeout=10)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("must use https", r.stderr)


if __name__ == "__main__":
    unittest.main()
