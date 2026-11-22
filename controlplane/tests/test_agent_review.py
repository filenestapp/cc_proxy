"""Regression tests for review findings CC-02 (confirm reload before reporting a version applied) and CC-03 (probe
rounds never block heartbeats or config updates)."""
import json
import os
import stat
import sys
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import agent as agentmod  # noqa: E402
import test_controlplane as tc  # noqa: E402
from test_controlplane import ADMIN, Clock  # noqa: E402


def topology_agent(test, name="hk-1"):
    _, _, topo = test.req("GET", "/admin/topology", ADMIN)
    return [a for a in topo["agents"] if a["name"] == name][0]


class ReloadCmdTest(tc.AgentFixture):
    """--reload-cmd: the command (and --status-cmd) must succeed before a version counts as applied."""

    def setUp(self):
        super().setUp()
        self.fail_flag = os.path.join(self.tmp, "fail-reload")
        script = os.path.join(self.tmp, "reload.sh")
        with open(script, "w") as f:
            f.write('#!/bin/sh\necho x >> "%s"\n[ -f "%s" ] && exit 1\nexit 0\n' % (self.reloads, self.fail_flag))
        os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)
        self.script = script

    def agent(self):
        a = self._agent()
        a.args.reload_cmd = self.script
        return a

    def test_failed_reload_keeps_previous_version_and_is_retried_after_304(self):
        self.setup_user()
        a = self.agent()
        a.loop()
        first = a.applied
        self.assertIsNotNone(first)
        self.assertTrue(topology_agent(self)["in_sync"])

        open(self.fail_flag, "w").close()
        self.login(device="alice-win")           # server config changes
        a.loop()                                  # written, reload fails
        self.assertEqual(a.applied, first)
        self.assertNotEqual(a.installed, first)
        agent_view = topology_agent(self)
        self.assertEqual(agent_view["config_etag"], first.strip('"'))  # dashboard still shows the old version
        self.assertFalse(agent_view["in_sync"])
        self.assertIn("reload failed", agent_view["apply_error"])

        a.loop()                                  # 304 for the written candidate, still failing: retried
        self.assertEqual(self.reload_count(), 3)
        self.assertEqual(a.applied, first)

        os.unlink(self.fail_flag)
        a.loop()                                  # 304 again, retry succeeds
        self.assertEqual(a.applied, a.installed)
        agent_view = topology_agent(self)
        self.assertTrue(agent_view["in_sync"])
        self.assertIsNone(agent_view["apply_error"])

    def test_status_cmd_failure_counts_as_failed_reload(self):
        self.setup_user()
        a = self.agent()
        a.args.status_cmd = "false"
        a.loop()
        self.assertIsNone(a.applied)
        self.assertIn("not running", a.apply_error)
        a.args.status_cmd = "true"
        a.loop()
        self.assertEqual(a.applied, a.installed)

    def test_invalid_candidate_leaves_the_working_config(self):
        self.setup_user()
        a = self.agent()
        a.loop()
        before, applied = tc.read(os.path.join(self.tmp, "config.json")), a.applied
        self.store.update_host("hk-1", server_name="REJECT_ME")
        a.loop()
        self.assertEqual(tc.read(os.path.join(self.tmp, "config.json")), before)
        self.assertEqual((a.applied, a.installed), (applied, applied))

    def test_burst_still_coalesces_into_one_successful_reload(self):
        self.setup_user()
        clock = Clock()
        a = self.agent()
        a.args.settle = 10
        a.clock = clock
        a.loop()
        for dev in ("b1", "b2", "b3"):
            self.login(device=dev)
            clock.now += 3
            a.loop()
        clock.now += 10
        a.loop()
        self.assertEqual(self.reload_count(), 2)
        self.assertEqual(a.applied, a.installed)


class RunModeTest(tc.AgentFixture):
    """--run: sing-box must survive start / SIGHUP before a version counts as applied."""

    def setUp(self):
        super().setUp()
        self.crash_flag = os.path.join(self.tmp, "crash-on-hup")
        # Fake sing-box: `check` as in the fixture; `run` idles, and on SIGHUP exits if the crash flag exists.
        with open(self.fake, "w") as f:
            f.write('#!/bin/sh\n'
                    'if [ "$1" = check ]; then grep -q REJECT_ME "$3" && exit 1; exit 0; fi\n'
                    'trap \'[ -f "%s" ] && exit 3\' HUP\n'
                    'while :; do sleep 0.1; done\n' % self.crash_flag)

    def tearDown(self):
        if self.agent_obj and self.agent_obj.child and self.agent_obj.child.poll() is None:
            self.agent_obj.child.kill()
            self.agent_obj.child.wait()
        super().tearDown()

    agent_obj = None

    def test_crash_on_reload_is_not_reported_applied_and_recovers(self):
        self.setup_user()
        a = self.agent_obj = self._agent()
        a.args.run, a.args.reload_cmd = True, None
        a.loop()
        first = a.applied
        self.assertIsNotNone(first)
        open(self.crash_flag, "w").close()
        self.login(device="alice-win")
        a.loop()                                  # SIGHUP -> fake sing-box exits -> not applied
        self.assertEqual(a.applied, first)
        self.assertIn("exited", a.apply_error)
        self.assertFalse(topology_agent(self)["in_sync"])
        os.unlink(self.crash_flag)
        a.loop()                                  # retried: restarted with the written config
        self.assertEqual(a.applied, a.installed)
        self.assertTrue(topology_agent(self)["in_sync"])


class ProbeIsolationTest(tc.AgentFixture):
    """A slow 200-IP probe round must not hold up heartbeats or config changes (CC-03)."""

    def setUp(self):
        super().setUp()
        ips = ["100.64.0.%d" % i for i in range(1, 201)]
        self.admin("POST", "/admin/hosts/hk-1/ips", {"ips": ips})
        self.store.configure(monitor={"egress_targets": ["http://probe.invalid/"]})
        self.release = threading.Event()
        self.started = threading.Semaphore(0)
        self.real_probe = agentmod.http_probe

        def slow_probe(url, ip, timeout):
            # Even last octets answer at once; odd ones hang until released (a timing-out target).
            if int(ip.rsplit(".", 1)[1]) % 2 == 0:
                return {"ok": False, "latency_ms": None, "detail": "HTTP 403"}
            self.release.wait(10)
            return {"ok": True, "latency_ms": 12.0, "detail": "HTTP 200"}

        agentmod.http_probe = slow_probe

    def tearDown(self):
        self.release.set()
        agentmod.http_probe = self.real_probe
        super().tearDown()

    def test_heartbeats_and_config_keep_flowing_during_a_slow_round(self):
        self.setup_user()
        a = self._agent()
        a.args.once = False                       # background probe rounds, as in production
        a.sync_ips()
        a.sync_config()
        a.apply()
        started = time.monotonic()
        a.report()                                # starts the round, returns at once
        self.assertLess(time.monotonic() - started, 2)
        self.assertTrue(a.probe_running)
        self.assertEqual(topology_agent(self)["config_etag"], a.applied.strip('"'))

        # Config change applied while the round is still running.
        self.login(device="alice-win")
        a.sync_config()
        self.assertTrue(a.apply())
        self.assertTrue(a.probe_running)

        # No second round starts while one runs, even once the interval has passed.
        a.last_probe -= 10 ** 6
        self.assertFalse(a.maybe_probe())

        # Results completed so far are reported before the round finishes. (Once every worker is held by a hanging
        # target the rest queue behind them, so wait until the buffer stops growing.)
        last, stable_since = -1, time.monotonic()
        while time.monotonic() - stable_since < 0.5:
            n = len(a.probe_buf)
            if n != last:
                last, stable_since = n, time.monotonic()
            time.sleep(0.05)
        self.assertGreater(last, 0)
        a.report()
        _, _, topo = self.req("GET", "/admin/topology", ADMIN)
        reported = {i["ip"] for i in topo["ips"] if i["probes"]}
        self.assertEqual(len(reported), last)
        self.assertTrue(a.probe_running)
        self.assertTrue(all(int(ip.rsplit(".", 1)[1]) % 2 == 0 for ip in reported))
        self.assertTrue(topology_agent(self)["in_sync"])

        self.release.set()
        deadline = time.monotonic() + 10
        while a.probe_running and time.monotonic() < deadline:
            time.sleep(0.05)
        a.report()
        _, _, topo = self.req("GET", "/admin/topology", ADMIN)
        self.assertEqual(len([i for i in topo["ips"] if i["ip"].startswith("100.64.") and i["probes"]]), 200)

    def test_buffer_is_bounded(self):
        a = self._agent()
        for i in range(agentmod.PROBE_BUFFER + 500):
            a._collect({"subject": "100.64.0.1", "target": "t", "ok": True, "n": i})
        self.assertEqual(len(a.probe_buf), agentmod.PROBE_BUFFER)
        self.assertEqual(len(a.drain_probes()), agentmod.REPORT_MAX)


if __name__ == "__main__":
    unittest.main()
