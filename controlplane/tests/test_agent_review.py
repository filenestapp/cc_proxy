"""Regression tests for review findings CC-02 / issue #2 (the running sing-box confirms a version before it is reported applied) and CC-03 (probe
rounds never block heartbeats or config updates)."""
import json
import os
import signal
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
    """--reload-cmd (systemd): a version counts as applied only when the running sing-box answers the confirmation
    API with that version's secret. The fixture's fake service plays `systemctl reload sing-box`."""

    def setUp(self):
        super().setUp()
        self.fail_flag = os.path.join(self.tmp, "fail-reload")
        script = os.path.join(self.tmp, "reload.sh")
        with open(script, "w") as f:
            f.write('#!/bin/sh\necho x >> "%s"\n[ -f "%s" ] && exit 1\nkill -HUP %d\n'
                    % (self.reloads, self.fail_flag, self.service.pid))
        os.chmod(script, os.stat(script).st_mode | stat.S_IEXEC)
        self.script = script

    def agent(self):
        a = self._agent()
        a.args.reload_cmd = self.script
        return a

    def start_confirmed(self):
        self.setup_user()
        a = self.agent()
        a.loop()
        self.assertIsNotNone(a.applied)
        self.assertEqual(topology_agent(self)["apply_state"], "confirmed")
        return a, a.applied

    def test_failed_reload_keeps_previous_version_and_is_retried_after_304(self):
        a, first = self.start_confirmed()
        self.assertTrue(topology_agent(self)["in_sync"])

        open(self.fail_flag, "w").close()
        self.login(device="alice-win")           # server config changes
        a.loop()                                  # written, reload fails
        self.assertEqual(a.applied, first)
        self.assertNotEqual(a.installed, first)
        agent_view = topology_agent(self)
        self.assertEqual(agent_view["config_etag"], first.strip('"'))  # dashboard still shows the old version
        self.assertFalse(agent_view["in_sync"])
        self.assertEqual(agent_view["apply_state"], "failed")
        self.assertIn("reload failed", agent_view["apply_error"])

        a.loop()                                  # 304 for the written candidate, still failing: retried
        self.assertEqual(self.reload_count(), 3)
        self.assertEqual(a.applied, first)

        os.unlink(self.fail_flag)
        a.loop()                                  # 304 again, retry succeeds and sing-box confirms it
        self.assertEqual(a.applied, a.installed)
        agent_view = topology_agent(self)
        self.assertTrue(agent_view["in_sync"])
        self.assertEqual(agent_view["apply_state"], "confirmed")
        self.assertIsNone(agent_view["apply_error"])

    def test_old_service_that_stays_alive_is_not_confirmed(self):
        """systemctl reload and is-active both succeed, but sing-box keeps serving the old revision."""
        a, first = self.start_confirmed()
        a.args.status_cmd = "true"
        self.flag("stubborn")
        self.login(device="alice-win")
        a.loop()
        self.assertEqual(self.reload_count(), 2)
        self.assertEqual(a.applied, first)
        agent_view = topology_agent(self)
        self.assertEqual((agent_view["apply_state"], agent_view["singbox_running"]), ("failed", True))
        self.assertIn("still serves another configuration", agent_view["apply_error"])
        self.assertFalse(agent_view["in_sync"])

        a.loop()                                  # 304: retried, still the old revision
        self.assertEqual((self.reload_count(), a.applied), (3, first))

        self.flag("stubborn", False)
        a.loop()                                  # 304: retried, now loaded
        self.assertEqual(self.reload_count(), 4)
        self.assertEqual(a.applied, a.installed)
        self.assertTrue(topology_agent(self)["in_sync"])

    def test_silent_service_is_reported_unknown_not_applied(self):
        a, first = self.start_confirmed()
        self.flag("silent")
        self.login(device="alice-win")
        a.loop()
        self.assertEqual(a.applied, first)
        agent_view = topology_agent(self)
        self.assertEqual(agent_view["apply_state"], "unknown")
        self.assertIn("not confirmed", agent_view["apply_error"])
        self.assertFalse(agent_view["in_sync"])

        a.loop()                                  # unknown: re-checked, but not reloaded again right away
        self.assertEqual((self.reload_count(), a.applied), (2, first))

        # The service starts answering (e.g. an operator reloaded it): confirmed without another reload.
        self.flag("silent", False)
        self.service.send_signal(signal.SIGHUP)
        time.sleep(0.3)
        a.loop()
        self.assertEqual(self.reload_count(), 2)
        self.assertEqual(a.applied, a.installed)
        self.assertEqual(topology_agent(self)["apply_state"], "confirmed")

    def test_unknown_is_reloaded_again_after_the_retry_interval(self):
        a, first = self.start_confirmed()
        self.flag("silent")
        self.login(device="alice-win")
        a.loop()
        self.assertEqual(a.state(), "unknown")
        self.flag("silent", False)
        a.last_reload -= agentmod.UNKNOWN_RETRY_SECONDS
        a.loop()
        self.assertEqual(self.reload_count(), 3)
        self.assertEqual(a.applied, a.installed)

    def test_each_candidate_carries_its_own_confirmation_secret(self):
        a, _ = self.start_confirmed()
        api = self.installed()["experimental"]["clash_api"]
        self.assertEqual(api["external_controller"], self.confirm_api)
        self.login(device="alice-win")
        a.loop()
        api2 = self.installed()["experimental"]["clash_api"]
        self.assertNotEqual(api["secret"], api2["secret"])
        self.assertEqual(self.installed()["inbounds"][0]["users"][-1]["name"], "alice/alice-win")  # rest kept
        # A clash_api block sent by the control plane is replaced, never trusted.
        body = json.dumps({"experimental": {"clash_api": {"external_controller": "0.0.0.0:9090", "secret": "x"}}})
        a.install('"forged"', body.encode())
        api3 = self.installed()["experimental"]["clash_api"]
        self.assertEqual(api3["external_controller"], self.confirm_api)
        self.assertNotEqual(api3["secret"], "x")

    def test_status_cmd_failure_is_reported_but_does_not_decide(self):
        self.setup_user()
        a = self.agent()
        a.args.status_cmd = "false"
        a.loop()
        self.assertEqual(a.applied, a.installed)  # confirmed by sing-box itself
        self.assertIs(topology_agent(self)["singbox_running"], False)

    def test_invalid_candidate_leaves_the_working_config(self):
        self.setup_user()
        a = self.agent()
        a.loop()
        before, applied = tc.read(os.path.join(self.tmp, "config.json")), a.applied
        self.store.update_host("hk-1", server_name="REJECT_ME")
        a.loop()
        self.assertEqual(tc.read(os.path.join(self.tmp, "config.json")), before)
        self.assertEqual((a.applied, a.installed), (applied, applied))
        self.assertEqual(topology_agent(self)["apply_state"], "confirmed")

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
    """--run: the agent's own sing-box child must confirm the candidate; a live PID or a delivered SIGHUP is not
    enough."""

    def tearDown(self):
        if self.agent_obj and self.agent_obj.child and self.agent_obj.child.poll() is None:
            self.agent_obj.child.kill()
            self.agent_obj.child.wait()
        super().tearDown()

    agent_obj = None

    def start_confirmed(self):
        self.setup_user()
        a = self.agent_obj = self._agent()
        a.args.run, a.args.reload_cmd = True, None
        a.loop()
        self.assertIsNotNone(a.applied)
        return a, a.applied

    def test_crash_on_reload_is_not_reported_applied_and_recovers(self):
        a, first = self.start_confirmed()
        self.flag("crash")
        self.login(device="alice-win")
        a.loop()                                  # SIGHUP -> exits; restart with it exits too -> not applied
        self.assertEqual(a.applied, first)
        self.assertIn("exited", a.apply_error)
        self.assertIsNotNone(a.child.poll())
        self.assertEqual(topology_agent(self)["apply_state"], "failed")
        self.assertFalse(topology_agent(self)["in_sync"])
        self.flag("crash", False)
        a.loop()                                  # retried: restarted with the written config, confirmed
        self.assertEqual(a.applied, a.installed)
        self.assertTrue(topology_agent(self)["in_sync"])

    def test_child_that_stays_alive_on_the_old_revision_is_not_confirmed(self):
        a, first = self.start_confirmed()
        pid = a.child.pid
        self.flag("stubborn")
        self.login(device="alice-win")
        a.loop()                                  # SIGHUP delivered, child alive, old revision served
        self.assertEqual(a.child.pid, pid)
        self.assertIsNone(a.child.poll())
        self.assertEqual(a.applied, first)
        self.assertEqual(topology_agent(self)["apply_state"], "failed")
        a.loop()                                  # 304: retried, still old
        self.assertEqual(a.applied, first)
        self.flag("stubborn", False)
        a.loop()                                  # 304: retried, loaded
        self.assertEqual(a.child.pid, pid)
        self.assertEqual(a.applied, a.installed)
        self.assertEqual(topology_agent(self)["apply_state"], "confirmed")


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
