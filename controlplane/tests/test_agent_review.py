"""Regression tests for review findings CC-02 / issue #2 (the running sing-box confirms a version before it is reported applied) and CC-03 (probe
rounds never block heartbeats or config updates)."""
import http.server
import json
import os
import shutil
import socket
import subprocess
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


def on_disk(test):
    return json.loads(tc.read(os.path.join(test.tmp, "config.json")))


def disk_marker(test, name="config.json"):
    outbounds = json.loads(tc.read(os.path.join(test.tmp, name)))["outbounds"]
    return [o["tag"] for o in outbounds if o["tag"].startswith(agentmod.MARKER_PREFIX)][0]


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
        # The working configuration is back at --config; the candidate is kept for the retry.
        self.assertEqual(disk_marker(self), a.applied_marker)
        self.assertEqual(disk_marker(self, "confirmed-config.json"), a.applied_marker)
        self.assertEqual(disk_marker(self, "candidate-config.json"), a.marker)
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
        self.assertEqual(disk_marker(self), a.applied_marker)
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
        self.assertIsNone(self.service.poll(), "the healthy old process is left alone")
        self.assertEqual(disk_marker(self), a.applied_marker, "the working configuration is back on disk")
        self.assertNotEqual(a.marker, a.applied_marker)
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
        self.assertEqual(disk_marker(self), a.marker, "inconclusive: the candidate may be running, it stays")
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

    def test_newer_candidate_replaces_an_unconfirmed_one_on_disk(self):
        a, first = self.start_confirmed()
        self.flag("silent")
        self.login(device="alice-win")
        a.loop()                                  # unknown: that candidate stays at --config
        older = a.marker
        self.assertEqual(disk_marker(self), older)
        self.flag("silent", False)
        self.login(device="alice-ipad")           # a newer version arrives meanwhile
        a.loop()
        self.assertNotEqual(a.marker, older)
        self.assertEqual(disk_marker(self), a.marker, "the newer candidate is what was reloaded")
        self.assertEqual(a.applied, a.installed)

    def test_unconfirmed_candidates_are_superseded_by_exact_generation(self):
        """Nothing was ever confirmed: B stays unconfirmed at --config, then C and D arrive. Each newer one is
        staged (not skipped because "a candidate" is already there), so the retry cannot stay stuck on B."""
        self.setup_user()
        a = self.agent()
        self.flag("silent")
        a.loop()                                  # B: reloaded, no answer
        self.assertEqual((a.applied, a.state()), (None, "unknown"))
        b = a.marker
        self.assertEqual((disk_marker(self), a.on_disk), (b, b))
        self.login(device="alice-win")
        a.loop()                                  # C: staged over B, still no answer
        c = a.marker
        self.assertNotEqual(c, b)
        self.assertEqual((disk_marker(self), a.on_disk, a.applied), (c, c, None))
        self.flag("silent", False)
        self.login(device="alice-ipad")
        a.loop()                                  # D: staged over C and confirmed
        self.assertEqual((disk_marker(self), a.applied_marker, a.applied), (a.marker, a.marker, a.installed))

    def test_late_confirmation_after_rollback_restores_the_proved_candidate(self):
        a, first = self.start_confirmed()
        old_marker = a.applied_marker
        self.flag("slow")                         # B takes effect after the confirmation window
        self.login(device="alice-win")
        a.loop()
        self.assertEqual((a.applied, a.state()), (first, "failed"))
        self.assertEqual(disk_marker(self), old_marker, "rolled back while A still answered")
        deadline = time.time() + 10
        while a.loaded_evidence() != "loaded":    # ...then sing-box finishes loading B
            self.assertLess(time.time(), deadline)
            time.sleep(0.1)
        self.flag("slow", False)
        reloads = self.reload_count()
        a.loop()                                  # 304: B is proved running
        self.assertEqual(self.reload_count(), reloads, "confirmed without another reload")
        self.assertEqual(a.applied, a.installed)
        self.assertEqual(disk_marker(self), a.marker, "the proved candidate is back at --config for restarts")
        self.assertEqual(disk_marker(self, "confirmed-config.json"), a.marker)

    def test_first_failure_after_agent_restart_keeps_the_existing_config(self):
        previous = json.dumps({"from": "an earlier agent run"})
        with open(os.path.join(self.tmp, "config.json"), "w") as f:
            f.write(previous)
        with open(os.path.join(self.tmp, "previous-config.json"), "w") as f:
            f.write("stale file from an older run")  # never trusted: this process did not save it
        self.setup_user()
        a = self.agent()
        open(self.fail_flag, "w").close()
        a.loop()                                  # a fresh agent's first candidate fails definitively
        self.assertEqual(tc.read(os.path.join(self.tmp, "config.json")), previous)
        self.assertEqual((a.applied, a.state()), (None, "failed"))
        view = topology_agent(self)
        self.assertIsNone(view["config_etag"], "no version is claimed without runtime evidence")
        self.assertEqual(view["apply_state"], "failed")
        os.unlink(self.fail_flag)
        a.loop()                                  # retried, staged again and confirmed
        self.assertEqual((a.applied, disk_marker(self)), (a.installed, a.marker))

    def test_first_failure_without_an_existing_config_restores_nothing(self):
        with open(os.path.join(self.tmp, "previous-config.json"), "w") as f:
            f.write("stale file from an older run")
        self.setup_user()
        a = self.agent()
        open(self.fail_flag, "w").close()
        a.loop()
        self.assertEqual(disk_marker(self), a.marker, "nothing better to put back; the stale copy is ignored")
        self.assertEqual((a.applied, a.state()), (None, "failed"))

    def test_revert_to_the_confirmed_etag_is_a_new_generation_to_prove(self):
        """A confirmed, B reloaded but unconfirmed (may be running, on disk), then the control plane goes back to A's
        exact content and ETag. A must be staged and proved again, not reported confirmed by ETag."""
        a, first = self.start_confirmed()
        a_marker = a.applied_marker
        original = on_disk(self)["inbounds"][0]["tls"]["server_name"]
        self.flag("silent")
        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": "www.example.org"})
        a.loop()                                  # B: unknown, at --config
        b_marker = a.marker
        self.assertEqual((a.state(), disk_marker(self)), ("unknown", b_marker))

        self.flag("silent", False)
        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": original})
        self.assertTrue(a.sync_config())          # A's content again
        self.assertEqual(a.installed, first, "same ETag as the confirmed version")
        self.assertNotIn(a.marker, (a_marker, b_marker))
        self.assertEqual(a.state(), "pending", "not confirmed by ETag alone")
        self.assertEqual(disk_marker(self), b_marker, "B is still on disk until A is staged")
        a.report()
        view = topology_agent(self)                # the dashboard agrees: same ETag, but not in sync
        self.assertEqual((view["config_etag"], view["apply_state"]), (first.strip('"'), "pending"))
        self.assertFalse(view["in_sync"])
        self.assertTrue(a.apply())                # staged and reloaded; sing-box returns the new marker
        self.assertEqual(disk_marker(self), a.marker)
        self.assertEqual(a.loaded_evidence(), "loaded")
        self.assertEqual((a.state(), a.applied, a.applied_marker), ("confirmed", first, a.marker))
        a.report()
        self.assertTrue(topology_agent(self)["in_sync"])
        # A legacy agent that sends no apply_state is judged by ETag alone, as before.
        a.post("/agent/report", {"config_etag": first, "singbox_running": True, "probes": []})
        view = topology_agent(self)
        self.assertEqual((view["apply_state"], view["in_sync"]), (None, True))

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
        api3 = json.loads(tc.read(os.path.join(self.tmp, "candidate-config.json")))["experimental"]["clash_api"]
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
        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": "REJECT_ME"})
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

    def test_child_exiting_on_a_checked_candidate_recovers_on_the_confirmed_config(self):
        a, first = self.start_confirmed()
        old_pid, old_marker = a.child.pid, a.applied_marker
        # Passes `sing-box check`, but the process exits when it loads it (after closing the old instance).
        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": "CRASH_ME.example.com"})
        a.sync_config()
        self.assertFalse(a.apply())               # the failing step itself recovers (not a later loop restart)
        self.assertIsNone(a.child.poll())
        a.report()
        self.assertEqual(a.applied, first)
        self.assertEqual(a.state(), "failed")
        self.assertIn("exited", a.apply_error)
        # Recovered once on the last confirmed configuration, which is what is on disk again.
        self.assertNotEqual(a.child.pid, old_pid)
        self.assertIsNone(a.child.poll())
        self.assertEqual(a.loaded_evidence("confirmed"), "loaded")
        self.assertEqual(disk_marker(self), old_marker)
        self.assertNotIn("CRASH_ME", tc.read(os.path.join(self.tmp, "config.json")))
        self.assertIn("CRASH_ME", tc.read(os.path.join(self.tmp, "candidate-config.json")))
        view = topology_agent(self)
        self.assertEqual((view["config_etag"], view["apply_state"]), (first.strip('"'), "failed"))

        pid = a.child.pid
        a.loop()                                  # 304: it took sing-box down, so no retry every cycle
        self.assertEqual((a.child.pid, a.applied), (pid, first))
        a.retry_after = 0
        a.loop()                                  # retried after the back-off: down again, recovered again
        self.assertEqual(a.applied, first)
        self.assertIsNone(a.child.poll())
        self.assertNotIn("CRASH_ME", tc.read(os.path.join(self.tmp, "config.json")))

        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": "www.example.org"})
        a.loop()                                  # a new candidate is not held back by the old one's back-off
        self.assertEqual(a.applied, a.installed)
        self.assertNotEqual(a.applied, first)
        self.assertTrue(topology_agent(self)["in_sync"])

    def test_agent_restart_then_crashing_candidate_recovers_the_existing_config_unclaimed(self):
        a, first = self.start_confirmed()         # an earlier agent run left A at --config
        a.child.kill()
        a.child.wait()
        previous = tc.read(os.path.join(self.tmp, "config.json"))
        b = self.agent_obj = self._agent()        # the agent restarts: nothing confirmed in this process
        b.args.run, b.args.reload_cmd = True, None
        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": "CRASH_ME.example.com"})
        b.sync_config()
        self.assertFalse(b.apply())               # starts B, which exits: A goes back and is started once
        self.assertEqual(tc.read(os.path.join(self.tmp, "config.json")), previous)
        self.assertIsNone(b.child.poll(), "running the configuration found at start")
        b.report()
        view = topology_agent(self)
        self.assertEqual((b.applied, view["config_etag"], view["apply_state"]), (None, None, "failed"))

    def test_restart_after_a_crash_reports_only_what_is_confirmed(self):
        a, first = self.start_confirmed()
        a.child.kill()                            # sing-box dies on its own, nothing pending
        a.child.wait()
        a.loop()
        self.assertIsNone(a.child.poll())
        self.assertEqual((a.applied, a.state()), (first, "confirmed"))

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


class ConfirmationGateTest(tc.AgentFixture):
    """What counts as evidence: only the candidate's own marker, returned by sing-box over a numeric loopback API,
    without redirects and within the size bound. Anything else on that port proves nothing."""

    def setUp(self):
        super().setUp()
        self.requests = []

    def listener(self, respond):
        """Replace the fixture's fake sing-box service with `respond(handler)` on the confirmation port."""
        self.service.kill()
        self.service.wait()
        test = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                test.requests.append((self.path, dict(self.headers)))
                respond(self)

            def log_message(self, *_):
                pass

        host, port = self.confirm_api.rsplit(":", 1)
        srv = http.server.ThreadingHTTPServer((host, int(port)), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        return srv

    @staticmethod
    def reply(h, status, obj=None, raw=None, headers=()):
        body = raw if raw is not None else json.dumps(obj).encode()
        h.send_response(status)
        for k, v in headers:
            h.send_header(k, v)
        h.send_header("Content-Length", str(len(body)))
        h.end_headers()
        h.wfile.write(body)

    def agent_without_service(self):
        self.setup_user()
        a = self._agent()
        a.args.reload_cmd = "true"  # "systemctl reload" that reports success whatever happened
        return a

    def marker_on_disk(self):
        tags = [o["tag"] for o in self.installed()["outbounds"]]
        return [t for t in tags if t.startswith(agentmod.MARKER_PREFIX)][0]

    def test_candidate_carries_an_unused_marker_outbound_separate_from_the_secret(self):
        a = self._agent()
        self.setup_user()
        a.loop()
        cfg = self.installed()
        marker, secret = self.marker_on_disk(), cfg["experimental"]["clash_api"]["secret"]
        self.assertEqual(cfg["outbounds"][-1], {"type": "block", "tag": marker})
        self.assertNotIn(secret, marker)
        self.assertNotEqual(cfg["outbounds"][0]["tag"], marker)  # the default outbound is unchanged
        self.assertNotIn(marker, json.dumps(cfg["route"]))      # no rule sends traffic to it
        self.assertEqual(a.state(), "confirmed")

    def test_legacy_listener_without_authentication_is_not_confirmed(self):
        a = self._agent()
        self.setup_user()
        a.loop()
        first = a.applied
        # The old revision keeps running and its API answers anyone (no secret configured).
        self.flag("stubborn")
        self.flag("noauth")
        self.login(device="alice-win")
        a.loop()
        self.assertEqual(a.applied, first)
        view = topology_agent(self)
        self.assertEqual(view["apply_state"], "failed")
        self.assertIn("still serves another configuration", view["apply_error"])
        a.loop()                                  # 304: retried, still the old revision
        self.assertEqual(a.applied, first)
        self.flag("stubborn", False)
        a.loop()                                  # 304: retried; the reloaded process lists the new marker
        self.assertEqual(a.applied, a.installed)

    def test_unrelated_listener_is_unknown_and_never_learns_the_marker(self):
        self.listener(lambda h: self.reply(h, 200, {"version": "1.0", "ok": True}))
        a = self.agent_without_service()
        a.loop()
        self.assertIsNone(a.applied)
        self.assertEqual(topology_agent(self)["apply_state"], "unknown")
        marker = self.marker_on_disk()
        self.assertTrue(self.requests)
        self.assertTrue(all(marker not in path + json.dumps(headers) for path, headers in self.requests))

    def test_listener_listing_other_outbounds_counts_as_another_configuration(self):
        self.listener(lambda h: self.reply(h, 200, {"proxies": {"direct": {}, "confirm-0000": {}}}))
        a = self.agent_without_service()
        a.loop()
        self.assertIsNone(a.applied)
        self.assertEqual(a.state(), "failed")

    def test_redirects_are_not_followed(self):
        hits = []

        class Elsewhere(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                tags = [o["tag"] for o in json.loads(tc.read(os.path.join(test.tmp, "config.json")))["outbounds"]]
                ConfirmationGateTest.reply(self, 200, {"proxies": {t: {} for t in tags}})

            def log_message(self, *_):
                pass

        test = self
        other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Elsewhere)
        threading.Thread(target=other.serve_forever, daemon=True).start()
        self.addCleanup(other.server_close)
        self.addCleanup(other.shutdown)
        target = "http://127.0.0.1:%d/proxies" % other.server_address[1]
        self.listener(lambda h: self.reply(h, 302, raw=b"", headers=[("Location", target)]))
        a = self.agent_without_service()
        a.loop()
        self.assertIsNone(a.applied)
        self.assertEqual(a.state(), "unknown")
        self.assertEqual(hits, [], "the redirect target was never asked")

    def test_truncated_chunked_answer_is_no_evidence_and_retried(self):
        def respond(h):
            h.send_response(200)
            h.send_header("Transfer-Encoding", "chunked")
            h.end_headers()
            h.wfile.write(b"1000\r\n{\"proxies\": {")  # announces 4096 bytes, sends a few, closes
            h.wfile.flush()
            h.close_connection = True

        self.listener(respond)
        a = self.agent_without_service()
        a.loop()                                  # must not escape the loop
        self.assertIsNone(a.applied)
        self.assertEqual(a.state(), "unknown")
        asked = len(self.requests)
        a.loop()                                  # still unknown, asked again
        self.assertGreater(len(self.requests), asked)
        self.assertEqual(a.state(), "unknown")

    def test_oversized_answer_is_not_evidence(self):
        old = agentmod.CONFIRM_MAX_BYTES
        agentmod.CONFIRM_MAX_BYTES = 2000
        self.addCleanup(setattr, agentmod, "CONFIRM_MAX_BYTES", old)

        def respond(h):
            # Valid JSON with the marker, then padding past the bound: only the size limit refuses it.
            tags = [o["tag"] for o in self.installed()["outbounds"]]
            self.reply(h, 200, raw=json.dumps({"proxies": {t: {} for t in tags}}).encode() + b" " * 5000)

        self.listener(respond)
        a = self.agent_without_service()
        a.loop()
        self.assertIsNone(a.applied)
        self.assertEqual(a.state(), "unknown")

    def test_confirmation_address_must_be_numeric_loopback(self):
        args = self._agent().args
        for bad in ["0.0.0.0:9095", "10.0.0.1:9095", "192.168.1.2:9095", "localhost:9095", "127.0.0.1",
                    "127.0.0.1:0", "127.0.0.1:70000", "[::]:9095", "example.com:80", "127.0.0.1:9095/x"]:
            args.confirm_api = bad
            with self.assertRaises(ValueError, msg=bad):
                agentmod.Agent(args)
            with self.assertRaises(SystemExit, msg=bad):
                agentmod.main(["--cp", "http://x", "--run", "--confirm-api", bad])
        for good, written in [("127.0.0.1:9095", "127.0.0.1:9095"), ("127.0.0.2:1", "127.0.0.2:1"),
                              ("[::1]:9095", "[::1]:9095"), ("::1:9095", "[::1]:9095")]:
            args.confirm_api = good
            self.assertEqual(agentmod.Agent(args).confirm_address, written)


REAL_SINGBOX = os.environ.get("CCPROXY_TEST_SINGBOX") or shutil.which("sing-box")


@unittest.skipUnless(REAL_SINGBOX, "set CCPROXY_TEST_SINGBOX to a sing-box binary (pinned: 1.14.4)")
class RealSingBoxTest(tc.AgentFixture):
    """The same gates against a real sing-box: it accepts the marker outbound and the API block, lists the marker
    only for the loaded configuration, and a legacy API without a secret does not confirm a candidate."""

    def setUp(self):
        super().setUp()
        self.service.kill()
        self.service.wait()
        self.procs = []
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.mixed_port = s.getsockname()[1]

    def tearDown(self):
        for p in self.procs:
            if p.poll() is None:
                p.terminate()
                p.wait(5)
        super().tearDown()

    def body(self, n, port=None):
        return json.dumps({"log": {"level": "warn"},
                           "inbounds": [{"type": "mixed", "tag": "in-%d" % n, "listen": "127.0.0.1",
                                         "listen_port": port or self.mixed_port}],
                           "outbounds": [{"type": "direct", "tag": "direct"}]}).encode()

    def agent(self, **kw):
        a = self._agent()
        a.args.singbox, a.args.confirm_timeout = REAL_SINGBOX, 10
        for k, v in kw.items():
            setattr(a.args, k, v)
        if a.args.run:
            self.addCleanup(lambda: a.child and a.child.poll() is None and (a.child.terminate(), a.child.wait(5)))
        return a

    def service_with(self, config_path):
        p = subprocess.Popen([REAL_SINGBOX, "run", "-c", config_path, "-D", self.tmp],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        return p

    def test_run_mode_start_and_sighup_are_confirmed_by_the_marker(self):
        a = self.agent(run=True, reload_cmd=None)
        self.assertTrue(a.install('"v1"', self.body(1)))
        self.assertTrue(a.apply())
        pid, first_marker = a.child.pid, a.marker
        self.assertTrue(a.install('"v2"', self.body(2)))
        self.assertTrue(a.apply())                # SIGHUP, same process, new marker listed
        self.assertEqual((a.child.pid, a.applied), (pid, '"v2"'))
        self.assertNotEqual(a.marker, first_marker)

    def test_run_mode_start_failure_after_check_restores_and_recovers(self):
        a = self.agent(run=True, reload_cmd=None)
        self.assertTrue(a.install('"v1"', self.body(1)))
        self.assertTrue(a.apply())
        old_marker = a.applied_marker
        # v2 passes `sing-box check` but cannot start: its inbound port is taken. On SIGHUP sing-box closes the
        # running instance first, then fails to start the new one and exits.
        busy = socket.socket()
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        self.addCleanup(busy.close)
        self.assertTrue(a.install('"v2"', self.body(2, port=busy.getsockname()[1])))
        self.assertFalse(a.apply())
        self.assertEqual((a.applied, a.state()), ('"v1"', "failed"))
        self.assertIn("exited", a.apply_error)
        self.assertEqual(a.loaded_evidence("confirmed"), "loaded", "recovered on v1")
        with open(a.args.config) as f:
            self.assertIn(old_marker, f.read())

    def test_reload_cmd_declined_keeps_the_confirmed_version_and_service(self):
        a = self.agent(reload_cmd="true")
        self.assertTrue(a.install('"v1"', self.body(1)))
        a._put_candidate()                        # the file the service starts from, as after a first deploy
        svc = self.service_with(a.args.config)
        deadline = time.time() + 10  # like systemd, reload only an active service (an early SIGHUP kills it)
        while a.loaded_evidence() != "loaded":
            self.assertLess(time.time(), deadline, "sing-box service did not come up")
            time.sleep(0.1)
        a.args.reload_cmd = "kill -HUP %d" % svc.pid
        self.assertTrue(a.apply())
        # The reload "succeeds" but nothing reloads: the old revision keeps serving and is reported.
        a.args.reload_cmd = "true"
        self.assertTrue(a.install('"v2"', self.body(2)))
        self.assertFalse(a.apply())
        self.assertEqual((a.applied, a.state()), ('"v1"', "failed"))
        self.assertIsNone(svc.poll(), "the working service keeps running")
        with open(a.args.config) as f:
            self.assertIn(a.applied_marker, f.read(), "the working configuration is back on disk")
        a.args.reload_cmd = "kill -HUP %d" % svc.pid
        self.assertTrue(a.apply())                # retried: now confirmed
        self.assertEqual(a.applied, '"v2"')

    def test_legacy_api_without_secret_does_not_confirm(self):
        legacy = os.path.join(self.tmp, "legacy.json")
        cfg = json.loads(self.body(0))
        cfg["experimental"] = {"clash_api": {"external_controller": self.confirm_api}}  # no secret: answers anyone
        with open(legacy, "w") as f:
            json.dump(cfg, f)
        self.service_with(legacy)
        a = self.agent(reload_cmd="true")
        self.assertTrue(a.install('"v1"', self.body(1)))
        deadline = time.time() + 10
        while a.loaded_evidence() is None:
            self.assertLess(time.time(), deadline, "legacy sing-box did not come up")
            time.sleep(0.1)
        self.assertEqual(a.loaded_evidence(), "other")  # it does answer, 200 without a secret...
        self.assertFalse(a.apply())                # ...but without the candidate's marker
        self.assertEqual((a.applied, a.state()), (None, "failed"))


class ProbeIsolationTest(tc.AgentFixture):
    """A slow 200-IP probe round must not hold up heartbeats or config changes (CC-03)."""

    def setUp(self):
        super().setUp()
        ips = ["100.64.0.%d" % i for i in range(1, 201)]
        self.admin("POST", "/admin/hosts/hk-1/ips", {"ips": ips})
        self.admin("PUT", "/admin/settings", {"monitor": {"egress_targets": ["http://probe.invalid/"]}})
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
