"""Alerting tests: rules, pending/firing/resolved transitions, delivery retries, payload formats, API."""
import http.server
import json
import os
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import alerts  # noqa: E402
import test_controlplane as tc  # noqa: E402
from monitor import Monitor  # noqa: E402
from store import Conflict, config_etag  # noqa: E402
from test_controlplane import ADMIN, PW, Clock, make_store  # noqa: E402

HOOK = "http://hooks.test/alert"
TARGET = "https://t.example/"


class Outbox:
    """Stand-in for post_json: records deliveries, or fails while .down is set."""

    def __init__(self):
        self.sent, self.down = [], False

    def __call__(self, url, body):
        if self.down:
            raise OSError("connection refused")
        self.sent.append((url, body))

    def statuses(self):
        return [(b["status"], b["rule"], b["subject"]) for _, b in self.sent]


class AlerterTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.s, _ = make_store(self.clock)
        self.s.delete_host("jp-1")  # one host keeps the expected alert lists short
        self.s.configure(monitor={"egress_targets": [TARGET]},
                         alerts={"webhooks": [{"url": HOOK}], "consecutive_failures": 3,
                                 "agent_stale_seconds": 120, "out_of_sync_seconds": 300})
        self.s.add_user("alice", PW)
        self.s.assign("alice", "203.0.113.3")
        self.m = Monitor(self.s, clock=self.clock)
        self.out = Outbox()
        self.a = alerts.Alerter(self.s, self.m, clock=self.clock, send=self.out, log=lambda m: None)
        self.heartbeat()

    def heartbeat(self, running=True, etag=None):
        self.m.heartbeat("hk-1", etag or config_etag(self.s.server_config("hk-1")), running)

    def probe(self, ip, ok, detail="HTTP 403"):
        self.clock.now += 60
        self.heartbeat()
        self.m.record("egress", "hk-1", [{"subject": ip, "target": TARGET, "ok": ok,
                                            "latency_ms": 30 if ok else None, "detail": "HTTP 200" if ok else detail}])
        self.a.evaluate()

    def test_fires_after_consecutive_failures_once_and_resolves_once(self):
        self.probe("203.0.113.3", False)
        self.probe("203.0.113.3", False)
        self.assertEqual(self.out.sent, [])
        self.probe("203.0.113.3", False)
        self.assertEqual(self.out.statuses(), [("firing", "egress_probe_failing", "203.0.113.3")])
        body = self.out.sent[0][1]
        self.assertEqual(body["severity"], "critical")
        self.assertIn("alice", body["summary"])
        self.assertIn("cpctl ban 203.0.113.3", body["summary"])
        self.probe("203.0.113.3", False)
        self.assertEqual(len(self.out.sent), 1)  # still firing: no duplicate
        self.probe("203.0.113.3", True)
        self.assertEqual(self.out.statuses()[-1], ("resolved", "egress_probe_failing", "203.0.113.3"))
        self.assertEqual(len(self.out.sent), 2)
        self.probe("203.0.113.3", True)
        self.assertEqual(len(self.out.sent), 2)

    def test_a_success_in_the_window_breaks_the_streak(self):
        for ok in (False, False, True, False, False):
            self.probe("203.0.113.3", ok)
        self.assertEqual(self.out.sent, [])

    def test_unassigned_ip_is_a_warning_and_ban_resolves(self):
        for _ in range(3):
            self.probe("203.0.113.4", False)
        self.assertEqual(self.out.sent[0][1]["severity"], "warning")
        self.s.ban_ip("203.0.113.4", "blocked")
        self.a.evaluate()
        self.assertEqual(self.out.statuses()[-1], ("resolved", "egress_probe_failing", "203.0.113.4"))

    def test_agent_stale_fires_and_heartbeat_resolves(self):
        self.clock.now += 121
        self.a.evaluate()
        self.assertEqual(self.out.statuses(), [("firing", "agent_stale", "hk-1")])
        self.heartbeat()
        self.a.evaluate()
        self.assertEqual(self.out.statuses()[-1], ("resolved", "agent_stale", "hk-1"))

    def test_singbox_down(self):
        self.heartbeat(running=False)
        self.a.evaluate()
        self.assertEqual(self.out.statuses(), [("firing", "singbox_down", "hk-1")])
        self.heartbeat(running=None)  # unknown is not "down"
        self.a.evaluate()
        self.assertEqual(self.out.statuses()[-1], ("resolved", "singbox_down", "hk-1"))

    def test_out_of_sync_waits_for_its_grace_period(self):
        self.heartbeat(etag="old")
        self.a.evaluate()
        self.assertEqual(self.a.list(include_resolved=True)[0]["state"], "pending")
        self.clock.now += 299
        self.heartbeat(etag="old")
        self.a.evaluate()
        self.assertEqual(self.out.sent, [])
        self.clock.now += 1
        self.heartbeat(etag="old")
        self.a.evaluate()
        self.assertEqual(self.out.statuses(), [("firing", "agent_out_of_sync", "hk-1")])

    def test_out_of_sync_that_recovers_in_time_leaves_no_trace(self):
        self.heartbeat(etag="old")
        self.a.evaluate()
        self.clock.now += 30
        self.heartbeat()
        self.a.evaluate()
        self.assertEqual(self.a.list(include_resolved=True), [])
        self.assertEqual(self.out.sent, [])

    def test_entry_unreachable_severity_depends_on_other_vantages(self):
        def round_(sh_ok, hb_ok):
            self.clock.now += 30
            self.heartbeat()
            self.m.record("entry", "sh-telecom", [{"subject": "hk-1", "target": "203.0.113.2:20000", "ok": sh_ok,
                                                   "latency_ms": 40 if sh_ok else None, "detail": "timeout"}])
            self.m.record("entry", "hb-mobile", [{"subject": "hk-1", "target": "203.0.113.2:20000", "ok": hb_ok,
                                                  "latency_ms": 50 if hb_ok else None, "detail": "timeout"}])
            self.a.evaluate()
        for _ in range(3):
            round_(False, True)
        self.assertEqual([(b["subject"], b["severity"]) for _, b in self.out.sent], [("hk-1", "warning")])
        for _ in range(3):
            round_(False, False)
        active = {a["key"]: a["severity"] for a in self.a.list()}
        self.assertEqual(active, {"entry_unreachable/hk-1/sh-telecom": "critical",
                                  "entry_unreachable/hk-1/hb-mobile": "critical"})

    def test_failed_delivery_is_retried_until_it_succeeds(self):
        self.out.down = True
        for _ in range(3):
            self.probe("203.0.113.3", False)
        self.assertEqual(self.out.sent, [])
        self.assertIn("connection refused", self.a.list()[0]["notify_error"])
        self.a.evaluate()
        self.assertEqual(self.out.sent, [])
        self.out.down = False
        self.a.evaluate()
        self.assertEqual(self.out.statuses(), [("firing", "egress_probe_failing", "203.0.113.3")])
        self.a.evaluate()
        self.assertEqual(len(self.out.sent), 1)

    def test_repeat_reminders(self):
        self.s.configure(alerts={"webhooks": [{"url": HOOK}], "repeat_seconds": 600})
        self.clock.now += 121
        self.a.evaluate()
        self.clock.now += 599
        self.a.evaluate()
        self.assertEqual(len(self.out.sent), 1)
        self.clock.now += 1
        self.a.evaluate()
        self.assertEqual(self.out.statuses(), [("firing", "agent_stale", "hk-1")] * 2)

    def test_alerting_never_bumps_the_config_version(self):
        v = self.s.version()
        for _ in range(3):
            self.probe("203.0.113.3", False)
        self.assertEqual(self.s.version(), v)

    def test_payload_formats(self):
        al = {"rule": "r", "subject": "s", "severity": "critical", "summary": "出口 IP 1.2.3.4 失败",
              "started_at": 1, "fired_at": 1, "resolved_at": None}
        self.assertEqual(alerts.payload("slack", al, "firing"), {"text": "[严重] 出口 IP 1.2.3.4 失败"})
        self.assertEqual(alerts.payload("feishu", al, "resolved"),
                         {"msg_type": "text", "content": {"text": "[已解除] 出口 IP 1.2.3.4 失败"}})
        self.assertEqual(alerts.payload("dingtalk", al, "firing")["text"]["content"], "[严重] 出口 IP 1.2.3.4 失败")
        self.assertEqual(alerts.payload("generic", al, "firing")["status"], "firing")

    def test_settings_are_validated(self):
        for bad in ({"webhooks": [{"url": "ftp://x"}]}, {"webhooks": [{"url": HOOK, "format": "sms"}]},
                    {"consecutive_failures": 0}, {"agent_stale_seconds": -1}, {"bogus": 1}):
            with self.assertRaises(Conflict):
                self.s.configure(alerts=bad)


class Sink(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        Sink.received.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class AlertApiTest(tc.ServerFixture):
    def setUp(self):
        super().setUp()
        Sink.received = []
        self.sink = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Sink)
        threading.Thread(target=self.sink.serve_forever, daemon=True).start()
        self.hook = "http://127.0.0.1:%d/hook" % self.sink.server_address[1]

    def tearDown(self):
        self.sink.shutdown()
        self.sink.server_close()
        super().tearDown()

    def test_test_endpoint_posts_to_every_webhook(self):
        status, out = self.admin("PUT", "/admin/settings", {"alerts": {"webhooks": [
            {"url": self.hook, "format": "feishu"}, {"url": "http://127.0.0.1:9/closed"}]}})
        self.assertEqual(status, 200)
        status, out = self.admin("POST", "/admin/alerts/test")
        self.assertEqual([r["ok"] for r in out["webhooks"]], [True, False])
        self.assertEqual(Sink.received, [{"msg_type": "text", "content": {"text": "[警告] 告警通道测试"}}])

    def test_bad_alert_settings_are_409(self):
        self.assertEqual(self.admin("PUT", "/admin/settings", {"alerts": {"webhooks": [{"url": "nope"}]}})[0], 409)

    def test_firing_alerts_reach_topology_and_list(self):
        self.admin("PUT", "/admin/settings", {"alerts": {"webhooks": [{"url": self.hook}], "agent_stale_seconds": 0}})
        mon = self.httpd.RequestHandlerClass.mon
        mon.heartbeat("hk-1", None, True)
        self.store.clock = lambda: 10 ** 10  # far future: the heartbeat is stale
        mon.clock = self.store.clock
        self.httpd.RequestHandlerClass.alerter.clock = self.store.clock
        self.httpd.RequestHandlerClass.alerter.evaluate()
        _, topo = self.admin("GET", "/admin/topology")
        self.assertEqual([a["rule"] for a in topo["alerts"]], ["agent_stale"])
        _, listed = self.admin("GET", "/admin/alerts")
        self.assertEqual(len(listed), 1)
        self.assertEqual(Sink.received[0]["rule"], "agent_stale")


if __name__ == "__main__":
    unittest.main()
