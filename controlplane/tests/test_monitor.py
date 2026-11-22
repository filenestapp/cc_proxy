"""Health monitoring tests (v2): probe storage, topology per host, report endpoints, agent probes, primitives."""
import http.server
import os
import socket
import sys
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import probes  # noqa: E402
import test_controlplane as tc  # noqa: E402
from monitor import HISTORY, RETENTION, Monitor  # noqa: E402
from store import Conflict, config_etag  # noqa: E402
from test_controlplane import ADMIN, PROBE, PW, Clock, make_store  # noqa: E402


def egress(ip, ok=True, latency=50.0, target="https://t.example/", detail=""):
    return {"subject": ip, "target": target, "ok": ok, "latency_ms": latency if ok else None, "detail": detail}


class MonitorTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.s, _ = make_store(self.clock)
        self.s.configure(monitor={"egress_targets": ["https://t.example/"],
                                  "entries": [{"name": "hk-relay", "host": "198.51.100.1", "port": 443}]})
        self.m = Monitor(self.s, clock=self.clock)

    def ip(self, topo, addr):
        return [i for i in topo["ips"] if i["ip"] == addr][0]

    def test_probes_never_bump_the_config_version(self):
        v = self.s.version()
        self.m.heartbeat("hk-1", "x", True)
        self.m.record("egress", "hk-1", [egress("203.0.113.3")])
        self.m.record("entry", "sh-telecom", [{"subject": "hk-1", "target": "203.0.113.2:20000", "ok": True, "latency_ms": 40}])
        self.assertEqual(self.s.version(), v)

    def test_latest_result_and_bounded_history(self):
        for i in range(HISTORY + 5):
            self.clock.now += 60
            self.m.record("egress", "hk-1", [egress("203.0.113.3", ok=(i != HISTORY + 4), detail="HTTP 403")])
        p = self.ip(self.m.topology(), "203.0.113.3")["probes"][0]
        self.assertFalse(p["ok"])
        self.assertEqual(p["detail"], "HTTP 403")
        self.assertEqual(len(p["history"]), HISTORY)
        self.assertEqual(p["history"][-1], False)  # newest last
        self.assertTrue(all(p["history"][:-1]))

    def test_old_results_are_pruned(self):
        self.m.record("egress", "hk-1", [egress("203.0.113.3")])
        self.clock.now += RETENTION + 1
        self.m.record("egress", "hk-1", [egress("203.0.113.4")])
        topo = self.m.topology()
        self.assertEqual(self.ip(topo, "203.0.113.3")["probes"], [])
        self.assertEqual(len(self.ip(topo, "203.0.113.4")["probes"]), 1)

    def test_bad_reports_are_rejected_whole(self):
        for bad in ([{"subject": "not-an-ip", "target": "x", "ok": True}],
                    [{"target": "x", "ok": True}],
                    "nope",
                    [egress("203.0.113.3")] * 5000):
            with self.assertRaises(ValueError):
                self.m.record("egress", "hk-1", bad)
        self.assertEqual(self.ip(self.m.topology(), "203.0.113.3")["probes"], [])

    def test_entries_are_hosts_with_users_plus_extras(self):
        self.assertEqual([e["name"] for e in self.m.entries()], ["hk-relay"])  # no users: nothing listens
        self.s.add_user("a", PW)
        self.s.assign("a", "203.0.113.3", 20004)
        self.assertEqual([(e["name"], e["host"], e["port"]) for e in self.m.entries()],
                         [("hk-1", "203.0.113.2", 20004), ("hk-relay", "198.51.100.1", 443)])

    def test_best_latency_skips_failed_vantages(self):
        self.s.add_user("a", PW)
        self.s.assign("a", "203.0.113.3")
        self.m.record("entry", "sh-telecom", [
            {"subject": "hk-1", "target": "203.0.113.2:20000", "ok": True, "latency_ms": 80},
            {"subject": "hk-relay", "target": "198.51.100.1:443", "ok": True, "latency_ms": 35}])
        self.m.record("entry", "hb-mobile", [
            {"subject": "hk-1", "target": "203.0.113.2:20000", "ok": True, "latency_ms": 60},
            {"subject": "hk-relay", "target": "198.51.100.1:443", "ok": False, "detail": "timeout"}])
        entries = {e["name"]: e for e in self.m.topology()["entries"]}
        self.assertEqual((entries["hk-1"]["best"]["source"], entries["hk-1"]["best"]["latency_ms"]), ("hb-mobile", 60))
        self.assertEqual(entries["hk-relay"]["best"]["source"], "sh-telecom")

    def test_sync_state_is_per_host(self):
        self.m.heartbeat("hk-1", config_etag(self.s.server_config("hk-1")), True)
        self.m.heartbeat("jp-1", config_etag(self.s.server_config("jp-1")), True)
        agents = {a["name"]: a for a in self.m.topology()["agents"]}
        self.assertTrue(agents["hk-1"]["in_sync"] and agents["jp-1"]["in_sync"])
        self.s.add_user("a", PW)
        self.s.assign("a", "198.51.100.3")  # only jp-1's config changes
        agents = {a["name"]: a for a in self.m.topology()["agents"]}
        self.assertTrue(agents["hk-1"]["in_sync"])
        self.assertFalse(agents["jp-1"]["in_sync"])

    def test_heartbeats_from_deleted_hosts_are_hidden(self):
        self.m.heartbeat("jp-1", "x", True)
        self.s.delete_host("jp-1")
        self.assertEqual(self.m.topology()["agents"], [])

    def test_ip_cards_carry_host_ports_and_device_count(self):
        self.s.add_user("a", PW, mode="shared")
        self.s.add_user("b", PW, mode="shared")
        self.s.assign("a", "203.0.113.3", 20001)
        self.s.assign("b", "203.0.113.3", 20002)
        self.s.add_device("a", "a1")
        self.s.add_device("a", "a2")
        self.s.add_device("b", "b1")
        self.s.revoke_device("a", "a2")
        card = self.ip(self.m.topology(), "203.0.113.3")
        self.assertEqual((card["host"], card["status"], card["users"], card["devices"], card["ports"]),
                         ("hk-1", "assigned", ["a", "b"], 2, {"a": 20001, "b": 20002}))

    def test_monitor_settings_are_validated(self):
        with self.assertRaises(Conflict):
            self.s.configure(monitor={"egress_targets": "https://x/"})


class MonitorApiTest(tc.ServerFixture):
    def test_probe_token_is_scoped(self):
        self.assertEqual(self.req("GET", "/probe/targets", PROBE)[0], 200)
        self.assertEqual(self.req("GET", "/probe/targets", self.hk)[0], 401)
        self.assertEqual(self.req("GET", "/admin/topology", PROBE)[0], 401)
        self.assertEqual(self.req("POST", "/agent/report", PROBE, {})[0], 401)

    def test_reports_show_up_in_topology(self):
        self.setup_user()
        status, _, out = self.req("POST", "/agent/report", self.hk, {
            "agent": "spoofed-name", "config_etag": None, "singbox_running": True,
            "probes": [egress("203.0.113.3", ok=False, detail="HTTP 429")]})
        self.assertEqual((status, out), (200, {"recorded": 1}))
        status, _, out = self.req("POST", "/probe/report", PROBE, {"vantage": "sh-telecom", "results": [
            {"subject": "hk-1", "target": "203.0.113.2:20000", "ok": True, "latency_ms": 41.5}]})
        self.assertEqual(status, 200)
        _, _, topo = self.req("GET", "/admin/topology", ADMIN)
        self.assertEqual([a["name"] for a in topo["agents"]], ["hk-1"])  # identity comes from the token
        card = [i for i in topo["ips"] if i["ip"] == "203.0.113.3"][0]
        self.assertEqual((card["probes"][0]["ok"], card["probes"][0]["detail"]), (False, "HTTP 429"))
        self.assertEqual([e["best"]["latency_ms"] for e in topo["entries"] if e["name"] == "hk-1"], [41.5])
        self.assertEqual([h["name"] for h in topo["hosts"]], ["hk-1", "jp-1"])

    def test_bad_report_is_400(self):
        self.assertEqual(self.req("POST", "/agent/report", self.hk, {"probes": [{"subject": "x"}]})[0], 400)
        self.assertEqual(self.req("POST", "/probe/report", PROBE, {"results": []})[0], 400)

    def test_dashboard_page_is_public_and_holds_no_data(self):
        self.setup_user()
        status, headers, body = self.req("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertIn(b"/admin/topology", body)
        self.assertNotIn(b"203.0.113.3", body)


class Target(http.server.BaseHTTPRequestHandler):
    """A probe target: /ok answers 200, /blocked answers 403 (an IP the site has started refusing)."""

    def do_GET(self):
        self.send_response(200 if self.path == "/ok" else 403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


class AgentProbeTest(tc.AgentFixture):
    def setUp(self):
        super().setUp()
        self.target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
        threading.Thread(target=self.target.serve_forever, daemon=True).start()
        port = self.target.server_address[1]
        self.ok_url = "http://127.0.0.1:%d/ok" % port
        self.blocked_url = "http://127.0.0.1:%d/blocked" % port
        self.store.configure(monitor={"egress_targets": [self.ok_url, self.blocked_url]})

    def tearDown(self):
        self.target.shutdown()
        self.target.server_close()
        super().tearDown()

    def test_agent_probes_each_ip_and_reports_heartbeat(self):
        # 127.0.0.1 is the only address the test can bind on every machine; it stands in for an egress IP.
        self.admin("POST", "/admin/hosts/hk-1/ips", {"ips": ["127.0.0.1"]})
        self._agent().loop()
        _, _, topo = self.req("GET", "/admin/topology", ADMIN)
        agent = topo["agents"][0]
        self.assertEqual((agent["name"], agent["in_sync"], agent["singbox_running"]), ("hk-1", True, None))
        card = [i for i in topo["ips"] if i["ip"] == "127.0.0.1"][0]
        by_target = {p["target"]: p for p in card["probes"]}
        self.assertTrue(by_target[self.ok_url]["ok"])
        self.assertIsNotNone(by_target[self.ok_url]["latency_ms"])
        self.assertEqual((by_target[self.blocked_url]["ok"], by_target[self.blocked_url]["detail"]), (False, "HTTP 403"))
        # Unbindable "egress IPs" from the test pool (203.0.113.x) fail with a bind error rather than a false ok.
        other = [i for i in topo["ips"] if i["ip"] == "203.0.113.3"][0]["probes"]
        self.assertTrue(other and not any(p["ok"] for p in other))
        # hk-1's agent probes only hk-1's IPs.
        self.assertEqual([i["probes"] for i in topo["ips"] if i["host"] == "jp-1"], [[]])

    def test_probe_interval_limits_probing_but_not_heartbeats(self):
        self.setup_user()
        clock = Clock()
        a = self._agent()
        a.clock = clock
        calls = []
        a.probe_ips = lambda **kw: calls.append(1) or []
        a.loop()
        clock.now += 30
        a.loop()
        clock.now += 31
        a.loop()
        self.assertEqual(len(calls), 2)


class ProbePrimitivesTest(unittest.TestCase):
    def test_tcp_probe(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(8)
        port = srv.getsockname()[1]
        try:
            self.assertTrue(probes.tcp_probe("127.0.0.1", port)["ok"])
        finally:
            srv.close()
        r = probes.tcp_probe("127.0.0.1", port, tries=1, timeout=1)
        self.assertFalse(r["ok"])
        self.assertIn("ConnectionRefused", r["detail"])

    def test_http_probe_rejects_unknown_scheme(self):
        self.assertFalse(probes.http_probe("ftp://x/")["ok"])


if __name__ == "__main__":
    unittest.main()
