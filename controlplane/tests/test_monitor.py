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
from test_controlplane import ADMIN, PROBE, Clock  # noqa: E402


def egress(ip, ok=True, latency=50.0, target="https://t.example/", detail=""):
    return {"subject": ip, "target": target, "ok": ok, "latency_ms": latency if ok else None, "detail": detail}


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
        self.admin("PUT", "/admin/settings", {"monitor": {"egress_targets": [self.ok_url, self.blocked_url]}})

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
