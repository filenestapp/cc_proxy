"""Webhook API behavior on the Go control plane."""
import http.server
import json
import threading
import unittest

import test_controlplane as tc

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

    def test_test_endpoint_posts_to_every_webhook(self):
        status, out = self.admin("PUT", "/admin/settings", {"alerts": {"webhooks": [
            {"url": self.hook, "format": "feishu"}, {"url": "http://127.0.0.1:9/closed"}]}})
        self.assertEqual(status, 200)
        status, out = self.admin("POST", "/admin/alerts/test")
        self.assertEqual([r["ok"] for r in out["webhooks"]], [True, False])
        self.assertEqual(Sink.received, [{"msg_type": "text", "content": {"text": "[Warning] Test alert"}}])

    def test_bad_alert_settings_are_409(self):
        self.assertEqual(self.admin("PUT", "/admin/settings", {"alerts": {"webhooks": [{"url": "nope"}]}})[0], 409)



if __name__ == "__main__":
    unittest.main()
