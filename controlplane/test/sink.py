"""Webhook receiver for the e2e test: prints every alert notification as one JSON line."""
import http.server
import json


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        print("ALERT " + json.dumps(body, ensure_ascii=False, sort_keys=True), flush=True)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
