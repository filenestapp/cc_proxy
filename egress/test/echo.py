"""Stand-in for the target site: replies with the source address it sees.

TCP 8080: HTTP, body is the client IP. /strict answers 403 to the IPs in $BLOCK_IPS (comma-separated),
          standing in for a site that has started refusing an egress IP.
UDP 9090 and 443: reply with the client IP.
"""
import http.server
import os
import socket
import threading

BLOCKED = {ip for ip in os.environ.get("BLOCK_IPS", "").split(",") if ip}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        blocked = self.path.startswith("/strict") and self.client_address[0] in BLOCKED
        self.send_response(403 if blocked else 200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("tcp", self.client_address[0], fmt % args, flush=True)


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        _, addr = s.recvfrom(2048)
        print("udp", port, addr[0], flush=True)
        s.sendto(addr[0].encode(), addr)


# 443 stands in for QUIC: clients must block it for tunnelled traffic.
for p in (9090, 443):
    threading.Thread(target=udp_echo, args=(p,), daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
