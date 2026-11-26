"""Stand-in for the target site: replies with the source address it sees.

TCP 8080: HTTP, body is the client IP. /strict answers 403 to the IPs in $BLOCK_IPS (comma-separated),
          standing in for a site that has started refusing an egress IP.
UDP 9090, 3478 and 443: echo the source IP or answer a STUN Binding request.
"""
import http.server
import os
import socket
import struct
import threading

BLOCKED = {ip for ip in os.environ.get("BLOCK_IPS", "").split(",") if ip}
STUN_COOKIE = bytes.fromhex("2112a442")
STUN_ALTERNATE = os.environ.get("STUN_ALTERNATE")


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


def udp_echo(host, port):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.bind((host, port))
    while True:
        packet, addr = s.recvfrom(2048)
        if len(packet) >= 20 and packet[:2] == b"\x00\x01" and packet[4:8] == STUN_COOKIE:
            # Use the actual source address for the XOR-MAPPED-ADDRESS attribute.
            print("stun", "ipv6" if family == socket.AF_INET6 else "ipv4", port, addr[0], flush=True)
            mask = packet[4:20]
            ip = socket.inet_pton(family, addr[0])
            mapped = bytes(a ^ b for a, b in zip(ip, mask))
            address = struct.pack("!BBH", 0, 2 if family == socket.AF_INET6 else 1, addr[1] ^ 0x2112)
            attribute = struct.pack("!HH", 0x0020, len(address) + len(mapped)) + address + mapped
            if port == 3478 and family == socket.AF_INET and STUN_ALTERNATE:
                # frpc discovers the mapping twice using RFC 5780's OTHER-ADDRESS.
                attribute += struct.pack("!HHBBH4s", 0x802C, 8, 0, 1, 3479, socket.inet_aton(STUN_ALTERNATE))
            reply = struct.pack("!HH", 0x0101, len(attribute)) + mask + attribute
        else:
            print("udp", port, addr[0], flush=True)
            reply = addr[0].encode()
        s.sendto(reply, addr)


# 443 also stands in for QUIC in the plain UDP checks.
for host in filter(None, ("0.0.0.0", os.environ.get("ECHO_IPV6"))):
    for port in (9090, 3478, 443):
        address = STUN_ALTERNATE if STUN_ALTERNATE and host == "0.0.0.0" and port == 3478 else host
        threading.Thread(target=udp_echo, args=(address, port), daemon=True).start()
if STUN_ALTERNATE:
    threading.Thread(target=udp_echo, args=(STUN_ALTERNATE, 3479), daemon=True).start()
http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
