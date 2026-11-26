"""Probe the dual-stack STUN responder from the real aifree client container."""
import errno
import ipaddress
import secrets
import socket
import sys

ECHO_V4 = "10.99.0.10"
ECHO_V6 = "fd10:99::10"
CLIENT_V4 = "10.88.0.60"
CLIENT_V6 = "fd10:88::60"
COOKIE = bytes.fromhex("2112a442")


def exchange(host, port, packet):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        try:
            sock.connect((host, port))
            sock.send(packet)
            return sock.recv(2048)
        except (TimeoutError, ConnectionRefusedError):
            return None
        except OSError as error:
            if error.errno != errno.ENETUNREACH:
                raise
            return None


def stun_address(host, port):
    request = b"\x00\x01\x00\x00" + COOKIE + secrets.token_bytes(12)
    reply = exchange(host, port, request)
    if reply is None:
        return None
    if reply[:2] != b"\x01\x01" or reply[4:20] != request[4:20] or reply[20:22] != b"\x00\x20":
        raise ValueError("invalid STUN Binding response")
    address = bytes(a ^ b for a, b in zip(reply[28:], request[4:20]))
    return str(ipaddress.ip_address(address))


def main():
    case, egress = sys.argv[1:]
    expected_v4, expected_v6 = {
        "disconnected": (CLIENT_V4, CLIENT_V6),
        "proxy": (egress, None),
        "reject": (None, None),
        # This is the original IPv4-only strict-route TUN, which rejects off-link IPv6 on Linux.
        "direct": (CLIENT_V4, None),
    }[case]
    checks = [
        (f"{case}: unmatched IPv4 STUN", stun_address(ECHO_V4, 3478), expected_v4),
        (f"{case}: unmatched IPv4 STUN on UDP 443", stun_address(ECHO_V4, 443), expected_v4),
        (f"{case}: IPv6 STUN", stun_address(ECHO_V6, 3478), expected_v6),
        (f"{case}: unmatched plain IPv4 UDP 443", exchange(ECHO_V4, 443, b"ping"), CLIENT_V4.encode()),
        (f"{case}: unmatched plain IPv6 UDP", exchange(ECHO_V6, 9090, b"ping"),
         None if case == "direct" else CLIENT_V6.encode()),
    ]
    if case == "proxy":
        checks.extend([
            ("STUN on a rule domain's UDP 443 precedes the QUIC block", stun_address("target.test", 443), egress),
            ("plain UDP 443 still blocked on a rule domain", exchange("target.test", 443, b"ping"), None),
        ])
    for label, observed, expected in checks:
        print(f"{'PASS' if observed == expected else 'FAIL'} {label}: {observed!r} (expected {expected!r})")
    return int(any(observed != expected for _, observed, expected in checks))


if __name__ == "__main__":
    sys.exit(main())
