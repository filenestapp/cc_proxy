"""Check the egress IP each device sees, through that device's local SOCKS5 proxy.

Usage: probe.py PHASE   (PHASE selects the expectation table)
Exit code 0 only when every expectation holds.
"""
import socket
import struct
import sys

CLIENTS = "clients"
ECHO_IP = "10.99.0.10"
ECHO_NAME = "echo"
DECOY = ("10.99.0.20", 443)

PORTS = {
    "alice-mac": 2081, "alice-win": 2082, "bob-mac": 2083, "carol-mac": 2084,
    "dave-mac": 2085, "erin-mac": 2086, "frank-old": 2087, "frank-new": 2088,
}

# None means the connection must not produce an egress IP.
EXPECT = {
    "initial": {
        "alice-mac": "10.99.0.3", "alice-win": "10.99.0.3", "bob-mac": "10.99.0.4",
        "carol-mac": "10.99.0.5", "dave-mac": "10.99.0.5", "erin-mac": None,
        "frank-old": None, "frank-new": "10.99.0.6",
    },
    # After reload: bob loses his IP, alice-win is revoked, erin gets 10.99.0.7.
    "reloaded": {
        "alice-mac": "10.99.0.3", "alice-win": None, "bob-mac": None,
        "carol-mac": "10.99.0.5", "dave-mac": "10.99.0.5", "erin-mac": "10.99.0.7",
        "frank-old": None, "frank-new": "10.99.0.6",
    },
}


def socks_handshake(sock, cmd, atyp_addr, port):
    sock.sendall(b"\x05\x01\x00")
    if sock.recv(2) != b"\x05\x00":
        raise OSError("socks auth refused")
    sock.sendall(b"\x05" + bytes([cmd]) + b"\x00" + atyp_addr + struct.pack(">H", port))
    head = sock.recv(4)
    if len(head) < 4 or head[1] != 0:
        raise OSError("socks reply %r" % head)
    atyp = head[3]
    if atyp == 1:
        addr = socket.inet_ntoa(sock.recv(4))
    elif atyp == 4:
        addr = socket.inet_ntop(socket.AF_INET6, sock.recv(16))
    else:
        addr = sock.recv(sock.recv(1)[0]).decode()
    bport = struct.unpack(">H", sock.recv(2))[0]
    return addr, bport


def ipv4(host):
    return b"\x01" + socket.inet_aton(host)


def domain(name):
    return b"\x03" + bytes([len(name)]) + name.encode()


def tcp_ip(port, target, tport):
    with socket.create_connection((CLIENTS, port), timeout=8) as s:
        socks_handshake(s, 1, target, tport)
        s.sendall(b"GET / HTTP/1.0\r\nHost: echo\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    if b"\r\n\r\n" not in data:
        raise OSError("no http response")
    return data.split(b"\r\n\r\n", 1)[1].decode().strip()


def udp_ip(port):
    with socket.create_connection((CLIENTS, port), timeout=8) as ctl:
        relay_host, relay_port = socks_handshake(ctl, 3, ipv4("0.0.0.0"), 0)
        if relay_host in ("0.0.0.0", "::"):
            relay_host = CLIENTS
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(5)
        header = b"\x00\x00\x00" + ipv4(ECHO_IP) + struct.pack(">H", 9090)
        for _ in range(3):
            u.sendto(header + b"ping", (relay_host, relay_port))
            try:
                data, _ = u.recvfrom(2048)
                return data[10:].decode().strip()
            except socket.timeout:
                continue
        raise OSError("udp timeout")


def attempt(fn, *args):
    try:
        return fn(*args)
    except OSError as e:
        return "ERR(%s)" % (e.__class__.__name__ if not str(e) else str(e)[:40])


def main():
    phase = sys.argv[1]
    failures = 0
    print("%-10s %-10s %-24s %-24s %-24s %s" % ("device", "expect", "tcp ip", "tcp domain", "udp", "blocked dest"))
    for dev, port in PORTS.items():
        want = EXPECT[phase][dev]
        got_tcp = attempt(tcp_ip, port, ipv4(ECHO_IP), 8080)
        got_dom = attempt(tcp_ip, port, domain(ECHO_NAME), 8080)
        got_udp = attempt(udp_ip, port)
        got_blk = attempt(tcp_ip, port, ipv4(DECOY[0]), DECOY[1])
        results = [got_tcp, got_dom, got_udp]
        if want is None:
            ok = all(r.startswith("ERR") or r == "" for r in results)
        else:
            ok = all(r == want for r in results)
        # The blocked destination must never return an HTTP body with an IP.
        ok = ok and (got_blk.startswith("ERR") or got_blk == "")
        failures += not ok
        print("%-10s %-10s %-24s %-24s %-24s %-14s %s" % (
            dev, want or "deny", got_tcp, got_dom, got_udp, got_blk, "PASS" if ok else "FAIL"))
    print("%s: %d failure(s)" % (phase, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
