"""Checks run inside the Linux client container while `ccproxy up` runs (app mode TUN).

Usage: desktop_probe.py EXPECTED_EGRESS_IP SELF_IP
"""
import ipaddress
import socket
import subprocess
import sys

FAKEIP = ipaddress.ip_network("198.18.0.0/15")
results = []


def check(name, got, ok):
    results.append(ok)
    print("%-4s %-48s %s" % ("PASS" if ok else "FAIL", name, got), flush=True)


def resolve(name):
    try:
        return socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror as e:
        return "ERR(%s)" % e.strerror


def http(host):
    try:
        with socket.create_connection((host, 8080), timeout=6) as s:
            s.sendall(("GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % host).encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.split(b"\r\n\r\n", 1)[1].decode().strip()
    except (OSError, IndexError) as e:
        return "ERR(%s)" % e.__class__.__name__


def route_dev(dst):
    parts = subprocess.run(["ip", "route", "get", dst], capture_output=True, text=True).stdout.split()
    return parts[parts.index("dev") + 1] if "dev" in parts else "?"


egress, me = sys.argv[1], sys.argv[2]
a = resolve("target.test")
check("target.test (rule domain) gets a fake IP", a, not a.startswith("ERR") and ipaddress.ip_address(a) in FAKEIP)
check("other names still resolve (DNS hijacked, sent direct)", resolve("cp"), resolve("cp") == "10.88.0.5")
check("target.test leaves via the user's exit IP", http("target.test"), http("target.test") == egress)
check("other.test is not proxied", http("other.test"), http("other.test") == me)
check("default route goes through the TUN (app mode)", route_dev("1.1.1.1"), route_dev("1.1.1.1").startswith("tun"))
failed = results.count(False)
print("desktop: %d failure(s)" % failed)
sys.exit(1 if failed else 0)
