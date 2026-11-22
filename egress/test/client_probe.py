"""Checks run inside a TUN client container.

Usage: <interpreter> client_probe.py CASE
  CASE = domain        (run as python3 in the domain-mode container)
         app-other     (run as python3 in the app-mode container: an app that is NOT selected)
         app-selected  (run as tunapp in the app-mode container: the selected app)
Each check prints PASS/FAIL; exit code 1 if any check fails.
"""
import ipaddress
import os
import socket
import subprocess
import sys

ECHO_IP = "10.99.0.10"
FAKEIP = ipaddress.ip_network("198.18.0.0/15")
DOMAIN_SELF, DOMAIN_EGRESS = "10.88.0.31", "10.99.0.3"   # alice-mac
APP_SELF, APP_EGRESS = "10.88.0.32", "10.99.0.4"         # bob-mac
EGRESS_LAN = "10.88.0.2"  # Docker DNS answer for the name "egress"; resolvable only through the original DNS

results = []


def check(name, got, ok):
    results.append(ok)
    print("%-4s %-46s %s" % ("PASS" if ok else "FAIL", name, got), flush=True)


def resolve_a(name):
    try:
        return socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror as e:
        return "ERR(%s)" % e.strerror


def resolve_aaaa(name):
    try:
        return socket.getaddrinfo(name, None, socket.AF_INET6, socket.SOCK_STREAM)[0][4][0]
    except socket.gaierror:
        return "none"


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
        return "ERR(%s)" % (e.__class__.__name__)


def udp(host, port):
    try:
        addr = (resolve_a(host), port)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        for _ in range(3):
            try:
                s.sendto(b"ping", addr)
                return s.recvfrom(2048)[0].decode()
            except socket.timeout:
                continue
        return "timeout"
    except OSError as e:
        return "ERR(%s)" % e.__class__.__name__


def default_route(table):
    return "\n".join(l.strip() for l in table.splitlines() if l.startswith("default"))


def route_dev(dst):
    out = subprocess.run(["ip", "route", "get", dst], capture_output=True, text=True).stdout
    parts = out.split()
    return parts[parts.index("dev") + 1] if "dev" in parts else out.strip()


def main():
    case = sys.argv[1]
    exe = os.path.realpath(sys.executable)
    print("== %s (process %s)" % (case, exe))

    if case == "domain":
        a = resolve_a("target.test")
        check("target.test resolves to a fake IP", a, not a.startswith("ERR") and ipaddress.ip_address(a) in FAKEIP)
        check("target.test has no AAAA", resolve_aaaa("target.test"), resolve_aaaa("target.test") == "none")
        check("other.test resolves to its real IP", resolve_a("other.test"), resolve_a("other.test") == ECHO_IP)
        check("non-target name answered by original DNS", resolve_a("egress"), resolve_a("egress") == EGRESS_LAN)
        check("http target.test leaves via egress IP", http("target.test"), http("target.test") == DOMAIN_EGRESS)
        check("http other.test stays direct", http("other.test"), http("other.test") == DOMAIN_SELF)
        check("http by bare IP stays direct", http(ECHO_IP), http(ECHO_IP) == DOMAIN_SELF)
        check("udp target.test:9090 via egress IP", udp("target.test", 9090), udp("target.test", 9090) == DOMAIN_EGRESS)
        check("udp target.test:443 (QUIC) blocked", udp("target.test", 443), udp("target.test", 443) != DOMAIN_EGRESS
              and udp("target.test", 443) != DOMAIN_SELF)
        check("udp other.test:443 not blocked, direct", udp("other.test", 443), udp("other.test", 443) == DOMAIN_SELF)
        before = default_route(open("/tmp/route.before").read())
        now = default_route(subprocess.run(["ip", "route", "show"], capture_output=True, text=True).stdout)
        check("default route unchanged", now, now == before and now != "")
        check("route to a public IP uses eth0", route_dev("1.1.1.1"), route_dev("1.1.1.1") == "eth0")

    elif case == "app-other":
        # The OS resolver is 192.0.2.53, which does not exist: an answer proves the TUN hijacked the query.
        check("system DNS (hijacked) resolves a name", resolve_a("egress"), resolve_a("egress") == EGRESS_LAN)
        check("http by IP from unselected app is direct", http(ECHO_IP), http(ECHO_IP) == APP_SELF)
        check("http target.test (domain rule) via egress", http("target.test"), http("target.test") == APP_EGRESS)
        check("udp 443 from unselected app not blocked", udp(ECHO_IP, 443), udp(ECHO_IP, 443) == APP_SELF)
        check("route to a public IP uses the TUN", route_dev("1.1.1.1"), route_dev("1.1.1.1").startswith("tun"))

    elif case == "app-selected":
        check("http by IP from selected app via egress", http(ECHO_IP), http(ECHO_IP) == APP_EGRESS)
        check("http other.test from selected app via egress", http("other.test"), http("other.test") == APP_EGRESS)
        check("udp 9090 from selected app via egress", udp(ECHO_IP, 9090), udp(ECHO_IP, 9090) == APP_EGRESS)
        check("udp 443 (QUIC) from selected app blocked", udp(ECHO_IP, 443), udp(ECHO_IP, 443) not in (APP_EGRESS, APP_SELF))

    else:
        sys.exit("unknown case " + case)

    failed = results.count(False)
    print("%s: %d failure(s)" % (case, failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
