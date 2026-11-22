"""Control-plane e2e (v2) expectations: the egress IP every device sees through its local SOCKS port.

Usage: cp_probe.py PHASE. Reuses the SOCKS/HTTP/UDP helpers of egress/test/probe.py.
"""
import sys

sys.path.insert(0, "/app")
from probe import DECOY, ECHO_IP, ECHO_NAME, attempt, domain, ipv4, tcp_ip, udp_ip  # noqa: E402

PORTS = {
    "alice-mac": 2081, "alice-win": 2082, "bob-mac": 2083, "carol-mac": 2084, "dave-mac": 2085,
    "erin-mac": 2086, "frank-old": 2087, "frank-new": 2088, "gina-mac": 2089,
}
# None: the connection must not produce an egress IP.
EXPECT = {
    "initial": {
        "alice-mac": "10.99.0.3", "alice-win": "10.99.0.3", "bob-mac": "10.99.0.4", "carol-mac": "10.99.0.5",
        "dave-mac": "10.99.0.5", "erin-mac": None, "frank-old": None, "frank-new": "10.99.0.6",
        "gina-mac": "10.99.0.13",
    },
    # bob released, alice-win revoked, erin assigned on the other host (jp-1).
    "reloaded": {
        "alice-mac": "10.99.0.3", "alice-win": None, "bob-mac": None, "carol-mac": "10.99.0.5",
        "dave-mac": "10.99.0.5", "erin-mac": "10.99.0.14", "frank-old": None, "frank-new": "10.99.0.6",
        "gina-mac": "10.99.0.13",
    },
}


def main():
    phase = sys.argv[1]
    failures = 0
    print("%-10s %-11s %-22s %-22s %-22s %s" % ("device", "expect", "tcp ip", "tcp domain", "udp", "blocked dest"))
    for dev, port in PORTS.items():
        want = EXPECT[phase][dev]
        got = [attempt(tcp_ip, port, ipv4(ECHO_IP), 8080), attempt(tcp_ip, port, domain(ECHO_NAME), 8080),
               attempt(udp_ip, port)]
        blk = attempt(tcp_ip, port, ipv4(DECOY[0]), DECOY[1])
        # The same blocked address by name: it must be refused too (the server resolves before matching IP rules).
        blk_name = attempt(tcp_ip, port, domain("decoy"), DECOY[1])
        ok = all(r.startswith("ERR") or r == "" for r in got) if want is None else all(r == want for r in got)
        ok = ok and all(b.startswith("ERR") or b == "" for b in (blk, blk_name))
        failures += not ok
        print("%-10s %-11s %-22s %-22s %-22s %-12s %s" % (dev, want or "deny", got[0][:22], got[1][:22], got[2][:22],
                                                         blk[:12], "PASS" if ok else "FAIL"))
    print("%s: %d failure(s)" % (phase, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
