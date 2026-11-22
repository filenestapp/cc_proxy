"""Regenerate the gen.py client configs the Rust supervisor must accept exactly (and nothing else).

    python3 client/core/tests/fixtures/regen.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "egress"))
import gen  # noqa: E402

SERVER = {"public_host": "203.0.113.2", "reality": {
    "private_key": "EGSaGchm41iCh8FO4zfoTYH2YXQdnnBztEXORzt9Y1w", "public_key": "-6Iuhkm557EwDtXUpdumSWb_nulhGCWMwpC238ioMhM",
    "short_id": "0123456789abcdef", "server_name": "www.example.com", "handshake_server": "www.example.com"}}
USER = {"name": "alice", "egress_ip": "203.0.113.3", "port": 20007,
        "devices": [{"name": "mac", "uuid": "8f1b5a52-7a8e-4c9f-9d0e-0d0b7d3c1a11"}]}
CASES = {
    "app-domains": {"domain_suffix": ["example.com", "echo.example.org"], "direct_dns": "1.1.1.1"},
    "app-processes": {"domain_suffix": ["example.com"], "process_name": ["Example"],
                      "process_path": ["/Applications/X.app/Contents/MacOS/X"], "block_quic": False, "direct_dns": "dhcp"},
    "app-local-dns": {"domain_suffix": ["example.com"], "direct_dns": "local"},
    "app-ipv6-dns": {"domain_suffix": ["example.com"], "direct_dns": "2606:4700:4700::1111"},
}
for name, policy in CASES.items():
    inv = {"server": SERVER, "client_policy": policy, "egress_ips": [{"ip": "203.0.113.3"}], "users": [USER]}
    gen.validate(inv)
    with open(os.path.join(HERE, name + ".json"), "w") as f:
        json.dump(gen.build_client(inv, "mac", mode="app"), f, indent=2)
        f.write("\n")
print("wrote", ", ".join(CASES))
