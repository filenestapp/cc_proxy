"""Regression tests for review findings CC-04 (IPv4-only exits), CC-05 (atomic reassignment), CC-06 (stale password
check at sign-in) and CC-08 (client address behind trusted proxies)."""
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import server  # noqa: E402
import store as storemod  # noqa: E402
import test_controlplane as tc  # noqa: E402
from store import AuthError, Conflict  # noqa: E402
from test_controlplane import ADMIN, PW, Clock, make_store  # noqa: E402


class IPv4OnlyExitTest(unittest.TestCase):
    def setUp(self):
        self.s, _ = make_store()
        self.s.add_user("a", PW)
        self.s.assign("a", "203.0.113.3")
        self.s.login("a", PW, "mac")

    def test_ipv6_destinations_are_rejected_before_user_routing(self):
        rules = self.s.server_config("hk-1")["route"]["rules"]
        self.assertEqual(rules[0], {"action": "sniff"})
        self.assertEqual(rules[1], {"action": "resolve", "strategy": "ipv4_only"})
        self.assertEqual(rules[2], {"ip_cidr": ["::/0"], "action": "reject"})
        first_user_rule = next(i for i, r in enumerate(rules) if "outbound" in r)
        self.assertGreater(first_user_rule, 2)
        # Private-address filtering and the final deny for unassigned users are still there.
        self.assertIn({"ip_is_private": True, "action": "reject"}, rules)
        self.assertEqual(self.s.server_config("hk-1")["route"]["final"], "deny")

    def test_ipv6_rule_present_even_with_private_targets_allowed(self):
        self.s.update_host("hk-1", block_private=False, block_cidrs=[])
        rules = self.s.server_config("hk-1")["route"]["rules"]
        self.assertIn({"ip_cidr": ["::/0"], "action": "reject"}, rules)

    def test_generated_config_passes_pinned_sing_box_check(self):
        image = "ghcr.io/sagernet/sing-box:v1.14.4"
        try:
            have = subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode == 0
        except FileNotFoundError:
            have = False
        if not have:
            self.skipTest("sing-box image not available locally")
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "c.json"), "w") as f:
            json.dump(self.s.server_config("hk-1"), f)
        r = subprocess.run(["docker", "run", "--rm", "-v", d + ":/c:ro", image, "check", "-c", "/c/c.json"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


class ReassignTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.s, _ = make_store(self.clock)
        self.s.add_user("a", PW)
        self.s.assign("a", "203.0.113.3", 20005)
        self.token, _ = self.s.login("a", PW, "mac")

    def device(self):
        return self.s.device_for_token(self.token)

    def test_cross_host_move_is_atomic_and_cools_the_old_ip(self):
        before = self.s.client_config(self.device(), "app")["outbounds"][0]
        # A concurrent subscriber polls through the public API for the whole move.
        seen = []
        done = threading.Event()

        def poll():
            while not done.is_set():
                try:
                    seen.append(self.s.client_config(self.device(), "app")["outbounds"][0]["server_port"])
                except Conflict:
                    seen.append("409")
        t = threading.Thread(target=poll)
        t.start()
        ip, port = self.s.reassign("a", host="jp-1")
        done.set()
        t.join()
        self.assertEqual((ip, port), ("198.51.100.3", 30000))
        self.assertNotIn("409", seen)
        self.assertTrue(set(seen) <= {before["server_port"], 30000})
        after = self.s.client_config(self.device(), "app")["outbounds"][0]
        self.assertEqual((after["server"], after["server_port"]), ("198.51.100.2", 30000))
        status = {e["ip"]: e["status"] for e in self.s.list_ips()}
        self.assertEqual(status["203.0.113.3"], "cooldown")

    def test_same_host_move_keeps_the_entry_port(self):
        self.assertEqual(self.s.reassign("a", "203.0.113.4"), ("203.0.113.4", 20005))

    def test_auto_pick_moves_to_a_different_ip(self):
        self.assertEqual(self.s.reassign("a")[0], "198.51.100.3")  # lowest free other than 203.0.113.3

    def test_failed_move_changes_nothing(self):
        self.s.add_user("b", PW)
        self.s.assign("b", "203.0.113.4", 20006)
        v = self.s.version()
        for bad in ({"ip": "203.0.113.4"},             # held exclusively by b
                    {"ip": "203.0.113.4", "port": 30000},
                    {"host": "jp-1", "port": 20005},      # outside jp-1's range
                    {"ip": "192.0.2.99"}):                # unknown
            with self.assertRaises((Conflict, storemod.NotFound)):
                self.s.reassign("a", **bad)
        u = {x["name"]: x for x in self.s.list_users()}
        self.assertEqual((u["a"]["egress_ip"], u["a"]["port"]), ("203.0.113.3", 20005))
        self.assertEqual((u["b"]["egress_ip"], u["b"]["port"]), ("203.0.113.4", 20006))
        self.assertEqual(self.s.version(), v)
        self.assertEqual({e["ip"]: e["status"] for e in self.s.list_ips()}["203.0.113.3"], "assigned")

    def test_assign_on_a_bound_user_points_at_reassign_and_release_still_works(self):
        with self.assertRaises(Conflict) as cm:
            self.s.assign("a", "203.0.113.4")
        self.assertIn("reassign", str(cm.exception))
        self.s.release("a")
        with self.assertRaises(Conflict):
            self.s.client_config(self.device(), "app")  # explicit release still unassigns (client disconnects)


class ReassignApiTest(tc.ServerFixture):
    def test_api_and_poll_follow_the_move(self):
        token = self.setup_user()
        _, h1, cfg1 = self.req("GET", "/v1/config", token)
        status, out = self.admin("POST", "/admin/users/alice/reassign", {"host": "jp-1"})
        self.assertEqual((status, out["host"], out["entry"]["port"]), (200, "jp-1", 30000))
        status, h2, cfg2 = self.req("GET", "/v1/config", token, headers={"If-None-Match": h1["ETag"]})
        self.assertEqual(status, 200)  # the waiting client gets the new config: no reconnect or login needed
        self.assertEqual(cfg2["outbounds"][0]["server_port"], 30000)
        self.assertEqual(self.admin("POST", "/admin/users/nobody/reassign")[0], 404)


class StalePasswordTest(unittest.TestCase):
    def test_reset_between_verification_and_issuing_wins(self):
        s, _ = make_store()
        s.add_user("a", PW)
        old_token, _ = s.login("a", PW, "laptop")
        real_check = storemod.check_password

        def check_then_reset(password, stored):
            ok = real_check(password, stored)
            # An admin resets the password (signing out every device) right after this sign-in verified it.
            s.set_password("a", "brand new password", revoke_devices=True)
            return ok

        storemod.check_password = check_then_reset
        try:
            with self.assertRaises(AuthError):
                s.login("a", PW, "laptop")
        finally:
            storemod.check_password = real_check
        self.assertIsNone(s.device_for_token(old_token))
        self.assertTrue(all(d["revoked"] for d in s.list_users()[0]["devices"]))
        token, _ = s.login("a", "brand new password", "laptop")
        self.assertEqual(s.device_for_token(token)["name"], "laptop")

    def test_ordinary_login_and_rotation_unchanged(self):
        s, _ = make_store()
        s.add_user("a", PW)
        t1, _ = s.login("a", PW, "mac")
        t2, _ = s.login("a", PW, "mac")
        self.assertIsNone(s.device_for_token(t1))
        self.assertIsNotNone(s.device_for_token(t2))


class ProxyServer(unittest.TestCase):
    def start(self, trusted):
        self.store, _ = make_store()
        self.store.add_user("alice", PW)
        self.httpd = server.build_server(self.store, "127.0.0.1", 0, ADMIN, trusted_proxies=server.parse_proxies(trusted))
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    req = tc.ServerFixture.req

    def login(self, xff=None, user="alice", password="wrong password"):
        h = {"X-Forwarded-For": xff} if xff else {}
        return self.req("POST", "/v1/login", body={"username": user, "password": password, "device": "d"}, headers=h)[0]


class TrustedProxyTest(ProxyServer):
    def test_clients_behind_a_trusted_proxy_have_their_own_counters(self):
        self.start(["127.0.0.1/32"])
        for _ in range(server.LOGIN_MAX_FAILURES):
            self.assertEqual(self.login("198.51.100.7", user="ghost-%d" % _), 401)  # per-address, not per-user
        self.assertEqual(self.login("198.51.100.7", user="other"), 429)            # that client is limited
        self.assertEqual(self.login("198.51.100.8", user="alice", password=PW), 200)  # a neighbour is not

    def test_rightmost_untrusted_hop_is_the_client(self):
        self.start(["127.0.0.1/32", "10.0.0.0/8"])
        for i in range(server.LOGIN_MAX_FAILURES):
            self.login("203.0.113.66, 198.51.100.7, 10.1.2.3", user="u%d" % i)  # spoofed first hop is ignored
        self.assertEqual(self.login("198.51.100.7", user="x"), 429)
        self.assertEqual(self.login("203.0.113.66", user="alice", password=PW), 200)


class UntrustedPeerTest(ProxyServer):
    def test_direct_request_cannot_choose_its_identity(self):
        self.start([])
        for i in range(server.LOGIN_MAX_FAILURES):
            self.login("198.51.100.%d" % i, user="u%d" % i)  # a different "client" every time
        self.assertEqual(self.login("192.0.2.1", user="alice", password=PW), 429)  # still the same peer

    def test_forwarded_proto_ignored_without_trust(self):
        self.start([])
        auth = server.AdminAuth(self.store)
        auth.add("root", "console password 1")
        _, h, _ = self.req("POST", "/admin/session", body={"username": "root", "password": "console password 1"},
                           headers={"X-Forwarded-Proto": "https"})
        self.assertNotIn("Secure", h["Set-Cookie"])

    def test_per_user_limit_still_applies(self):
        self.start([])
        for _ in range(server.LOGIN_MAX_FAILURES):
            self.login(user="alice")
        self.assertEqual(self.login(user="alice", password=PW), 429)


if __name__ == "__main__":
    unittest.main()
