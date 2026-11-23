"""HTTP compatibility for atomic reassignment and trusted reverse proxies."""
import unittest

import test_controlplane as tc
from test_controlplane import PW, LOGIN_MAX_FAILURES


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


class ProxyServer(tc.ServerFixture):
    def start(self, trusted):
        self.start_server(trusted_proxies=",".join(trusted))
        self.admin("POST", "/admin/users", {"name": "alice", "password": PW})

    def login(self, xff=None, user="alice", password="wrong password"):
        h = {"X-Forwarded-For": xff} if xff else {}
        return self.req("POST", "/v1/login", body={"username": user, "password": password, "device": "d"}, headers=h)[0]


class TrustedProxyTest(ProxyServer):
    def test_clients_behind_a_trusted_proxy_have_their_own_counters(self):
        self.start(["127.0.0.1/32"])
        for _ in range(LOGIN_MAX_FAILURES):
            self.assertEqual(self.login("198.51.100.7", user="ghost-%d" % _), 401)  # per-address, not per-user
        self.assertEqual(self.login("198.51.100.7", user="other"), 429)            # that client is limited
        self.assertEqual(self.login("198.51.100.8", user="alice", password=PW), 200)  # a neighbour is not

    def test_rightmost_untrusted_hop_is_the_client(self):
        self.start(["127.0.0.1/32", "10.0.0.0/8"])
        for i in range(LOGIN_MAX_FAILURES):
            self.login("203.0.113.66, 198.51.100.7, 10.1.2.3", user="u%d" % i)  # spoofed first hop is ignored
        self.assertEqual(self.login("198.51.100.7", user="x"), 429)
        self.assertEqual(self.login("203.0.113.66", user="alice", password=PW), 200)


class UntrustedPeerTest(ProxyServer):
    def test_direct_request_cannot_choose_its_identity(self):
        self.start([])
        for i in range(LOGIN_MAX_FAILURES):
            self.login("198.51.100.%d" % i, user="u%d" % i)  # a different "client" every time
        self.assertEqual(self.login("192.0.2.1", user="alice", password=PW), 429)  # still the same peer

    def test_forwarded_proto_ignored_without_trust(self):
        self.start([])
        self.admin("POST", "/admin/admins", {"name": "root", "password": "console password 1"})
        _, h, _ = self.req("POST", "/admin/session", body={"username": "root", "password": "console password 1"},
                           headers={"X-Forwarded-Proto": "https"})
        self.assertNotIn("Secure", h["Set-Cookie"])

    def test_per_user_limit_still_applies(self):
        self.start([])
        for _ in range(LOGIN_MAX_FAILURES):
            self.login(user="alice")
        self.assertEqual(self.login(user="alice", password=PW), 429)


if __name__ == "__main__":
    unittest.main()
