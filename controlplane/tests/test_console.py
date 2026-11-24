"""Admin console backend: admin accounts, cookie sessions + CSRF, audit log, settings read, IP delete, page."""
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import test_controlplane as tc
from test_controlplane import ADMIN, PW, LOGIN_MAX_FAILURES  # noqa: E402

ADMIN_PW = "console password 1"


class ConsoleFixture(tc.ServerFixture):
    def setUp(self):
        super().setUp()
        status, _, _ = self.req("POST", "/admin/admins", {"name": "root", "password": ADMIN_PW}, token=ADMIN)
        self.assertEqual(status, 201)

    def admin(self, method, path, body=None):
        status, _, out = self.req(method, path, body, token=ADMIN)
        return status, out

    def req(self, method, path, body=None, cookie=None, csrf=None, token=None, headers=None):
        cookies = {"Cookie": "cp_session=" + cookie} if cookie else {}
        csrf_header = {"X-CSRF-Token": csrf} if csrf else {}
        return super().req(method, path, token=token, body=body, headers={**cookies, **csrf_header, **(headers or {})})

    def login(self, name="root", password=ADMIN_PW, headers=None):
        status, h, out = self.req("POST", "/admin/session", {"username": name, "password": password}, headers=headers)
        cookie = None
        if status == 200:
            cookie = h["Set-Cookie"].split(";")[0].split("=", 1)[1]
        return status, h, out, cookie


class SessionTest(ConsoleFixture):
    def test_login_sets_a_strict_httponly_cookie(self):
        status, h, out, cookie = self.login()
        self.assertEqual((status, out["admin"]), (200, "root"))
        sc = h["Set-Cookie"]
        for part in ("HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=%d" % (12 * 3600)):
            self.assertIn(part, sc)
        self.assertNotIn("Secure", sc)  # plain HTTP here
        # A forwarded-proto header counts only from a trusted proxy (review finding CC-08).
        self.assertNotIn("Secure", self.login(headers={"X-Forwarded-Proto": "https"})[1]["Set-Cookie"])
        raw = self.sql(f"SELECT token_hash FROM {self.schema}.admin_sessions")
        self.assertNotIn(cookie, raw)
        self.start_server(trusted_proxies="127.0.0.1")
        self.assertIn("Secure", self.login(headers={"X-Forwarded-Proto": "https"})[1]["Set-Cookie"])

    def test_cookie_reads_but_changes_need_csrf(self):
        _, _, out, cookie = self.login()
        self.assertEqual(self.req("GET", "/admin/users", cookie=cookie)[0], 200)
        body = {"name": "alice", "password": PW}
        self.assertEqual(self.req("POST", "/admin/users", body, cookie=cookie)[0], 403)
        self.assertEqual(self.req("POST", "/admin/users", body, cookie=cookie, csrf="forged")[0], 403)
        self.assertEqual(self.req("POST", "/admin/users", body, cookie=cookie, csrf=out["csrf"])[0], 201)
        # The page can recover its CSRF token after a reload.
        status, _, who = self.req("GET", "/admin/session", cookie=cookie)
        self.assertEqual((who["admin"], who["csrf"]), ("root", out["csrf"]))

    def test_wrong_password_unknown_admin_and_lockout(self):
        self.assertEqual(self.login(password="nope")[0], 401)
        self.assertEqual(self.login(name="ghost")[0], 401)
        for _ in range(LOGIN_MAX_FAILURES):
            self.login(password="nope")
        self.assertEqual(self.login()[0], 429)

    def test_logout_and_expiry_end_the_session(self):
        _, _, _, cookie = self.login()
        self.assertEqual(self.req("DELETE", "/admin/session", cookie=cookie)[0], 200)
        self.assertEqual(self.req("GET", "/admin/users", cookie=cookie)[0], 401)
        _, _, _, cookie = self.login()
        self.sql(f"UPDATE {self.schema}.admin_sessions SET expires_at = 0")
        self.assertEqual(self.req("GET", "/admin/users", cookie=cookie)[0], 401)

    def test_api_token_still_works(self):
        self.assertEqual(self.req("POST", "/admin/users", {"name": "bob", "password": PW}, token=ADMIN)[0], 201)
        self.assertEqual(self.req("GET", "/admin/session", token=ADMIN)[2]["admin"], "api-token")
        self.assertEqual(self.req("GET", "/admin/users", token="wrong")[0], 401)


class AuditTest(ConsoleFixture):
    def test_changes_are_audited_with_secrets_scrubbed(self):
        _, _, out, cookie = self.login()
        c = {"cookie": cookie, "csrf": out["csrf"]}
        self.req("POST", "/admin/users", {"name": "alice", "password": PW}, **c)
        self.req("POST", "/admin/users/alice/assign", {"host": "hk-1"}, **c)
        self.req("POST", "/admin/users", {"name": "alice", "password": PW}, **c)  # 409: not audited
        self.req("GET", "/admin/users", cookie=cookie)                             # reads are not audited
        self.req("POST", "/admin/hosts/hk-1/rotate-token", token=ADMIN)
        log = self.req("GET", "/admin/audit", cookie=cookie)[2]
        actions = [(e["actor"], e["action"], e["target"]) for e in log]
        self.assertEqual(actions[:3], [
            ("api-token", "POST hosts_rotate", "/admin/hosts/hk-1/rotate-token"),
            ("root", "POST users_assign", "/admin/users/alice/assign"),
            ("root", "POST users_add", "/admin/users"),
        ])
        self.assertEqual(actions[3][1], "admin sign-in")
        add = [e for e in log if e["action"] == "POST users_add"][0]
        self.assertNotIn(PW, json.dumps(log))
        self.assertEqual(json.loads(add["detail"]), {"name": "alice", "password": "***"})

    def test_failed_sign_in_is_audited(self):
        self.login(password="nope")
        log = self.req("GET", "/admin/audit", token=ADMIN)[2]
        self.assertEqual((log[0]["actor"], log[0]["action"]), ("root", "admin sign-in failed"))

    def test_paging(self):
        for i in range(5):
            self.sql(f"INSERT INTO {self.schema}.audit(at, actor, action) VALUES (0, 'root', 'a{i}')")
        first = self.req("GET", "/admin/audit?actor=root&limit=2", token=ADMIN)[2]
        self.assertEqual([e["action"] for e in first], ["a4", "a3"])
        page = self.req("GET", f"/admin/audit?actor=root&limit=2&before={first[-1]['id']}", token=ADMIN)[2]
        self.assertEqual([e["action"] for e in page], ["a2", "a1"])


class AdminAccountsTest(ConsoleFixture):
    def test_manage_admins(self):
        _, _, out, cookie = self.login()
        c = {"cookie": cookie, "csrf": out["csrf"]}
        status, _, made = self.req("POST", "/admin/admins", {"name": "ops"}, **c)
        self.assertEqual(status, 201)
        ops_pw = made["password"]  # generated, shown once
        self.assertEqual(self.login("ops", ops_pw)[0], 200)
        self.assertEqual(sorted(a["name"] for a in self.req("GET", "/admin/admins", cookie=cookie)[2]), ["ops", "root"])
        self.assertEqual(self.req("DELETE", "/admin/admins/ops", **c)[0], 200)
        self.assertEqual(self.req("DELETE", "/admin/admins/root", **c)[0], 409)  # the last admin stays

    def test_password_change_ends_that_admins_sessions(self):
        _, _, _, cookie = self.login()
        self.req("POST", "/admin/admins/root/password", {"password": "brand new password"}, token=ADMIN)
        self.assertEqual(self.req("GET", "/admin/users", cookie=cookie)[0], 401)
        self.assertEqual(self.login(password="brand new password")[0], 200)

    def test_weak_admin_password_rejected(self):
        self.assertEqual(self.req("POST", "/admin/admins", {"name": "x", "password": "short"}, token=ADMIN)[0], 409)


class EndpointTest(ConsoleFixture):
    def test_settings_read_back(self):
        self.admin("PUT", "/admin/settings", {"client_policy": {"domain_suffix": ["a.example"]},
                     "monitor": {"egress_targets": ["https://t/"]},
                     "alerts": {"webhooks": [{"url": "https://hook/", "format": "feishu"}]}})
        s = self.req("GET", "/admin/settings", token=ADMIN)[2]
        self.assertEqual(s["client_policy"]["domain_suffix"], ["a.example"])
        self.assertEqual(s["monitor"]["egress_targets"], ["https://t/"])
        self.assertEqual(s["alerts"]["webhooks"][0]["format"], "feishu")
        self.assertEqual(s["cooldown_seconds"], 3600)

    def test_delete_ip_only_when_free(self):
        self.admin("POST", "/admin/users", {"name": "a", "password": PW})
        self.admin("POST", "/admin/users/a/assign", {"ip": "203.0.113.3"})
        self.assertEqual(self.req("DELETE", "/admin/ips/203.0.113.3", token=ADMIN)[0], 409)
        self.assertEqual(self.req("DELETE", "/admin/ips/203.0.113.4", token=ADMIN)[0], 200)
        self.assertEqual(self.req("DELETE", "/admin/ips/203.0.113.4", token=ADMIN)[0], 404)
        self.assertNotIn("203.0.113.4", [e["ip"] for e in self.admin("GET", "/admin/ips")[1]])

    def test_console_page_is_static_and_locked_down(self):
        self.admin("POST", "/admin/users", {"name": "secretive-user", "password": PW})
        for path in ("/", "/console", "/dashboard"):
            status, h, body = self.req("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIn("frame-ancestors 'none'", h["Content-Security-Policy"])
            self.assertEqual(h["X-Frame-Options"], "DENY")
            self.assertIn(b"/admin/session", body)
            self.assertNotIn(b"secretive-user", body)


if __name__ == "__main__":
    unittest.main()
