"""Control plane tests (v2): store rules, HTTP API, and the agent's sync loop (with a stand-in sing-box).

  python3 -m unittest discover -s controlplane/tests -v
"""
import argparse
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "..", "egress"))

import agent as agentmod  # noqa: E402
import server  # noqa: E402
from store import AuthError, Conflict, NotFound, Store, check_password, hash_password  # noqa: E402

ADMIN, PROBE = "admin-secret", "probe-secret"
POLICY = {"domain_suffix": ["example-target.com"]}
PW = "correct horse battery"


def read(path):
    with open(path) as f:
        return f.read()


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def make_store(clock=None):
    """Two exit hosts: hk-1 (IPs .3, .4; ports 20000-20009) and jp-1 (IP 198.51.100.3; ports 30000-30009)."""
    s = Store(":memory:", clock=clock) if clock else Store(":memory:")
    s.configure(client_policy=POLICY, cooldown_seconds=3600)
    tokens = {
        "hk-1": s.add_host("hk-1", "203.0.113.2", "www.example.com", port_min=20000, port_max=20009),
        "jp-1": s.add_host("jp-1", "198.51.100.2", "www.example.org", port_min=30000, port_max=30009),
    }
    s.add_ips("hk-1", ["203.0.113.4", "203.0.113.3"])
    s.add_ips("jp-1", ["198.51.100.3"])
    return s, tokens


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.s, self.agent_tokens = make_store(self.clock)

    def test_passwords_are_salted_pbkdf2(self):
        h1, h2 = hash_password(PW), hash_password(PW)
        self.assertNotEqual(h1, h2)
        self.assertTrue(h1.startswith("pbkdf2_sha256$"))
        self.assertTrue(check_password(PW, h1))
        self.assertFalse(check_password("wrong", h1))
        self.s.add_user("a", PW)
        stored = self.s.db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn(PW, stored)

    def test_weak_password_and_bad_names_rejected(self):
        with self.assertRaises(Conflict):
            self.s.add_user("a", "short")
        for bad in ("", "a/b", "a b", "x" * 65):
            with self.assertRaises(Conflict):
                self.s.add_user(bad, PW)

    def test_assign_takes_lowest_free_ip_and_port(self):
        self.s.add_user("a", PW)
        self.s.add_user("b", PW)
        self.assertEqual(self.s.assign("a"), ("198.51.100.3", 30000))  # lowest IP numerically, on jp-1
        self.assertEqual(self.s.assign("b"), ("203.0.113.3", 20000))
        self.s.add_user("c", PW)
        self.assertEqual(self.s.assign("c", host="hk-1"), ("203.0.113.4", 20001))

    def test_explicit_port_must_be_free_and_in_the_host_range(self):
        self.s.add_user("a", PW, mode="shared")
        self.s.add_user("b", PW, mode="shared")
        self.assertEqual(self.s.assign("a", "203.0.113.3", 20005), ("203.0.113.3", 20005))
        with self.assertRaises(Conflict):
            self.s.assign("b", "203.0.113.3", 20005)  # taken
        with self.assertRaises(Conflict):
            self.s.assign("b", "203.0.113.3", 30000)  # jp-1's range
        self.assertEqual(self.s.assign("b", "203.0.113.3"), ("203.0.113.3", 20000))

    def test_ports_are_per_host(self):
        self.s.update_host("jp-1", port_min=20000, port_max=20009)
        self.s.add_user("a", PW)
        self.s.add_user("b", PW)
        self.s.assign("a", "203.0.113.3", 20000)
        self.assertEqual(self.s.assign("b", "198.51.100.3", 20000), ("198.51.100.3", 20000))

    def test_host_filter_and_ip_host_mismatch(self):
        self.s.add_user("a", PW)
        with self.assertRaises(Conflict):
            self.s.assign("a", "198.51.100.3", host="hk-1")
        with self.assertRaises(Conflict):
            self.s.add_ips("jp-1", ["203.0.113.3"])  # belongs to hk-1

    def test_port_range_exhaustion(self):
        self.s.update_host("hk-1", port_min=20000, port_max=20000)
        self.s.add_user("a", PW, mode="shared")
        self.s.add_user("b", PW, mode="shared")
        self.s.assign("a", "203.0.113.3")
        with self.assertRaises(Conflict):
            self.s.assign("b", "203.0.113.3")

    def test_shrinking_a_range_below_a_bound_port_is_refused(self):
        self.s.add_user("a", PW)
        self.s.assign("a", "203.0.113.3", 20009)
        with self.assertRaises(Conflict):
            self.s.update_host("hk-1", port_max=20005)

    def test_exclusive_and_shared_rules(self):
        self.s.add_user("a", PW)
        self.s.add_user("b", PW, mode="shared")
        self.s.assign("a", "203.0.113.3")
        with self.assertRaises(Conflict):
            self.s.assign("b", "203.0.113.3")

    def test_release_frees_port_and_cools_ip(self):
        self.s.add_user("a", PW)
        self.s.add_user("b", PW)
        self.s.assign("a", "203.0.113.3", 20000)
        self.s.release("a")
        with self.assertRaises(Conflict):
            self.s.assign("b", "203.0.113.3")
        self.assertEqual(self.s.assign("b", "203.0.113.4", 20000), ("203.0.113.4", 20000))  # port reusable
        self.clock.now += 3601
        self.assertEqual(self.s.assign("a", "203.0.113.3")[0], "203.0.113.3")

    def test_ban_releases_holders(self):
        self.s.add_user("a", PW)
        self.s.assign("a", "203.0.113.3")
        self.assertEqual(self.s.ban_ip("203.0.113.3", "blocked"), ["a"])
        u = self.s.list_users()[0]
        self.assertEqual((u["egress_ip"], u["port"]), (None, None))
        with self.assertRaises(Conflict):
            self.s.assign("a", "203.0.113.3")

    def test_host_with_users_cannot_be_deleted(self):
        self.s.add_user("a", PW)
        self.s.assign("a", "198.51.100.3")
        with self.assertRaises(Conflict):
            self.s.delete_host("jp-1")
        self.s.release("a")
        self.s.delete_host("jp-1")
        self.assertEqual([h["name"] for h in self.s.list_hosts()], ["hk-1"])

    def test_agent_tokens_identify_hosts_and_rotate(self):
        self.assertEqual(self.s.host_for_agent_token(self.agent_tokens["jp-1"]), "jp-1")
        new = self.s.rotate_agent_token("jp-1")
        self.assertIsNone(self.s.host_for_agent_token(self.agent_tokens["jp-1"]))
        self.assertEqual(self.s.host_for_agent_token(new), "jp-1")

    def test_each_host_gets_its_own_reality_keys(self):
        k1 = self.s.inventory("hk-1")["server"]["reality"]
        k2 = self.s.inventory("jp-1")["server"]["reality"]
        self.assertNotEqual(k1["private_key"], k2["private_key"])
        self.assertNotIn(k1["private_key"], json.dumps(self.s.list_hosts()))

    def test_login_creates_device_and_relogin_rotates_token(self):
        self.s.add_user("a", PW)
        t1, info = self.s.login("a", PW, "MacBook", "macos")
        self.assertEqual(info["entry"], None)  # not assigned yet
        t2, _ = self.s.login("a", PW, "MacBook", "macos")
        self.assertIsNone(self.s.device_for_token(t1))
        self.assertEqual(self.s.device_for_token(t2)["name"], "MacBook")
        self.assertEqual(len(self.s.list_users()[0]["devices"]), 1)

    def test_login_errors_do_not_reveal_which_part_was_wrong(self):
        self.s.add_user("a", PW)
        for user, pw in (("a", "wrong password"), ("nobody", PW)):
            with self.assertRaises(AuthError) as cm:
                self.s.login(user, pw, "x")
            self.assertEqual(str(cm.exception), "wrong username or password")

    def test_device_limit(self):
        self.s.add_user("a", PW, max_devices=2)
        self.s.login("a", PW, "d1")
        self.s.login("a", PW, "d2")
        with self.assertRaises(Conflict):
            self.s.login("a", PW, "d3")
        self.s.login("a", PW, "d2")  # re-login on an existing device is always allowed
        self.s.revoke_device("a", "d1")
        self.s.login("a", PW, "d3")

    def test_same_device_name_for_two_users(self):
        for u, ip in (("a", "203.0.113.3"), ("b", "203.0.113.4")):
            self.s.add_user(u, PW)
            self.s.assign(u, ip)
        ta, _ = self.s.login("a", PW, "MacBook")
        tb, _ = self.s.login("b", PW, "MacBook")
        ca = self.s.client_config(self.s.device_for_token(ta), "app")["outbounds"][0]
        cb = self.s.client_config(self.s.device_for_token(tb), "app")["outbounds"][0]
        self.assertNotEqual(ca["uuid"], cb["uuid"])
        self.assertEqual((ca["server_port"], cb["server_port"]), (20000, 20001))

    def test_password_reset_can_sign_out_everywhere(self):
        self.s.add_user("a", PW)
        t, _ = self.s.login("a", PW, "d1")
        self.s.set_password("a", "new password 123", revoke_devices=True)
        self.assertIsNone(self.s.device_for_token(t))
        with self.assertRaises(AuthError):
            self.s.login("a", PW, "d1")
        self.s.login("a", "new password 123", "d1")

    def test_config_for_unassigned_user_is_a_conflict(self):
        self.s.add_user("a", PW)
        t, _ = self.s.login("a", PW, "d1")
        with self.assertRaises(Conflict):
            self.s.client_config(self.s.device_for_token(t), "app")

    def test_server_config_only_contains_the_hosts_own_users(self):
        for u, ip in (("a", "203.0.113.3"), ("b", "198.51.100.3")):
            self.s.add_user(u, PW)
            self.s.assign(u, ip)
            self.s.login(u, PW, "d1")
        hk = self.s.server_config("hk-1")
        self.assertEqual([(i["tag"], i["listen_port"], [x["name"] for x in i["users"]]) for i in hk["inbounds"]],
                         [("user-a", 20000, ["a/d1"])])
        rules = [r for r in hk["route"]["rules"] if "outbound" in r]
        self.assertEqual(rules, [{"inbound": ["user-a"], "outbound": "egress-203.0.113.3"}])
        self.assertEqual(hk["route"]["final"], "deny")
        jp = self.s.server_config("jp-1")
        self.assertEqual([i["listen_port"] for i in jp["inbounds"]], [30000])

    def test_client_config_points_at_the_bound_host_and_port(self):
        self.s.add_user("a", PW)
        self.s.assign("a", "198.51.100.3", 30004)
        t, _ = self.s.login("a", PW, "d1")
        cfg = self.s.client_config(self.s.device_for_token(t), "app")
        out = cfg["outbounds"][0]
        self.assertEqual((out["server"], out["server_port"]), ("198.51.100.2", 30004))
        self.assertEqual(out["tls"]["reality"]["public_key"], self.s.inventory("jp-1")["server"]["reality"]["public_key"])
        self.assertEqual(cfg["inbounds"][0]["type"], "tun")

    def test_every_mutation_bumps_version_and_failures_do_not(self):
        v = self.s.version()
        self.s.add_user("a", PW)
        self.assertEqual(self.s.version(), v + 1)
        with self.assertRaises(Conflict):
            self.s.add_user("a", PW)
        with self.assertRaises(Conflict):
            self.s.release("a")
        with self.assertRaises(NotFound):
            self.s.assign("nobody")
        self.assertEqual(self.s.version(), v + 1)

    def test_v1_database_is_refused(self):
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        import sqlite3
        db = sqlite3.connect(path)
        db.execute("CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        db.execute("INSERT INTO settings VALUES('version', '3')")
        db.commit()
        db.close()
        with self.assertRaises(RuntimeError):
            Store(path)
        Store(os.path.join(os.path.dirname(path), "new.db"))  # a fresh file works, and reopens
        Store(os.path.join(os.path.dirname(path), "new.db"))
        shutil.rmtree(os.path.dirname(path))


class ServerFixture(unittest.TestCase):
    """A live API server on an ephemeral port, over make_store()."""

    def setUp(self):
        self.store, self.agent_tokens = make_store()
        self.httpd = server.build_server(self.store, "127.0.0.1", 0, ADMIN, PROBE)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.httpd.server_address[1]
        self.hk = self.agent_tokens["hk-1"]
        self.jp = self.agent_tokens["jp-1"]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def req(self, method, path, token=None, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            r.add_header("Authorization", "Bearer " + token)
        for k, v in (headers or {}).items():
            r.add_header(k, v)
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                raw = resp.read()
                return resp.status, resp.headers, (json.loads(raw) if raw and raw[:1] in b"{[" else raw)
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, e.headers, (json.loads(raw) if raw else None)

    def admin(self, method, path, body=None):
        status, _, out = self.req(method, path, ADMIN, body)
        return status, out

    def login(self, user="alice", password=PW, device="alice-mac"):
        return self.req("POST", "/v1/login", body={"username": user, "password": password, "device": device,
                                                   "platform": "macos"})

    def setup_user(self, name="alice", device="alice-mac", ip="203.0.113.3"):
        self.admin("POST", "/admin/users", {"name": name, "password": PW})
        self.admin("POST", "/admin/users/%s/assign" % name, {"ip": ip})
        return self.login(name, PW, device)[2]["token"]


class ApiTest(ServerFixture):
    def test_tokens_are_scoped(self):
        token = self.setup_user()
        self.assertEqual(self.req("GET", "/admin/users")[0], 401)
        for t in (self.hk, token, PROBE):
            self.assertEqual(self.req("GET", "/admin/users", t)[0], 401)
        for t in (ADMIN, token, PROBE):
            self.assertEqual(self.req("GET", "/agent/server-config", t)[0], 401)
        for t in (ADMIN, self.hk, "not-a-token"):
            self.assertEqual(self.req("GET", "/v1/config", t)[0], 401)
        self.assertEqual(self.req("GET", "/healthz")[0], 200)

    def test_login_flow(self):
        status, out = self.admin("POST", "/admin/users", {"name": "alice"})
        self.assertEqual(status, 201)
        password = out["password"]  # generated, shown once
        self.admin("POST", "/admin/users/alice/assign", {"host": "jp-1", "port": 30007})
        status, _, out = self.login("alice", password)
        self.assertEqual(status, 200)
        self.assertEqual((out["egress_ip"], out["entry"]), ("198.51.100.3", {"host": "198.51.100.2", "port": 30007}))
        token = out["token"]
        status, _, me = self.req("GET", "/v1/me", token)
        self.assertEqual((me["user"], me["device"], me["host"]), ("alice", "alice-mac", "jp-1"))
        status, _, cfg = self.req("GET", "/v1/config", token)  # default mode: app
        self.assertEqual(cfg["outbounds"][0]["server_port"], 30007)
        self.assertEqual(self.req("POST", "/v1/logout", token)[0], 200)
        self.assertEqual(self.req("GET", "/v1/me", token)[0], 401)

    def test_wrong_password_is_401_and_repeated_failures_are_429(self):
        self.admin("POST", "/admin/users", {"name": "alice", "password": PW})
        for _ in range(server.LOGIN_MAX_FAILURES):
            self.assertEqual(self.login("alice", "wrong password")[0], 401)
        self.assertEqual(self.login("alice", PW)[0], 429)  # locked even with the right password

    def test_device_limit_is_409(self):
        self.admin("POST", "/admin/users", {"name": "alice", "password": PW, "max_devices": 1})
        self.assertEqual(self.login(device="d1")[0], 200)
        status, _, out = self.login(device="d2")
        self.assertEqual(status, 409)
        self.assertIn("device limit", out["error"])

    def test_config_before_assignment_is_409(self):
        self.admin("POST", "/admin/users", {"name": "alice", "password": PW})
        token = self.login()[2]["token"]
        status, _, out = self.req("GET", "/v1/config", token)
        self.assertEqual(status, 409)
        self.assertIn("no exit IP", out["error"])

    def test_agent_only_sees_its_own_host(self):
        self.setup_user("alice", ip="203.0.113.3")
        self.setup_user("bob", ip="198.51.100.3")
        _, _, hk = self.req("GET", "/agent/server-config", self.hk)
        _, _, jp = self.req("GET", "/agent/server-config", self.jp)
        self.assertEqual([i["tag"] for i in hk["inbounds"]], ["user-alice"])
        self.assertEqual([i["tag"] for i in jp["inbounds"]], ["user-bob"])
        self.assertEqual(self.req("GET", "/agent/ips", self.jp)[2].decode(), "198.51.100.3\n")
        status, _, _ = self.req("POST", "/agent/report", self.jp, {"probes": [
            {"subject": "203.0.113.3", "target": "https://t/", "ok": True}]})
        self.assertEqual(status, 400)  # cannot report on another host's IPs

    def test_etag_gives_304_until_something_changes(self):
        self.setup_user()
        status, headers, _ = self.req("GET", "/agent/server-config", self.hk)
        etag = headers["ETag"]
        self.assertEqual(self.req("GET", "/agent/server-config", self.hk, headers={"If-None-Match": etag})[0], 304)
        self.login(device="alice-win")
        status, headers, _ = self.req("GET", "/agent/server-config", self.hk, headers={"If-None-Match": etag})
        self.assertEqual(status, 200)
        self.assertNotEqual(headers["ETag"], etag)

    def test_changes_on_another_host_keep_the_etag(self):
        token = self.setup_user()
        _, h_srv, _ = self.req("GET", "/agent/server-config", self.hk)
        _, h_dev, _ = self.req("GET", "/v1/config", token)
        self.setup_user("bob", ip="198.51.100.3")  # jp-1 only
        self.admin("POST", "/admin/hosts/jp-1/ips", {"ips": ["198.51.100.9"]})
        self.assertEqual(self.req("GET", "/agent/server-config", self.hk, headers={"If-None-Match": h_srv["ETag"]})[0], 304)
        self.assertEqual(self.req("GET", "/v1/config", token, headers={"If-None-Match": h_dev["ETag"]})[0], 304)

    def test_revoke_cuts_subscription_and_server_credential(self):
        token = self.setup_user()
        self.assertEqual(self.admin("POST", "/admin/users/alice/devices/alice-mac/revoke")[0], 200)
        self.assertEqual(self.req("GET", "/v1/config", token)[0], 401)
        _, _, srv = self.req("GET", "/agent/server-config", self.hk)
        self.assertEqual(srv["inbounds"][0]["users"], [])
        self.assertEqual(self.admin("POST", "/admin/users/alice/devices/alice-mac/revoke")[0], 404)

    def test_host_admin(self):
        status, out = self.admin("POST", "/admin/hosts", {"name": "sg-1", "public_host": "192.0.2.10",
                                                         "server_name": "www.example.net", "port_min": 40000,
                                                         "port_max": 40100})
        self.assertEqual(status, 201)
        sg = out["agent_token"]
        self.assertEqual(self.req("GET", "/agent/ips", sg)[0], 200)
        hosts = {h["name"]: h for h in self.admin("GET", "/admin/hosts")[1]}
        self.assertEqual(hosts["sg-1"]["port_range"], [40000, 40100])
        self.assertNotIn("reality_private", json.dumps(hosts))
        _, out = self.admin("POST", "/admin/hosts/sg-1/rotate-token")
        self.assertEqual(self.req("GET", "/agent/ips", sg)[0], 401)
        self.assertEqual(self.req("GET", "/agent/ips", out["agent_token"])[0], 200)
        self.assertEqual(self.admin("DELETE", "/admin/hosts/sg-1")[0], 200)

    def test_errors_map_to_status_codes(self):
        self.setup_user()
        self.assertEqual(self.admin("POST", "/admin/users", {"name": "alice", "password": PW})[0], 409)
        self.assertEqual(self.admin("POST", "/admin/users", {})[0], 400)
        self.assertEqual(self.admin("POST", "/admin/users/nobody/assign")[0], 404)
        self.assertEqual(self.admin("POST", "/admin/users/alice/assign")[0], 409)
        self.assertEqual(self.admin("POST", "/admin/hosts/hk-1/ips", {"ips": ["not-an-ip"]})[0], 400)
        self.assertEqual(self.admin("POST", "/admin/hosts/nope/ips", {"ips": ["192.0.2.1"]})[0], 404)
        self.assertEqual(self.admin("GET", "/admin/nothing")[0], 404)
        self.assertEqual(self.req("POST", "/v1/login", body={"username": "x"})[0], 400)


class AgentFixture(ServerFixture):
    """API server plus a fake sing-box (tests/fake_singbox.py); _agent() builds a real Agent for host hk-1 that syncs
    once per loop(). By default the agent uses --reload-cmd against a fake sing-box service started here, which
    answers the confirmation API like the real one (see fake_singbox.py for its flag files)."""

    def setUp(self):
        super().setUp()
        self.tmp = tempfile.mkdtemp()
        self.fake = os.path.join(self.tmp, "sing-box")
        fake_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_singbox.py")
        with open(self.fake, "w") as f:
            f.write('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, fake_py))
        os.chmod(self.fake, os.stat(self.fake).st_mode | stat.S_IEXEC)
        self.reloads = os.path.join(self.tmp, "reloads")
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.confirm_api = "127.0.0.1:%d" % s.getsockname()[1]
        # The "systemd" service: reloaded by --reload-cmd with SIGHUP, like `systemctl reload sing-box`.
        self.service = subprocess.Popen([self.fake, "run", "-c", os.path.join(self.tmp, "config.json")])
        deadline = time.time() + 10
        while not os.path.exists(os.path.join(self.tmp, "fake.ready")):
            self.assertLess(time.time(), deadline, "fake sing-box service did not start")
            time.sleep(0.02)
        os.environ["CP_AGENT_TOKEN"] = self.hk

    def tearDown(self):
        self.service.kill()
        self.service.wait()
        super().tearDown()
        shutil.rmtree(self.tmp)

    def flag(self, name, on=True):
        """Set or clear a fake_singbox.py flag file (stubborn, crash, silent)."""
        path = os.path.join(self.tmp, name)
        if on:
            open(path, "w").close()
        elif os.path.exists(path):
            os.unlink(path)

    def reload_count(self):
        return len(read(self.reloads).splitlines()) if os.path.exists(self.reloads) else 0

    def installed(self):
        return json.loads(read(os.path.join(self.tmp, "config.json")))

    def _agent(self, settle=0, max_delay=60):
        args = argparse.Namespace(
            cp=self.base, cafile=None, iface=None, ips_script=agentmod.DEFAULT_IPS_SCRIPT,
            config=os.path.join(self.tmp, "config.json"), state_dir=self.tmp, singbox=self.fake,
            interval=0, settle=settle, max_delay=max_delay, once=True, run=False,
            name="hk-1", probe_interval=60, probe_timeout=5, status_cmd=None,
            confirm_api=self.confirm_api, confirm_timeout=1.5,
            reload_cmd="sh -c 'echo x >> %s; kill -HUP %d'" % (self.reloads, self.service.pid))
        return agentmod.Agent(args)


class AgentTest(AgentFixture):
    """Runs the real agent loop once per step against the API."""

    def test_agent_installs_new_versions_and_skips_unchanged(self):
        self.setup_user()
        a = self._agent()
        a.loop()
        self.assertEqual(self.reload_count(), 1)
        self.assertEqual(self.installed()["inbounds"][0]["users"][0]["name"], "alice/alice-mac")
        self.assertEqual(read(os.path.join(self.tmp, "ips.txt")), "203.0.113.3\n203.0.113.4\n")
        a.loop()
        self.assertEqual(self.reload_count(), 1)  # 304: no reload
        self.admin("POST", "/admin/users/alice/devices/alice-mac/revoke")
        a.loop()
        self.assertEqual(self.reload_count(), 2)
        self.assertEqual(self.installed()["inbounds"][0]["users"], [])

    def test_changes_on_another_host_do_not_reload_this_one(self):
        self.setup_user()
        a = self._agent()
        a.loop()
        self.setup_user("bob", ip="198.51.100.3")
        a.loop()
        self.assertEqual(self.reload_count(), 1)

    def test_agent_keeps_old_config_when_check_fails(self):
        self.setup_user()
        a = self._agent()
        a.loop()
        before = read(os.path.join(self.tmp, "config.json"))
        self.store.update_host("hk-1", server_name="REJECT_ME")
        a.loop()
        self.assertEqual(read(os.path.join(self.tmp, "config.json")), before)
        self.assertEqual(self.reload_count(), 1)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith("tmp")], [])

    def test_rejected_version_is_not_rechecked(self):
        self.setup_user()
        a = self._agent()
        a.loop()
        self.store.update_host("hk-1", server_name="REJECT_ME")
        checks = []
        real_run = agentmod.subprocess.run

        def counting_run(cmd, *args, **kwargs):
            if cmd[:2] == [self.fake, "check"]:
                checks.append(cmd)
            return real_run(cmd, *args, **kwargs)

        agentmod.subprocess.run = counting_run
        try:
            a.loop()
            a.loop()
        finally:
            agentmod.subprocess.run = real_run
        self.assertEqual(len(checks), 1)

    def test_burst_of_changes_costs_one_reload(self):
        self.setup_user()
        clock = Clock()
        a = self._agent(settle=10, max_delay=60)
        a.clock = clock
        a.loop()
        self.assertEqual(self.reload_count(), 1)  # first config is installed at once
        for dev in ("a2", "a3", "a4"):
            self.login(device=dev)
            clock.now += 3
            a.loop()
        self.assertEqual(self.reload_count(), 1)  # still settling
        clock.now += 9
        a.loop()
        self.assertEqual(self.reload_count(), 1)  # 9s quiet < 10s settle
        clock.now += 1
        a.loop()
        self.assertEqual(self.reload_count(), 2)  # one reload for three changes
        users = [u["name"] for u in self.installed()["inbounds"][0]["users"]]
        self.assertEqual(users, ["alice/a2", "alice/a3", "alice/a4", "alice/alice-mac"])

    def test_max_delay_bounds_a_steady_stream_of_changes(self):
        self.setup_user()
        self.admin("PUT", "/admin/users/alice", {"max_devices": 20})
        clock = Clock()
        a = self._agent(settle=10, max_delay=30)
        a.clock = clock
        a.loop()
        for i in range(8):  # a change every 5s never leaves 10s of quiet
            self.login(device="d%d" % i)
            a.loop()
            clock.now += 5
        self.assertEqual(self.reload_count(), 2)  # forced once 30s had passed

    def test_change_and_revert_before_settling_causes_no_reload(self):
        self.setup_user()
        clock = Clock()
        a = self._agent(settle=10, max_delay=60)
        a.clock = clock
        a.loop()
        self.admin("POST", "/admin/ips/203.0.113.3/ban")      # alice loses her IP: server config changes
        a.loop()
        self.admin("POST", "/admin/ips/203.0.113.3/available")
        self.admin("POST", "/admin/users/alice/assign", {"ip": "203.0.113.3", "port": 20000})  # back as before
        clock.now += 20
        a.loop()
        self.assertEqual(self.reload_count(), 1)


if __name__ == "__main__":
    unittest.main()
