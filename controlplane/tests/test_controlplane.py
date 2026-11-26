"""Control plane HTTP and agent integration tests against the Go server and PostgreSQL.

  python3 -m unittest discover -s controlplane/tests -v
"""
import argparse
import atexit
import json
import os
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "..", "egress"))

import agent as agentmod  # noqa: E402

ADMIN, PROBE = "admin-secret", "probe-secret"
POLICY = {"domain_suffix": ["example-target.com"]}
PW = "correct horse battery"
LOGIN_MAX_FAILURES = 10
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
BUILD = None


def read(path):
    with open(path) as f:
        return f.read()


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def server_binary():
    global BUILD
    if BUILD is None:
        tmp = tempfile.TemporaryDirectory(prefix="cc-controlplane-test-")
        binary = Path(tmp.name) / "cc-controlplane"
        subprocess.run(["go", "build", "-o", str(binary), "."], cwd=Path(HERE).parent, check=True)
        BUILD = binary
        atexit.register(tmp.cleanup)
    return BUILD


@unittest.skipUnless(TEST_DATABASE_URL and shutil.which("psql"), "set TEST_DATABASE_URL and install psql")
class ServerFixture(unittest.TestCase):
    """Run the real server on its own port and PostgreSQL schema for each test."""

    trusted_proxies = ""

    def setUp(self):
        self.create_schema()
        self.start_server()
        self.assertEqual(self.admin("PUT", "/admin/settings", {
            "client_policy": POLICY, "cooldown_seconds": 3600,
        })[0], 200)
        self.hk = self.create_host("hk-1", "203.0.113.2", 20000, ["203.0.113.4", "203.0.113.3"])
        self.jp = self.create_host("jp-1", "198.51.100.2", 30000, ["198.51.100.3"])

    def create_schema(self):
        self.schema = "cp_test_" + secrets.token_hex(8)
        self.sql("CREATE SCHEMA " + self.schema)
        self.addCleanup(self.sql, "DROP SCHEMA " + self.schema + " CASCADE")
        url = urlsplit(TEST_DATABASE_URL)
        params = dict(parse_qsl(url.query), search_path=self.schema)
        self.dsn = urlunsplit(url._replace(query=urlencode(params)))

    def sql(self, statement):
        return subprocess.run(
            ["psql", "-X", "-wqAt", "-v", "ON_ERROR_STOP=1", "--dbname", TEST_DATABASE_URL, "-c", statement],
            check=True, capture_output=True, text=True,
        ).stdout

    def start_server(self, trusted_proxies=None):
        if hasattr(self, "process"):
            self.stop_server(self.process)
        env = dict(os.environ, DATABASE_URL=self.dsn, CP_ADMIN_TOKEN=ADMIN, CP_PROBE_TOKEN=PROBE,
                   CP_TRUSTED_PROXIES=self.trusted_proxies if trusted_proxies is None else trusted_proxies)
        self.process = subprocess.Popen([str(server_binary()), "serve", "--port", "0"], env=env,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_server, self.process)
        ready = self.process.stdout.readline()
        if not ready.startswith("control plane listening on "):
            self.fail("Go server failed to start: " + self.process.stderr.read())
        self.base = "http://" + ready.split()[-1]

    @staticmethod
    def stop_server(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        process.stdout.close()
        process.stderr.close()

    def create_host(self, name, address, port, ips):
        status, obj = self.admin("POST", "/admin/hosts", {
            "name": name, "public_host": address, "server_name": "www.example.com",
            "port_min": port, "port_max": port + 9,
        })
        self.assertEqual(status, 201, obj)
        self.assertEqual(self.admin("POST", f"/admin/hosts/{name}/ips", {"ips": ips})[0], 201)
        return obj["agent_token"]

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
        for _ in range(LOGIN_MAX_FAILURES):
            self.assertEqual(self.login("alice", "wrong password")[0], 401)
        self.assertEqual(self.login("alice", PW)[0], 429)  # locked even with the right password

    def test_new_users_default_to_shared_egress(self):
        self.assertEqual(self.admin("POST", "/admin/users", {"name": "api-default", "password": PW})[0], 201)
        self.assertEqual(self.admin("POST", "/admin/users", {
            "name": "api-dedicated", "password": PW, "mode": "exclusive",
        })[0], 201)
        cli = Path(HERE).parent / "cpctl.py"
        env = dict(os.environ, CP_URL=self.base, CP_ADMIN_TOKEN=ADMIN)
        for name, flags in (("cli-default", []), ("cli-dedicated", ["--exclusive"]), ("cli-shared", ["--shared"])):
            result = subprocess.run([sys.executable, str(cli), "user-add", name, "--password", PW, *flags],
                                    env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
        status, users = self.admin("GET", "/admin/users")
        self.assertEqual(status, 200)
        self.assertEqual({user["name"]: user["mode"] for user in users}, {
            "api-default": "shared",
            "api-dedicated": "exclusive",
            "cli-default": "shared",
            "cli-dedicated": "exclusive",
            "cli-shared": "shared",
        })
        ports = set()
        for name in ("api-default", "cli-default"):
            status, result = self.admin("POST", f"/admin/users/{name}/assign", {"ip": "203.0.113.3"})
            self.assertEqual(status, 200, result)
            ports.add(result["entry"]["port"])
        self.assertEqual(ports, {20000, 20001})

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
        self.addCleanup(shutil.rmtree, self.tmp)
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
        self.addCleanup(self.stop_fake_service)
        deadline = time.time() + 10
        while not os.path.exists(os.path.join(self.tmp, "fake.ready")):
            self.assertLess(time.time(), deadline, "fake sing-box service did not start")
            time.sleep(0.02)
        os.environ["CP_AGENT_TOKEN"] = self.hk

    def stop_fake_service(self):
        self.service.kill()
        self.service.wait(timeout=5)

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
        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": "REJECT_ME"})
        a.loop()
        self.assertEqual(read(os.path.join(self.tmp, "config.json")), before)
        self.assertEqual(self.reload_count(), 1)
        self.assertEqual([f for f in os.listdir(self.tmp) if f.startswith("tmp")], [])

    def test_rejected_version_is_not_rechecked(self):
        self.setup_user()
        a = self._agent()
        a.loop()
        self.admin("PUT", "/admin/hosts/hk-1", {"server_name": "REJECT_ME"})
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
