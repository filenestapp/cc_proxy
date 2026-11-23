"""Exit-node installer against the real Go control plane (PostgreSQL), over real TLS.

The Go tests (installer_test.go) cover command generation, script rendering, digests, tamper detection and the
console. These tests need the running server: the agent download with a host token, the exit status of the copied
command, and the rendered exit.sh run end to end with this machine's own sh, grep, curl, tar and shasum, installing
under a test root (CCPROXY_EXIT_TEST_ROOT). launchctl and systemctl are stubs that record their arguments, so nothing
is loaded into the host's service manager. The agent binaries are the reproducible build from egress/agent/build.sh
(built here when Go is available).

sing-box: the control plane embeds the pinned digests, so by default each install starts from a pre-seeded sing-box
whose marker matches the pinned digest (the installer's own "already installed" path), and a served fake archive
must fail the digest check. Set CCPROXY_TEST_SINGBOX_ARCHIVES to a directory holding the official release archives
(for example sing-box-1.14.4-darwin-arm64.tar.gz) to run the download path with the genuine files.
"""
import hashlib
import io
import json
import os
import platform
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.request
import threading
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import test_controlplane as tc  # noqa: E402
from test_controlplane import ADMIN  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BUILD = os.path.join(REPO, "egress", "agent", "build.sh")
DEFAULT_DIST = os.path.join(REPO, "egress", "agent", "dist")
PINS = os.path.join(REPO, "controlplane", "install", "sing-box.json")
TEMPLATE = os.path.join(REPO, "controlplane", "install", "exit.sh")
PLATFORMS = ("darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64")
ARCH = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(platform.machine().lower())
REAL_ARCHIVES = os.environ.get("CCPROXY_TEST_SINGBOX_ARCHIVES")


def read_text(path):
    with open(path) as f:
        return f.read()


def agent_file(name):
    return "ccproxy-exit-agent-%s%s" % (name, ".exe" if name.startswith("windows") else "")


def dist_release(dist):
    """{"version", "digests"} when every binary in dist matches its SHA256SUMS line, else None."""
    try:
        sums = dict(reversed(l.split()) for l in read_text(os.path.join(dist, "SHA256SUMS")).splitlines() if l.strip())
        version = read_text(os.path.join(dist, "VERSION")).strip()
        digests = {}
        for name in PLATFORMS:
            with open(os.path.join(dist, agent_file(name)), "rb") as f:
                if hashlib.sha256(f.read()).hexdigest() != sums[agent_file(name)]:
                    return None
            digests[name] = sums[agent_file(name)]
        return {"version": version, "digests": digests}
    except (OSError, KeyError, ValueError):
        return None


def ensure_dist():
    if dist_release(DEFAULT_DIST):
        return DEFAULT_DIST
    if not shutil.which("go"):
        return None
    subprocess.run(["sh", BUILD], check=True, stdout=subprocess.DEVNULL)
    return DEFAULT_DIST if dist_release(DEFAULT_DIST) else None


DIST = ensure_dist()
RELEASE = dist_release(DIST) if DIST else None


class TLS:
    """A self-signed certificate for 127.0.0.1, made once."""
    cert = key = None

    @classmethod
    def ensure(cls):
        if cls.cert:
            return
        d = tempfile.mkdtemp()
        cls.cert, cls.key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", cls.key, "-out",
                        cls.cert, "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-days", "1"],
                       check=True, capture_output=True)


class TLSServer:
    """A small TLS server for release archives, redirects and recording requests."""

    def __init__(self, handler, directory=None):
        TLS.ensure()
        if directory:
            handler = type("H", (handler,), {"log_message": lambda *a: None,
                                             "__init__": lambda self, *a, **k: SimpleHTTPRequestHandler.__init__(
                                                 self, *a, directory=directory, **k)})
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS.cert, TLS.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = "https://127.0.0.1:%d" % self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@unittest.skipUnless(RELEASE and shutil.which("openssl"), "needs the agent build (Go) and openssl")
class GoControlPlaneFixture(tc.ServerFixture):
    """tc.ServerFixture (Go server, own PostgreSQL schema) served over TLS with CP_AGENT_DIST set."""

    def start_server(self, trusted_proxies=None):
        TLS.ensure()
        if hasattr(self, "process"):
            self.stop_server(self.process)
        env = dict(os.environ, DATABASE_URL=self.dsn, CP_ADMIN_TOKEN=ADMIN, CP_PROBE_TOKEN=tc.PROBE,
                   CP_TRUSTED_PROXIES="", CP_AGENT_DIST=DIST)
        self.process = subprocess.Popen([str(tc.server_binary()), "serve", "--port", "0", "--tls-cert", TLS.cert,
                                         "--tls-key", TLS.key], env=env, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_server, self.process)
        ready = self.process.stdout.readline()
        if not ready.startswith("control plane listening on "):
            self.fail("Go server failed to start: " + self.process.stderr.read())
        self.base = "https://127.0.0.1:" + ready.split()[-1].rsplit(":", 1)[1]
        self.ctx = ssl.create_default_context(cafile=TLS.cert)

    def req(self, method, path, token=None, body=None, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        if token:
            r.add_header("Authorization", "Bearer " + token)
        for k, v in (headers or {}).items():
            r.add_header(k, v)
        try:
            with urllib.request.urlopen(r, timeout=10, context=self.ctx) as resp:
                raw = resp.read()
                return resp.status, resp.headers, (json.loads(raw) if raw and raw[:1] in b"{[" else raw)
        except urllib.error.HTTPError as e:
            raw = e.read()
            return e.code, e.headers, (json.loads(raw) if raw[:1] in b"{[" else raw)

    def get(self, path, token=None):
        return self.req("GET", path, token)


class CopiedCommandTest(GoControlPlaneFixture):
    def commands(self, cp):
        status, out = self.admin("GET", "/admin/install-commands?cp=" + cp)
        self.assertEqual(status, 200, out)
        return out

    def test_unix_command_reports_a_failed_download_and_cleans_up(self):
        """curl exits 22 on HTTP 404 (and 7 when nothing listens): the copied command must exit non-zero too."""
        srv = TLSServer(SimpleHTTPRequestHandler, tempfile.mkdtemp())   # empty directory: every path is 404
        self.addCleanup(srv.close)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        cmd = self.commands(srv.url)["macos"]["install"]
        for shell in ("sh", "bash", "zsh", "dash"):
            if shutil.which(shell):
                r = subprocess.run([shell, "-c", cmd], env=dict(os.environ, TMPDIR=tmp, CURL_CA_BUNDLE=TLS.cert),
                                   capture_output=True, text=True)
                self.assertEqual(r.returncode, 22, (shell, r.stderr))
                self.assertEqual(os.listdir(tmp), [], shell)
        dead = self.commands("https://127.0.0.1:9")["linux"]["uninstall"]
        self.assertEqual(subprocess.run(["sh", "-c", dead], capture_output=True).returncode, 7)

    def test_template_passes_shellcheck(self):
        if not shutil.which("shellcheck"):
            self.skipTest("shellcheck not installed")
        r = subprocess.run(["shellcheck", "-s", "sh", TEMPLATE], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


class AgentDownloadTest(GoControlPlaneFixture):
    def test_scripts_carry_the_built_digests(self):
        status, _, body = self.get("/install/exit.sh")
        self.assertEqual(status, 200)
        for name, digest in RELEASE["digests"].items():
            self.assertIn("%s) echo '%s' ;;" % (name, digest), body.decode())
        status, _, manifest = self.get("/install/manifest.json")
        self.assertEqual((status, manifest["agent"]), (200, RELEASE))

    def test_agent_binaries_need_the_host_token_and_match_the_digest(self):
        self.assertEqual(self.get("/install/agent/darwin-arm64")[0], 401)
        self.assertEqual(self.get("/install/agent/darwin-arm64", "wrong-token-0123456789")[0], 401)
        self.assertEqual(self.get("/install/agent/darwin-arm64", ADMIN)[0], 401)   # the admin token is not a host token
        for name in PLATFORMS:
            status, headers, body = self.get("/install/agent/" + name, self.hk)
            self.assertEqual(status, 200, name)
            self.assertEqual(headers["Content-Type"], "application/octet-stream")
            self.assertEqual(hashlib.sha256(body).hexdigest(), RELEASE["digests"][name])
        self.assertEqual(self.get("/install/agent/plan9-mips", self.hk)[0], 404)
        self.assertEqual(self.get("/install/agent/..%2f..%2fVERSION", self.hk)[0], 404)


class Recorder(BaseHTTPRequestHandler):
    """Remembers every Authorization header it is sent."""
    seen = []

    def do_GET(self):
        Recorder.seen.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_):
        pass


def fake_singbox_archive(directory, filename):
    """A release-shaped archive whose binary only prints a version (its digest cannot match the pin)."""
    name = filename[:-len(".tar.gz")]
    data = b"#!/bin/sh\necho 'sing-box version fake'\n"
    with tarfile.open(os.path.join(directory, filename), "w:gz") as tar:
        info = tarfile.TarInfo(name + "/sing-box")
        info.size, info.mode = len(data), 0o755
        tar.addfile(info, io.BytesIO(data))


@unittest.skipUnless(ARCH, "unknown CPU")
class InstallScriptTest(GoControlPlaneFixture):
    """Runs the rendered exit.sh with this machine's own tools."""

    def setUp(self):
        super().setUp()
        self.tmp = os.path.realpath(tempfile.mkdtemp())   # macOS: /var is a link to /private/var
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "root")
        os.mkdir(self.root, 0o700)
        with open(PINS) as f:
            self.pins = json.load(f)
        # Release archives: the genuine ones when provided, else fakes under the pinned names.
        self.archives = REAL_ARCHIVES or os.path.join(self.tmp, "releases")
        if not REAL_ARCHIVES:
            os.mkdir(self.archives)
            for asset in self.pins["assets"].values():
                fake_singbox_archive(self.archives, asset["file"])
        self.releases = TLSServer(SimpleHTTPRequestHandler, self.archives)
        self.addCleanup(self.releases.close)
        # Service manager stubs.
        self.bin = os.path.join(self.tmp, "bin")
        os.mkdir(self.bin)
        self.calls = os.path.join(self.tmp, "calls")
        for tool in ("launchctl", "systemctl"):
            path = os.path.join(self.bin, tool)
            with open(path, "w") as f:
                f.write('#!/bin/sh\necho "%s $*" >> "%s"\ncase "$1" in print|is-active) exit 1 ;; esac\nexit 0\n'
                        % (tool, self.calls))
            os.chmod(path, 0o755)
        # The token and the CA are under the test root, like root-owned files would be.
        os.makedirs(os.path.join(self.root, "etc", "ssl"))
        self.ca = os.path.join(self.root, "etc", "ssl", "cp.pem")
        shutil.copy(TLS.cert, self.ca)
        self.token_file = os.path.join(self.tmp, "token")
        with open(self.token_file, "w") as f:
            f.write(self.hk + "\n")
        self.script = os.path.join(self.tmp, "exit.sh")
        with open(self.script, "wb") as f:
            f.write(self.get("/install/exit.sh")[2])
        self.cp = type("CP", (), {"url": self.base})

    def seed_singbox(self, os_name):
        """An installed sing-box with the pinned digest's marker: the installer keeps it (no download)."""
        if REAL_ARCHIVES:
            return
        bin_dir = self.p("opt", "ccproxy-exit", "bin")
        os.makedirs(bin_dir, exist_ok=True)
        path = os.path.join(bin_dir, "sing-box")
        with open(path, "w") as f:
            f.write("#!/bin/sh\necho 'sing-box version seeded'\n")
        os.chmod(path, 0o755)
        with open(self.p("opt", "ccproxy-exit", "sing-box.sha256"), "w") as f:
            f.write(self.pins["assets"]["%s-%s" % (os_name, ARCH)]["sha256"] + "\n")

    def run_script(self, *args, os_name=None, env=None):
        e = dict(os.environ, CCPROXY_EXIT_TEST_ROOT=self.root, CCPROXY_EXIT_TEST_TRUSTED_UID=str(os.getuid()),
                 CCPROXY_EXIT_SINGBOX_BASE_URL=self.releases.url, CURL_CA_BUNDLE=TLS.cert,
                 PATH=self.bin + os.pathsep + os.environ["PATH"])
        if os_name:
            e["CCPROXY_EXIT_TEST_OS"] = os_name
        e.update(env or {})
        # A new session has no controlling terminal: the script must not wait for a prompt.
        return subprocess.run(["sh", self.script] + list(args), env=e, capture_output=True, text=True,
                              start_new_session=True, timeout=120)

    def p(self, *parts):
        return os.path.join(self.root, *parts)

    def calls_text(self):
        return read_text(self.calls) if os.path.exists(self.calls) else ""

    def assert_token_only_in_token_file(self, result):
        self.assertNotIn(self.hk, result.stdout + result.stderr)
        for d, _, files in os.walk(self.root):
            for name in files:
                path = os.path.join(d, name)
                if path == self.p("etc", "ccproxy-exit", "agent.token"):
                    continue
                with open(path, "rb") as f:
                    self.assertNotIn(self.hk.encode(), f.read(), path)
        self.assertNotIn(self.hk, self.calls_text())

    def assert_common_install(self, platform_name):
        agent = self.p("opt", "ccproxy-exit", "bin", "ccproxy-exit-agent")
        with open(agent, "rb") as f:
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), RELEASE["digests"][platform_name])
        self.assertTrue(os.access(agent, os.X_OK))
        token = self.p("etc", "ccproxy-exit", "agent.token")
        self.assertEqual(read_text(token).strip(), self.hk)
        self.assertEqual(stat.S_IMODE(os.stat(token).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(self.p("etc", "ccproxy-exit")).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(self.p("var", "lib", "ccproxy-exit")).st_mode), 0o700)
        conf = read_text(self.p("etc", "ccproxy-exit", "install.conf"))
        self.assertIn("CP_URL='%s'" % self.cp.url, conf)

    @unittest.skipUnless(sys.platform == "darwin", "native macOS path (launchd plists, plutil, BSD tools)")
    def test_macos_install_rerun_and_uninstall(self):
        self.seed_singbox("darwin")
        r = self.run_script("--cp", self.cp.url, "--cafile", self.ca, "--token-file", self.token_file)
        self.assertEqual(r.returncode, 0, r.stderr)
        platform_name = "darwin-" + ARCH
        self.assert_common_install(platform_name)
        self.assert_token_only_in_token_file(r)
        daemons = self.p("Library", "LaunchDaemons")
        agent_plist = os.path.join(daemons, "com.ccproxy.exit.agent.plist")
        singbox_plist = os.path.join(daemons, "com.ccproxy.exit.singbox.plist")
        self.assertEqual(subprocess.run(["plutil", "-lint", agent_plist, singbox_plist], capture_output=True).returncode, 0)
        args = subprocess.run(["plutil", "-extract", "ProgramArguments", "json", "-o", "-", agent_plist],
                              capture_output=True, text=True).stdout
        args = json.loads(args)
        self.assertEqual(args[0], self.p("opt", "ccproxy-exit", "bin", "ccproxy-exit-agent"))
        self.assertIn("--token-file", args)
        self.assertIn(self.p("opt", "ccproxy-exit", "libexec", "singbox-ctl") + " reload", args)
        self.assertNotIn("--iface", args)
        self.assertIn("--cafile", args)
        calls = self.calls_text()
        self.assertIn("launchctl bootstrap system %s" % singbox_plist, calls)
        self.assertIn("launchctl bootstrap system %s" % agent_plist, calls)
        ctl = read_text(self.p("opt", "ccproxy-exit", "libexec", "singbox-ctl"))
        self.assertIn("launchctl kill SIGHUP", ctl)
        self.assertTrue(os.path.exists(self.p("etc", "newsyslog.d", "ccproxy-exit.conf")))

        # Rerun without --cp or a token: the remembered URL and the installed token are kept; sing-box is not
        # downloaded again.
        open(self.calls, "w").close()
        r = self.run_script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("keeping the installed token", r.stderr)
        self.assertIn("already installed", r.stderr)
        self.assert_token_only_in_token_file(r)
        self.assertIn("launchctl bootstrap system %s" % agent_plist, self.calls_text())

        r = self.run_script("--uninstall")
        self.assertEqual(r.returncode, 0, r.stderr)
        for gone in (("opt", "ccproxy-exit"), ("etc", "ccproxy-exit"), ("var", "lib", "ccproxy-exit"),
                     ("var", "log", "ccproxy-exit"), ("Library", "LaunchDaemons", "com.ccproxy.exit.agent.plist")):
            self.assertFalse(os.path.exists(self.p(*gone)), gone)
        self.assertIn("launchctl bootout system/com.ccproxy.exit.agent", self.calls_text())

    def test_linux_install_with_routed_ips_and_uninstall(self):
        self.seed_singbox("linux")
        r = self.run_script("--cp", self.cp.url, "--cafile", self.ca, "--token-file", self.token_file,
                            "--iface", "eth1", os_name="Linux")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assert_common_install("linux-" + ARCH)
        self.assert_token_only_in_token_file(r)
        units = self.p("etc", "systemd", "system")
        agent_unit = read_text(os.path.join(units, "ccproxy-exit-agent.service"))
        exec_start = [l for l in agent_unit.splitlines() if l.startswith("ExecStart=")][0]
        self.assertIn('"--token-file" "%s"' % self.p("etc", "ccproxy-exit", "agent.token"), exec_start)
        self.assertIn('"--iface" "eth1"', exec_start)
        self.assertIn('"--reload-cmd" "%s reload"' % self.p("opt", "ccproxy-exit", "libexec", "singbox-ctl"), exec_start)
        ips_unit = read_text(os.path.join(units, "ccproxy-exit-ips.service"))
        self.assertIn("ccproxy-exit-agent ips up eth1 ", ips_unit)
        self.assertIn("Wants=ccproxy-exit-ips.service", read_text(os.path.join(units, "ccproxy-exit-singbox.service")))
        calls = self.calls_text()
        self.assertIn("systemctl enable ccproxy-exit-ips.service ccproxy-exit-singbox.service ccproxy-exit-agent.service", calls)
        self.assertIn("systemctl restart ccproxy-exit-agent.service", calls)

        r = self.run_script("--no-iface", os_name="Linux")       # rerun drops the IP unit
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(units, "ccproxy-exit-ips.service")))
        self.assertIn("systemctl disable --now ccproxy-exit-ips.service", self.calls_text())

        r = self.run_script("--uninstall", os_name="Linux")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(units, "ccproxy-exit-agent.service")))
        self.assertFalse(os.path.exists(self.p("etc", "ccproxy-exit")))

    def assert_nothing_installed(self, r, message):
        self.assertNotEqual(r.returncode, 0)
        self.assertIn(message, r.stderr)
        self.assertFalse(os.path.exists(self.p("opt", "ccproxy-exit", "bin", "ccproxy-exit-agent")))
        self.assertFalse(os.path.exists(self.p("etc", "ccproxy-exit")))
        self.assertNotIn(self.hk, r.stdout + r.stderr)

    def test_wrong_token_changes_nothing(self):
        bad = os.path.join(self.tmp, "bad")
        with open(bad, "w") as f:
            f.write("not-the-token-0123456789\n")
        self.assert_nothing_installed(self.run_script("--cp", self.cp.url, "--cafile", self.ca, "--token-file", bad),
                                      "rejected the token")

    def test_unverified_singbox_changes_nothing(self):
        if REAL_ARCHIVES:
            self.skipTest("uses fake archives")
        for name in os.listdir(self.archives):
            with open(os.path.join(self.archives, name), "ab") as f:
                f.write(b"tampered")
        self.assert_nothing_installed(self.run_script("--cp", self.cp.url, "--cafile", self.ca, "--token-file",
                                                      self.token_file), "pinned digest")

    def test_plain_http_and_unvalidated_values_are_refused(self):
        for args in (["--cp", "http://127.0.0.1:1"], ["--cp", self.cp.url + "\nid"], ["--cp", self.cp.url + "'x"],
                     ["--cp", self.cp.url, "--iface", "eth0;id"], ["--cp", self.cp.url, "--name", "a b"]):
            r = self.run_script(*(args + ["--token-file", self.token_file]), os_name="Linux")
            self.assertNotEqual(r.returncode, 0, args)
            self.assertFalse(os.path.exists(self.p("opt", "ccproxy-exit")), args)
        r = self.run_script("--cp", self.cp.url, "--iface", "eth0", "--token-file", self.token_file, os_name="Darwin")
        self.assertIn("Linux-only", r.stderr)

    def test_a_token_bearing_request_never_follows_a_redirect(self):
        Recorder.seen = []
        target = TLSServer(type("R", (Recorder,), {}))
        self.addCleanup(target.close)

        class Redirect(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", target.url + self.path)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *_):
                pass

        redirector = TLSServer(Redirect)
        self.addCleanup(redirector.close)
        # A curlrc asking for --location must not change that either (curl -q ignores it).
        home = os.path.join(self.tmp, "home")
        os.mkdir(home)
        with open(os.path.join(home, ".curlrc"), "w") as f:
            f.write("location\n")
        r = self.run_script("--cp", redirector.url, "--token-file", self.token_file, env={"HOME": home,
                                                                                         "CURL_HOME": home})
        self.assert_nothing_installed(r, "HTTP 302")
        self.assertEqual(Recorder.seen, [])

    def test_untrusted_install_root_is_refused(self):
        os.chmod(self.root, 0o777)   # writable by anyone: a root service must not run from here
        r = self.run_script("--cp", self.cp.url, "--cafile", self.ca, "--token-file", self.token_file)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("changeable by a non-root user", r.stderr)
        self.assertFalse(os.path.exists(self.p("Library", "LaunchDaemons")))
        self.assertNotIn("bootstrap", self.calls_text())


if __name__ == "__main__":
    unittest.main()
