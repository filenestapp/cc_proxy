"""Exit-node installer: commands, assets served by the control plane, and the rendered exit.sh run end to end.

The end-to-end tests run the real rendered script with the host's own sh, grep, curl, tar and shasum over real TLS
(self-signed CA) against a real control plane, installing under a test root (CCPROXY_EXIT_TEST_ROOT). launchctl and
systemctl are stubs that record their arguments, so nothing is loaded into the host's service manager. The agent
binary is the reproducible build from egress/agent/build.sh (built here when Go is available); sing-box is a fake
archive whose digest is pinned for the test.
"""
import hashlib
import io
import json
import os
import platform
import re
import shutil
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, ".."))

import installer  # noqa: E402
import server  # noqa: E402
from test_controlplane import ADMIN, Clock, make_store  # noqa: E402

REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
BUILD = os.path.join(REPO, "egress", "agent", "build.sh")
ARCH = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(platform.machine().lower())


def read_text(path):
    with open(path) as f:
        return f.read()


def ensure_dist():
    """A valid agent dist directory, or None (then the tests that need binaries are skipped)."""
    try:
        installer.agent_release(installer.DEFAULT_DIST)
        return installer.DEFAULT_DIST
    except installer.NotBuilt:
        pass
    if not shutil.which("go"):
        return None
    subprocess.run(["sh", BUILD, "test"], check=True, stdout=subprocess.DEVNULL)
    return installer.DEFAULT_DIST


DIST = ensure_dist()


class CommandTest(unittest.TestCase):
    def test_commands_are_https_only_and_fully_validated(self):
        for bad in ["http://cp.example", "https://cp.example\n", "https://cp.example\nrm -rf /", "https://cp'x",
                    "https://cp.example;id", "https://cp example", "https://cp.example/$(id)", "", None]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                installer.install_commands(bad)
        for bad in ["eth0\n", "eth0;id", "eth 0", "x" * 16, ""]:
            with self.assertRaises(ValueError, msg=repr(bad)):
                installer.install_commands("https://cp.example", bad)

    def test_unix_command_downloads_first_and_keeps_the_failure_status(self):
        cmds = installer.install_commands("https://cp.example:8443/", "eth0")
        for os_name in ("macos", "linux"):
            for kind in ("install", "uninstall"):
                c = cmds[os_name][kind]
                self.assertTrue(c.startswith("(f=$(mktemp) || exit; curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL "), c)
                self.assertIn("'https://cp.example:8443/install/exit.sh' -o \"$f\" && sudo sh \"$f\" ", c)
                self.assertTrue(c.endswith('; s=$?; rm -f "$f"; exit $s)'), c)
                self.assertNotIn("| sudo", c)
        self.assertIn("--cp 'https://cp.example:8443' --iface 'eth0';", cmds["linux"]["install"])
        self.assertNotIn("--iface", cmds["macos"]["install"])
        self.assertIn("--uninstall;", cmds["macos"]["uninstall"])

    def test_unix_command_reports_a_failed_download_and_cleans_up(self):
        """curl exits 22 on HTTP 404 (and 7 when nothing listens): the copied command must exit non-zero too."""
        srv = TLSServer(SimpleHTTPRequestHandler, tempfile.mkdtemp())  # empty directory: every path is 404
        self.addCleanup(srv.close)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        cmd = installer.install_commands(srv.url)["macos"]["install"]
        for shell in ("sh", "bash", "zsh", "dash"):
            if not shutil.which(shell):
                continue
            r = subprocess.run([shell, "-c", cmd], env=dict(os.environ, TMPDIR=tmp, CURL_CA_BUNDLE=TLS.cert),
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 22, (shell, r.stderr))
            self.assertEqual(os.listdir(tmp), [], shell)
        dead = installer.install_commands("https://127.0.0.1:9")["linux"]["uninstall"]
        self.assertEqual(subprocess.run(["sh", "-c", dead], capture_output=True).returncode, 7)

    def test_windows_command_runs_only_a_complete_script_without_redirects(self):
        c = installer.install_commands("https://cp.example")["windows"]["install"]
        self.assertIn("-MaximumRedirection 0 -Uri 'https://cp.example/install/exit.ps1'", c)
        self.assertIn("$s.StartsWith('%s')" % installer.PS1_FIRST_LINE, c)
        self.assertIn("-ControlPlane 'https://cp.example'", c)
        with open(installer.SCRIPTS["exit.ps1"]) as f:
            self.assertEqual(f.readline().rstrip("\r\n")[:len(installer.PS1_FIRST_LINE)], installer.PS1_FIRST_LINE)

    def test_singbox_pin_matches_the_desktop_build(self):
        with open(os.path.join(REPO, "client", "desktop", "scripts", "fetch-binaries.sh")) as f:
            pinned = re.search(r'^SINGBOX_VERSION="([^"]+)"', f.read(), re.M).group(1)
        pins = installer.load_pins()
        self.assertEqual(pins["version"], pinned)
        self.assertEqual(sorted(pins["assets"]), sorted(installer.PLATFORMS))

    def test_scripts_stay_within_bsd_grep_limits(self):
        with open(installer.SCRIPTS["exit.sh"]) as f:
            text = f.read()
        for n in re.findall(r"\{(\d+),(\d+)\}", text):
            self.assertLessEqual(int(n[1]), 255, "BSD grep rejects ERE repetition counts above 255")
        r = subprocess.run(["shellcheck", "-s", "sh", installer.SCRIPTS["exit.sh"]], capture_output=True, text=True) \
            if shutil.which("shellcheck") else None
        if r is not None:
            self.assertEqual(r.returncode, 0, r.stdout)


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
    def __init__(self, handler, directory=None):
        TLS.ensure()
        if directory:
            handler = type("H", (handler,), {"log_message": lambda *a: None,
                                             "__init__": lambda self, *a, **k: SimpleHTTPRequestHandler.__init__(
                                                 self, *a, directory=directory, **k)})
        self.httpd = handler if isinstance(handler, ThreadingHTTPServer) else ThreadingHTTPServer(("127.0.0.1", 0), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(TLS.cert, TLS.key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = "https://127.0.0.1:%d" % self.httpd.server_address[1]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


TLS.ensure()


class ControlPlaneFixture(unittest.TestCase):
    def setUp(self):
        self.store, tokens = make_store(Clock())
        self.hk = tokens["hk-1"]
        httpd = server.build_server(self.store, "127.0.0.1", 0, ADMIN)
        self.cp = TLSServer(httpd)
        self.addCleanup(self.cp.close)
        self.ctx = ssl.create_default_context(cafile=TLS.cert)

    def req(self, path, token=None, cp=None):
        r = urllib.request.Request((cp or self.cp.url) + path)
        if token:
            r.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(r, timeout=10, context=self.ctx) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.headers, e.read()


@unittest.skipUnless(DIST, "agent binaries not built and Go not available")
class AssetRouteTest(ControlPlaneFixture):
    def test_scripts_are_public_and_carry_the_digests(self):
        release = installer.agent_release()
        status, headers, body = self.req("/install/exit.sh")
        self.assertEqual(status, 200)
        text = body.decode()
        self.assertNotIn(installer.MARKER, text)
        self.assertIn("AGENT_VERSION='%s'" % release["version"], text)
        for platform_name, digest in release["digests"].items():
            self.assertIn("%s) echo '%s' ;;" % (platform_name, digest), text)
        for asset in installer.load_pins()["assets"].values():
            self.assertIn(asset["sha256"], text)
        status, _, body = self.req("/install/exit.ps1")
        self.assertEqual(status, 200)
        self.assertIn(b"\r\n", body)
        self.assertNotIn(b"\n", body.replace(b"\r\n", b""))
        self.assertTrue(body.startswith(installer.PS1_FIRST_LINE.encode()))
        self.assertIn(("'windows-arm64' = '%s'" % release["digests"]["windows-arm64"]).encode(), body)
        status, _, body = self.req("/install/manifest.json")
        self.assertEqual(json.loads(body)["agent"], release)

    def test_agent_binaries_need_the_host_token_and_match_the_digest(self):
        release = installer.agent_release()
        self.assertEqual(self.req("/install/agent/darwin-arm64")[0], 401)
        self.assertEqual(self.req("/install/agent/darwin-arm64", "wrong-token-0123456789")[0], 401)
        for platform_name in installer.PLATFORMS:
            status, _, body = self.req("/install/agent/" + platform_name, self.hk)
            self.assertEqual(status, 200, platform_name)
            self.assertEqual(hashlib.sha256(body).hexdigest(), release["digests"][platform_name])
        self.assertEqual(self.req("/install/agent/plan9-mips", self.hk)[0], 404)
        self.assertEqual(self.req("/install/agent/..%2f..%2fstore.py", self.hk)[0], 404)

    def test_a_tampered_or_missing_build_is_not_served(self):
        dist = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dist)
        for name in os.listdir(DIST):
            shutil.copy(os.path.join(DIST, name), dist)
        os.environ["CP_AGENT_DIST"] = dist
        self.addCleanup(os.environ.pop, "CP_AGENT_DIST")
        self.assertEqual(self.req("/install/exit.sh")[0], 200)
        with open(os.path.join(dist, installer.agent_file("linux-amd64")), "ab") as f:
            f.write(b"x")
        self.assertEqual(self.req("/install/agent/linux-amd64", self.hk)[0], 503)
        status, _, body = self.req("/install/exit.sh")
        self.assertEqual(status, 503)
        self.assertIn(b"does not match SHA256SUMS", body)
        os.environ["CP_AGENT_DIST"] = os.path.join(dist, "missing")
        self.assertIn(b"build.sh", self.req("/install/exit.ps1")[2])

    def test_admin_commands_route(self):
        self.assertEqual(self.req("/admin/install-commands?cp=https://cp.example")[0], 401)
        status, _, body = self.req("/admin/install-commands?cp=https://cp.example&iface=eth1", ADMIN)
        self.assertEqual(status, 200)
        self.assertIn("--iface 'eth1'", json.loads(body)["linux"]["install"])
        status, _, body = self.req("/admin/install-commands?cp=http://cp.example", ADMIN)
        self.assertEqual(status, 400)
        self.assertIn(b"https", body)
        self.assertEqual(self.req("/admin/install-commands?cp=https://cp.example%0Aid", ADMIN)[0], 400)

    def test_console_offers_the_three_commands_after_add_and_rotate(self):
        with open(os.path.join(HERE, "..", "console.html")) as f:
            page = f.read()
        self.assertIn('[["macos", "macOS"], ["linux", "Linux"], ["windows", "Windows"]]', page)
        self.assertIn('api("GET", "/admin/install-commands?" + q)', page)
        self.assertEqual(page.count("installPanel($(\"#install-panel\", ov))"), 2)  # token dialog and Install command
        self.assertIn('id="install" type="button">Install command', page)
        self.assertNotIn("python3 controlplane/agent.py", page)
        # Switching OS or editing the URL clears the commands and disables Copy at once, and only the response to the
        # latest request may fill them (a slow answer for the previous OS was once copied).
        self.assertIn("if (mine !== seq || want !== os) return;", page)
        self.assertIn('root.querySelectorAll("[data-copy-cmd]").forEach((b) => { b.disabled = true; });', page)
        self.assertIn('root.addEventListener("input", () => { invalidate();', page)


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


def fake_singbox_archive(directory, platform_name, version):
    """A sing-box release archive whose binary only prints a version."""
    name = "sing-box-%s-%s" % (version, platform_name)
    data = b"#!/bin/sh\necho 'sing-box version fake'\n"
    path = os.path.join(directory, name + ".tar.gz")
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo(name + "/sing-box")
        info.size, info.mode = len(data), 0o755
        tar.addfile(info, io.BytesIO(data))
    with open(path, "rb") as f:
        return name + ".tar.gz", hashlib.sha256(f.read()).hexdigest()


@unittest.skipUnless(DIST and ARCH and shutil.which("openssl"), "needs the agent build, openssl and a known CPU")
class InstallScriptTest(ControlPlaneFixture):
    """Runs the rendered exit.sh with this machine's own tools."""

    def setUp(self):
        super().setUp()
        self.tmp = os.path.realpath(tempfile.mkdtemp())   # macOS: /var is a link to /private/var
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "root")
        os.mkdir(self.root, 0o700)
        # Fake sing-box releases (all platforms) on their own TLS server, pinned for this test.
        self.archives = os.path.join(self.tmp, "releases")
        os.mkdir(self.archives)
        pins = installer.load_pins()
        for key in pins["assets"]:
            pins["assets"][key]["file"], pins["assets"][key]["sha256"] = fake_singbox_archive(self.archives, key, pins["version"])
        self.pins = pins
        real_load = installer.load_pins
        installer.load_pins = lambda path=None: json.loads(json.dumps(pins))
        self.addCleanup(setattr, installer, "load_pins", real_load)
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
            f.write(self.req("/install/exit.sh")[2])

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
            self.assertEqual(hashlib.sha256(f.read()).hexdigest(), installer.agent_release()["digests"][platform_name])
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
        self.assertFalse(os.path.exists(self.p("opt", "ccproxy-exit")))
        self.assertFalse(os.path.exists(self.p("etc", "ccproxy-exit")))
        self.assertNotIn(self.hk, r.stdout + r.stderr)

    def test_wrong_token_changes_nothing(self):
        bad = os.path.join(self.tmp, "bad")
        with open(bad, "w") as f:
            f.write("not-the-token-0123456789\n")
        self.assert_nothing_installed(self.run_script("--cp", self.cp.url, "--cafile", self.ca, "--token-file", bad),
                                      "rejected the token")

    def test_unverified_singbox_changes_nothing(self):
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
