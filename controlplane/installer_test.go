package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const testAdminToken = "test-admin-token-0123456789"

// fakeDist writes a dist directory like egress/agent/build.sh does, with small stand-in binaries.
func fakeDist(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()
	digests := map[string]string{}
	var sums strings.Builder
	for _, platform := range installPlatforms {
		name := agentFileName(platform)
		data := []byte("agent build for " + platform)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		digests[platform] = hex.EncodeToString(sum[:])
		sums.WriteString(digests[platform] + "  " + name + "\n")
	}
	os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644)
	os.WriteFile(filepath.Join(dir, "VERSION"), []byte("agent-test1234\n"), 0o644)
	return dir, digests
}

func TestInstallCommandsAreHTTPSOnlyAndFullyValidated(t *testing.T) {
	cmds, err := installCommands("https://cp.example:8443/", "eth0")
	if err != nil {
		t.Fatal(err)
	}
	for _, osName := range []string{"macos", "linux"} {
		for _, c := range []string{cmds[osName].Install, cmds[osName].Uninstall} {
			if !strings.HasPrefix(c, `(f=$(mktemp) || exit; curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL 'https://cp.example:8443/install/exit.sh' -o "$f" && sudo sh "$f" `) ||
				!strings.HasSuffix(c, `; s=$?; rm -f "$f"; exit $s)`) || strings.Contains(c, "| sudo") {
				t.Errorf("%s: %s", osName, c)
			}
		}
	}
	if !strings.Contains(cmds["linux"].Install, "--cp 'https://cp.example:8443' --iface 'eth0';") || strings.Contains(cmds["macos"].Install, "--iface") {
		t.Error("iface placement")
	}
	win := cmds["windows"].Install
	for _, want := range []string{"-MaximumRedirection 0 -Uri 'https://cp.example:8443/install/exit.ps1'", "$s.StartsWith('" + ps1FirstLine + "')", "-ControlPlane 'https://cp.example:8443'"} {
		if !strings.Contains(win, want) {
			t.Errorf("windows command lacks %q", want)
		}
	}
	for _, bad := range []string{"http://cp.example", "https://cp.example\n", "https://cp.example\nid", "https://cp'x", "https://cp.example;id",
		"https://cp example", "https://cp.example/$(id)", ""} {
		if _, err := installCommands(bad, ""); err == nil || statusOf(err) != 400 {
			t.Errorf("accepted cp %q", bad)
		}
	}
	for _, bad := range []string{"eth0\n", "eth0;id", "eth 0", strings.Repeat("x", 16)} {
		if _, err := installCommands("https://cp.example", bad); err == nil {
			t.Errorf("accepted iface %q", bad)
		}
	}
}

func TestInstallersCarryTheDigests(t *testing.T) {
	dist, digests := fakeDist(t)
	pins, err := loadSingBoxPins()
	if err != nil {
		t.Fatal(err)
	}
	sh, err := renderInstaller("exit.sh", dist)
	if err != nil {
		t.Fatal(err)
	}
	text := string(sh)
	if strings.Contains(text, "@@INSTALLER_DATA@@") || !strings.Contains(text, "AGENT_VERSION='agent-test1234'") {
		t.Fatal("data block not filled in")
	}
	for platform, digest := range digests {
		if !strings.Contains(text, platform+") echo '"+digest+"' ;;") || !strings.Contains(text, pins.Assets[platform].SHA256) {
			t.Errorf("%s digests missing", platform)
		}
	}
	// BSD grep (macOS) rejects ERE repetition counts above 255.
	for _, m := range regexp.MustCompile(`\{\d+,(\d+)\}`).FindAllStringSubmatch(text, -1) {
		if n, _ := strconv.Atoi(m[1]); n > 255 {
			t.Errorf("repetition count %s exceeds what BSD grep accepts", m[0])
		}
	}
	ps, err := renderInstaller("exit.ps1", dist)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(ps, []byte(ps1FirstLine)) || bytes.Contains(bytes.ReplaceAll(ps, []byte("\r\n"), nil), []byte("\n")) {
		t.Fatal("exit.ps1 must start with the guarded first line and use CRLF only")
	}
	if !bytes.Contains(ps, []byte("'windows-arm64' = '"+digests["windows-arm64"]+"'")) {
		t.Fatal("exit.ps1 lacks the agent digest")
	}
}

func TestTamperedOrMissingBuildIsNotOffered(t *testing.T) {
	dist, _ := fakeDist(t)
	if _, err := loadAgentRelease(""); statusOf(err) != 503 {
		t.Fatal("no CP_AGENT_DIST must be 503")
	}
	os.WriteFile(filepath.Join(dist, agentFileName("linux-amd64")), []byte("replaced"), 0o755)
	_, err := renderInstaller("exit.sh", dist)
	if statusOf(err) != 503 || !strings.Contains(err.Error(), "does not match SHA256SUMS") {
		t.Fatalf("tampered build: %v", err)
	}
}

func TestSingBoxPinMatchesTheDesktopBuild(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "client", "desktop", "scripts", "fetch-binaries.sh"))
	if err != nil {
		t.Skip("desktop build script not present:", err)
	}
	m := regexp.MustCompile(`(?m)^SINGBOX_VERSION="([^"]+)"`).FindSubmatch(script)
	pins, err := loadSingBoxPins()
	if err != nil || m == nil || pins.Version != string(m[1]) {
		t.Fatalf("pinned %s, desktop %s, %v", pins.Version, m, err)
	}
}

// The desktop app bundles the same frpc the exit installer pins (issue #61): same version, and the build script
// verifies each asset against frpc.json itself rather than a copy of the digests.
func TestFrpcPinMatchesTheDesktopBuild(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "client", "desktop", "scripts", "fetch-binaries.sh"))
	if err != nil {
		t.Skip("desktop build script not present:", err)
	}
	m := regexp.MustCompile(`(?m)^FRP_VERSION="([^"]+)"`).FindSubmatch(script)
	pins, err := loadFrpcPins()
	if err != nil || m == nil || pins.Version != string(m[1]) {
		t.Fatalf("pinned %s, desktop %s, %v", pins.Version, m, err)
	}
	if !bytes.Contains(script, []byte(`FRP_PINS="$CLIENT/../controlplane/install/frpc.json"`)) {
		t.Fatal("fetch-binaries.sh must verify frpc against controlplane/install/frpc.json")
	}
	if _, err := os.Stat(filepath.Join("install", "frpc.json")); err != nil {
		t.Fatal(err)
	}
	// Every desktop target the script builds has a pinned frpc asset.
	for _, asset := range regexp.MustCompile(`asset="([a-z0-9-]+)"`).FindAllSubmatch(script, -1) {
		a, ok := pins.Assets[string(asset[1])]
		if !ok || len(a.SHA256) != 64 || !strings.Contains(a.File, pins.Version) {
			t.Fatalf("no frpc pin for desktop asset %s: %+v", asset[1], a)
		}
	}
	conf, err := os.ReadFile(filepath.Join("..", "client", "desktop", "src-tauri", "tauri.conf.json"))
	if err != nil || !bytes.Contains(conf, []byte(`"binaries/frpc"`)) {
		t.Fatalf("tauri.conf.json must bundle binaries/frpc: %v", err)
	}
}

func get(t *testing.T, h http.Handler, path, token string) (int, []byte) {
	return getHTTP(t, h, path, token, "")
}

func getHTTP(t *testing.T, h http.Handler, path, token, host string) (int, []byte) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if host != "" {
		req.Host = host
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, body
}

func TestInstallCommandsDefaultToConfiguredPublicURL(t *testing.T) {
	h := newAPIWithPublicURL(nil, testAdminToken, "", nil, "https://cp.aifree.sg")
	code, body := getHTTP(t, h, "/admin/install-commands?iface=eth1", testAdminToken, customerHost)
	if code != 404 {
		t.Fatalf("customer host served admin route: %d %s", code, body)
	}
	code, body = getHTTP(t, h, "/admin/install-commands?iface=eth1", testAdminToken, controlPlaneHost)
	if code != 200 || !bytes.Contains(body, []byte("https://cp.aifree.sg/install/exit.sh")) {
		t.Fatalf("install commands did not use configured public URL: %d %s", code, body)
	}
}

func TestInstallCommandsAcceptHTTPSOverride(t *testing.T) {
	h := newAPIWithPublicURL(nil, testAdminToken, "", nil, "https://cp.aifree.sg")
	code, body := getHTTP(t, h, "/admin/install-commands?cp=https://ccproxy.macmini.sg/&iface=eth1", testAdminToken, controlPlaneHost)
	if code != 200 || !bytes.Contains(body, []byte("https://ccproxy.macmini.sg/install/exit.sh")) || bytes.Contains(body, []byte("cp.aifree.sg")) {
		t.Fatalf("install commands did not use HTTPS override: %d %s", code, body)
	}
	if code, _ := getHTTP(t, h, "/admin/install-commands?cp=http://ccproxy.macmini.sg", testAdminToken, controlPlaneHost); code != 400 {
		t.Fatalf("non-HTTPS override: HTTP %d", code)
	}
}

func TestInstallURLReportsConfiguredPublicURL(t *testing.T) {
	h := newAPIWithPublicURL(nil, testAdminToken, "", nil, "https://cp.aifree.sg")
	code, body := getHTTP(t, h, "/admin/install-url", testAdminToken, controlPlaneHost)
	if code != 200 || !bytes.Contains(body, []byte(`"public_url":"https://cp.aifree.sg"`)) {
		t.Fatalf("configured install URL: %d %s", code, body)
	}
}

func TestControlPlanePublicURL(t *testing.T) {
	if got, err := controlPlanePublicURL(""); err != nil || got != defaultPublicURL {
		t.Fatalf("default public URL = %q, %v", got, err)
	}
	if got, err := controlPlanePublicURL("https://control.example/"); err != nil || got != "https://control.example" {
		t.Fatalf("normalized public URL = %q, %v", got, err)
	}
	if _, err := controlPlanePublicURL("http://control.example"); statusOf(err) != 400 {
		t.Fatalf("http public URL error = %v", err)
	}
}

// Public and admin-token routes through the real router. Agent downloads with a valid host token need PostgreSQL;
// tests/test_installer.py covers them against the running server.
func TestInstallRoutes(t *testing.T) {
	dist, digests := fakeDist(t)
	t.Setenv("CP_AGENT_DIST", dist)
	h := newAPI(nil, testAdminToken, "", nil)

	code, body := get(t, h, "/install/exit.sh", "")
	if code != 200 || !bytes.Contains(body, []byte(digests["darwin-arm64"])) {
		t.Fatalf("exit.sh: %d", code)
	}
	if code, body = get(t, h, "/install/exit.ps1", ""); code != 200 || !bytes.HasPrefix(body, []byte(ps1FirstLine)) {
		t.Fatalf("exit.ps1: %d", code)
	}
	code, body = get(t, h, "/install/manifest.json", "")
	var manifest struct {
		Agent agentRelease `json:"agent"`
	}
	if code != 200 || json.Unmarshal(body, &manifest) != nil || manifest.Agent.Version != "agent-test1234" || len(manifest.Agent.Digests) != 6 {
		t.Fatalf("manifest: %d %s", code, body)
	}
	if code, _ = get(t, h, "/install/agent/darwin-arm64", ""); code != 401 {
		t.Fatalf("agent download without a token: %d", code)
	}
	if code, _ = get(t, h, "/admin/install-commands?cp=https://cp.example", ""); code != 401 {
		t.Fatalf("commands without admin: %d", code)
	}
	code, body = get(t, h, "/admin/install-commands?cp=https://cp.example&iface=eth1", testAdminToken)
	if code != 200 || !bytes.Contains(body, []byte(`--iface 'eth1'`)) {
		t.Fatalf("commands: %d %s", code, body)
	}
	t.Setenv("CP_AGENT_DIST", filepath.Join(dist, "missing"))
	if code, body = get(t, h, "/install/exit.sh", ""); code != 503 || !bytes.Contains(body, []byte("build.sh")) {
		t.Fatalf("missing dist: %d %s", code, body)
	}
}

func TestConsoleOffersTheThreeCommands(t *testing.T) {
	page := string(consolePage)
	for _, want := range []string{
		`[["macos", "macOS"], ["linux", "Linux"], ["windows", "Windows"]]`,
		`id="inst-cp" type="url"`,
		`api("GET", "/admin/install-url")`,
		`new URLSearchParams({ cp: $("#inst-cp", root).value.trim() })`,
		`api("GET", "/admin/install-commands?" + q)`,
		`id="install" type="button">${trHTML("Install command")}`,
		// Switching OS or editing the URL clears the commands and disables Copy at once, and only the response to
		// the latest request may fill them.
		"if (mine !== seq || want !== os) return;",
		`root.querySelectorAll("[data-copy-cmd]").forEach((b) => { b.disabled = true; });`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("console lacks %q", want)
		}
	}
	if strings.Contains(page, "location.origin") {
		t.Error("install commands must not use the request origin")
	}
	if !strings.Contains(page, `installPanel($("#install-panel", ov), transport)`) ||
		!strings.Contains(page, `installPanel($("#install-panel", ov), transport, true)`) {
		t.Error("the token dialog and the Install command dialog must both show the commands for the host's transport")
	}
	// XTCP hosts: the help names frpc instead of port forwarding; the Install command offers Enter to reuse a token.
	for _, want := range []string{
		`transport?.transport === "xtcp"`,
		"the installer also downloads the pinned frpc and starts it at boot",
		"so no inbound port forwarding is needed",
		"press Enter to reuse the token already installed on this host",
		`$("#install").onclick = () => showInstall(name, xtcp);`,
		`showAgentToken(name, r.agent_token, xtcp)`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("console lacks %q", want)
		}
	}
}
