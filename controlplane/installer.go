package main

// Exit-node installer assets.
//
//	GET /install/exit.sh                macOS and Linux installer (public: holds no secret)
//	GET /install/exit.ps1               Windows installer (public)
//	GET /install/manifest.json          agent version and digests, pinned sing-box release (public)
//	GET /install/agent/{os}-{arch}      the compiled exit agent (host agent token: the project is private)
//	GET /admin/install-commands         copy-ready install / uninstall commands per OS (admin)
//
// Nodes run the compiled Go exit agent (egress/agent, built reproducibly by egress/agent/build.sh into a directory
// with SHA256SUMS and VERSION) and the official sing-box release pinned in install/sing-box.json; hosts on the XTCP
// transport (xtcp.go) also run the official frpc pinned in install/frpc.json. The scripts and
// pins are embedded in this binary; the agent directory is read at run time from CP_AGENT_DIST, and every binary is
// hashed against SHA256SUMS before its digest goes into a script or the file is served. Rendering replaces the
// script's "@@INSTALLER_DATA@@" line with those digests, so the installer verifies everything it downloads. The
// agent token is never part of a command: the installer prompts for it without echo.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

//go:embed install/exit.sh install/exit.ps1 install/sing-box.json install/frpc.json
var installFiles embed.FS

var (
	installPlatforms = []string{"darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"}
	// Whole-string patterns: without (?m), Go's ^ and $ match only at the ends, so a trailing newline fails.
	installURLPattern     = regexp.MustCompile(`^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$`)
	installIfacePattern   = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	installHexPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	installVersionPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	installMarker         = regexp.MustCompile(`(?m)^# @@INSTALLER_DATA@@[ \t]*$`)
)

// ps1FirstLine: the Windows command runs only a downloaded script that starts with this line.
const ps1FirstLine = "# aifree exit-node installer for Windows."

type singBoxAsset struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type singBoxPins struct {
	Version string                  `json:"version"`
	URL     string                  `json:"url"`
	Assets  map[string]singBoxAsset `json:"assets"`
}

func (p singBoxPins) baseURL() string {
	return strings.TrimRight(strings.NewReplacer("{version}", p.Version, "{asset}", "").Replace(p.URL), "/")
}

func loadSingBoxPins() (singBoxPins, error) { return loadPins("sing-box.json") }

// loadFrpcPins: the frp release whose frpc runs on XTCP hosts (same shape as the sing-box pins).
func loadFrpcPins() (singBoxPins, error) { return loadPins("frpc.json") }

func loadPins(file string) (singBoxPins, error) {
	var pins singBoxPins
	data, err := installFiles.ReadFile("install/" + file)
	if err == nil {
		err = json.Unmarshal(data, &pins)
	}
	if err != nil {
		return pins, fmt.Errorf("%s: %w", file, err)
	}
	for _, platform := range installPlatforms {
		asset, ok := pins.Assets[platform]
		if !ok || !installHexPattern.MatchString(asset.SHA256) || !strings.Contains(asset.File, pins.Version) {
			return pins, fmt.Errorf("bad %s pin for %s", file, platform)
		}
	}
	return pins, nil
}

type agentRelease struct {
	Version string            `json:"version"`
	Digests map[string]string `json:"digests"`
}

func agentFileName(platform string) string {
	if strings.HasPrefix(platform, "windows") {
		return "ccproxy-exit-agent-" + platform + ".exe"
	}
	return "ccproxy-exit-agent-" + platform
}

func agentDistDir() string { return os.Getenv("CP_AGENT_DIST") }

func notBuilt(format string, args ...any) error {
	return failure(503, "exit agent binaries are not available (build them with egress/agent/build.sh and set CP_AGENT_DIST): "+format, args...)
}

func sha256File(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// loadAgentRelease reads VERSION and SHA256SUMS from dir and hashes every binary: a missing, half-copied or
// replaced file is never offered to a node.
func loadAgentRelease(dir string) (agentRelease, error) {
	if dir == "" {
		return agentRelease{}, notBuilt("CP_AGENT_DIST is not set")
	}
	version, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		return agentRelease{}, notBuilt("%v", err)
	}
	release := agentRelease{Version: strings.TrimSpace(string(version)), Digests: map[string]string{}}
	if !installVersionPattern.MatchString(release.Version) {
		return agentRelease{}, notBuilt("bad VERSION %q", release.Version)
	}
	sums, err := os.Open(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return agentRelease{}, notBuilt("%v", err)
	}
	defer sums.Close()
	listed := map[string]string{}
	scanner := bufio.NewScanner(sums)
	for scanner.Scan() {
		if f := strings.Fields(scanner.Text()); len(f) == 2 {
			listed[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	for _, platform := range installPlatforms {
		name := agentFileName(platform)
		want := listed[name]
		got, err := sha256File(filepath.Join(dir, name))
		if !installHexPattern.MatchString(want) || err != nil || got != want {
			return agentRelease{}, notBuilt("%s is missing or does not match SHA256SUMS", name)
		}
		release.Digests[platform] = want
	}
	return release, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func shellData(pins, frpc singBoxPins, release agentRelease) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Filled in by the control plane when it serves this script.\nAGENT_VERSION='%s'\nSINGBOX_VERSION='%s'\nSINGBOX_BASE_URL='%s'\n",
		release.Version, pins.Version, pins.baseURL())
	b.WriteString("agent_sha256() {\n  case $1 in\n")
	for _, k := range sortedKeys(release.Digests) {
		fmt.Fprintf(&b, "    %s) echo '%s' ;;\n", k, release.Digests[k])
	}
	b.WriteString("  esac\n}\nsingbox_asset_file() {\n  case $1 in\n")
	for _, k := range sortedKeys(pins.Assets) {
		fmt.Fprintf(&b, "    %s) echo '%s' ;;\n", k, pins.Assets[k].File)
	}
	b.WriteString("  esac\n}\nsingbox_asset_sha256() {\n  case $1 in\n")
	for _, k := range sortedKeys(pins.Assets) {
		fmt.Fprintf(&b, "    %s) echo '%s' ;;\n", k, pins.Assets[k].SHA256)
	}
	fmt.Fprintf(&b, "  esac\n}\nFRPC_VERSION='%s'\nFRPC_BASE_URL='%s'\nfrpc_asset_file() {\n  case $1 in\n", frpc.Version, frpc.baseURL())
	for _, k := range sortedKeys(frpc.Assets) {
		fmt.Fprintf(&b, "    %s) echo '%s' ;;\n", k, frpc.Assets[k].File)
	}
	b.WriteString("  esac\n}\nfrpc_asset_sha256() {\n  case $1 in\n")
	for _, k := range sortedKeys(frpc.Assets) {
		fmt.Fprintf(&b, "    %s) echo '%s' ;;\n", k, frpc.Assets[k].SHA256)
	}
	b.WriteString("  esac\n}")
	return b.String()
}

func powershellData(pins, frpc singBoxPins, release agentRelease) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Filled in by the control plane when it serves this script.\n$AgentVersion = '%s'\n$AgentSha256 = @{\n", release.Version)
	for _, k := range sortedKeys(release.Digests) {
		fmt.Fprintf(&b, "    '%s' = '%s'\n", k, release.Digests[k])
	}
	fmt.Fprintf(&b, "}\n$SingBoxVersion = '%s'\n$SingBoxBaseUrl = '%s'\n$SingBoxAssets = @{\n", pins.Version, pins.baseURL())
	for _, k := range sortedKeys(pins.Assets) {
		fmt.Fprintf(&b, "    '%s' = @{ File = '%s'; Sha256 = '%s' }\n", k, pins.Assets[k].File, pins.Assets[k].SHA256)
	}
	fmt.Fprintf(&b, "}\n$FrpcVersion = '%s'\n$FrpcBaseUrl = '%s'\n$FrpcAssets = @{\n", frpc.Version, frpc.baseURL())
	for _, k := range sortedKeys(frpc.Assets) {
		fmt.Fprintf(&b, "    '%s' = @{ File = '%s'; Sha256 = '%s' }\n", k, frpc.Assets[k].File, frpc.Assets[k].SHA256)
	}
	b.WriteString("}")
	return b.String()
}

// renderInstaller returns exit.sh or exit.ps1 with its data block filled in.
func renderInstaller(name, dist string) ([]byte, error) {
	pins, err := loadSingBoxPins()
	if err != nil {
		return nil, err
	}
	frpc, err := loadFrpcPins()
	if err != nil {
		return nil, err
	}
	release, err := loadAgentRelease(dist)
	if err != nil {
		return nil, err
	}
	text, err := installFiles.ReadFile("install/" + name)
	if err != nil {
		return nil, failure(404, "no such installer")
	}
	data := shellData(pins, frpc, release)
	if strings.HasSuffix(name, ".ps1") {
		data = powershellData(pins, frpc, release)
	}
	if n := len(installMarker.FindAllIndex(text, -1)); n != 1 {
		return nil, fmt.Errorf("%s must have exactly one @@INSTALLER_DATA@@ line, has %d", name, n)
	}
	out := installMarker.ReplaceAllLiteral(text, []byte(data))
	if strings.HasSuffix(name, ".ps1") { // CRLF is native for Windows PowerShell 5.1
		out = bytes.ReplaceAll(bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n")), []byte("\n"), []byte("\r\n"))
	}
	return out, nil
}

type osCommands struct {
	Install   string `json:"install"`
	Uninstall string `json:"uninstall"`
}

// installCommands builds the one-line commands for each OS. Only an https control plane URL is accepted, and every
// command fetches the script with downgrades ruled out (curl -q so no curlrc can change the options, then
// --proto =https for the request and its redirects; Invoke-RestMethod without redirects) into a file or variable
// first, so a failed or partial download is never handed to sudo or executed. The Unix command runs in a subshell
// that removes the temporary file and still exits with the status of curl or the installer.
func installCommands(cp, iface string) (map[string]osCommands, error) {
	cp = strings.TrimRight(cp, "/")
	if !installURLPattern.MatchString(cp) {
		return nil, failure(400, "cp must be the control plane's https URL, such as https://cp.example:8443 "+
			"(exit nodes send their token to it, so plain http is refused)")
	}
	if iface != "" && !installIfacePattern.MatchString(iface) {
		return nil, failure(400, "iface: invalid interface name")
	}
	sh := func(args string) string {
		return fmt.Sprintf(`(f=$(mktemp) || exit; curl -q --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL `+
			`'%s/install/exit.sh' -o "$f" && sudo sh "$f" %s; s=$?; rm -f "$f"; exit $s)`, cp, args)
	}
	ps := func(args string) string {
		return fmt.Sprintf(`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `+
			`$s = Invoke-RestMethod -UseBasicParsing -MaximumRedirection 0 -Uri '%s/install/exit.ps1'; `+
			`if ($s -is [string] -and $s.StartsWith('%s')) { & ([scriptblock]::Create($s)) %s } `+
			`else { Write-Error 'download failed; nothing was run' }`, cp, ps1FirstLine, args)
	}
	linux := fmt.Sprintf("--cp '%s'", cp)
	if iface != "" {
		linux += fmt.Sprintf(" --iface '%s'", iface)
	}
	return map[string]osCommands{
		"macos":   {Install: sh(fmt.Sprintf("--cp '%s'", cp)), Uninstall: sh("--uninstall")},
		"linux":   {Install: sh(linux), Uninstall: sh("--uninstall")},
		"windows": {Install: ps(fmt.Sprintf("-ControlPlane '%s'", cp)), Uninstall: ps("-Uninstall")},
	}, nil
}

func controlPlanePublicURL(value string) (string, error) {
	if value == "" {
		value = defaultPublicURL
	}
	value = strings.TrimRight(value, "/")
	if !installURLPattern.MatchString(value) {
		return "", failure(400, "public URL must be the control plane's https URL, such as https://cp.example:8443")
	}
	return value, nil
}

func (a *api) installRoutes() {
	a.bind("GET /install/exit.sh", "", "", a.installScript("exit.sh"))
	a.bind("GET /install/exit.ps1", "", "", a.installScript("exit.ps1"))
	a.bind("GET /install/manifest.json", "", "", a.installManifest)
	a.bind("GET /install/agent/{platform}", "agent", "", a.installAgent)
	a.bind("GET /admin/install-url", "admin", "", func(*apiRequest) (response, error) {
		return ok(object{"public_url": a.publicURL}, nil)
	})
	a.bind("GET /admin/install-commands", "admin", "", func(r *apiRequest) (response, error) {
		cp := r.URL.Query().Get("cp")
		if cp == "" {
			cp = a.publicURL
		}
		return ok(installCommands(cp, r.URL.Query().Get("iface")))
	})
}

func (a *api) installScript(name string) endpoint {
	return func(*apiRequest) (response, error) {
		body, err := renderInstaller(name, agentDistDir())
		if err != nil {
			return response{}, err
		}
		return response{status: 200, body: body, contentType: "text/plain; charset=utf-8"}, nil
	}
}

func (a *api) installManifest(*apiRequest) (response, error) {
	pins, err := loadSingBoxPins()
	if err != nil {
		return response{}, err
	}
	frpc, err := loadFrpcPins()
	if err != nil {
		return response{}, err
	}
	release, err := loadAgentRelease(agentDistDir())
	if err != nil {
		return response{}, err
	}
	return ok(object{"agent": release,
		"singbox": object{"version": pins.Version, "base_url": pins.baseURL(), "assets": pins.Assets},
		"frpc":    object{"version": frpc.Version, "base_url": frpc.baseURL(), "assets": frpc.Assets}}, nil)
}

// installAgent serves one platform's agent to a valid host token, and only while it still matches SHA256SUMS
// (the installer checks the same digest again).
func (a *api) installAgent(r *apiRequest) (response, error) {
	platform := r.PathValue("platform")
	known := false
	for _, p := range installPlatforms {
		known = known || p == platform
	}
	if !known {
		return response{}, failure(404, "no agent build for %s", platform)
	}
	dist := agentDistDir()
	release, err := loadAgentRelease(dist)
	if err != nil {
		return response{}, err
	}
	data, err := os.ReadFile(filepath.Join(dist, agentFileName(platform)))
	if err != nil {
		return response{}, notBuilt("%v", err)
	}
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != release.Digests[platform] {
		return response{}, failure(503, "agent binary changed while being read; try again")
	}
	return response{status: 200, body: data, contentType: "application/octet-stream"}, nil
}
