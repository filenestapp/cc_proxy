package main

// XTCP mapping sync (issue #45): keep the exit host's frpc proxies in step with the control plane, the way the rest
// of the agent keeps sing-box in step.
//
// Enabled by --frpc-config (the installer passes it, with --frpc, --frpc-ca and --frpc-restart-cmd, on XTCP hosts).
// Every cycle the agent asks GET /agent/xtcp (If-None-Match) for the host's desired generation: a number, the
// fingerprint of the configuration, the rendered frpc.toml (proxies and frps settings, with this host's own CA and
// log paths) and the CA. A generation the running frpc already confirmed is left alone. A new one is
//
//  1. checked: the CA must parse as CA certificates, the file must name --frpc-ca and must not set the admin API
//     itself, and `frpc verify` must accept the candidate. A rejected generation is not tried again; the running
//     frpc and its files stay as they are.
//  2. written: the local admin block (webServer on --frpc-admin, loopback, with a password kept in
//     <state-dir>/frpc-admin.secret) is inserted before the first proxy, and the CA and file replace the live ones
//     atomically. The first time, the files found at start are kept as the fallback.
//  3. loaded: by frpc's hot reload when only proxies changed, which leaves unchanged proxies (the primary visitor)
//     running; by --frpc-restart-cmd when the frps settings or CA changed (frpc reloads proxies only) or the
//     running frpc has no admin API yet (installed before this change).
//  4. confirmed: frpc's live status (GET /api/status on the admin API) must list exactly the desired proxies, all
//     "running", within --frpc-confirm-timeout. frpc reports "running" once frps accepted the registration.
//
// Only a confirmed generation is reported as applied. Otherwise the last confirmed (or the start-up) files go back in
// place and are loaded again, the attempt is reported as failed, and it is retried after a minute or as soon as a
// newer generation arrives. The confirmed generation is kept in <state-dir>/xtcp-state.json, so a restarted agent
// neither reloads an unchanged configuration nor forgets what it confirmed. Messages leave out every secret value.
// Removing XTCP from a host stays with the installer (frpc and its service are removed on the next install run).

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	xtcpApplied     = "applied"
	xtcpPending     = "pending"
	xtcpFailed      = "failed"
	xtcpRetry       = 60 * time.Second
	frpcAdminUser   = "ccproxy-agent"
	frpcAdminSecret = "frpc-admin.secret"
	frpcProxyLine   = "[[proxies]]"
)

var (
	frpcPasswordPattern = regexp.MustCompile(`^[0-9a-f]{32,64}$`)
	frpcSecretLine      = regexp.MustCompile(`(?m)^\s*(auth\.token|secretKey|webServer\.password)\s*=\s*["']([^"'\r\n]+)["']`)
)

type xtcpProxy struct {
	Name   string `json:"name"`
	Port   int    `json:"port"`
	Digest string `json:"digest"`
}

type xtcpDesired struct {
	Generation int64       `json:"generation"`
	SHA256     string      `json:"sha256"`
	FrpcTOML   string      `json:"frpc_toml"`
	CAPEM      string      `json:"ca_pem"`
	Proxies    []xtcpProxy `json:"proxies"`
}

// xtcpState is what survives an agent restart.
type xtcpState struct {
	ConfirmedGeneration int64       `json:"confirmed_generation"`
	ConfirmedSHA256     string      `json:"confirmed_sha256"`
	ConfirmedProxies    []xtcpProxy `json:"confirmed_proxies"`
	RejectedGeneration  int64       `json:"rejected_generation"`
	KeptPrevious        bool        `json:"kept_previous"`
}

type xtcpSync struct {
	a        *Agent
	admin    string // loopback host:port of frpc's admin API
	password string
	client   *http.Client

	etag        string
	desired     *xtcpDesired
	unsupported bool // the control plane predates /agent/xtcp
	st          xtcpState

	attempt    int64 // generation last tried in this process
	state, err string
	retryAfter time.Time
	now        func() time.Time
	poll       time.Duration
}

func newXTCPSync(a *Agent) (*xtcpSync, error) {
	o := a.opt
	if o.FrpcBin == "" || o.FrpcCA == "" || o.FrpcRestartCmd == "" {
		return nil, errors.New("--frpc-config needs --frpc, --frpc-ca and --frpc-restart-cmd")
	}
	if !filepath.IsAbs(o.FrpcConfig) || !filepath.IsAbs(o.FrpcCA) || (o.FrpcLog != "" && !filepath.IsAbs(o.FrpcLog)) {
		return nil, errors.New("--frpc-config, --frpc-ca and --frpc-log must be absolute paths")
	}
	if _, err := splitCommand(o.FrpcRestartCmd); err != nil {
		return nil, fmt.Errorf("--frpc-restart-cmd: %w", err)
	}
	admin, err := loopbackAPI(o.FrpcAdmin)
	if err != nil {
		return nil, errors.New(strings.Replace(err.Error(), "--confirm-api", "--frpc-admin", 1))
	}
	if admin == a.confirmAddress {
		return nil, errors.New("--frpc-admin must differ from --confirm-api")
	}
	x := &xtcpSync{a: a, admin: admin, now: time.Now, poll: 250 * time.Millisecond,
		client: &http.Client{
			Timeout:       5 * time.Second,
			Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
	return x, nil
}

func (x *xtcpSync) path(name string) string { return filepath.Join(x.a.opt.StateDir, name) }

// load reads the persisted state and the admin password (created on first use; the installer may have created it).
func (x *xtcpSync) load() error {
	if data, err := os.ReadFile(x.path("xtcp-state.json")); err == nil {
		if err := json.Unmarshal(data, &x.st); err != nil {
			x.a.logf("xtcp: ignoring unreadable state file: %v", err)
			x.st = xtcpState{}
		}
	}
	data, err := os.ReadFile(x.path(frpcAdminSecret))
	x.password = strings.TrimSpace(string(data))
	if err != nil || !frpcPasswordPattern.MatchString(x.password) {
		x.password = randomHex()
		tmp, err := writeTemp(x.a.opt.StateDir, []byte(x.password+"\n"))
		if err != nil {
			return err
		}
		if err := os.Rename(tmp, x.path(frpcAdminSecret)); err != nil {
			os.Remove(tmp)
			return err
		}
	}
	return nil
}

func (x *xtcpSync) save() {
	data, _ := json.MarshalIndent(x.st, "", "  ")
	tmp, err := writeTemp(x.a.opt.StateDir, data)
	if err == nil {
		err = os.Rename(tmp, x.path("xtcp-state.json"))
	}
	if err != nil {
		x.a.logf("xtcp: could not save state: %v", err)
	}
}

// adminBlock is the local admin API section inserted before the first proxy. exit.sh and exit.ps1 insert the same
// lines, so a freshly installed file already equals the agent's candidate and needs no reload.
func (x *xtcpSync) adminBlock() string {
	host, port, _ := net.SplitHostPort(x.admin)
	return "# Local admin API for the CC Proxy exit agent: loopback only, password in the agent's state directory.\n" +
		"webServer.addr = \"" + host + "\"\n" +
		"webServer.port = " + port + "\n" +
		"webServer.user = \"" + frpcAdminUser + "\"\n" +
		"webServer.password = \"" + x.password + "\"\n\n"
}

// spliceAdmin inserts block before the first [[proxies]] line (or appends it when there is none).
func spliceAdmin(toml, block string) string {
	lines := strings.Split(toml, "\n")
	for i, line := range lines {
		if line == frpcProxyLine {
			return strings.Join(lines[:i], "\n") + "\n" + block + strings.Join(lines[i:], "\n")
		}
	}
	if !strings.HasSuffix(toml, "\n") {
		toml += "\n"
	}
	return toml + "\n" + block
}

// commonSection is everything frpc only reads at start: the settings before the first proxy, without comments.
func commonSection(toml string) string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(toml, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == frpcProxyLine {
			break
		}
		if t := strings.TrimSpace(line); t != "" && !strings.HasPrefix(t, "#") {
			out = append(out, t)
		}
	}
	return strings.Join(out, "\n")
}

func normalizeText(data []byte) string {
	return strings.ReplaceAll(strings.TrimPrefix(string(data), "\uFEFF"), "\r\n", "\n")
}

// checkCA accepts PEM CA certificates only, as the control plane does.
func checkCA(text string) error {
	rest := []byte(text)
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return errors.New("the CA holds a non-certificate PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("the CA does not parse: %v", err)
		}
		if !cert.IsCA {
			return errors.New("the CA certificate is not a CA")
		}
		n++
	}
	if n == 0 || strings.TrimSpace(string(rest)) != "" {
		return errors.New("the CA is not PEM-encoded certificates")
	}
	return nil
}

// redact removes every secret value found in the given configurations (and the admin password) from text.
func (x *xtcpSync) redact(text string, configs ...string) string {
	secrets := []string{x.password}
	for _, c := range configs {
		for _, m := range frpcSecretLine.FindAllStringSubmatch(c, -1) {
			secrets = append(secrets, m[2])
		}
	}
	for _, s := range secrets {
		if len(s) >= 4 {
			text = strings.ReplaceAll(text, s, "[redacted]")
		}
	}
	text = strings.TrimSpace(text)
	if len(text) > 400 {
		text = text[:400] + "..."
	}
	return text
}

// fetch updates x.desired from the control plane.
func (x *xtcpSync) fetch() error {
	q := url.Values{"ca_file": {x.a.opt.FrpcCA}}
	if x.a.opt.FrpcLog != "" {
		q.Set("log_file", x.a.opt.FrpcLog)
	}
	req, err := http.NewRequest("GET", x.a.opt.CP+"/agent/xtcp?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+x.a.token)
	if x.etag != "" {
		req.Header.Set("If-None-Match", x.etag)
	}
	resp, err := x.a.cp.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusNoContent:
		if x.desired != nil {
			x.a.logf("xtcp: this host no longer uses XTCP; frpc is left to the installer")
		}
		x.desired, x.etag = nil, ""
		return nil
	case http.StatusNotFound:
		x.unsupported = true
		x.a.logf("xtcp: the control plane has no XTCP sync (/agent/xtcp); frpc stays as installed")
		return nil
	case http.StatusOK:
	default:
		return fmt.Errorf("GET /agent/xtcp: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	var d xtcpDesired
	if err := json.Unmarshal(body, &d); err != nil || d.Generation <= 0 || d.SHA256 == "" || len(d.Proxies) == 0 {
		return errors.New("GET /agent/xtcp: not a desired XTCP configuration")
	}
	if x.desired == nil || x.desired.Generation != d.Generation {
		x.a.logf("xtcp: control plane wants generation %d (%d proxies)", d.Generation, len(d.Proxies))
	}
	x.desired, x.etag = &d, resp.Header.Get("ETag")
	return nil
}

// Sync runs one XTCP round. Errors are about reaching the control plane; outcomes are reported, not returned.
func (x *xtcpSync) Sync() error {
	if x.unsupported {
		return nil
	}
	if err := x.fetch(); err != nil || x.desired == nil {
		return err
	}
	d := *x.desired
	switch {
	case d.Generation == x.st.ConfirmedGeneration && d.SHA256 == x.st.ConfirmedSHA256:
		x.attempt, x.state, x.err = d.Generation, xtcpApplied, ""
		return nil // already confirmed: never reloaded again
	case d.Generation == x.st.RejectedGeneration:
		return nil
	case d.Generation == x.attempt && x.now().Before(x.retryAfter):
		return nil
	}
	x.reconcile(d)
	return nil
}

// reconcile tries to make the running frpc serve d, and restores the working configuration when it cannot.
func (x *xtcpSync) reconcile(d xtcpDesired) {
	o := x.a.opt
	x.attempt, x.state, x.err = d.Generation, xtcpPending, ""
	live, _ := os.ReadFile(o.FrpcConfig)
	liveCA, _ := os.ReadFile(o.FrpcCA)
	reject := func(format string, args ...any) {
		x.state, x.err = xtcpFailed, x.redact(fmt.Sprintf(format, args...), d.FrpcTOML, string(live))
		x.st.RejectedGeneration = d.Generation
		x.save()
		x.a.logf("xtcp: generation %d rejected, frpc keeps its current proxies: %s", d.Generation, x.err)
	}
	if err := checkCA(d.CAPEM); err != nil {
		reject("%v", err)
		return
	}
	if err := checkFrpcTOML(d.FrpcTOML, o.FrpcCA, o.FrpcLog, d.Proxies); err != nil {
		reject("%v", err)
		return
	}
	candidate := spliceAdmin(d.FrpcTOML, x.adminBlock())
	candidatePath := x.path("frpc-candidate.toml")
	tmp, err := writeTemp(o.StateDir, []byte(candidate))
	if err == nil {
		err = os.Rename(tmp, candidatePath)
	}
	if err != nil {
		x.fail(d, "", "staging the candidate: %v", err)
		return
	}
	var out bytes.Buffer
	verify := exec.Command(o.FrpcBin, "verify", "-c", candidatePath)
	verify.Stdout, verify.Stderr = &out, &out
	if err := verify.Run(); err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			x.fail(d, "", "running frpc verify: %v", err)
			return
		}
		reject("frpc verify: %s", out.String())
		return
	}

	sameConfig := normalizeText(live) == candidate
	sameCA := strings.TrimSpace(normalizeText(liveCA)) == strings.TrimSpace(d.CAPEM)
	mode := ""
	switch {
	case sameConfig && sameCA:
		mode = "" // already in place (a fresh install): confirm only
	case !sameCA || commonSection(normalizeText(live)) != commonSection(candidate):
		mode = "restart"
	case x.adminUp():
		mode = "reload"
	default:
		mode = "restart" // frpc predates the admin API, or is not running
	}
	if mode != "" {
		if err := x.keepPrevious(); err != nil {
			x.fail(d, "", "keeping the current frpc files: %v", err)
			return
		}
		if !sameCA {
			if err := writeFile(o.FrpcCA, []byte(d.CAPEM)); err != nil {
				x.fail(d, mode, "writing the CA: %v", err)
				return
			}
		}
		if err := writeFile(o.FrpcConfig, []byte(candidate)); err != nil {
			x.fail(d, mode, "writing %s: %v", o.FrpcConfig, err)
			return
		}
		if err := x.loadConfig(mode); err != nil {
			x.fail(d, mode, "%v", err)
			return
		}
	}
	if err := x.awaitRegistered(d.Proxies); err != nil {
		x.fail(d, mode, "frpc did not confirm generation %d: %v", d.Generation, err)
		return
	}
	err = writeFile(x.path("frpc-confirmed.toml"), []byte(candidate))
	if err == nil {
		err = writeFile(x.path("frpc-confirmed-ca.pem"), []byte(d.CAPEM))
	}
	if err != nil { // the generation is live; only the fallback copy is missing
		x.a.logf("xtcp: could not keep a copy of the confirmed configuration: %v", err)
	}
	x.st.ConfirmedGeneration, x.st.ConfirmedSHA256, x.st.ConfirmedProxies = d.Generation, d.SHA256, d.Proxies
	x.save()
	x.state, x.err = xtcpApplied, ""
	how := map[string]string{"": "already in place", "reload": "hot reload", "restart": "frpc restart"}[mode]
	x.a.logf("xtcp: frpc confirmed generation %d (%s): %s registered", d.Generation, how, proxyNames(d.Proxies))
}

var (
	// The only settings the control plane renders (controlplane/xtcp.go renderFrpcTOML). Anything else (plugins,
	// visitors, other proxy types, a non-loopback target, frpc's own admin API, Go template actions) is refused, so the
	// agent only ever installs xtcp proxies that forward to this host's own loopback.
	frpcCommonKeys = regexp.MustCompile(`^(serverAddr = "[A-Za-z0-9.-]+"|serverPort = [0-9]{1,5}|loginFailExit = false|` +
		`auth\.method = "token"|auth\.token = "[A-Za-z0-9_.~+/=-]+"|transport\.tls\.enable = true|` +
		`transport\.tls\.trustedCaFile = '[^'\r\n]+'|transport\.tls\.serverName = "[A-Za-z0-9.-]+"|` +
		`log\.to = ("console"|'[^'\r\n]+')|log\.level = "info"|log\.maxDays = [0-9]{1,3})$`)
	frpcProxyKeys = regexp.MustCompile(`^(name = "[A-Za-z0-9_.-]+"|type = "xtcp"|secretKey = "[A-Za-z0-9_.~+/=-]+"|` +
		`localIP = "127\.0\.0\.1"|localPort = [0-9]{1,5})$`)
)

// checkFrpcTOML accepts exactly the shape the control plane renders: frps settings naming this host's CA (and log)
// file, then xtcp proxies to 127.0.0.1, one per desired proxy, each on its own port.
func checkFrpcTOML(toml, caFile, logFile string, want []xtcpProxy) error {
	if strings.Contains(toml, "{{") || strings.Contains(toml, "\r") {
		return errors.New("the configuration contains template actions or CR characters")
	}
	type proxy struct {
		name string
		port int
	}
	var proxies []proxy
	inProxy := false
	for _, line := range strings.Split(toml, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "" || strings.HasPrefix(t, "#"):
		case line == frpcProxyLine:
			inProxy = true
			proxies = append(proxies, proxy{})
		case !inProxy && frpcCommonKeys.MatchString(line):
			if strings.HasPrefix(line, "transport.tls.trustedCaFile") && line != "transport.tls.trustedCaFile = '"+caFile+"'" {
				return errors.New("the configuration names another CA file than this host's --frpc-ca")
			}
			if strings.HasPrefix(line, "log.to = '") && line != "log.to = '"+logFile+"'" {
				return errors.New("the configuration names another log file than this host's --frpc-log")
			}
		case inProxy && frpcProxyKeys.MatchString(line):
			p := &proxies[len(proxies)-1]
			if v, ok := strings.CutPrefix(line, `name = "`); ok {
				p.name = strings.TrimSuffix(v, `"`)
			}
			if v, ok := strings.CutPrefix(line, "localPort = "); ok {
				fmt.Sscan(v, &p.port)
			}
		default:
			return fmt.Errorf("the configuration has a setting this agent does not install: %q", strings.SplitN(t, "=", 2)[0])
		}
	}
	if !strings.Contains(toml, "\ntransport.tls.trustedCaFile = '") {
		return errors.New("the configuration does not verify frps against this host's CA file")
	}
	if len(proxies) != len(want) {
		return fmt.Errorf("the configuration has %d proxies, the control plane listed %d", len(proxies), len(want))
	}
	for i, p := range proxies {
		if p.name != want[i].Name || p.port != want[i].Port || p.port < 1 || p.port > 65535 {
			return fmt.Errorf("the configuration's proxy %d (%s, port %d) does not match the listed %s on port %d", i+1, p.name, p.port, want[i].Name, want[i].Port)
		}
	}
	return nil
}

func proxyNames(ps []xtcpProxy) string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.Name)
	}
	return strings.Join(names, ", ")
}

// writeFile atomically replaces path (temp file in the same directory, then rename).
func writeFile(path string, data []byte) error {
	tmp, err := writeTemp(filepath.Dir(path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// keepPrevious saves the files found at start as the fallback, once, before this agent first replaces them.
func (x *xtcpSync) keepPrevious() error {
	o := x.a.opt
	if x.st.ConfirmedGeneration != 0 || x.st.KeptPrevious || !isRegular(o.FrpcConfig) {
		return nil
	}
	if err := place(o.FrpcConfig, x.path("frpc-previous.toml")); err != nil {
		return err
	}
	if isRegular(o.FrpcCA) {
		if err := place(o.FrpcCA, x.path("frpc-previous-ca.pem")); err != nil {
			return err
		}
	}
	x.st.KeptPrevious = true
	x.save()
	x.a.logf("xtcp: kept the existing %s as the fallback configuration", o.FrpcConfig)
	return nil
}

// fail records a failed attempt. When files were replaced (mode != ""), the working ones go back and are loaded
// again the same way, so the proxies frpc served before keep working.
func (x *xtcpSync) fail(d xtcpDesired, mode, format string, args ...any) {
	live, _ := os.ReadFile(x.a.opt.FrpcConfig)
	x.state, x.err = xtcpFailed, x.redact(fmt.Sprintf(format, args...), d.FrpcTOML, string(live))
	x.retryAfter = x.now().Add(xtcpRetry)
	x.a.logf("xtcp: generation %d not active, will retry: %s", d.Generation, x.err)
	if mode == "" {
		return
	}
	conf, ca, what := x.path("frpc-confirmed.toml"), x.path("frpc-confirmed-ca.pem"), fmt.Sprintf("generation %d", x.st.ConfirmedGeneration)
	if x.st.ConfirmedGeneration == 0 {
		conf, ca, what = x.path("frpc-previous.toml"), x.path("frpc-previous-ca.pem"), "the configuration found at start"
	}
	if !isRegular(conf) {
		return
	}
	if isRegular(ca) {
		if err := place(ca, x.a.opt.FrpcCA); err != nil {
			x.a.logf("xtcp: could not restore the CA: %v", err)
		}
	}
	if err := place(conf, x.a.opt.FrpcConfig); err != nil {
		x.a.logf("xtcp: could not restore %s: %v", what, err)
		return
	}
	if err := x.loadConfig(mode); err != nil {
		x.a.logf("xtcp: restored %s, loading it failed: %s", what, x.redact(err.Error()))
		return
	}
	x.a.logf("xtcp: restored %s at %s", what, x.a.opt.FrpcConfig)
}

// loadConfig makes frpc read --frpc-config: hot reload through the admin API, or a service restart.
func (x *xtcpSync) loadConfig(mode string) error {
	if mode == "restart" {
		if err := runCommand(x.a.opt.FrpcRestartCmd, x.a.output); err != nil {
			return fmt.Errorf("frpc restart (%s): %v", x.a.opt.FrpcRestartCmd, err)
		}
		return nil
	}
	resp, err := x.adminGet("/api/reload")
	if err != nil {
		return fmt.Errorf("frpc reload: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("frpc reload: HTTP %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (x *xtcpSync) adminGet(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "http://"+x.admin+path, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(frpcAdminUser, x.password)
	return x.client.Do(req)
}

// adminUp: the running frpc answers on the admin API with this agent's password.
func (x *xtcpSync) adminUp() bool {
	resp, err := x.adminGet("/api/status")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type frpcProxyStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Err    string `json:"err"`
}

// liveProxies reads frpc's status: proxy name -> status (with its error).
func (x *xtcpSync) liveProxies() (map[string]frpcProxyStatus, error) {
	resp, err := x.adminGet("/api/status")
	if err != nil {
		return nil, fmt.Errorf("no answer from frpc's admin API at %s", x.admin)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("frpc's admin API answered HTTP %d", resp.StatusCode)
	}
	var byType map[string][]frpcProxyStatus
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&byType); err != nil {
		return nil, fmt.Errorf("unreadable frpc status: %v", err)
	}
	out := map[string]frpcProxyStatus{}
	for _, list := range byType {
		for _, p := range list {
			out[p.Name] = p
		}
	}
	return out, nil
}

// awaitRegistered waits until frpc lists exactly the wanted proxies, every one running (accepted by frps).
func (x *xtcpSync) awaitRegistered(want []xtcpProxy) error {
	deadline := x.now().Add(time.Duration(x.a.opt.FrpcConfirmTimeout * float64(time.Second)))
	for {
		live, err := x.liveProxies()
		problem := ""
		if err != nil {
			problem = err.Error()
		} else {
			problem = registrationProblem(want, live)
		}
		if problem == "" {
			return nil
		}
		if !x.now().Before(deadline) {
			return fmt.Errorf("%s (after %gs)", problem, x.a.opt.FrpcConfirmTimeout)
		}
		time.Sleep(x.poll)
	}
}

func registrationProblem(want []xtcpProxy, live map[string]frpcProxyStatus) string {
	var problems []string
	wanted := map[string]bool{}
	for _, p := range want {
		wanted[p.Name] = true
		s, ok := live[p.Name]
		switch {
		case !ok:
			problems = append(problems, p.Name+" not loaded")
		case s.Status != "running":
			detail := s.Status
			if s.Err != "" {
				detail += ": " + s.Err
			}
			problems = append(problems, p.Name+" "+detail)
		}
	}
	var extra []string
	for name := range live {
		if !wanted[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		problems = append(problems, name+" still registered (retired)")
	}
	return strings.Join(problems, "; ")
}

// report is the heartbeat's "xtcp" object, or nil when there is nothing to say (sync off, public-entry host).
func (x *xtcpSync) report() map[string]any {
	if x.unsupported || (x.attempt == 0 && x.st.ConfirmedGeneration == 0) {
		return nil
	}
	generation, state := x.attempt, x.state
	if generation == 0 {
		generation, state = x.st.ConfirmedGeneration, xtcpApplied
	}
	proxies := x.st.ConfirmedProxies
	if proxies == nil {
		proxies = []xtcpProxy{}
	}
	return map[string]any{
		"generation": generation, "state": state, "error": x.err,
		"applied_generation": x.st.ConfirmedGeneration, "applied_sha256": x.st.ConfirmedSHA256,
		"applied_proxies": proxies,
	}
}
