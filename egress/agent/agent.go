package main

// Port of controlplane/agent.py: the same control-plane API, the same settle / check / stage / confirm state
// machine and the same heartbeat contract. See the package documentation in main.go.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	probeWorkers             = 16
	probeBuffer              = 4000 // results kept for reporting; the oldest are dropped beyond this
	reportMax                = 2000 // results per report (the control plane accepts up to this many)
	confirmMaxBytes          = 4 << 20
	markerPrefix             = "confirm-"
	unknownRetry             = 60 * time.Second // reload again when a reload stayed unconfirmed this long
	failedOutageRetry        = 60 * time.Second // retry a candidate that made sing-box exit only after this long
	previousGeneration       = "previous"       // onDisk: the --config found at start (never claimed applied)
	stateConfirmed           = "confirmed"
	statePending             = "pending"
	stateFailed              = "failed"
	stateUnknown             = "unknown"
	evidenceLoaded           = "loaded"
	evidenceOther            = "other"
	versionCandidate         = "candidate"
	versionConfirmedSnapshot = "confirmed"
)

// Options mirrors the agent.py command line.
type Options struct {
	CP, CAFile, Iface, Config, StateDir, SingBox, Name string
	StatusCmd, ReloadCmd, ConfirmAPI, RunReload        string
	UsageAPI                                           string // loopback address of sing-box's API service, or "off"
	Interval, Settle, MaxDelay                         float64
	ProbeInterval, ProbeTimeout, ConfirmTimeout        float64
	UsageInterval                                      float64
	Once, Run                                          bool
	// XTCP sync (xtcp.go): off unless FrpcConfig is set. All of these come from the local installation.
	FrpcBin, FrpcConfig, FrpcCA, FrpcLog, FrpcAdmin, FrpcRestartCmd string
	FrpcConfirmTimeout                                              float64
	// Managed updates (update.go).
	Update, UpdateRestartCmd            string
	UpdateInterval, UpdateHealthTimeout float64
}

// errNotLoaded: the running sing-box demonstrably does not serve the version asked about.
type errNotLoaded struct{ reason string }

func (e errNotLoaded) Error() string { return e.reason }

type pendingVersion struct {
	etag        string
	body        []byte
	first, last float64
}

// ProbeResult is one egress probe as /agent/report expects it.
type ProbeResult struct {
	OK        bool     `json:"ok"`
	LatencyMS *float64 `json:"latency_ms"`
	Detail    string   `json:"detail"`
	Subject   string   `json:"subject"`
	Target    string   `json:"target"`
}

type Agent struct {
	opt     Options
	token   string
	cp      *http.Client
	confirm *http.Client
	logf    func(format string, args ...any)
	now     func() float64 // wall clock in seconds; replaceable in tests (settle window)

	applied, installed, applyError, applyState   string // "" stands for none / null
	secret, marker, appliedSecret, appliedMarker string
	onDisk                                       string // a version's marker, previousGeneration, or "" (not written yet)
	keptPrevious                                 bool
	retryAfter, lastReload                       time.Time
	confirmAddress                               string
	pending                                      *pendingVersion
	rejected                                     string
	child                                        *child
	ips                                          *string

	probeMu      sync.Mutex
	lastProbe    *float64
	probeRunning bool
	probeBuf     []ProbeResult
	probeFunc    func(url, sourceIP string, timeout time.Duration) ProbeResult
	output       io.Writer // where a --run child writes (the agent's log)

	usage     *usageCollector // nil with --once or when usage collection could not be set up
	stopUsage context.CancelFunc

	xtcp *xtcpSync // nil unless --frpc-config is set

	update   *updater     // nil in tests that do not set one up
	download *http.Client // control-plane downloads (agent updates): like cp, with a longer timeout
}

func NewAgent(opt Options, token string, logf func(string, ...any), output io.Writer) (*Agent, error) {
	if token == "" {
		return nil, errors.New("set CP_AGENT_TOKEN or pass --token-file")
	}
	if err := checkControlPlaneURL(opt.CP); err != nil {
		return nil, err
	}
	addr, err := loopbackAPI(opt.ConfirmAPI)
	if err != nil {
		return nil, err
	}
	if opt.UsageAPI != "" && !strings.EqualFold(opt.UsageAPI, "off") {
		usageAddr, err := loopbackAPI(opt.UsageAPI)
		if err != nil {
			return nil, errors.New(strings.Replace(err.Error(), "--confirm-api", "--usage-api", 1))
		}
		if usageAddr == addr {
			return nil, errors.New("--usage-api must differ from --confirm-api")
		}
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if opt.CAFile != "" {
		pem, err := os.ReadFile(opt.CAFile)
		if err != nil {
			return nil, fmt.Errorf("--cafile: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--cafile %s holds no PEM certificate", opt.CAFile)
		}
		tlsConf.RootCAs = pool
	}
	cpURL := strings.TrimRight(opt.CP, "/")
	a := &Agent{
		opt:   opt,
		token: token,
		cp: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConf, DialContext: dialControlPlane,
			},
			// Every control-plane request carries the agent token: a redirect is refused, never followed.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("refused redirect to %s: the agent token is sent to --cp only", req.URL)
			},
		},
		// Loopback only: no proxy from the environment, no redirects.
		confirm: &http.Client{
			Timeout:       2 * time.Second,
			Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		logf:           logf,
		now:            func() float64 { return float64(time.Now().UnixNano()) / 1e9 },
		confirmAddress: addr,
		probeFunc:      httpProbe,
		output:         output,
	}
	a.opt.CP = cpURL
	a.download = &http.Client{Timeout: 10 * time.Minute, Transport: a.cp.Transport, CheckRedirect: a.cp.CheckRedirect}
	if opt.FrpcConfig != "" {
		if a.xtcp, err = newXTCPSync(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// A dual-stack Agent prefers IPv4 so the control plane can learn its IPv4 from the heartbeat.
// Keep the ordinary dial as a fallback for an IPv6-only control plane or network.
func dialControlPlane(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	if network == "tcp" {
		ipv4Ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := dialer.DialContext(ipv4Ctx, "tcp4", address)
		cancel()
		if err == nil {
			return conn, nil
		}
	}
	return dialer.DialContext(ctx, network, address)
}

// checkControlPlaneURL: https, or http to a loopback address (tests and a co-located control plane only).
func checkControlPlaneURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("--cp must be a URL such as https://cp.example:8443")
	}
	if u.Scheme == "https" {
		return nil
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("--cp must use https: the agent token must not cross the network in clear text")
}

// loopbackAPI checks --confirm-api: a numeric loopback IP and port. Returns it in the form sing-box and URLs accept.
func loopbackAPI(addr string) (string, error) {
	bad := errors.New("--confirm-api must be a numeric loopback address with a port, e.g. 127.0.0.1:9095")
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return "", bad
	}
	host, portText := strings.TrimSuffix(strings.TrimPrefix(addr[:i], "["), "]"), addr[i+1:]
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || err != nil || !ip.IsLoopback() || port < 1 || port > 65535 {
		return "", bad
	}
	if ip.To4() == nil {
		return fmt.Sprintf("[%s]:%d", ip, port), nil
	}
	return fmt.Sprintf("%s:%d", ip, port), nil
}

// -- control plane ----------------------------------------------------------------------------------------------

func (a *Agent) get(path, etag string) (int, string, []byte, error) {
	req, err := http.NewRequest("GET", a.opt.CP+path, nil)
	if err != nil {
		return 0, "", nil, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := a.cp.Do(req)
	if err != nil {
		return 0, "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return 304, etag, nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return 0, "", nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, "", nil, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	return 200, resp.Header.Get("ETag"), body, nil
}

func (a *Agent) post(path string, obj any) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("POST", a.opt.CP+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.cp.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

// -- state --------------------------------------------------------------------------------------------------------

// settled: the installed generation is the confirmed one (by marker: A -> B -> A must be proved again).
func (a *Agent) settled() bool { return a.installed != "" && a.marker == a.appliedMarker }

func (a *Agent) state() string {
	if a.installed == "" {
		return ""
	}
	if a.settled() {
		return stateConfirmed
	}
	return a.applyState
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (a *Agent) singboxRunning() any {
	if a.opt.Run {
		return a.child != nil && a.child.alive()
	}
	if a.opt.StatusCmd != "" {
		return runCommand(a.opt.StatusCmd, a.output) == nil
	}
	return nil
}

// -- probes -------------------------------------------------------------------------------------------------------

func (a *Agent) probeIPs(onResult func(ProbeResult)) error {
	_, _, body, err := a.get("/agent/probe-targets", "")
	if err != nil {
		return err
	}
	var targets struct {
		EgressTargets []string `json:"egress_targets"`
	}
	if err := json.Unmarshal(body, &targets); err != nil {
		return err
	}
	var ips []string
	if a.ips != nil {
		ips = strings.Fields(*a.ips)
	}
	type job struct{ ip, url string }
	jobs := make(chan job)
	var wg sync.WaitGroup
	workers := probeWorkers
	if n := len(ips) * len(targets.EgressTargets); n < workers {
		workers = n
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := a.probeFunc(j.url, j.ip, time.Duration(a.opt.ProbeTimeout*float64(time.Second)))
				r.Subject, r.Target = j.ip, j.url
				onResult(r)
			}
		}()
	}
	for _, ip := range ips {
		for _, u := range targets.EgressTargets {
			jobs <- job{ip, u}
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}

func (a *Agent) collect(r ProbeResult) {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	a.probeBuf = append(a.probeBuf, r)
	if len(a.probeBuf) > probeBuffer {
		a.probeBuf = a.probeBuf[len(a.probeBuf)-probeBuffer:]
	}
}

// maybeProbe starts a probe round when one is due and none is running. Rounds never overlap or pile up.
func (a *Agent) maybeProbe(background bool) bool {
	now := a.now()
	a.probeMu.Lock()
	if a.probeRunning || (a.lastProbe != nil && now-*a.lastProbe < a.opt.ProbeInterval) {
		a.probeMu.Unlock()
		return false
	}
	a.lastProbe, a.probeRunning = &now, true
	a.probeMu.Unlock()
	run := func() {
		defer func() {
			if r := recover(); r != nil {
				a.logf("probe round failed: %v", r)
			}
			a.probeMu.Lock()
			a.probeRunning = false
			a.probeMu.Unlock()
		}()
		if err := a.probeIPs(a.collect); err != nil {
			a.logf("probe round failed: %v", err)
		}
	}
	if background {
		go run()
	} else {
		run()
	}
	return true
}

func (a *Agent) drainProbes() []ProbeResult {
	a.probeMu.Lock()
	defer a.probeMu.Unlock()
	n := len(a.probeBuf)
	if n > reportMax {
		n = reportMax
	}
	out := append([]ProbeResult(nil), a.probeBuf[:n]...)
	a.probeBuf = a.probeBuf[n:]
	return out
}

// report posts the heartbeat with whatever probe results completed since the last one. Never waits for a round.
func (a *Agent) report() error {
	a.maybeProbe(!a.opt.Once)
	probes := a.drainProbes()
	var bad []string
	for _, p := range probes {
		if !p.OK {
			bad = append(bad, fmt.Sprintf("%s %s %s", p.Subject, p.Target, p.Detail))
		}
	}
	if len(bad) > 0 {
		a.logf("probe failures: %s", strings.Join(bad, "; "))
	}
	candidate := ""
	if !a.settled() {
		candidate = a.installed
	}
	if probes == nil {
		probes = []ProbeResult{}
	}
	report := map[string]any{
		"agent": a.opt.Name, "config_etag": nullable(a.applied), "apply_state": nullable(a.state()),
		"apply_error": nullable(a.applyError), "candidate_etag": nullable(candidate),
		"agent_version": version, "singbox_running": a.singboxRunning(), "probes": probes,
	}
	if a.update != nil {
		report["update"] = a.update.report()
	}
	if a.xtcp != nil {
		if x := a.xtcp.report(); x != nil {
			report["xtcp"] = x
		}
	}
	if a.ips != nil && strings.TrimSpace(*a.ips) == "" {
		if address := detectMacEgressIPv4(); address != "" {
			report["local_egress_ipv4"] = address
		}
	}
	err := a.post("/agent/report", report)
	if err != nil { // keep them for the next heartbeat (the buffer bound still applies)
		a.probeMu.Lock()
		a.probeBuf = append(probes, a.probeBuf...)
		if len(a.probeBuf) > probeBuffer {
			a.probeBuf = a.probeBuf[:probeBuffer]
		}
		a.probeMu.Unlock()
	}
	return err
}

// -- egress IPs and config ------------------------------------------------------------------------------------------

func (a *Agent) syncIPs() error {
	_, _, body, err := a.get("/agent/ips", "")
	if err != nil {
		return err
	}
	ips := string(body)
	if a.ips != nil && *a.ips == ips {
		return nil
	}
	path := filepath.Join(a.opt.StateDir, "ips.txt")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return err
	}
	if a.opt.Iface != "" {
		if err := ipsUp(a.opt.Iface, path, a.logf); err != nil {
			return err
		}
	}
	a.ips = &ips
	return nil
}

// syncConfig polls once; true when a new version was checked and staged and sing-box should reload.
func (a *Agent) syncConfig() (bool, error) {
	known := a.installed
	if a.pending != nil {
		known = a.pending.etag
	}
	status, etag, body, err := a.get("/agent/server-config", known)
	if err != nil {
		return false, err
	}
	now := a.now()
	if status == 200 && etag == a.installed {
		a.pending = nil // changed and changed back before it settled
	} else if status == 200 && etag != a.rejected {
		if a.pending == nil {
			a.pending = &pendingVersion{first: now}
			a.logf("version %s seen, settling", etag)
		}
		a.pending.etag, a.pending.body, a.pending.last = etag, body, now
	}
	if a.pending == nil {
		return false, nil
	}
	quiet, waited := now-a.pending.last, now-a.pending.first
	firstConfig := a.applied == "" // nothing is serving yet: do not make a fresh node wait
	if !firstConfig && quiet < a.opt.Settle && waited < a.opt.MaxDelay {
		return false, nil
	}
	p := a.pending
	a.pending = nil
	return a.install(p.etag, p.body)
}

func randomHex() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (a *Agent) candidateCopy() string { return filepath.Join(a.opt.StateDir, "candidate-config.json") }
func (a *Agent) confirmedCopy() string { return filepath.Join(a.opt.StateDir, "confirmed-config.json") }
func (a *Agent) previousCopy() string  { return filepath.Join(a.opt.StateDir, "previous-config.json") }

func (a *Agent) install(etag string, body []byte) (bool, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber() // numbers go back out exactly as they came
	var config map[string]any
	if err := dec.Decode(&config); err != nil || config == nil {
		return false, fmt.Errorf("server config is not a JSON object: %v", err)
	}
	if _, ok := config["experimental"]; !ok {
		config["experimental"] = map[string]any{}
	}
	experimental, ok := config["experimental"].(map[string]any)
	if !ok {
		return false, errors.New("server config is not a JSON object with an object 'experimental'")
	}
	if _, ok := config["outbounds"]; !ok {
		config["outbounds"] = []any{}
	}
	outbounds, ok := config["outbounds"].([]any)
	if !ok {
		return false, errors.New("server config 'outbounds' is not a list")
	}
	// Per-candidate values: the secret authorizes the question, the marker is the answer only a sing-box running
	// this file can give. Appended, so the first (default) outbound is unchanged.
	secret, marker := randomHex(), markerPrefix+randomHex()
	experimental["clash_api"] = map[string]any{"external_controller": a.confirmAddress, "secret": secret}
	config["outbounds"] = append(outbounds, map[string]any{"type": "block", "tag": marker})
	if a.usage != nil {
		a.usage.inject(config) // never refuses the candidate; collection just reports itself unavailable
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return false, err
	}
	tmp, err := writeTemp(a.opt.StateDir, data)
	if err != nil {
		return false, err
	}
	var stderr bytes.Buffer
	check := exec.Command(a.opt.SingBox, "check", "-c", tmp)
	check.Stderr = &stderr
	if err := check.Run(); err != nil {
		os.Remove(tmp)
		if _, isExit := err.(*exec.ExitError); !isExit {
			return false, fmt.Errorf("sing-box check: %w", err)
		}
		a.rejected = etag
		a.logf("version %s rejected by sing-box check, keeping current config: %s", etag, strings.TrimSpace(stderr.String()))
		return false, nil
	}
	if err := os.Rename(tmp, a.candidateCopy()); err != nil { // --config is untouched until the reload
		os.Remove(tmp)
		return false, err
	}
	a.installed, a.secret, a.marker = etag, secret, marker
	a.applyState, a.applyError, a.retryAfter = statePending, "installed, not yet reloaded", time.Time{}
	a.logf("wrote config version %s", etag)
	return true, nil
}

// writeTemp writes data to a new 0600 file in dir, synced to disk, and returns its path.
func writeTemp(dir string, data []byte) (string, error) {
	f, err := os.CreateTemp(dir, "tmp-*.json")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Chmod(0o600); err != nil && !isWindows() {
		f.Close()
		os.Remove(name)
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil && cerr != nil {
		err = cerr
	}
	if err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// place atomically makes dst a copy of src (temp file in dst's directory, then rename).
func place(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(dst)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(filepath.Dir(abs), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, abs); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// putCandidate stages exactly the installed candidate at --config. The first time this process writes --config,
// whatever was there before is kept as the working configuration to fall back to.
func (a *Agent) putCandidate() error {
	if a.onDisk == a.marker {
		return nil
	}
	if a.onDisk == "" && a.applied == "" && isRegular(a.opt.Config) {
		if err := place(a.opt.Config, a.previousCopy()); err != nil {
			return err
		}
		a.keptPrevious = true
		a.logf("kept the existing %s as the fallback configuration", a.opt.Config)
	}
	if err := place(a.candidateCopy(), a.opt.Config); err != nil {
		return err
	}
	a.onDisk = a.marker
	return nil
}

// restoreWorking puts the working configuration back at --config: the last confirmed version or, before this
// process confirmed anything, the --config found at start. False when there is neither.
func (a *Agent) restoreWorking() bool {
	var src, generation, what string
	switch {
	case a.applied != "":
		src, generation, what = a.confirmedCopy(), a.appliedMarker, "config version "+a.applied
	case a.keptPrevious:
		src, generation, what = a.previousCopy(), previousGeneration, "the configuration found at start"
	default:
		return false
	}
	if a.onDisk != generation {
		if err := place(src, a.opt.Config); err != nil {
			a.logf("could not restore %s: %v", what, err)
			return false
		}
		a.onDisk = generation
		a.logf("restored %s at %s", what, a.opt.Config)
	}
	return true
}

// loadedEvidence asks the running sing-box whether it serves the installed candidate (or the confirmed version):
// evidenceLoaded, evidenceOther (sing-box answered without the marker) or "" (no usable answer).
func (a *Agent) loadedEvidence(version string) string {
	secret, marker := a.secret, a.marker
	if version != versionCandidate {
		secret, marker = a.appliedSecret, a.appliedMarker
	}
	req, err := http.NewRequest("GET", "http://"+a.confirmAddress+"/proxies", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := a.confirm.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return evidenceOther // sing-box refusing this candidate's secret
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, confirmMaxBytes+1))
	if err != nil || resp.StatusCode != 200 || len(body) > confirmMaxBytes {
		return ""
	}
	var answer map[string]any
	if json.Unmarshal(body, &answer) != nil {
		return ""
	}
	proxies, ok := answer["proxies"].(map[string]any)
	if !ok {
		return "" // not sing-box's answer
	}
	if _, has := proxies[marker]; marker != "" && has {
		return evidenceLoaded
	}
	return evidenceOther
}

// awaitConfirmation: (true, nil) once sing-box serves version; (false, nil) when it never answered within
// --confirm-timeout; errNotLoaded when it keeps serving another configuration or exits.
func (a *Agent) awaitConfirmation(version string) (bool, error) {
	deadline := time.Now().Add(time.Duration(a.opt.ConfirmTimeout * float64(time.Second)))
	evidence := ""
	for {
		if a.opt.Run && !a.child.alive() {
			return false, errNotLoaded{fmt.Sprintf("sing-box exited with %d", a.child.exitCode())}
		}
		evidence = a.loadedEvidence(version)
		if evidence == evidenceLoaded {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if evidence == evidenceOther {
		return false, errNotLoaded{"the running sing-box still serves another configuration"}
	}
	return false, nil
}

// reload starts sing-box or asks it to load --config. It says nothing about whether it did.
func (a *Agent) reload() error {
	a.lastReload = time.Now()
	if a.opt.Run {
		if a.child == nil || !a.child.alive() {
			c, err := startChild(a.opt.SingBox, a.opt.Config, a.opt.StateDir, a.output)
			if err != nil {
				return err
			}
			a.child = c
			a.logf("started sing-box pid %d", c.pid())
			return nil
		}
		if a.restartReload() {
			// No SIGHUP (Windows) or --run-reload restart: stop the child and start it again on the new file.
			old := a.child.pid()
			a.child.stop(10 * time.Second)
			c, err := startChild(a.opt.SingBox, a.opt.Config, a.opt.StateDir, a.output)
			if err != nil {
				return err
			}
			a.child = c
			a.logf("restarted sing-box (pid %d -> %d) to load the new config", old, c.pid())
			return nil
		}
		if err := a.child.hangup(); err != nil {
			return err
		}
		a.logf("sent SIGHUP to sing-box")
		return nil
	}
	if a.opt.ReloadCmd != "" {
		if err := runCommand(a.opt.ReloadCmd, a.output); err != nil {
			return fmt.Errorf("%s: %w", a.opt.ReloadCmd, err)
		}
		a.logf("ran %s", a.opt.ReloadCmd)
	}
	return nil
}

func (a *Agent) restartReload() bool {
	if a.opt.RunReload != "" {
		return a.opt.RunReload == "restart"
	}
	return !canHangup
}

// confirmed: sing-box proved it runs the installed candidate. If --config was rolled back meanwhile (a reload
// that looked failed took effect late), that exact candidate goes back first, so a restart keeps it.
func (a *Agent) confirmed() (bool, error) {
	if a.onDisk != a.marker {
		if err := place(a.candidateCopy(), a.opt.Config); err != nil {
			return false, err
		}
		a.onDisk = a.marker
	}
	if err := place(a.candidateCopy(), a.confirmedCopy()); err != nil {
		return false, err
	}
	a.applied, a.appliedSecret, a.appliedMarker = a.installed, a.secret, a.marker
	a.applyState, a.applyError = "", ""
	a.logf("sing-box confirmed running config version %s", a.applied)
	a.saveConfirmed()
	return true, nil
}

// confirmedState is confirmed-state.json: what the running sing-box was last proved to serve, so that a restarted
// agent (an update, a crash) can adopt it instead of reloading sing-box and dropping its connections.
type confirmedState struct {
	ETag   string `json:"etag"`
	Secret string `json:"secret"`
	Marker string `json:"marker"`
}

func (a *Agent) confirmedStatePath() string {
	return filepath.Join(a.opt.StateDir, "confirmed-state.json")
}

func (a *Agent) saveConfirmed() {
	data, _ := json.Marshal(confirmedState{ETag: a.applied, Secret: a.appliedSecret, Marker: a.appliedMarker})
	tmp, err := writeTemp(a.opt.StateDir, data)
	if err == nil {
		err = os.Rename(tmp, a.confirmedStatePath())
	}
	if err != nil {
		os.Remove(tmp)
		a.logf("could not record the confirmed state (a restart will reload sing-box): %v", err)
	}
}

// adoptConfirmed runs once at start. When sing-box (a separate service: --reload-cmd) still serves the confirmed
// copy that --config holds, the agent takes it over as applied and the next sync is a 304 with no reload. With --run
// the child did not survive the previous agent, so there is nothing to adopt.
func (a *Agent) adoptConfirmed() {
	if a.opt.Run {
		return
	}
	data, err := os.ReadFile(a.confirmedStatePath())
	if err != nil {
		return
	}
	var c confirmedState
	if json.Unmarshal(data, &c) != nil || c.ETag == "" || c.Secret == "" || !strings.HasPrefix(c.Marker, markerPrefix) {
		return
	}
	live, err1 := os.ReadFile(a.opt.Config)
	saved, err2 := os.ReadFile(a.confirmedCopy())
	if err1 != nil || err2 != nil || !bytes.Equal(live, saved) {
		return
	}
	a.appliedSecret, a.appliedMarker = c.Secret, c.Marker
	if a.loadedEvidence(versionConfirmedSnapshot) != evidenceLoaded {
		a.appliedSecret, a.appliedMarker = "", ""
		return
	}
	a.applied, a.installed, a.secret, a.marker, a.onDisk = c.ETag, c.ETag, c.Secret, c.Marker, c.Marker
	a.logf("sing-box is running confirmed config version %s; adopted it without a reload", c.ETag)
}

// attachUpdater connects managed updates to this agent's control-plane client.
func (a *Agent) attachUpdater(u *updater) {
	a.update = u
	u.cp = func(path string) (int, []byte, error) {
		status, _, body, err := a.get(path, "")
		return status, body, err
	}
	u.download = a.fetch
}

// fetch streams a control-plane GET (with the token, no redirects) into w, refusing more than limit bytes.
func (a *Agent) fetch(path string, w io.Writer, limit int64) error {
	req, err := http.NewRequest("GET", a.opt.CP+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	resp, err := a.download.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n != limit {
		return fmt.Errorf("received %d bytes, the signed record says %d", n, limit)
	}
	return nil
}

// fail records a definitive failure for the candidate: the working configuration goes back on disk, and with
// --run an exited sing-box is started once on it.
func (a *Agent) fail(reason string) {
	a.applyState, a.applyError = stateFailed, reason
	a.logf("version %s not running, will retry: %s", a.installed, reason)
	restored := a.restoreWorking()
	if a.opt.Run && a.child != nil && !a.child.alive() {
		a.retryAfter = time.Now().Add(failedOutageRetry)
		if restored {
			a.recoverWorking()
		}
	}
}

// recoverWorking (--run): start sing-box on the restored working configuration, once.
func (a *Agent) recoverWorking() {
	what := "the configuration found at start"
	if a.applied != "" {
		what = "version " + a.applied
	}
	err := a.reload()
	ok := false
	if err == nil && a.applied != "" {
		ok, err = a.awaitConfirmation(versionConfirmedSnapshot)
	}
	if err != nil {
		a.applyError += fmt.Sprintf("; recovery on %s failed: %v", what, err)
		a.logf("%s", a.applyError)
		return
	}
	result := "started, not confirmed"
	if ok {
		result = "confirmed"
	}
	a.logf("recovery on %s: %s", what, result)
}

// restart (--run): start sing-box again after it exited and wait for it to confirm what --config holds.
func (a *Agent) restart() {
	version := ""
	switch {
	case !a.settled() && a.onDisk == a.marker:
		version = versionCandidate
	case a.applied != "" && a.onDisk == a.appliedMarker:
		version = versionConfirmedSnapshot
	}
	err := a.reload()
	loaded := false
	if err == nil && version != "" {
		loaded, err = a.awaitConfirmation(version)
	}
	if err != nil {
		if version == versionCandidate {
			a.fail("restart failed: " + err.Error())
		} else {
			a.applyError = "restart failed: " + err.Error()
			a.logf("%s", a.applyError)
		}
		return
	}
	if loaded && version == versionCandidate {
		if _, err := a.confirmed(); err != nil {
			a.logf("could not record the confirmed version: %v", err)
		}
	}
}

// apply reloads until the running sing-box confirms the installed version; only then is it reported applied.
func (a *Agent) apply() (bool, error) {
	if a.installed == "" || a.settled() {
		return false, nil
	}
	if (a.applyState == stateFailed || a.applyState == stateUnknown) && a.loadedEvidence(versionCandidate) == evidenceLoaded {
		return a.confirmed() // an earlier reload took effect late
	}
	now := time.Now()
	if a.applyState == stateUnknown && now.Sub(a.lastReload) < unknownRetry {
		return false, nil
	}
	if a.applyState == stateFailed && now.Before(a.retryAfter) {
		return false, nil
	}
	if err := a.putCandidate(); err != nil {
		return false, err
	}
	err := a.reload()
	loaded := false
	if err == nil {
		loaded, err = a.awaitConfirmation(versionCandidate)
	}
	if err != nil {
		a.fail("reload failed: " + err.Error())
		return false, nil
	}
	if !loaded { // inconclusive: the candidate may be running, so it stays at --config
		a.applyState = stateUnknown
		a.applyError = "reload not confirmed: no answer from sing-box at " + a.confirmAddress
		a.logf("version %s: %s", a.installed, a.applyError)
		return false, nil
	}
	return a.confirmed()
}

// Cycle runs one sync, apply and heartbeat round (what --once does), then the update check. It returns
// errRestartForUpdate when the agent must exit for a new (or restored) release.
func (a *Agent) Cycle() error {
	if err := a.syncAndApply(); err != nil {
		a.logf("sync failed: %v", err)
	}
	if a.xtcp != nil { // independent of sing-box: a failure here never holds back the sing-box sync, or the reverse
		if err := a.xtcp.Sync(); err != nil {
			a.logf("xtcp sync failed: %v", err)
		}
	}
	err := a.report()
	if err != nil {
		a.logf("report failed: %v", err)
	}
	if a.update != nil {
		return a.update.tick(a, err)
	}
	return nil
}

func (a *Agent) syncAndApply() error {
	if err := a.syncIPs(); err != nil {
		return err
	}
	if _, err := a.syncConfig(); err != nil {
		return err
	}
	applied, err := a.apply()
	if err != nil {
		return err
	}
	if !applied && a.opt.Run && a.child != nil && !a.child.alive() {
		a.logf("sing-box exited with %d, restarting", a.child.exitCode())
		a.restart()
	}
	return nil
}

// Loop runs until --once is done (or forever).
func (a *Agent) Loop() error {
	if err := os.MkdirAll(a.opt.StateDir, 0o700); err != nil {
		return err
	}
	if a.opt.Run {
		cleanupStaleChild(a.opt.StateDir, a.opt.SingBox, a.logf)
	}
	if a.xtcp != nil {
		if err := a.xtcp.load(); err != nil {
			return fmt.Errorf("xtcp state: %w", err)
		}
	}
	a.adoptConfirmed()
	a.startUsage()
	for {
		if err := a.Cycle(); err != nil {
			return err
		}
		if a.opt.Once {
			return nil
		}
		time.Sleep(time.Duration(a.opt.Interval * float64(time.Second)))
	}
}

// startUsage sets up per-device traffic collection. Problems leave the agent fully working without it.
func (a *Agent) startUsage() {
	if a.opt.Once || a.opt.UsageAPI == "" {
		return
	}
	collector, err := newUsageCollector(a)
	if err != nil {
		a.logf("usage collection disabled: %v", err)
		return
	}
	if state, detail := collector.status(); state == usageUnavailable {
		a.logf("usage collection unavailable: %s", detail)
	}
	ctx, cancel := context.WithCancel(context.Background())
	a.usage, a.stopUsage = collector, cancel
	collector.Start(ctx)
}

// Close stops a --run child (tests; the service keeps it until the agent exits).
func (a *Agent) Close() {
	if a.stopUsage != nil {
		a.stopUsage()
		a.usage.Wait() // the final usage report and state write finish before the caller moves on
	}
	if a.child != nil && a.child.alive() {
		a.child.stop(5 * time.Second)
	}
}
