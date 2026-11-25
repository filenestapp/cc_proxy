package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// The test binary doubles as frpc's command line (CCPROXY_FAKE_FRPC=1):
//
//	verify -c FILE      fails when FILE contains REJECT_ME, echoing that line (with its secret) like a parser would
//	frpc-restart FLAG   stands in for systemctl restart: asks the in-process fake frpc to restart and waits for it
func fakeFrpcCommand(args []string) int {
	switch args[0] {
	case "verify":
		data, err := os.ReadFile(args[2])
		if err != nil {
			return 2
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "REJECT_ME") {
				fmt.Fprintf(os.Stderr, "decode proxy: invalid line %q\n", line)
				return 1
			}
		}
		fmt.Println("frpc: the configuration file syntax is ok")
		return 0
	case "frpc-restart":
		if err := os.WriteFile(args[1], nil, 0o600); err != nil {
			return 2
		}
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(args[1]); os.IsNotExist(err) {
				return 0
			}
		}
		return 3
	}
	return 2
}

// fakeFrpc models the frpc 0.72 behaviour the agent depends on: the admin API (basic auth) exists only when the
// file it started with sets webServer; /api/reload re-reads the proxies but not the frps settings; a restart
// re-reads everything; /api/status lists the loaded proxies. It counts proxy (re)starts per name.
type fakeFrpc struct {
	t                 *testing.T
	conf, restartFlag string

	mu        sync.Mutex
	srv       *http.Server
	user, pw  string
	common    string
	proxies   map[string]string // name -> secretKey line (identity of the running proxy)
	starts    map[string]int
	reloads   int
	restarts  int
	failing   map[string]string // name -> registration error
	deaf      bool              // reload answers 200 without loading anything
	stop      chan struct{}
	adminAddr string
}

var (
	fakeProxyRe = regexp.MustCompile(`(?m)^\[\[proxies\]\]\nname = "([^"]+)"\ntype = "xtcp"\nsecretKey = "([^"]+)"`)
	fakeWebRe   = regexp.MustCompile(`(?m)^webServer\.(port|password|user) = "?([^"\n]+)"?$`)
)

func newFakeFrpc(t *testing.T, conf string) *fakeFrpc {
	f := &fakeFrpc{t: t, conf: conf, restartFlag: conf + ".restart", proxies: map[string]string{}, starts: map[string]int{},
		failing: map[string]string{}, stop: make(chan struct{})}
	f.start()
	go func() {
		for {
			select {
			case <-f.stop:
				return
			case <-time.After(10 * time.Millisecond):
			}
			if _, err := os.Stat(f.restartFlag); err == nil {
				f.restart()
				os.Remove(f.restartFlag)
			}
		}
	}()
	t.Cleanup(func() { close(f.stop); f.shutdown() })
	return f
}

func (f *fakeFrpc) shutdown() {
	f.mu.Lock()
	srv := f.srv
	f.srv = nil
	f.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

func (f *fakeFrpc) restart() {
	f.shutdown()
	f.mu.Lock()
	f.restarts++
	f.proxies = map[string]string{}
	f.mu.Unlock()
	f.start()
}

// start loads the whole file and opens the admin API when the file asks for it.
func (f *fakeFrpc) start() {
	data, _ := os.ReadFile(f.conf)
	text := string(data)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.common = commonSection(text)
	f.load(text)
	web := map[string]string{}
	for _, m := range fakeWebRe.FindAllStringSubmatch(text, -1) {
		web[m[1]] = m[2]
	}
	if web["port"] == "" {
		return // an frpc installed before the admin API
	}
	f.user, f.pw = web["user"], web["password"]
	ln, err := net.Listen("tcp", "127.0.0.1:"+web["port"])
	if err != nil {
		f.t.Errorf("fake frpc admin listen: %v", err)
		return
	}
	f.adminAddr = ln.Addr().String()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/", f.serve)
	f.srv = &http.Server{Handler: mux}
	go f.srv.Serve(ln)
}

// load replaces the running proxy set; unchanged proxies keep running (are not restarted).
func (f *fakeFrpc) load(text string) {
	next := map[string]string{}
	for _, m := range fakeProxyRe.FindAllStringSubmatch(text, -1) {
		next[m[1]] = m[2]
		if f.proxies[m[1]] != m[2] {
			f.starts[m[1]]++
		}
	}
	f.proxies = next
}

func (f *fakeFrpc) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, ok := r.BasicAuth(); !ok || u != f.user || p != f.pw {
		w.WriteHeader(401)
		return
	}
	switch r.URL.Path {
	case "/api/reload":
		f.reloads++
		data, err := os.ReadFile(f.conf)
		if err != nil || strings.Contains(string(data), "bogus = =") {
			w.WriteHeader(400)
			fmt.Fprint(w, `{"Code":400,"Msg":"invalid argument"}`)
			return
		}
		if !f.deaf {
			f.load(string(data)) // frps settings are not reloaded, as in frpc
		}
	case "/api/status":
		var list []map[string]string
		for name := range f.proxies {
			status, err := "running", ""
			if e, bad := f.failing[name]; bad {
				status, err = "start error", e
			}
			list = append(list, map[string]string{"name": name, "type": "xtcp", "status": status, "err": err})
		}
		out := map[string]any{}
		if len(list) > 0 {
			out["xtcp"] = list
		}
		json.NewEncoder(w).Encode(out)
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeFrpc) snapshot() (reloads, restarts int, starts map[string]int, names []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	starts = map[string]int{}
	for k, v := range f.starts {
		starts[k] = v
	}
	for name := range f.proxies {
		names = append(names, name)
	}
	return f.reloads, f.restarts, starts, names
}

func testCA(t *testing.T) string {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// xtcpEnv is an agent with XTCP sync, its fake control plane and a fake frpc running the installed file.
type xtcpEnv struct {
	t     *testing.T
	cp    *fakeCP
	a     *Agent
	frpc  *fakeFrpc
	dir   string
	ca    string
	token string // the frps token in the rendered configuration
	gen   int64
}

// render is what the control plane serves: frps settings, then one xtcp proxy per mapping.
func (e *xtcpEnv) render(token string, proxies ...string) *xtcpDesired {
	var b strings.Builder
	fmt.Fprintf(&b, "# frpc for CC Proxy exit host test\nserverAddr = \"127.0.0.1\"\nserverPort = 7003\nloginFailExit = false\n\n"+
		"auth.method = \"token\"\nauth.token = \"%s\"\n\ntransport.tls.enable = true\ntransport.tls.trustedCaFile = '%s'\n"+
		"transport.tls.serverName = \"frps\"\n\nlog.to = \"console\"\nlog.level = \"info\"\n", token, e.a.opt.FrpcCA)
	d := &xtcpDesired{CAPEM: e.ca}
	for _, spec := range proxies { // "name:port:key"
		parts := strings.Split(spec, ":")
		fmt.Fprintf(&b, "\n[[proxies]]\nname = \"%s\"\ntype = \"xtcp\"\nsecretKey = \"%s\"\nlocalIP = \"127.0.0.1\"\nlocalPort = %s\n", parts[0], parts[2], parts[1])
		var port int
		fmt.Sscan(parts[1], &port)
		sum := sha256.Sum256([]byte(spec))
		d.Proxies = append(d.Proxies, xtcpProxy{Name: parts[0], Port: port, Digest: hex.EncodeToString(sum[:8])})
	}
	d.FrpcTOML = b.String()
	sum := sha256.Sum256([]byte(d.FrpcTOML + d.CAPEM))
	d.SHA256 = hex.EncodeToString(sum[:])
	return d
}

// publish makes the control plane serve a new generation.
func (e *xtcpEnv) publish(d *xtcpDesired) *xtcpDesired {
	e.gen += 10 // generations come from a global sequence: gaps are normal
	d.Generation = e.gen
	e.cp.mu.Lock()
	e.cp.xtcp = d
	e.cp.mu.Unlock()
	return d
}

const (
	primary = "ccproxy-t-direct:20443:primary-secret-0123456789"
	second  = "ccproxy-t-direct-20444:20444:second-secret-0123456789"
	third   = "ccproxy-t-direct-20444:20444:other-user-secret-0123456789"
)

// newXTCPEnv installs generation 1 (the primary proxy) the way the installer does. legacy leaves out the admin
// block, like a host installed before this change.
func newXTCPEnv(t *testing.T, legacy bool, mutate func(*Options)) *xtcpEnv {
	t.Setenv("CCPROXY_FAKE_FRPC", "1")
	cp := newFakeCP(t)
	e := &xtcpEnv{t: t, cp: cp, ca: testCA(t), token: "frps-token-0123456789abcdef"}
	exe, _ := os.Executable()
	etc := t.TempDir()
	a, dir := newTestAgent(t, cp, func(o *Options) {
		o.FrpcBin, o.FrpcConfig, o.FrpcCA = exe, filepath.Join(etc, "frpc.toml"), filepath.Join(etc, "frp-ca.pem")
		o.FrpcAdmin, o.FrpcConfirmTimeout = freePort(t), 1.5
		o.FrpcRestartCmd = exe + " frpc-restart " + filepath.Join(etc, "frpc.toml.restart")
		if mutate != nil {
			mutate(o)
		}
	})
	e.a, e.dir = a, dir
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := a.xtcp.load(); err != nil {
		t.Fatal(err)
	}
	a.xtcp.poll = 20 * time.Millisecond
	d := e.publish(e.render(e.token, primary))
	installed := d.FrpcTOML
	if !legacy { // exit.sh / exit.ps1 insert the same admin block
		installed = spliceAdmin(installed, a.xtcp.adminBlock())
	}
	os.WriteFile(a.opt.FrpcConfig, []byte(installed), 0o600)
	os.WriteFile(a.opt.FrpcCA, []byte(e.ca), 0o644)
	e.frpc = newFakeFrpc(t, a.opt.FrpcConfig)
	return e
}

func (e *xtcpEnv) xtcpReport() map[string]any {
	e.t.Helper()
	r, _ := e.cp.last()["xtcp"].(map[string]any)
	if r == nil {
		e.t.Fatalf("the heartbeat has no xtcp report: %v", e.cp.last())
	}
	return r
}

func (e *xtcpEnv) wantReport(state string, generation, applied int64) map[string]any {
	e.t.Helper()
	r := e.xtcpReport()
	if r["state"] != state || r["generation"] != float64(generation) || r["applied_generation"] != float64(applied) {
		e.t.Fatalf("xtcp report: want %s %d (applied %d), got %v", state, generation, applied, r)
	}
	return r
}

func (e *xtcpEnv) live() string {
	data, _ := os.ReadFile(e.a.opt.FrpcConfig)
	return string(data)
}

func TestXTCPFreshInstallIsConfirmedWithoutReload(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.a.Cycle()
	r := e.wantReport(xtcpApplied, e.gen, e.gen)
	reloads, restarts, _, _ := e.frpc.snapshot()
	if reloads != 0 || restarts != 0 {
		t.Fatalf("an installed, current file must not be reloaded: %d reloads, %d restarts", reloads, restarts)
	}
	if proxies, _ := r["applied_proxies"].([]any); len(proxies) != 1 {
		t.Fatalf("applied proxies %v", r["applied_proxies"])
	}
	if e.cp.last()["apply_state"] != "confirmed" {
		t.Fatal("sing-box sync is unaffected")
	}
	if st, _ := os.Stat(filepath.Join(e.dir, frpcAdminSecret)); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatal("the admin password is kept in a 0600 file")
	}
}

func TestXTCPSecondPortIsHotReloadedAndPrimaryKeepsRunning(t *testing.T) {
	e := newXTCPEnv(t, true, nil) // installed before the admin API: one restart to adopt it
	e.a.Cycle()
	e.wantReport(xtcpApplied, e.gen, e.gen)
	if _, restarts, _, _ := e.frpc.snapshot(); restarts != 1 {
		t.Fatalf("a legacy frpc is restarted once to load the admin API, got %d", restarts)
	}
	if !strings.Contains(e.live(), "webServer.addr = \"127.0.0.1\"") {
		t.Fatal("the live file has the admin API")
	}
	first := e.gen
	_, _, startsBefore, _ := e.frpc.snapshot()

	// Assign a second user on the same IP: hot reload, the primary proxy is not restarted.
	d := e.publish(e.render(e.token, primary, second))
	e.a.Cycle()
	r := e.wantReport(xtcpApplied, d.Generation, d.Generation)
	reloads, restarts, starts, names := e.frpc.snapshot()
	if reloads != 1 || restarts != 1 || len(names) != 2 {
		t.Fatalf("second port: %d reloads, %d restarts, proxies %v", reloads, restarts, names)
	}
	if starts["ccproxy-t-direct"] != startsBefore["ccproxy-t-direct"] {
		t.Fatal("the primary proxy was restarted by the hot reload")
	}
	if r["applied_sha256"] != d.SHA256 || first == d.Generation {
		t.Fatalf("report %v", r)
	}

	// The same generation again: nothing is reloaded.
	for i := 0; i < 3; i++ {
		e.a.Cycle()
	}
	if again, _, _, _ := e.frpc.snapshot(); again != reloads {
		t.Fatalf("an unchanged generation was reloaded (%d -> %d)", reloads, again)
	}

	// Reassign the second port to another user (new key, same name), then release it.
	e.publish(e.render(e.token, primary, third))
	e.a.Cycle()
	e.wantReport(xtcpApplied, e.gen, e.gen)
	if _, _, s, _ := e.frpc.snapshot(); s["ccproxy-t-direct-20444"] != starts["ccproxy-t-direct-20444"]+1 || s["ccproxy-t-direct"] != startsBefore["ccproxy-t-direct"] {
		t.Fatalf("reassignment restarts only the moved proxy: %v", s)
	}
	e.publish(e.render(e.token, primary))
	e.a.Cycle()
	e.wantReport(xtcpApplied, e.gen, e.gen)
	if _, _, s, names := e.frpc.snapshot(); len(names) != 1 || names[0] != "ccproxy-t-direct" || s["ccproxy-t-direct"] != startsBefore["ccproxy-t-direct"] {
		t.Fatalf("release removes the retired proxy and keeps the primary: %v %v", names, s)
	}
}

func TestXTCPFailedActivationRestoresTheWorkingMappings(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.a.Cycle()
	good := e.gen
	working := e.live()
	_, _, startsBefore, _ := e.frpc.snapshot()

	// frps refuses the new proxy (for example the name is taken): not confirmed, previous file back and reloaded.
	e.frpc.mu.Lock()
	e.frpc.failing["ccproxy-t-direct-20444"] = "proxy [ccproxy-t-direct-20444] already exists"
	e.frpc.mu.Unlock()
	d := e.publish(e.render(e.token, primary, second))
	e.a.Cycle()
	r := e.wantReport(xtcpFailed, d.Generation, good)
	if msg := fmt.Sprint(r["error"]); !strings.Contains(msg, "ccproxy-t-direct-20444 start error") || !strings.Contains(msg, "already exists") {
		t.Fatalf("the error names the proxy and the cause: %q", msg)
	}
	if e.live() != working {
		t.Fatal("the working configuration was not restored")
	}
	if _, _, s, names := e.frpc.snapshot(); len(names) != 1 || s["ccproxy-t-direct"] != startsBefore["ccproxy-t-direct"] {
		t.Fatalf("after the restore only the primary runs, never restarted: %v %v", names, s)
	}

	// Within the retry delay nothing happens; after it, the generation is tried again and succeeds.
	reloads, _, _, _ := e.frpc.snapshot()
	e.a.Cycle()
	if again, _, _, _ := e.frpc.snapshot(); again != reloads {
		t.Fatal("retried before the retry delay")
	}
	e.frpc.mu.Lock()
	delete(e.frpc.failing, "ccproxy-t-direct-20444")
	e.frpc.mu.Unlock()
	e.a.xtcp.now = func() time.Time { return time.Now().Add(xtcpRetry + time.Second) }
	e.a.Cycle()
	e.wantReport(xtcpApplied, d.Generation, d.Generation)
}

func TestXTCPFetchedButInactiveIsNotConfirmed(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.a.Cycle()
	good, working := e.gen, e.live()
	e.frpc.mu.Lock()
	e.frpc.deaf = true // reload answers 200 but the running frpc keeps its old proxies
	e.frpc.mu.Unlock()
	d := e.publish(e.render(e.token, primary, second))
	e.a.Cycle()
	r := e.wantReport(xtcpFailed, d.Generation, good)
	if !strings.Contains(fmt.Sprint(r["error"]), "ccproxy-t-direct-20444 not loaded") || e.live() != working {
		t.Fatalf("a reload that loaded nothing must fail and restore: %v", r["error"])
	}
}

func TestXTCPMalformedAndRejectedCandidatesNeverTouchFrpc(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.a.Cycle()
	good, working := e.gen, e.live()

	bad := e.render(e.token, primary, "ccproxy-t-direct-20444:20444:REJECT_ME-leaky-secret-value")
	e.publish(bad)
	e.a.Cycle()
	r := e.wantReport(xtcpFailed, e.gen, good)
	msg := fmt.Sprint(r["error"])
	if !strings.Contains(msg, "frpc verify") || strings.Contains(msg, "REJECT_ME-leaky-secret-value") {
		t.Fatalf("a rejection is reported without the secret: %q", msg)
	}
	reloads, restarts, _, _ := e.frpc.snapshot()
	if e.live() != working || reloads != 0 || restarts != 0 {
		t.Fatal("a rejected candidate touched frpc")
	}
	e.a.Cycle() // the same generation is not tried again
	if again, _, _, _ := e.frpc.snapshot(); again != 0 {
		t.Fatal("a rejected generation was retried")
	}

	malformedCA := e.render(e.token, primary, second)
	malformedCA.CAPEM = "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"
	e.publish(malformedCA)
	e.a.Cycle()
	if r := e.wantReport(xtcpFailed, e.gen, good); !strings.Contains(fmt.Sprint(r["error"]), "CA") {
		t.Fatalf("a malformed CA is rejected: %v", r["error"])
	}
	ca, _ := os.ReadFile(e.a.opt.FrpcCA)
	if string(ca) != e.ca || e.live() != working {
		t.Fatal("a malformed CA replaced the working one")
	}

	// A newer, valid generation is applied normally afterwards.
	e.publish(e.render(e.token, primary, second))
	e.a.Cycle()
	e.wantReport(xtcpApplied, e.gen, e.gen)
}

func TestXTCPFrpsSettingsChangeRestartsFrpc(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.a.Cycle()
	e.publish(e.render("rotated-frps-token-0123456789", primary))
	e.a.Cycle()
	e.wantReport(xtcpApplied, e.gen, e.gen)
	reloads, restarts, _, _ := e.frpc.snapshot()
	if restarts != 1 || reloads != 0 {
		t.Fatalf("frpc reloads proxies only; a token change needs a restart: %d reloads, %d restarts", reloads, restarts)
	}
	e.frpc.mu.Lock()
	common := e.frpc.common
	e.frpc.mu.Unlock()
	if !strings.Contains(common, "rotated-frps-token") {
		t.Fatal("the restarted frpc runs the new frps settings")
	}
}

func TestXTCPAgentRestartAndOfflineCatchUp(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.a.Cycle()
	e.publish(e.render(e.token, primary, second))
	e.a.Cycle()
	confirmed := e.gen
	reloads, _, _, _ := e.frpc.snapshot()

	// A restarted agent remembers the confirmed generation: no reload, and it reports it applied at once.
	e.a.Close() // stops its sing-box child, which holds the confirmation port
	b, err := NewAgent(e.a.opt, testToken, t.Logf, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(b.Close)
	if err := b.xtcp.load(); err != nil {
		t.Fatal(err)
	}
	b.xtcp.poll = 20 * time.Millisecond
	b.Cycle()
	e.a = b
	e.wantReport(xtcpApplied, confirmed, confirmed)
	if again, _, _, _ := e.frpc.snapshot(); again != reloads {
		t.Fatal("a restarted agent reloaded an unchanged generation")
	}

	// Offline while two more changes are committed: after reconnecting it goes straight to the latest.
	e.cp.mu.Lock()
	e.cp.offline = true
	e.cp.mu.Unlock()
	e.publish(e.render(e.token, primary, third))
	b.Cycle()
	latest := e.publish(e.render(e.token, primary))
	b.Cycle()
	e.cp.mu.Lock()
	e.cp.offline = false
	e.cp.mu.Unlock()
	b.Cycle()
	e.wantReport(xtcpApplied, latest.Generation, latest.Generation)
	if now, _, _, names := e.frpc.snapshot(); now != reloads+1 || len(names) != 1 {
		t.Fatalf("catch-up applies only the latest generation: %d reloads, proxies %v", now-reloads, names)
	}
}

func TestXTCPOldControlPlaneAndPublicHost(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.cp.mu.Lock()
	e.cp.noXTCP = true
	e.cp.mu.Unlock()
	e.a.Cycle()
	e.a.Cycle()
	if _, has := e.cp.last()["xtcp"]; has || e.cp.last()["apply_state"] != "confirmed" {
		t.Fatalf("against an old control plane the heartbeat is unchanged: %v", e.cp.last())
	}
	if e.cp.xtcpGets != 1 {
		t.Fatalf("a 404 stops XTCP polling, got %d requests", e.cp.xtcpGets)
	}

	f := newXTCPEnv(t, false, nil)
	f.cp.mu.Lock()
	f.cp.xtcp = nil // a public-entry host
	f.cp.mu.Unlock()
	f.a.Cycle()
	if _, has := f.cp.last()["xtcp"]; has {
		t.Fatal("a public-entry host reports no xtcp state")
	}
	if reloads, restarts, _, _ := f.frpc.snapshot(); reloads+restarts != 0 {
		t.Fatal("frpc on a public-entry host is left to the installer")
	}
}

func TestXTCPOptionsComeFromTheInstallation(t *testing.T) {
	cp := newFakeCP(t)
	base := Options{CP: cp.srv.URL, ConfirmAPI: "127.0.0.1:9095", FrpcConfig: "/etc/ccproxy-exit/frpc.toml",
		FrpcBin: "/opt/ccproxy-exit/bin/frpc", FrpcCA: "/etc/ccproxy-exit/frp-ca.pem",
		FrpcRestartCmd: "/opt/ccproxy-exit/libexec/frpc-ctl restart", FrpcAdmin: "127.0.0.1:9097"}
	if _, err := NewAgent(base, testToken, t.Logf, nil); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Options){
		"no restart command": func(o *Options) { o.FrpcRestartCmd = "" },
		"admin off loopback": func(o *Options) { o.FrpcAdmin = "0.0.0.0:9097" },
		"admin on confirm":   func(o *Options) { o.FrpcAdmin = "127.0.0.1:9095" },
		"relative config":    func(o *Options) { o.FrpcConfig = "frpc.toml" },
	} {
		o := base
		mutate(&o)
		if _, err := NewAgent(o, testToken, t.Logf, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSpliceAdminMatchesTheInstallers(t *testing.T) {
	toml := "a = 1\n\n[[proxies]]\nname = \"p\"\n\n[[proxies]]\nname = \"q\"\n"
	got := spliceAdmin(toml, "B\n\n")
	if got != "a = 1\n\nB\n\n[[proxies]]\nname = \"p\"\n\n[[proxies]]\nname = \"q\"\n" {
		t.Fatalf("splice: %q", got)
	}
	if commonSection(got) != "a = 1\nB" || commonSection("# c\r\na = 1\r\n") != "a = 1" {
		t.Fatalf("common section: %q", commonSection(got))
	}
}

// exit.ps1 passes the restart command with the PowerShell path in single quotes: the agent's command splitting
// treats a backslash outside quotes as an escape, so an unquoted Windows path would lose its separators.
func TestWindowsFrpcRestartCommandSplits(t *testing.T) {
	line := `'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -NoProfile -NonInteractive -Command Stop-ScheduledTask -TaskName CCProxyExitFrpc; Start-ScheduledTask -TaskName CCProxyExitFrpc`
	argv, err := splitCommand(line)
	if err != nil || argv[0] != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` || argv[4] != "Stop-ScheduledTask" ||
		strings.Join(argv[4:], " ") != "Stop-ScheduledTask -TaskName CCProxyExitFrpc; Start-ScheduledTask -TaskName CCProxyExitFrpc" {
		t.Fatalf("split: %q %v", argv, err)
	}
}

func TestXTCPInstallsOnlyTheRenderedShape(t *testing.T) {
	e := newXTCPEnv(t, false, nil)
	e.a.Cycle()
	good, working := e.gen, e.live()
	for name, mutate := range map[string]func(string) string{
		"plugin":      func(s string) string { return s + "plugin.type = \"static_file\"\n" },
		"visitor":     func(s string) string { return s + "\n[[visitors]]\nname = \"v\"\n" },
		"remote host": func(s string) string { return strings.Replace(s, `localIP = "127.0.0.1"`, `localIP = "10.0.0.1"`, 1) },
		"tcp proxy":   func(s string) string { return strings.Replace(s, `type = "xtcp"`, `type = "tcp"`, 1) },
		"template": func(s string) string {
			return strings.Replace(s, `serverAddr = "127.0.0.1"`, `serverAddr = "{{ .Envs.HOME }}"`, 1)
		},
		"other CA": func(s string) string { return strings.Replace(s, e.a.opt.FrpcCA, "/tmp/evil-ca.pem", 1) },
		"admin API": func(s string) string {
			return strings.Replace(s, "log.level", "webServer.addr = \"0.0.0.0\"\nlog.level", 1)
		},
		"port swapped": func(s string) string { return strings.Replace(s, "localPort = 20443", "localPort = 22", 1) },
	} {
		d := e.render(e.token, primary)
		d.FrpcTOML = mutate(d.FrpcTOML)
		e.publish(d)
		e.a.Cycle()
		if r := e.wantReport(xtcpFailed, e.gen, good); !strings.Contains(fmt.Sprint(r["error"]), "configuration") {
			t.Errorf("%s: %v", name, r["error"])
		}
		if reloads, restarts, _, _ := e.frpc.snapshot(); e.live() != working || reloads+restarts != 0 {
			t.Fatalf("%s: a refused configuration reached frpc", name)
		}
	}
}

// A hung service manager (systemctl, launchctl, the scheduled task) must not stall the agent's whole cycle.
func TestXTCPHungRestartCommandDoesNotStallTheAgent(t *testing.T) {
	start := time.Now()
	if err := runCommandTimeout("sleep 30", nil, 300*time.Millisecond); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("a hung command must time out: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the timeout took %s", elapsed)
	}
}
