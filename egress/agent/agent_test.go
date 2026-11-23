package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as a fake sing-box (like controlplane/tests/fake_singbox.py) when started as
// "<test binary> check|run -c FILE" with CCPROXY_FAKE_SINGBOX=1 in the environment:
//
//	check   fails when FILE contains REJECT_ME
//	run     serves FILE's clash_api /proxies (outbound tags, only with the loaded secret); SIGHUP reloads FILE.
//	        A "crash" file next to FILE makes it exit 3 at start or on SIGHUP; "stubborn" ignores SIGHUP.
func TestMain(m *testing.M) {
	if os.Getenv("CCPROXY_FAKE_SINGBOX") == "1" && len(os.Args) > 2 && (os.Args[1] == "check" || os.Args[1] == "run") {
		os.Exit(fakeSingBox(os.Args[1], os.Args[3]))
	}
	os.Exit(m.Run())
}

func fakeSingBox(cmd, path string) int {
	data, _ := os.ReadFile(path)
	if cmd == "check" {
		if strings.Contains(string(data), "REJECT_ME") {
			fmt.Fprintln(os.Stderr, "fake check: rejected")
			return 1
		}
		return 0
	}
	flag := func(name string) bool { _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); return err == nil }
	if flag("crash") {
		return 3
	}
	var mu sync.Mutex
	var secret string
	var tags []string
	load := func() error {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var c struct {
			Experimental struct {
				ClashAPI struct {
					Controller string `json:"external_controller"`
					Secret     string `json:"secret"`
				} `json:"clash_api"`
			} `json:"experimental"`
			Outbounds []struct {
				Tag string `json:"tag"`
			} `json:"outbounds"`
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		mu.Lock()
		defer mu.Unlock()
		secret, tags = c.Experimental.ClashAPI.Secret, nil
		for _, o := range c.Outbounds {
			tags = append(tags, o.Tag)
		}
		return nil
	}
	if err := load(); err != nil {
		return 4
	}
	var raw struct {
		Experimental struct {
			ClashAPI struct {
				Controller string `json:"external_controller"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	json.Unmarshal(data, &raw)
	ln, err := net.Listen("tcp", raw.Experimental.ClashAPI.Controller)
	if err != nil {
		return 5
	}
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ok := r.Header.Get("Authorization") == "Bearer "+secret && r.URL.Path == "/proxies"
		proxies := map[string]any{}
		for _, t := range tags {
			proxies[t] = map[string]string{"type": "Reject"}
		}
		mu.Unlock()
		if !ok {
			w.WriteHeader(401)
			w.Write([]byte(`{"message":"Unauthorized"}`))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"proxies": proxies})
	}))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM)
	for s := range sig {
		if s == syscall.SIGTERM {
			return 0
		}
		if flag("crash") {
			return 3
		}
		if !flag("stubborn") {
			load()
		}
	}
	return 0
}

// fakeCP is the agent side of the control-plane API.
type fakeCP struct {
	mu      sync.Mutex
	config  string
	ips     string
	reports []map[string]any
	srv     *httptest.Server
}

const testToken = "test-agent-token-0123456789"

func newFakeCP(t *testing.T) *fakeCP {
	cp := &fakeCP{ips: "127.0.0.1\n", config: `{"log":{"level":"warn"},"outbounds":[{"type":"direct","tag":"direct"}]}`}
	cp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken {
			w.WriteHeader(401)
			return
		}
		cp.mu.Lock()
		defer cp.mu.Unlock()
		switch r.URL.Path {
		case "/agent/ips":
			io.WriteString(w, cp.ips)
		case "/agent/probe-targets":
			io.WriteString(w, `{"egress_targets": []}`)
		case "/agent/server-config":
			etag := `"` + fmt.Sprint(hash(cp.config)) + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(304)
				return
			}
			io.WriteString(w, cp.config)
		case "/agent/report":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			cp.reports = append(cp.reports, body)
			io.WriteString(w, `{"recorded":0}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(cp.srv.Close)
	return cp
}

func hash(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * 16777619
	}
	return h
}

func (cp *fakeCP) set(config string) { cp.mu.Lock(); cp.config = config; cp.mu.Unlock() }

func (cp *fakeCP) last() map[string]any {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.reports[len(cp.reports)-1]
}

func freePort(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func newTestAgent(t *testing.T, cp *fakeCP, mutate func(*Options)) (*Agent, string) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake sing-box uses SIGHUP")
	}
	t.Setenv("CCPROXY_FAKE_SINGBOX", "1")
	dir := t.TempDir()
	exe, _ := os.Executable()
	o := Options{CP: cp.srv.URL, Config: filepath.Join(dir, "config.json"), StateDir: dir, SingBox: exe,
		Name: "test", Interval: 0, Settle: 0, MaxDelay: 60, ProbeInterval: 3600, ProbeTimeout: 2,
		ConfirmAPI: freePort(t), ConfirmTimeout: 3, Once: true, Run: true}
	if mutate != nil {
		mutate(&o)
	}
	a, err := NewAgent(o, testToken, t.Logf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a, dir
}

func TestFirstConfigIsConfirmedAndReported(t *testing.T) {
	cp := newFakeCP(t)
	a, dir := newTestAgent(t, cp, nil)
	a.Cycle()
	r := cp.last()
	if r["apply_state"] != "confirmed" || r["config_etag"] == nil || r["candidate_etag"] != nil || r["singbox_running"] != true {
		t.Fatalf("unexpected heartbeat %v", r)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if !strings.Contains(string(data), a.marker) || !strings.Contains(string(data), a.confirmAddress) {
		t.Fatal("config at --config lacks the candidate's marker and API address")
	}
	if st, _ := os.Stat(filepath.Join(dir, "config.json")); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("config mode %v, want 0600", st.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(dir, "confirmed-config.json")); err != nil {
		t.Fatal("no confirmed copy")
	}
}

func testReloadOnChange(t *testing.T, runReload string) {
	cp := newFakeCP(t)
	a, _ := newTestAgent(t, cp, func(o *Options) { o.RunReload = runReload })
	a.Cycle()
	first, pid := a.applied, a.child.pid()
	cp.set(`{"log":{"level":"info"},"outbounds":[{"type":"direct","tag":"direct"}]}`)
	a.Cycle()
	if a.applied == first || a.applied != a.installed || cp.last()["apply_state"] != "confirmed" {
		t.Fatalf("new version not confirmed: applied=%s installed=%s report=%v", a.applied, a.installed, cp.last())
	}
	if restarted := a.child.pid() != pid; restarted != (runReload == "restart") {
		t.Fatalf("run-reload %s: pid %d -> %d", runReload, pid, a.child.pid())
	}
}

func TestSignalReloadKeepsTheProcess(t *testing.T)     { testReloadOnChange(t, "signal") }
func TestRestartReloadReplacesTheProcess(t *testing.T) { testReloadOnChange(t, "restart") }

func TestRejectedVersionKeepsWorkingConfigAndIsNotRetried(t *testing.T) {
	cp := newFakeCP(t)
	a, dir := newTestAgent(t, cp, nil)
	a.Cycle()
	before, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	cp.set(`{"log":{"level":"REJECT_ME"},"outbounds":[]}`)
	a.Cycle()
	after, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if string(before) != string(after) || a.rejected == "" || a.installed != a.applied {
		t.Fatal("rejected version touched the running config")
	}
	a.Cycle() // same version again: not checked again
	if cp.last()["apply_state"] != "confirmed" {
		t.Fatalf("heartbeat %v", cp.last())
	}
}

func TestCrashOnReloadRestoresTheConfirmedConfig(t *testing.T) {
	cp := newFakeCP(t)
	a, dir := newTestAgent(t, cp, nil)
	a.Cycle()
	confirmed, _ := os.ReadFile(filepath.Join(dir, "confirmed-config.json"))
	os.WriteFile(filepath.Join(dir, "crash"), nil, 0o600)
	cp.set(`{"log":{"level":"debug"},"outbounds":[]}`)
	a.Cycle()
	r := cp.last()
	if r["apply_state"] != "failed" || !strings.Contains(fmt.Sprint(r["apply_error"]), "exited") {
		t.Fatalf("heartbeat %v", r)
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, "config.json"))
	if string(onDisk) != string(confirmed) {
		t.Fatal("the confirmed configuration was not put back at --config")
	}
	if r["config_etag"] != fmt.Sprint(a.applied) || r["candidate_etag"] != a.installed {
		t.Fatalf("heartbeat versions %v", r)
	}
}

func TestStubbornProcessIsNotConfirmed(t *testing.T) {
	cp := newFakeCP(t)
	a, _ := newTestAgent(t, cp, func(o *Options) { o.ConfirmTimeout = 0.5 })
	a.Cycle()
	os.WriteFile(filepath.Join(a.opt.StateDir, "stubborn"), nil, 0o600)
	cp.set(`{"log":{"level":"error"},"outbounds":[]}`)
	a.Cycle()
	if cp.last()["apply_state"] != "failed" || !strings.Contains(fmt.Sprint(cp.last()["apply_error"]), "another configuration") {
		t.Fatalf("heartbeat %v", cp.last())
	}
}

func TestReloadCommandAndStatusCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	cp := newFakeCP(t)
	// The reload command stands in for systemctl / launchctl: SIGHUP the fake sing-box, or start it.
	a, dir := newTestAgent(t, cp, func(o *Options) {
		ctl := filepath.Join(o.StateDir, "ctl.sh")
		os.WriteFile(ctl, []byte(`#!/bin/sh
pid=$(cat "$0.pid" 2>/dev/null)
case $1 in
  reload) if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then kill -HUP "$pid"
          else "`+o.SingBox+`" run -c "`+o.Config+`" >/dev/null 2>&1 & echo $! > "$0.pid"; fi ;;
  status) [ -n "$pid" ] && kill -0 "$pid" ;;
esac
`), 0o700)
		o.Run, o.ReloadCmd, o.StatusCmd = false, ctl+" reload", ctl+" status"
	})
	t.Cleanup(func() {
		if pid, err := os.ReadFile(filepath.Join(dir, "ctl.sh.pid")); err == nil {
			var n int
			fmt.Sscan(string(pid), &n)
			if p, err := os.FindProcess(n); err == nil {
				p.Kill()
			}
		}
	})
	a.Cycle()
	if cp.last()["apply_state"] != "confirmed" || cp.last()["singbox_running"] != true {
		t.Fatalf("heartbeat %v", cp.last())
	}
	cp.set(`{"log":{"level":"trace"},"outbounds":[]}`)
	a.Cycle()
	if cp.last()["apply_state"] != "confirmed" || a.applied != a.installed {
		t.Fatalf("heartbeat %v", cp.last())
	}
}

func TestSettleCoalescesABurst(t *testing.T) {
	cp := newFakeCP(t)
	now := 1000.0
	a, _ := newTestAgent(t, cp, func(o *Options) { o.Settle = 10 })
	a.now = func() float64 { return now }
	a.Cycle()
	first := a.applied
	for i, level := range []string{"a", "b", "c"} {
		cp.set(fmt.Sprintf(`{"log":{"level":"%s-%d"},"outbounds":[]}`, level, i))
		now += 3
		a.Cycle()
		if a.applied != first {
			t.Fatal("installed before the burst settled")
		}
	}
	now += 10
	a.Cycle()
	if a.applied == first || a.applied != a.installed {
		t.Fatal("settled version not applied")
	}
}

func TestRedirectsAreRefusedSoTheTokenStaysOnTheControlPlane(t *testing.T) {
	var leaked string
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = r.Header.Get("Authorization") }))
	defer other.Close()
	cp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer cp.Close()
	a, err := NewAgent(Options{CP: cp.URL, ConfirmAPI: "127.0.0.1:9095"}, testToken, t.Logf, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := a.get("/agent/ips", ""); err == nil || !strings.Contains(err.Error(), "refused redirect") {
		t.Fatalf("redirect followed: %v", err)
	}
	if leaked != "" {
		t.Fatal("token sent to the redirect target")
	}
}

func TestControlPlaneURLMustBeHTTPS(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://cp.example:8443": true, "http://127.0.0.1:8443": true, "http://localhost:1": true,
		"http://cp.example": false, "http://10.0.0.1": false, "ftp://cp": false, "cp.example": false,
	} {
		if err := checkControlPlaneURL(raw); (err == nil) != ok {
			t.Errorf("%s: %v", raw, err)
		}
	}
}

func TestLoopbackAPI(t *testing.T) {
	for in, want := range map[string]string{"127.0.0.1:9095": "127.0.0.1:9095", "[::1]:1": "[::1]:1",
		"localhost:9095": "", "10.0.0.1:9095": "", "127.0.0.1:0": "", "127.0.0.1": ""} {
		got, err := loopbackAPI(in)
		if (err == nil) != (want != "") || got != want {
			t.Errorf("%s -> %q, %v", in, got, err)
		}
	}
}

func TestSplitCommand(t *testing.T) {
	cases := map[string][]string{
		`systemctl reload-or-restart x`: {"systemctl", "reload-or-restart", "x"},
		`/opt/a\ b/ctl "re load" 'q"x'`: {"/opt/a b/ctl", "re load", `q"x`},
		`sh -c "echo \"hi\" \\ $"`:      {"sh", "-c", `echo "hi" \ $`},
	}
	for in, want := range cases {
		got, err := splitCommand(in)
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s -> %q %v", in, got, err)
		}
	}
	for _, bad := range []string{`"open`, `'open`, ``} {
		if _, err := splitCommand(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRotatingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	w, err := openRotating(path, 100, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		w.Write([]byte(strings.Repeat("x", 40) + "\n"))
	}
	for _, p := range []string{path, path + ".1", path + ".2"} {
		if st, err := os.Stat(p); err != nil || st.Size() > 100 {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatal("kept more files than asked")
	}
}

func TestReadIPs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ips.txt")
	os.WriteFile(path, []byte("# c\n203.0.113.3\n\n 203.0.113.4 \n"), 0o600)
	ips, err := readIPs(path)
	if err != nil || strings.Join(ips, ",") != "203.0.113.3,203.0.113.4" {
		t.Fatal(ips, err)
	}
	os.WriteFile(path, []byte("203.0.113.3; rm -rf /\n"), 0o600)
	if _, err := readIPs(path); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestHTTPProbeBindsTheSourceAddress(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _, _ = net.SplitHostPort(r.RemoteAddr)
		if r.URL.Path == "/blocked" {
			w.WriteHeader(403)
		}
	}))
	defer srv.Close()
	r := httpProbe(srv.URL+"/", "127.0.0.1", 2*time.Second)
	if !r.OK || r.LatencyMS == nil || r.Detail != "HTTP 200" || seen != "127.0.0.1" {
		t.Fatalf("%+v seen=%s", r, seen)
	}
	if r := httpProbe(srv.URL+"/blocked", "127.0.0.1", 2*time.Second); r.OK || r.Detail != "HTTP 403" {
		t.Fatalf("%+v", r)
	}
	if r := httpProbe("ftp://x/", "", time.Second); r.OK || !strings.Contains(r.Detail, "unsupported") {
		t.Fatalf("%+v", r)
	}
}
