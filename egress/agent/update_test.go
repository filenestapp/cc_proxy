package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/filenestapp/cc_proxy/egress/agent/release"
)

// fakeAgentCommand: the test binary as a candidate release ("version", "check-args"), with CCPROXY_FAKE_AGENT=1.
func fakeAgentCommand(cmd string) int {
	if cmd == "version" {
		fmt.Println("ccproxy-exit-agent " + os.Getenv("CCPROXY_FAKE_AGENT_VERSION"))
		return 0
	}
	if os.Getenv("CCPROXY_FAKE_AGENT_ARGS_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "flag provided but not defined: -new-flag")
		return 2
	}
	return 0
}

var testPlatform = currentPlatform()

// updateEnv is one host's update setup, all disposable: a fake control plane, a launcher binary in a temporary
// home, a throwaway signing key, and a candidate (the test binary: it answers version and check-args).
type updateEnv struct {
	t        *testing.T
	cp       *fakeCP
	a        *Agent
	u        *updater
	home     string
	self     string // the launcher (the release installed by the installer)
	stateDir string
	key      ed25519.PrivateKey
	keys     []ed25519.PublicKey
	clock    time.Time
	cand     []byte
}

const oldBinary = "#!/bin/sh\n# the release the installer put in place (the launcher)\n"

func newUpdateEnv(t *testing.T) *updateEnv {
	t.Helper()
	cp := newFakeCP(t)
	a, dir := newTestAgent(t, cp, nil)
	return newUpdateEnvFor(t, cp, a, dir)
}

func newUpdateEnvFor(t *testing.T, cp *fakeCP, a *Agent, stateDir string) *updateEnv {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	self := filepath.Join(home, "ccproxy-exit-agent")
	if err := os.WriteFile(self, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	cand, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	e := &updateEnv{t: t, cp: cp, a: a, home: home, self: self, stateDir: stateDir, key: priv,
		keys: []ed25519.PublicKey{pub}, cand: cand, clock: time.Unix(1_800_000_000, 0)}
	// The installer's release is signed with sequence 1, and the control plane serves that record.
	e.cp.mu.Lock()
	e.cp.releases = map[string]*updateOffer{"agent-old": e.offer("agent-old", 1, 0, []byte(oldBinary), nil)}
	e.cp.mu.Unlock()
	if path, ver := e.launcher().choose(); path != "" || ver != "agent-old" {
		t.Fatalf("initial launcher chose %q %q", path, ver)
	}
	e.u = e.updaterAs("agent-old", self)
	t.Setenv("CCPROXY_FAKE_AGENT", "1")
	t.Setenv("CCPROXY_FAKE_AGENT_VERSION", "agent-new")
	return e
}

// updaterAs is the updater a process of version ver, running the executable self, would build.
func (e *updateEnv) updaterAs(ver, self string) *updater {
	u := &updater{stateDir: e.stateDir, home: e.home, self: self, platform: testPlatform, version: ver, keys: e.keys,
		argv: []string{"--cp", "https://cp.example", "--reload-cmd", "true"}, interval: time.Minute,
		healthTimeout: 10 * time.Minute, logf: e.t.Logf, now: func() time.Time { return e.clock }}
	u.st = loadUpdateFile(e.stateDir, e.t.Logf)
	e.a.attachUpdater(u)
	return u
}

func (e *updateEnv) launcher() *launcher {
	return &launcher{stateDir: e.stateDir, home: e.home, self: e.self, version: "agent-old", platform: testPlatform,
		healthTimeout: 10 * time.Minute, logf: e.t.Logf, now: func() time.Time { return e.clock }}
}

// offer is a signed record for data as ver's build for this platform.
func (e *updateEnv) offer(ver string, sequence, rollout int64, data []byte, mutate func(*release.Record)) *updateOffer {
	sum := sha256.Sum256(data)
	r := release.Record{Schema: 1, Product: release.Product, Version: ver, Sequence: sequence,
		Binaries: map[string]release.Binary{testPlatform: {File: release.FileName(testPlatform), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}}}
	if mutate != nil {
		mutate(&r)
	}
	record, err := release.Encode(r)
	if err != nil {
		e.t.Fatal(err)
	}
	return &updateOffer{Rollout: rollout, Record: string(record), Signature: release.Sign(e.key, record)}
}

// publish makes the rollout target the candidate as ver (sequence, rollout).
func (e *updateEnv) publish(ver string, sequence, rollout int64, mutate func(*release.Record)) {
	o := e.offer(ver, sequence, rollout, e.cand, mutate)
	e.cp.mu.Lock()
	e.cp.offer = o
	e.cp.binaries = map[string][]byte{ver + "/" + testPlatform: e.cand}
	e.cp.mu.Unlock()
}

func (e *updateEnv) pause() { e.cp.mu.Lock(); e.cp.offer = nil; e.cp.mu.Unlock() }

func (e *updateEnv) cycle() error {
	e.t.Helper()
	e.clock = e.clock.Add(5 * time.Minute) // always past --update-interval
	return e.a.Cycle()
}

// prepared waits for the background download and self-test to finish.
func (e *updateEnv) prepared() {
	e.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		e.u.mu.Lock()
		done := e.u.done != nil
		e.u.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatal("the candidate was not prepared in time")
}

// activate runs the check, waits for the background preparation and runs the cycle that activates.
func (e *updateEnv) activate() error {
	e.t.Helper()
	if err := e.cycle(); err != nil {
		e.t.Fatalf("a check must not restart before the candidate is ready: %v", err)
	}
	e.prepared()
	return e.cycle()
}

func (e *updateEnv) staged(ver string) string { return releaseBinary(e.home, ver, testPlatform) }

func (e *updateEnv) lastUpdate() map[string]any {
	r := e.cp.last()
	u, _ := r["update"].(map[string]any)
	return u
}

func (e *updateEnv) launcherUnchanged() {
	e.t.Helper()
	if got, _ := os.ReadFile(e.self); string(got) != oldBinary {
		e.t.Fatal("the launcher binary was changed by an update")
	}
}

func TestUpdateUpgradesConfirmsAndReports(t *testing.T) {
	e := newUpdateEnv(t)
	if err := e.cycle(); err != nil {
		t.Fatal(err)
	}
	if got := e.lastUpdate(); got["state"] != updIdle {
		t.Fatalf("no rollout: %v", got)
	}
	if v := e.cp.last()["agent_version"]; v != version {
		t.Fatalf("heartbeat agent_version %v", v)
	}
	e.publish("agent-new", 7, 1, nil)
	if err := e.cycle(); err != nil {
		t.Fatalf("the check itself never restarts: %v", err)
	}
	if err := e.a.report(); err != nil {
		t.Fatal(err)
	}
	if got := e.lastUpdate(); got["state"] != updDownloading {
		t.Fatalf("while preparing: %v", got)
	}
	e.prepared()
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatalf("expected a restart for the update, got %v", err)
	}
	if got, _ := os.ReadFile(e.staged("agent-new")); !bytes.Equal(got, e.cand) {
		t.Fatal("candidate not staged under releases/")
	}
	e.launcherUnchanged()
	if e.u.st.Phase != phaseActivating || e.u.st.Previous != "agent-old" || e.u.st.PreviousSequence != 1 {
		t.Fatalf("activation state %+v", e.u.st)
	}

	// The service manager starts the launcher, which starts the candidate.
	path, ver := e.launcher().choose()
	if path != e.staged("agent-new") || ver != "agent-new" {
		t.Fatalf("launcher chose %q %q", path, ver)
	}
	e.u = e.updaterAs("agent-new", e.staged("agent-new"))
	if err := e.cycle(); err != nil {
		t.Fatal(err)
	}
	if got := e.lastUpdate(); got["state"] != updConfirming || got["previous_version"] != "agent-old" {
		t.Fatalf("while confirming: %v", got)
	}
	e.cycle()
	e.cycle()
	got := e.lastUpdate()
	if got["state"] != updUpdated || got["target_version"] != "agent-new" || got["running_sequence"] != float64(7) {
		t.Fatalf("after confirmation: %v", got)
	}
	if path, ver := e.launcher().choose(); path != e.staged("agent-new") || ver != "agent-new" {
		t.Fatalf("after confirmation the launcher must run the new release, chose %q", path)
	}
	before := e.cp.downloads
	e.cycle()
	if e.cp.downloads != before || e.lastUpdate()["state"] != updUpdated {
		t.Fatalf("the current release must not be fetched again: %v", e.lastUpdate())
	}
	e.launcherUnchanged()
}

// A slow download must not hold back heartbeats or the sing-box and XTCP sync.
func TestUpdateDownloadDoesNotBlockHeartbeatsOrSync(t *testing.T) {
	x := newXTCPEnv(t, false, nil)
	e := newUpdateEnvFor(t, x.cp, x.a, x.dir)
	x.a.Cycle()
	x.wantReport(xtcpApplied, x.gen, x.gen)

	release := make(chan struct{})
	started := make(chan struct{}, 1)
	e.publish("agent-new", 7, 1, nil)
	data := e.cand
	e.u.download = func(path string, w io.Writer, limit int64) error {
		started <- struct{}{}
		w.Write(data[:len(data)/2])
		<-release // a stalled transfer
		_, err := w.Write(data[len(data)/2:])
		return err
	}
	if err := e.cycle(); err != nil {
		t.Fatal(err)
	}
	<-started
	reports, configs := len(x.cp.reports), x.cp.configGets
	// While the download hangs: a second XTCP port and a new sing-box configuration arrive.
	d := x.publish(x.render(x.token, primary, second))
	x.cp.set(`{"log":{"level":"info"},"outbounds":[{"type":"direct","tag":"direct"}]}`)
	for i := 0; i < 4; i++ {
		if err := e.cycle(); err != nil {
			t.Fatalf("cycle %d during the download: %v", i, err)
		}
	}
	x.cp.mu.Lock()
	gotReports, gotConfigs := len(x.cp.reports)-reports, x.cp.configGets-configs
	x.cp.mu.Unlock()
	if gotReports != 4 || gotConfigs < 4 {
		t.Fatalf("during the download: %d heartbeats, %d config polls (want 4 and 4)", gotReports, gotConfigs)
	}
	x.wantReport(xtcpApplied, d.Generation, d.Generation)
	if r := x.cp.last(); r["apply_state"] != "confirmed" || r["config_etag"] != `"`+fmt.Sprint(hash(x.cp.config))+`"` {
		t.Fatalf("the new sing-box configuration was not applied during the download: %v", r)
	}
	if got := e.lastUpdate(); got["state"] != updDownloading {
		t.Fatalf("update state during the download: %v", got)
	}
	close(release)
	e.prepared()
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatalf("after the download: %v", err)
	}
}

func TestUpdateTamperedOrInterruptedDownloadKeepsCurrent(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	e.cp.mu.Lock()
	e.cp.binaries["agent-new/"+testPlatform] = append([]byte("tampered"), e.cand[8:]...)
	e.cp.mu.Unlock()
	if err := e.activate(); err != nil {
		t.Fatalf("tampered download must not restart: %v", err)
	}
	e.cycle()
	if got := e.lastUpdate(); got["state"] != updFailed || !strings.Contains(fmt.Sprint(got["error"]), "SHA-256") {
		t.Fatalf("tampered: %v", got)
	}
	if _, err := os.Stat(e.staged("agent-new")); err == nil {
		t.Fatal("a tampered binary was staged")
	}
	if _, err := os.Stat(e.staged("agent-new") + ".download"); err == nil {
		t.Fatal("partial download left behind")
	}

	e.cp.mu.Lock()
	e.cp.binaries["agent-new/"+testPlatform] = e.cand
	e.cp.truncate = true
	e.cp.mu.Unlock()
	if err := e.activate(); err != nil {
		t.Fatalf("interrupted download must not restart: %v", err)
	}
	if !strings.Contains(e.u.transientErr, "received") {
		t.Fatalf("interrupted: %q", e.u.transientErr)
	}
	if e.u.st.Phase != phaseIdle {
		t.Fatalf("state after a failed download: %+v", e.u.st)
	}
	// Not blocked: once the control plane serves the right file, the next check resumes.
	e.cp.mu.Lock()
	e.cp.truncate = false
	e.cp.mu.Unlock()
	if err := e.activate(); err != errRestartForUpdate {
		t.Fatalf("retry after a failed download: %v", err)
	}
	e.launcherUnchanged()
}

func TestUpdateRefusesUntrustedOrIncompatibleReleases(t *testing.T) {
	cases := map[string]struct {
		setup      func(e *updateEnv)
		want       string
		downloaded bool
	}{
		"unsigned key": {func(e *updateEnv) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			e.key = other
			e.publish("agent-new", 7, 1, nil)
		}, "signature does not match", false},
		"no build for platform": {func(e *updateEnv) {
			e.publish("agent-new", 7, 1, func(r *release.Record) {
				other := "windows-arm64"
				if testPlatform == other {
					other = "linux-arm64"
				}
				b := r.Binaries[testPlatform]
				b.File = release.FileName(other)
				r.Binaries = map[string]release.Binary{other: b}
			})
		}, "no build for", false},
		"older than the running release": {func(e *updateEnv) {
			e.publish("agent-new", 1, 1, nil)
		}, "not newer", false},
		"candidate reports another version": {func(e *updateEnv) {
			e.t.Setenv("CCPROXY_FAKE_AGENT_VERSION", "agent-something-else")
			e.publish("agent-new", 7, 1, nil)
		}, "expected version agent-new", true},
		"candidate rejects the command line": {func(e *updateEnv) {
			e.t.Setenv("CCPROXY_FAKE_AGENT_ARGS_FAIL", "1")
			e.publish("agent-new", 7, 1, nil)
		}, "command line", true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newUpdateEnv(t)
			c.setup(e)
			if err := e.cycle(); err != nil {
				t.Fatalf("must not restart: %v", err)
			}
			if c.downloaded {
				e.prepared()
				if err := e.cycle(); err != nil {
					t.Fatalf("must not restart: %v", err)
				}
			}
			e.cycle()
			got := e.lastUpdate()
			if got["state"] != updRejected || !strings.Contains(fmt.Sprint(got["error"]), c.want) {
				t.Fatalf("got %v, want rejected with %q", got, c.want)
			}
			if _, err := os.Stat(e.staged("agent-new")); err == nil {
				t.Fatal("refused candidate left staged")
			}
			downloads := e.cp.downloads
			e.cycle()
			e.cycle()
			if e.cp.downloads != downloads || e.u.st.Phase != phaseIdle {
				t.Fatal("refused release fetched or activated again for the same rollout")
			}
		})
	}
}

// A fresh install knows no sequence locally: it must learn it from the signed record of its own binary before it
// accepts any target, so an older signed release is never accepted because local state is empty.
func TestUpdateEstablishesTheRunningSequence(t *testing.T) {
	t.Run("older signed release refused on a fresh install", func(t *testing.T) {
		e := newUpdateEnv(t)
		e.cp.mu.Lock()
		e.cp.releases["agent-old"] = e.offer("agent-old", 9, 0, []byte(oldBinary), nil)
		e.cp.mu.Unlock()
		if e.u.st.RunningSequence != 0 {
			t.Fatal("expected empty local state")
		}
		e.publish("agent-new", 5, 1, nil)
		e.cycle()
		e.cycle()
		if got := e.lastUpdate(); got["state"] != updRejected || !strings.Contains(fmt.Sprint(got["error"]), "not newer than the running release (9)") {
			t.Fatalf("got %v", got)
		}
		if e.cp.downloads != 0 || e.u.st.RunningSequence != 9 {
			t.Fatalf("downloads %d, running sequence %d", e.cp.downloads, e.u.st.RunningSequence)
		}
	})
	for name, setup := range map[string]func(e *updateEnv){
		"no signed record of the running release": func(e *updateEnv) { delete(e.cp.releases, "agent-old") },
		"signed record of other bytes": func(e *updateEnv) {
			e.cp.releases["agent-old"] = e.offer("agent-old", 1, 0, []byte("a different build"), nil)
		},
		"record signed by an untrusted key": func(e *updateEnv) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			good := e.key
			e.key = other
			e.cp.releases["agent-old"] = e.offer("agent-old", 1, 0, []byte(oldBinary), nil)
			e.key = good
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newUpdateEnv(t)
			e.cp.mu.Lock()
			setup(e)
			e.cp.mu.Unlock()
			e.publish("agent-new", 5, 1, nil)
			for i := 0; i < 3; i++ {
				if err := e.cycle(); err != nil {
					t.Fatalf("unestablished release must not update: %v", err)
				}
			}
			got := e.lastUpdate()
			if got["state"] != updFailed || !strings.Contains(fmt.Sprint(got["error"]), "not established") {
				t.Fatalf("got %v", got)
			}
			if e.cp.downloads != 0 || e.u.st.RunningSequence != 0 {
				t.Fatalf("downloads %d, sequence %d", e.cp.downloads, e.u.st.RunningSequence)
			}
		})
	}
	t.Run("a rollout of the running release establishes it", func(t *testing.T) {
		e := newUpdateEnv(t)
		delete(e.cp.releases, "agent-old")
		o := e.offer("agent-old", 4, 1, []byte(oldBinary), nil)
		e.cp.mu.Lock()
		e.cp.offer = o
		e.cp.mu.Unlock()
		e.cycle()
		e.cycle()
		if got := e.lastUpdate(); got["state"] != updCurrent || got["running_sequence"] != float64(4) {
			t.Fatalf("got %v", got)
		}
	})
}

func TestUpdateRefusesAStagedBinaryThatChangedBeforeActivation(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	if err := e.cycle(); err != nil {
		t.Fatal(err)
	}
	e.prepared()
	if err := os.WriteFile(e.staged("agent-new"), []byte("corrupt staged file"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.cycle(); err != nil {
		t.Fatalf("a changed staged file must not restart the Agent: %v", err)
	}
	if e.u.st.Phase != phaseIdle || e.u.transient != updFailed {
		t.Fatalf("changed staged file: phase %q, update state %q", e.u.st.Phase, e.u.transient)
	}
	e.launcherUnchanged()
}

func TestUpdatePausedRolloutDoesNotActivate(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	e.cycle()
	e.prepared()
	e.pause() // paused while the candidate was being prepared
	if err := e.cycle(); err != nil {
		t.Fatalf("paused rollout activated: %v", err)
	}
	e.cycle()
	if got := e.lastUpdate(); got["state"] != updIdle || e.u.st.Phase != phaseIdle {
		t.Fatalf("paused: %v %+v", got, e.u.st)
	}
	// Resumed: the staged candidate is activated without a second download.
	e.publish("agent-new", 7, 1, nil)
	downloads := e.cp.downloads
	if err := e.activate(); err != errRestartForUpdate {
		t.Fatalf("resumed: %v", err)
	}
	if e.cp.downloads != downloads {
		t.Fatal("downloaded again after the pause")
	}
}

func TestUpdateRollsBackUnhealthyCandidate(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	if err := e.activate(); err != errRestartForUpdate {
		t.Fatal(err)
	}
	e.launcher().choose()
	e.u = e.updaterAs("agent-new", e.staged("agent-new"))
	e.cp.mu.Lock()
	e.cp.reportFailFor = version // the candidate's heartbeats fail
	e.cp.mu.Unlock()
	var err error
	for i := 0; i < 3 && err == nil; i++ {
		err = e.cycle() // 15 minutes pass: beyond the 10-minute health timeout
	}
	if err != errRestartForUpdate {
		t.Fatalf("expected a rollback restart, got %v", err)
	}
	e.cp.mu.Lock()
	e.cp.reportFailFor = ""
	e.cp.mu.Unlock()

	if path, ver := e.launcher().choose(); path != "" || ver != "agent-old" {
		t.Fatalf("after the rollback the launcher must run itself, chose %q", path)
	}
	e.u = e.updaterAs("agent-old", e.self)
	e.cycle()
	got := e.lastUpdate()
	if got["state"] != updRolledBack || got["target_version"] != "agent-new" || !strings.Contains(fmt.Sprint(got["error"]), "heartbeat failed") {
		t.Fatalf("after rollback: %v", got)
	}
	e.cycle()
	if e.u.st.Phase != phaseIdle || e.u.running != nil || e.u.done != nil {
		t.Fatal("rolled-back target tried again without a new rollout")
	}
	// The operator retries (a new rollout id): the staged candidate is used again.
	e.publish("agent-new", 7, 2, nil)
	if err := e.activate(); err != errRestartForUpdate {
		t.Fatalf("retry after a new rollout id: %v", err)
	}
	e.launcherUnchanged()
}

func TestUpdateDisabledWithoutKeys(t *testing.T) {
	u := newUpdater(Options{StateDir: t.TempDir(), UpdateInterval: 120, UpdateHealthTimeout: 600}, nil, t.Logf)
	if len(u.keys) == 0 && u.disabled == "" {
		t.Fatal("no keys must disable updates")
	}
	if r := u.report(); r["state"] != updDisabled {
		t.Fatalf("report %v", r)
	}
	off := newUpdater(Options{StateDir: t.TempDir(), Update: "off"}, nil, t.Logf)
	if off.disabled == "" {
		t.Fatal("--update off must disable updates")
	}
}

func TestCheckArgs(t *testing.T) {
	good := []string{"--cp", "https://cp.example", "--token-file", "/x", "--reload-cmd", "true", "--update-interval", "300"}
	if code := checkArgs(good); code != 0 {
		t.Fatalf("good args: %d", code)
	}
	for _, bad := range [][]string{
		{"--cp", "https://cp.example", "--reload-cmd", "true", "--no-such-flag"},
		{"--cp", "https://cp.example"},
		{"--cp", "https://cp.example", "--reload-cmd", "true", "--update", "sometimes"},
		{"--cp", "https://cp.example", "--reload-cmd", "true", "--update-health-timeout", "5"},
	} {
		if code := checkArgs(bad); code == 0 {
			t.Errorf("accepted %v", bad)
		}
	}
}

var _ = errors.New
