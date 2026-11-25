package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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

var testPlatform = runtime.GOOS + "-" + runtime.GOARCH

// updateEnv is one host's update setup: a fake control plane, a fake installed binary and a signing key.
type updateEnv struct {
	t     *testing.T
	cp    *fakeCP
	a     *Agent
	u     *updater
	exe   string
	key   ed25519.PrivateKey
	clock time.Time
	cand  []byte // the candidate's bytes (the test binary: it answers version and check-args)
}

const oldBinary = "#!/bin/sh\n# the release this host ran before the update\n"

func newUpdateEnv(t *testing.T) *updateEnv {
	t.Helper()
	cp := newFakeCP(t)
	a, dir := newTestAgent(t, cp, nil)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "ccproxy-exit-agent")
	if err := os.WriteFile(exe, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	cand, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	e := &updateEnv{t: t, cp: cp, a: a, exe: exe, key: priv, cand: cand, clock: time.Unix(1_800_000_000, 0)}
	e.u = e.newUpdater(dir, "agent-old", []ed25519.PublicKey{pub})
	t.Setenv("CCPROXY_FAKE_AGENT", "1")
	t.Setenv("CCPROXY_FAKE_AGENT_VERSION", "agent-new")
	return e
}

// newUpdater is an updater for this host as a process of version ver would build it.
func (e *updateEnv) newUpdater(stateDir, ver string, keys []ed25519.PublicKey) *updater {
	u := &updater{stateDir: stateDir, exe: e.exe, platform: testPlatform, version: ver, keys: keys,
		argv: []string{"--cp", "https://cp.example", "--reload-cmd", "true"}, interval: time.Minute,
		healthTimeout: 10 * time.Minute, logf: e.t.Logf, now: func() time.Time { return e.clock }}
	u.load()
	e.a.attachUpdater(u)
	return u
}

// restart simulates the service manager starting the binary now at exe, which reports version ver.
func (e *updateEnv) restart(ver string) (exitAgain bool) {
	keys := e.u.keys
	e.u = e.newUpdater(e.u.stateDir, ver, keys)
	return e.u.onStart()
}

// publish offers a signed record for the candidate bytes (or another version/sequence) under rollout id.
func (e *updateEnv) publish(ver string, sequence, rollout int64, mutate func(*release.Record)) {
	sum := sha256.Sum256(e.cand)
	r := release.Record{Schema: 1, Product: release.Product, Version: ver, Sequence: sequence,
		Binaries: map[string]release.Binary{testPlatform: {File: release.FileName(testPlatform), SHA256: hex.EncodeToString(sum[:]), Size: int64(len(e.cand))}}}
	if mutate != nil {
		mutate(&r)
	}
	data, err := release.Encode(r)
	if err != nil {
		e.t.Fatal(err)
	}
	e.cp.mu.Lock()
	e.cp.offer = &updateOffer{Rollout: rollout, Record: string(data), Signature: release.Sign(e.key, data)}
	e.cp.binaries = map[string][]byte{ver + "/" + testPlatform: e.cand}
	e.cp.mu.Unlock()
}

func (e *updateEnv) tick() error {
	e.t.Helper()
	e.clock = e.clock.Add(5 * time.Minute) // always past --update-interval
	e.a.Cycle()                            // heartbeat (and its own tick, at the same clock)
	return nil
}

func (e *updateEnv) cycle() error {
	e.t.Helper()
	e.clock = e.clock.Add(5 * time.Minute)
	return e.a.Cycle()
}

func (e *updateEnv) exeIs(want []byte) bool {
	got, _ := os.ReadFile(e.exe)
	return bytes.Equal(got, want)
}

func (e *updateEnv) lastUpdate() map[string]any {
	r := e.cp.last()
	u, _ := r["update"].(map[string]any)
	return u
}

func noLeftovers(t *testing.T, exe string) {
	t.Helper()
	for _, suffix := range []string{".download", ".restore", ".previous.tmp"} {
		if _, err := os.Stat(exe + suffix); err == nil {
			t.Errorf("%s left behind", exe+suffix)
		}
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
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatalf("expected a restart for the update, got %v", err)
	}
	if !e.exeIs(e.cand) {
		t.Fatal("candidate not at the executable path")
	}
	if prev, _ := os.ReadFile(e.exe + ".previous"); string(prev) != oldBinary {
		t.Fatal("previous release not kept")
	}
	noLeftovers(t, e.exe)

	// The service manager starts the candidate; it confirms after two healthy cycles.
	if e.restart("agent-new") {
		t.Fatal("candidate must not exit at its first start")
	}
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
	if e.u.st.Running != "agent-new" || e.u.st.Phase != phaseIdle {
		t.Fatalf("state %+v", e.u.st)
	}
	// The same target is now current: nothing downloads again.
	before := e.cp.downloads
	e.cycle()
	if e.cp.downloads != before {
		t.Fatal("current release downloaded again")
	}
}

func TestUpdateTamperedOrInterruptedDownloadKeepsCurrent(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	e.cp.mu.Lock()
	e.cp.binaries["agent-new/"+testPlatform] = append([]byte("tampered"), e.cand[8:]...)
	e.cp.mu.Unlock()
	if err := e.cycle(); err != nil {
		t.Fatalf("tampered download must not restart: %v", err)
	}
	e.cycle() // report the outcome
	if !e.exeIs([]byte(oldBinary)) {
		t.Fatal("tampered binary installed")
	}
	if got := e.lastUpdate(); got["state"] != updFailed || !strings.Contains(fmt.Sprint(got["error"]), "SHA-256") {
		t.Fatalf("tampered: %v", got)
	}
	noLeftovers(t, e.exe)

	e.cp.mu.Lock()
	e.cp.binaries["agent-new/"+testPlatform] = e.cand
	e.cp.truncate = true
	e.cp.mu.Unlock()
	e.cycle()
	if !e.exeIs([]byte(oldBinary)) {
		t.Fatal("interrupted download installed")
	}
	if got := e.u.transientErr; !strings.Contains(got, "received") {
		t.Fatalf("interrupted: %q", got)
	}
	noLeftovers(t, e.exe)

	// Not blocked: once the control plane serves the right file, the next check resumes and activates.
	e.cp.mu.Lock()
	e.cp.truncate = false
	e.cp.mu.Unlock()
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatalf("retry after a failed download: %v", err)
	}
}

func TestUpdateRefusesUntrustedOrIncompatibleReleases(t *testing.T) {
	cases := map[string]struct {
		setup func(e *updateEnv)
		want  string
	}{
		"unsigned key": {func(e *updateEnv) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			e.key = other
			e.publish("agent-new", 7, 1, nil)
		}, "signature does not match"},
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
		}, "no build for"},
		"older sequence": {func(e *updateEnv) {
			e.u.st.RunningSequence = 9
			e.publish("agent-new", 7, 1, nil)
		}, "not newer"},
		"candidate reports another version": {func(e *updateEnv) {
			e.t.Setenv("CCPROXY_FAKE_AGENT_VERSION", "agent-something-else")
			e.publish("agent-new", 7, 1, nil)
		}, "expected version agent-new"},
		"candidate rejects the command line": {func(e *updateEnv) {
			e.t.Setenv("CCPROXY_FAKE_AGENT_ARGS_FAIL", "1")
			e.publish("agent-new", 7, 1, nil)
		}, "command line"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newUpdateEnv(t)
			c.setup(e)
			if err := e.cycle(); err != nil {
				t.Fatalf("must not restart: %v", err)
			}
			e.cycle()
			got := e.lastUpdate()
			if got["state"] != updRejected || !strings.Contains(fmt.Sprint(got["error"]), c.want) {
				t.Fatalf("got %v, want rejected with %q", got, c.want)
			}
			if !e.exeIs([]byte(oldBinary)) {
				t.Fatal("refused release installed")
			}
			if _, err := os.Stat(e.exe + ".candidate"); name != "unsigned key" && name != "no build for platform" &&
				name != "older sequence" && err == nil {
				t.Fatal("refused candidate left staged")
			}
			// Not retried for the same rollout.
			downloads := e.cp.downloads
			e.cycle()
			if e.cp.downloads != downloads {
				t.Fatal("refused release fetched again")
			}
		})
	}
}

func TestUpdatePausedRolloutDoesNotActivate(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	// Pause (204) while the binary downloads: the agent gets the binary, then sees no target before activation.
	e.cp.mu.Lock()
	data := e.cp.binaries["agent-new/"+testPlatform]
	e.cp.mu.Unlock()
	e.u.download = func(path string, w io.Writer, limit int64) error {
		e.cp.mu.Lock()
		e.cp.offer = nil
		e.cp.mu.Unlock()
		_, err := w.Write(data)
		return err
	}
	if err := e.cycle(); err != nil {
		t.Fatalf("paused rollout activated: %v", err)
	}
	if !e.exeIs([]byte(oldBinary)) {
		t.Fatal("paused rollout replaced the binary")
	}
	e.cycle()
	if got := e.lastUpdate(); got["state"] != updIdle {
		t.Fatalf("paused: %v", got)
	}
	// Resumed: the staged candidate is used without a second download.
	e.publish("agent-new", 7, 1, nil)
	e.u.download = func(string, io.Writer, int64) error { t.Fatal("downloaded again"); return nil }
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatalf("resumed: %v", err)
	}
}

func TestUpdateRollsBackUnhealthyCandidate(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatal(err)
	}
	e.restart("agent-new")
	e.cp.mu.Lock()
	e.cp.reportFailFor = version // the candidate's heartbeats fail (the test binary's version)
	e.cp.mu.Unlock()
	var err error
	for i := 0; i < 3 && err == nil; i++ {
		err = e.cycle() // 15 minutes pass: beyond the 10-minute health timeout
	}
	if err != errRestartForUpdate {
		t.Fatalf("expected a rollback restart, got %v", err)
	}
	if !e.exeIs([]byte(oldBinary)) {
		t.Fatal("previous release not restored")
	}
	noLeftovers(t, e.exe)
	e.cp.mu.Lock()
	e.cp.reportFailFor = ""
	e.cp.mu.Unlock()

	// The previous release starts again and reports the outcome; the same target is not retried.
	if e.restart("agent-old") {
		t.Fatal("previous release must keep running")
	}
	e.cycle()
	got := e.lastUpdate()
	if got["state"] != updRolledBack || got["target_version"] != "agent-new" || !strings.Contains(fmt.Sprint(got["error"]), "heartbeat failed") {
		t.Fatalf("after rollback: %v", got)
	}
	downloads := e.cp.downloads
	e.cycle()
	if e.cp.downloads != downloads || !e.exeIs([]byte(oldBinary)) {
		t.Fatal("rolled-back target tried again without a new rollout")
	}
	// The operator retries (a new rollout id): the agent tries again.
	e.publish("agent-new", 7, 2, nil)
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatalf("retry after a new rollout id: %v", err)
	}
}

func TestUpdateRollsBackCandidateThatKeepsCrashing(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatal(err)
	}
	for start := 1; start <= updateMaxStarts; start++ {
		if e.restart("agent-new") {
			t.Fatalf("rolled back at start %d", start)
		}
		// ... and it dies before confirming (no cycle).
	}
	if !e.restart("agent-new") {
		t.Fatal("expected a rollback at the start after the limit")
	}
	if !e.exeIs([]byte(oldBinary)) {
		t.Fatal("previous release not restored")
	}
	e.restart("agent-old")
	e.cycle()
	if got := e.lastUpdate(); got["state"] != updRolledBack || !strings.Contains(fmt.Sprint(got["error"]), "started 3 times") {
		t.Fatalf("crash loop: %v", got)
	}
}

func TestUpdateStateSurvivesInterruptionAndReinstall(t *testing.T) {
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	// Stopped after recording the activation but before the swap: the old binary starts again and retries.
	e.u.st.Phase, e.u.st.Target, e.u.st.Previous = phaseActivating, updateTarget{Version: "agent-new", Sequence: 7, Rollout: 1}, "agent-old"
	e.u.mustSave()
	if e.restart("agent-old") {
		t.Fatal("interrupted activation must not exit")
	}
	if e.u.st.Phase != phaseIdle || e.u.st.Result.State != updFailed || e.u.st.Result.Blocked != "" {
		t.Fatalf("interrupted: %+v", e.u.st)
	}
	if err := e.cycle(); err != errRestartForUpdate {
		t.Fatalf("retry after interruption: %v", err)
	}
	// The installer puts another binary in place while the candidate was confirming: start over from that binary.
	e.restart("agent-new")
	e.restart("agent-installed-by-hand")
	if e.u.st.Phase != phaseIdle || e.u.st.Running != "agent-installed-by-hand" {
		t.Fatalf("reinstall: %+v", e.u.st)
	}
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
	good := []string{"--cp", "https://cp.example", "--token-file", "/x", "--reload-cmd", "true", "--update-restart-cmd", "'a b' c"}
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
