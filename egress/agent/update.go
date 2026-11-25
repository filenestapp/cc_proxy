package main

// Managed automatic updates (docs/exit-agent-updates.md). launcher.go decides which binary a service start runs;
// this file is the part that runs inside the agent.
//
// Every --update-interval seconds, after the heartbeat, the agent asks GET /agent/update for its rollout target.
// 204 means none: the host is not targeted, the rollout is paused, or there is no rollout. A target is a signed
// release record (egress/agent/release) with a rollout id. The agent moves to it only when all of these hold:
//
//   - the signature verifies against a key compiled into this binary (release_keys.txt);
//   - the agent knows the signed sequence of the release it runs: from its last update, or established from the
//     control plane's signed record of its own version (GET /agent/release/{version}), whose digest for this
//     platform must equal this executable's SHA-256. Without that, no target is accepted, so an empty local state
//     never lets an older signed release in;
//   - the target's sequence is higher than the running release's (versions are source hashes, unordered);
//   - the record has a build for this platform; the download matches its size and SHA-256;
//   - the candidate runs here: "<candidate> version" prints the record's version and "<candidate> check-args"
//     accepts this agent's command line;
//   - the rollout still targets the host once the candidate is ready (a pause stops activation).
//
// Download and self-test run in the background: heartbeats, sing-box config sync and XTCP sync go on, and a slow or
// broken download only delays the update. The candidate is written to <bin>/releases/<version>/ (never over a
// running file). Activation only records the target in update-state.json and exits with status 75; the launcher
// starts the candidate and counts its starts. The candidate confirms itself after two consecutive healthy cycles:
// a heartbeat the control plane accepted, and sing-box (and, on XTCP hosts, frpc) at least as healthy as before the
// update. When it is not there within --update-health-timeout it records the rollback and exits; the launcher
// starts the previous release, which reports "rolled_back". A rolled-back or rejected target is not tried again
// until the operator changes the rollout (a new rollout id).
//
// Enrollment (token), configuration, sing-box and frpc files and services are never touched. The heartbeat carries
// "agent_version" and an "update" object (updater.report).

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/filenestapp/cc_proxy/egress/agent/release"
)

//go:embed release_keys.txt
var embeddedReleaseKeys string

// extraReleaseKeys adds trusted keys at build time (-ldflags "-X main.extraReleaseKeys=ed25519:..."), for test
// builds; production keys belong in release_keys.txt.
var extraReleaseKeys = ""

const (
	exitForUpdate   = 75 // EX_TEMPFAIL: the launcher (or the service manager) starts the agent again
	updateMaxStarts = 3  // starts of a candidate without confirming before the launcher rolls it back
	updateHealthy   = 2  // consecutive healthy cycles that confirm a candidate
	updateStateFile = "update-state.json"

	// Phases persisted across restarts.
	phaseIdle       = ""
	phaseActivating = "activating"
	phaseConfirming = "confirming"

	// Reported states ("update.state" in the heartbeat).
	updDisabled    = "disabled"
	updIdle        = "idle"
	updCurrent     = "current"
	updDownloading = "downloading"
	updConfirming  = "confirming"
	updUpdated     = "updated"
	updRolledBack  = "rolled_back"
	updRejected    = "rejected"
	updFailed      = "failed"
)

// errRestartForUpdate ends Loop so that run exits with exitForUpdate.
var errRestartForUpdate = errors.New("restarting for an agent update")

func currentPlatform() string { return runtime.GOOS + "-" + runtime.GOARCH }

type updateTarget struct {
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
	Rollout  int64  `json:"rollout"`
}

func targetKey(t updateTarget) string {
	return fmt.Sprintf("%d:%d:%s", t.Rollout, t.Sequence, t.Version)
}

// updateBaseline: what was healthy before activation; the candidate must reach at least the same.
type updateBaseline struct {
	SingboxConfirmed bool `json:"singbox_confirmed"`
	SingboxRunning   bool `json:"singbox_running"`
	XTCPApplied      bool `json:"xtcp_applied"`
}

type updateResult struct {
	State   string       `json:"state"` // updated, rolled_back, rejected, failed
	Target  updateTarget `json:"target"`
	Error   string       `json:"error,omitempty"`
	At      float64      `json:"at"`
	Blocked string       `json:"blocked,omitempty"` // target key that is not retried automatically
}

// updateFile is update-state.json in --state-dir, shared by the launcher and the agent (never at the same time:
// the launcher writes it before the agent starts).
type updateFile struct {
	Launcher         string         `json:"launcher_version"`
	Phase            string         `json:"phase"`
	Running          string         `json:"running_version"` // the release that runs when no candidate is confirming
	RunningSequence  int64          `json:"running_sequence"`
	Target           updateTarget   `json:"target"`
	Previous         string         `json:"previous_version"`
	PreviousSequence int64          `json:"previous_sequence"`
	ActivatedAt      float64        `json:"activated_at"`
	Starts           int            `json:"starts"`
	Baseline         updateBaseline `json:"baseline"`
	Result           *updateResult  `json:"result,omitempty"`
}

// rollback abandons the candidate: the previous release runs again and the target is not retried for its rollout.
func (st *updateFile) rollback(now time.Time, reason string) {
	st.Result = &updateResult{State: updRolledBack, Target: st.Target, Error: reason, At: float64(now.Unix()), Blocked: targetKey(st.Target)}
	st.Phase, st.Running, st.RunningSequence, st.Starts = phaseIdle, st.Previous, st.PreviousSequence, 0
}

func loadUpdateFile(stateDir string, logf func(string, ...any)) updateFile {
	var st updateFile
	data, err := os.ReadFile(filepath.Join(stateDir, updateStateFile))
	if err != nil {
		return st
	}
	if json.Unmarshal(data, &st) != nil {
		logf("update: ignoring unreadable %s", updateStateFile)
		return updateFile{}
	}
	return st
}

func saveUpdateFile(stateDir string, st updateFile) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	tmp, err := writeTemp(stateDir, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(stateDir, updateStateFile)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// updateOffer is the 200 answer of GET /agent/update (and of GET /agent/release/{version}, without rollout_id).
type updateOffer struct {
	Rollout   int64  `json:"rollout_id"`
	Record    string `json:"release"`   // release.json, byte for byte
	Signature string `json:"signature"` // release.json.sig
}

// prepJob is a candidate being downloaded and self-tested in the background.
type prepJob struct {
	key    string
	err    error
	reject bool // the candidate itself is unusable (not retried for this rollout)
}

type updater struct {
	stateDir, home, self, platform, version string
	argv                                    []string // this agent's command line, for the candidate's check-args
	keys                                    []ed25519.PublicKey
	disabled                                string
	interval, healthTimeout                 time.Duration
	st                                      updateFile
	lastCheck                               time.Time
	healthyCycles                           int
	transient, transientErr                 string // current check's state when no result is newer
	target                                  *updateTarget
	logf                                    func(string, ...any)
	now                                     func() time.Time
	cp                                      func(path string) (int, []byte, error) // GET with the agent token
	download                                func(path string, w io.Writer, limit int64) error

	mu      sync.Mutex
	running *prepJob // in the background
	done    *prepJob // finished, not yet acted on
}

// newUpdater sets up updates for this process. A disabled updater still reports.
func newUpdater(o Options, argv []string, logf func(string, ...any)) *updater {
	u := &updater{stateDir: o.StateDir, platform: currentPlatform(), version: version, argv: argv,
		interval:      time.Duration(o.UpdateInterval * float64(time.Second)),
		healthTimeout: time.Duration(o.UpdateHealthTimeout * float64(time.Second)), logf: logf, now: time.Now}
	keys, err := release.ParsePublicKeys(embeddedReleaseKeys + "\n" + strings.ReplaceAll(extraReleaseKeys, ",", "\n"))
	switch {
	case o.Update == "off":
		u.disabled = "turned off with --update off"
	case o.Once:
		u.disabled = "not with --once"
	case err != nil:
		u.disabled = "bad release key: " + err.Error()
	case len(keys) == 0:
		u.disabled = "no release signing key in this build"
	case version == "dev" || strings.HasSuffix(version, "-dirty"):
		u.disabled = "development build " + version
	}
	u.keys = keys
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	home, herr := agentHome()
	if (err != nil || herr != nil) && u.disabled == "" {
		u.disabled = "cannot locate this binary"
	}
	u.self, u.home = self, home
	u.st = loadUpdateFile(u.stateDir, logf)
	return u
}

func (u *updater) mustSave() {
	if err := saveUpdateFile(u.stateDir, u.st); err != nil {
		u.logf("update: cannot write %s: %v", updateStateFile, err)
	}
}

func (u *updater) finish(state string, target updateTarget, block bool, format string, args ...any) {
	r := &updateResult{State: state, Target: target, Error: fmt.Sprintf(format, args...), At: float64(u.now().Unix())}
	if block {
		r.Blocked = targetKey(target)
	}
	u.st.Result = r
	u.transient, u.transientErr = "", ""
}

func (u *updater) confirming() bool {
	return u.st.Phase == phaseConfirming && u.st.Target.Version == u.version
}

// -- reporting -----------------------------------------------------------------------------------------------------

// report is the heartbeat's "update" object.
func (u *updater) report() map[string]any {
	out := map[string]any{"running_sequence": u.st.RunningSequence}
	set := func(state string, t updateTarget, errText string, at float64) {
		out["state"] = state
		if t.Version != "" {
			out["target_version"], out["target_sequence"], out["rollout_id"] = t.Version, t.Sequence, t.Rollout
		}
		if errText != "" {
			out["error"] = truncateText(errText, 300)
		}
		if at > 0 {
			out["at"] = at
		}
	}
	switch {
	case u.disabled != "":
		set(updDisabled, updateTarget{}, u.disabled, 0)
	case u.confirming():
		set(updConfirming, u.st.Target, "", u.st.ActivatedAt)
		out["previous_version"] = u.st.Previous
	case u.transient != "" && u.target != nil:
		set(u.transient, *u.target, u.transientErr, 0)
	case u.st.Result != nil && (u.target == nil || targetKey(*u.target) == targetKey(u.st.Result.Target) ||
		u.st.Result.State == updUpdated && u.st.Result.Target.Version == u.version):
		r := u.st.Result
		set(r.State, r.Target, r.Error, r.At)
		if r.State == updRolledBack || r.State == updUpdated {
			out["previous_version"] = u.st.Previous
		}
	case u.target != nil && u.target.Version == u.version:
		set(updCurrent, *u.target, "", 0)
	default:
		set(updIdle, updateTarget{}, "", 0)
	}
	return out
}

// -- per cycle -----------------------------------------------------------------------------------------------------

// tick runs after each heartbeat and never blocks on the network for long: downloads run in the background.
// errRestartForUpdate means: exit now so the launcher starts the new (or the previous) release.
func (u *updater) tick(a *Agent, reportErr error) error {
	if u.disabled != "" {
		return nil
	}
	if u.confirming() {
		return u.confirm(a, reportErr)
	}
	u.mu.Lock()
	ready := u.done != nil
	u.mu.Unlock()
	if !ready && !u.lastCheck.IsZero() && u.now().Sub(u.lastCheck) < u.interval {
		return nil
	}
	u.lastCheck = u.now()
	return u.check(a)
}

func baselineOf(a *Agent) updateBaseline {
	b := updateBaseline{SingboxConfirmed: a.state() == stateConfirmed}
	if running, ok := a.singboxRunning().(bool); ok {
		b.SingboxRunning = running
	}
	if a.xtcp != nil {
		if x := a.xtcp.report(); x != nil {
			b.XTCPApplied = x["state"] == xtcpApplied
		}
	}
	return b
}

// healthProblem is "" when the candidate is at least as healthy as the release it replaced.
func (u *updater) healthProblem(a *Agent, reportErr error) string {
	if reportErr != nil {
		return "heartbeat failed: " + reportErr.Error()
	}
	now, want := baselineOf(a), u.st.Baseline
	switch {
	case want.SingboxConfirmed && !now.SingboxConfirmed:
		return "sing-box has not confirmed the configuration"
	case want.SingboxRunning && !now.SingboxRunning:
		return "sing-box is not running"
	case want.XTCPApplied && !now.XTCPApplied:
		return "frpc has not confirmed the XTCP mappings"
	}
	return ""
}

func (u *updater) confirm(a *Agent, reportErr error) error {
	problem := u.healthProblem(a, reportErr)
	if problem == "" {
		u.healthyCycles++
	} else {
		u.healthyCycles = 0
	}
	st := &u.st
	if u.healthyCycles >= updateHealthy {
		st.Phase, st.Running, st.RunningSequence, st.Starts = phaseIdle, st.Target.Version, st.Target.Sequence, 0
		u.finish(updUpdated, st.Target, false, "")
		u.mustSave()
		u.logf("update: %s (sequence %d) confirmed healthy; previous release %s", st.Target.Version, st.Target.Sequence, st.Previous)
		u.prune()
		return nil
	}
	if u.now().Sub(time.Unix(int64(st.ActivatedAt), 0)) > u.healthTimeout {
		if problem == "" {
			problem = "not confirmed in time"
		}
		target := st.Target.Version
		st.rollback(u.now(), fmt.Sprintf("not healthy within %s: %s", u.healthTimeout, problem))
		u.mustSave()
		u.logf("update: rolling back %s to %s: %s", target, st.Running, st.Result.Error)
		return errRestartForUpdate
	}
	return nil
}

// prune removes staged releases other than the running and the previous one.
func (u *updater) prune() {
	entries, err := os.ReadDir(filepath.Join(u.home, "releases"))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.Name() != u.st.Running && e.Name() != u.st.Previous {
			os.RemoveAll(filepath.Join(u.home, "releases", e.Name()))
		}
	}
}

// -- the running release's sequence ----------------------------------------------------------------------------------

// verifyOffer checks a signed record from the control plane.
func (u *updater) verifyOffer(o updateOffer) (release.Record, error) {
	if err := release.Verify(u.keys, []byte(o.Record), o.Signature); err != nil {
		return release.Record{}, err
	}
	return release.Parse([]byte(o.Record))
}

// adopt records r's sequence as the running release's when r is this binary: same version and, for this platform,
// this executable's SHA-256.
func (u *updater) adopt(r release.Record) error {
	if r.Version != u.version {
		return fmt.Errorf("the record is for %s, this agent is %s", r.Version, u.version)
	}
	bin, ok := r.Binaries[u.platform]
	if !ok {
		return fmt.Errorf("the record of %s has no build for %s", r.Version, u.platform)
	}
	sum, _, err := release.HashFile(u.self)
	if err != nil {
		return err
	}
	if sum != bin.SHA256 {
		return fmt.Errorf("this executable is not the signed %s build for %s", r.Version, u.platform)
	}
	if u.st.Running != u.version || u.st.RunningSequence < r.Sequence {
		u.st.Running, u.st.RunningSequence = u.version, r.Sequence
		u.mustSave()
		u.logf("update: running release %s is sequence %d", u.version, r.Sequence)
	}
	return nil
}

// establish makes sure the running release's sequence is known, from the control plane's signed record of it.
func (u *updater) establish() error {
	if u.st.Running == u.version && u.st.RunningSequence > 0 {
		return nil
	}
	status, body, err := u.cp("/agent/release/" + u.version)
	switch {
	case status == http.StatusNotFound || status == http.StatusNoContent:
		return fmt.Errorf("the control plane has no signed record of %s (install from a signed release)", u.version)
	case err != nil:
		return err
	}
	var o updateOffer
	if err := json.Unmarshal(body, &o); err != nil {
		return fmt.Errorf("release record of %s: %w", u.version, err)
	}
	r, err := u.verifyOffer(o)
	if err != nil {
		return fmt.Errorf("release record of %s: %w", u.version, err)
	}
	return u.adopt(r)
}

// -- check, prepare, activate --------------------------------------------------------------------------------------

// offer fetches the rollout target; nil without one.
func (u *updater) offer() (*updateOffer, *release.Record, *updateTarget, error) {
	status, body, err := u.cp("/agent/update?platform=" + u.platform + "&version=" + u.version)
	switch {
	case status == http.StatusNoContent || status == http.StatusNotFound: // 404: a control plane without updates
		return nil, nil, nil, nil
	case err != nil:
		return nil, nil, nil, err
	}
	var o updateOffer
	if err := json.Unmarshal(body, &o); err != nil {
		return nil, nil, nil, fmt.Errorf("update offer: %w", err)
	}
	t := &updateTarget{Rollout: o.Rollout, Version: "unverified"}
	r, err := u.verifyOffer(o)
	if err != nil {
		return &o, nil, t, err
	}
	t.Version, t.Sequence = r.Version, r.Sequence
	return &o, &r, t, nil
}

func (u *updater) reject(t updateTarget, format string, args ...any) {
	u.finish(updRejected, t, true, format, args...)
	u.mustSave()
	u.logf("update: %s", u.st.Result.Error)
}

func (u *updater) check(a *Agent) error {
	u.mu.Lock()
	running, done := u.running, u.done
	u.done = nil
	u.mu.Unlock()

	o, r, t, err := u.offer()
	u.target = t
	if o == nil {
		if err != nil {
			u.logf("update: cannot read the rollout target: %v", err)
		} else {
			u.transient = ""
		}
		return nil
	}
	key := targetKey(*t)
	if err != nil { // signature or record: never retried for this rollout
		if u.st.Result == nil || u.st.Result.Blocked != key {
			u.reject(*t, "release record refused: %v", err)
		}
		return nil
	}
	if r.Version == u.version {
		if err := u.adopt(*r); err != nil {
			u.logf("update: %v", err)
		}
		u.transient = ""
		return nil
	}
	if res := u.st.Result; res != nil && res.Blocked == key {
		return nil // rolled back or rejected before: wait for the operator to change the rollout
	}
	if err := u.establish(); err != nil {
		if u.transientErr == "" || !strings.Contains(u.transientErr, "not established") {
			u.logf("update: not moving to %s: the running release is not established: %v", r.Version, err)
		}
		u.transient, u.transientErr = updFailed, "running release not established: "+err.Error()
		return nil
	}
	if r.Sequence <= u.st.RunningSequence {
		u.reject(*t, "release sequence %d is not newer than the running release (%d)", r.Sequence, u.st.RunningSequence)
		return nil
	}
	bin, ok := r.Binaries[u.platform]
	if !ok {
		u.reject(*t, "incompatible: release %s has no build for %s", r.Version, u.platform)
		return nil
	}
	if done != nil && done.key == key {
		switch {
		case done.err == nil:
			sum, size, err := release.HashFile(releaseBinary(u.home, r.Version, u.platform))
			if err != nil || sum != bin.SHA256 || size != bin.Size {
				u.transient, u.transientErr = updFailed, "the staged binary no longer matches the signed release"
				return nil
			}
			return u.activate(a, *t)
		case done.reject:
			u.reject(*t, "incompatible: %v", done.err)
		default:
			u.transient, u.transientErr = updFailed, done.err.Error()
			u.logf("update: preparing %s failed, the current release keeps running: %v", r.Version, done.err)
		}
		return nil
	}
	if running == nil {
		job := &prepJob{key: key}
		u.mu.Lock()
		u.running = job
		u.mu.Unlock()
		u.logf("update: preparing %s (sequence %d, rollout %d) for %s in the background", r.Version, r.Sequence, t.Rollout, u.platform)
		go func(ver string) {
			job.err, job.reject = u.prepare(ver, bin)
			u.mu.Lock()
			u.running, u.done = nil, job
			u.mu.Unlock()
		}(r.Version)
	}
	u.transient, u.transientErr = updDownloading, ""
	return nil
}

// prepare downloads (unless already staged) and self-tests a candidate under <home>/releases/<version>/.
func (u *updater) prepare(ver string, bin release.Binary) (err error, reject bool) {
	path := releaseBinary(u.home, ver, u.platform)
	if sum, size, herr := release.HashFile(path); herr == nil && sum == bin.SHA256 && size == bin.Size {
		u.logf("update: %s is already staged", ver)
	} else if err := u.fetchBinary(ver, bin, path); err != nil {
		return fmt.Errorf("download: %w", err), false
	}
	if err := u.selfTest(path, ver); err != nil {
		os.RemoveAll(filepath.Dir(path))
		return err, true
	}
	return nil, false
}

// fetchBinary downloads into <path>.download and renames it to path once size and SHA-256 match.
func (u *updater) fetchBinary(ver string, bin release.Binary, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".download"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
	if err != nil {
		return err
	}
	h := sha256.New()
	err = u.download("/agent/update/"+ver+"/"+u.platform, io.MultiWriter(f, h), bin.Size)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if got := hex.EncodeToString(h.Sum(nil)); got != bin.SHA256 {
			err = fmt.Errorf("SHA-256 %s does not match the signed record", got)
		} else if info, serr := os.Stat(tmp); serr != nil || info.Size() != bin.Size {
			err = errors.New("size does not match the signed record")
		}
	}
	if err == nil {
		err = os.Chmod(tmp, 0o755)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// selfTest runs the candidate: it must start on this platform, be the signed version and accept our flags.
func (u *updater) selfTest(path, want string) error {
	out, err := runWithTimeout(30*time.Second, path, "version")
	if err != nil {
		return fmt.Errorf("does not run here: %v %s", err, truncateText(strings.TrimSpace(out), 200))
	}
	if strings.TrimSpace(out) != release.Product+" "+want {
		return fmt.Errorf("reports %q, expected version %s", truncateText(strings.TrimSpace(out), 100), want)
	}
	args := append([]string{"check-args"}, u.argv...)
	if out, err := runWithTimeout(30*time.Second, path, args...); err != nil {
		return fmt.Errorf("rejects this host's command line: %v %s", err, truncateText(strings.TrimSpace(out), 200))
	}
	return nil
}

func runWithTimeout(limit time.Duration, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return out.String(), err
	case <-time.After(limit):
		_ = cmd.Process.Kill()
		<-done
		return out.String(), fmt.Errorf("timed out after %s", limit)
	}
}

// activate records the candidate as the target; the launcher starts it once this process exits.
func (u *updater) activate(a *Agent, t updateTarget) error {
	st := &u.st
	st.Baseline = baselineOf(a)
	st.Phase, st.Target, st.Previous, st.PreviousSequence = phaseActivating, t, u.version, st.RunningSequence
	st.ActivatedAt, st.Starts = float64(u.now().Unix()), 0
	if err := saveUpdateFile(u.stateDir, *st); err != nil {
		st.Phase = phaseIdle
		u.transient, u.transientErr = updFailed, "cannot record the activation: "+err.Error()
		return nil
	}
	u.logf("update: activating %s (sequence %d, rollout %d) in place of %s; restarting", t.Version, t.Sequence, t.Rollout, u.version)
	return errRestartForUpdate
}
