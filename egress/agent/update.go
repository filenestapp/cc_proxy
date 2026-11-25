package main

// Managed automatic updates (docs/exit-agent-updates.md).
//
// Every --update-interval seconds the agent asks GET /agent/update for its rollout target. 204 means none: the
// host is not targeted, the rollout is paused, or there is no rollout. A target is a signed release record
// (egress/agent/release) with a rollout id. The agent moves to it only when all of these hold:
//
//   - the signature verifies against a key compiled into this binary (release_keys.txt);
//   - the record's sequence is higher than the release this agent runs (versions are source hashes, unordered);
//   - the record has a build for this platform, whose download matches its size and SHA-256;
//   - the candidate runs here: "<candidate> version" prints the record's version and "<candidate> check-args"
//     accepts this agent's command line;
//   - the rollout still targets the host after the download (a pause stops activation).
//
// Activation keeps a copy of the running binary as <exe>.previous, puts the candidate at <exe> with a rename, writes
// the update state and exits with status 75 so the service manager starts the new binary (systemd Restart=always,
// launchd KeepAlive, or --update-restart-cmd for the Windows scheduled task). The new binary confirms itself only
// after two consecutive healthy cycles: a heartbeat the control plane accepted, and sing-box (and, on XTCP hosts,
// frpc) at least as healthy as before the update. When it does not get there within --update-health-timeout, or
// when it has been started more than updateMaxStarts times without confirming, it puts <exe>.previous back and
// exits again; the previous binary reports the outcome "rolled_back". A rolled-back or rejected target is not tried
// again until the operator changes the rollout (a new rollout id).
//
// Enrollment (token), configuration, sing-box and frpc files and services are never touched: only <exe> changes.
// The heartbeat carries "agent_version" and an "update" object (updateReport).

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
	"time"

	"github.com/filenestapp/cc_proxy/egress/agent/release"
)

//go:embed release_keys.txt
var embeddedReleaseKeys string

// extraReleaseKeys adds trusted keys at build time (-ldflags "-X main.extraReleaseKeys=ed25519:..."), for test
// builds; production keys belong in release_keys.txt.
var extraReleaseKeys = ""

const (
	exitForUpdate   = 75 // EX_TEMPFAIL: the service manager starts the agent again
	updateMaxStarts = 3  // starts of a candidate without confirming before it is rolled back
	updateHealthy   = 2  // consecutive healthy cycles that confirm a candidate
	updateStateFile = "update-state.json"

	// Phases persisted across restarts.
	phaseIdle        = ""
	phaseActivating  = "activating"
	phaseConfirming  = "confirming"
	phaseRollingBack = "rolling_back"

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

type updateTarget struct {
	Version  string `json:"version"`
	Sequence int64  `json:"sequence"`
	Rollout  int64  `json:"rollout"`
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

// updateFile is update-state.json in --state-dir.
type updateFile struct {
	Phase            string         `json:"phase"`
	Running          string         `json:"running_version"` // the version last confirmed (or found) running
	RunningSequence  int64          `json:"running_sequence"`
	Target           updateTarget   `json:"target"`
	Previous         string         `json:"previous_version"`
	PreviousSequence int64          `json:"previous_sequence"`
	ActivatedAt      float64        `json:"activated_at"`
	Starts           int            `json:"starts"`
	Interrupted      int            `json:"interrupted"`
	Baseline         updateBaseline `json:"baseline"`
	Result           *updateResult  `json:"result,omitempty"`
}

// updateOffer is the 200 answer of GET /agent/update.
type updateOffer struct {
	Rollout   int64  `json:"rollout_id"`
	Record    string `json:"release"`   // release.json, byte for byte
	Signature string `json:"signature"` // release.json.sig
}

type updater struct {
	stateDir, exe, platform, version string
	argv                             []string // this agent's command line, for the candidate's check-args
	keys                             []ed25519.PublicKey
	disabled                         string
	interval, healthTimeout          time.Duration
	restartCmd                       string
	st                               updateFile
	lastCheck                        time.Time
	healthyCycles                    int
	transient, transientErr          string // current check's state when no result is newer
	target                           *updateTarget
	logf                             func(string, ...any)
	now                              func() time.Time
	cp                               func(path string) (int, []byte, error) // GET with the agent token
	download                         func(path string, w io.Writer, limit int64) error
}

// newUpdater sets up updates for this process. A disabled updater still answers report() and onStart().
func newUpdater(o Options, argv []string, logf func(string, ...any)) *updater {
	u := &updater{stateDir: o.StateDir, platform: runtime.GOOS + "-" + runtime.GOARCH, version: version, argv: argv,
		interval:      time.Duration(o.UpdateInterval * float64(time.Second)),
		healthTimeout: time.Duration(o.UpdateHealthTimeout * float64(time.Second)),
		restartCmd:    o.UpdateRestartCmd, logf: logf, now: time.Now}
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
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.EvalSymlinks(exe)
	}
	if err != nil && u.disabled == "" {
		u.disabled = "cannot locate this binary: " + err.Error()
	}
	u.exe = exe
	u.load()
	return u
}

func (u *updater) path() string { return filepath.Join(u.stateDir, updateStateFile) }

func (u *updater) load() {
	data, err := os.ReadFile(u.path())
	if err != nil {
		return
	}
	var st updateFile
	if json.Unmarshal(data, &st) != nil {
		u.logf("update: ignoring unreadable %s", u.path())
		return
	}
	u.st = st
}

func (u *updater) save() error {
	data, err := json.MarshalIndent(u.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(u.stateDir, 0o700); err != nil {
		return err
	}
	tmp, err := writeTemp(u.stateDir, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, u.path()); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func (u *updater) mustSave() {
	if err := u.save(); err != nil {
		u.logf("update: cannot write %s: %v", u.path(), err)
	}
}

func targetKey(t updateTarget) string {
	return fmt.Sprintf("%d:%d:%s", t.Rollout, t.Sequence, t.Version)
}

func (u *updater) finish(state string, target updateTarget, block bool, format string, args ...any) {
	r := &updateResult{State: state, Target: target, Error: fmt.Sprintf(format, args...), At: float64(u.now().Unix())}
	if block {
		r.Blocked = targetKey(target)
	}
	u.st.Result = r
	u.transient, u.transientErr = "", ""
}

// -- start ---------------------------------------------------------------------------------------------------------

// onStart runs first in every agent process, before anything that could fail. True means: exit for a restart now
// (a candidate that failed too often was rolled back).
func (u *updater) onStart() bool {
	for _, leftover := range []string{u.exe + ".download", u.exe + ".replaced", u.exe + ".restore"} {
		os.Remove(leftover) // best effort; Windows keeps a running image's old name until it exits
	}
	st := &u.st
	switch st.Phase {
	case phaseActivating, phaseConfirming:
		switch u.version {
		case st.Target.Version:
			st.Phase = phaseConfirming
			st.Starts++
			u.mustSave()
			elapsed := u.now().Sub(time.Unix(int64(st.ActivatedAt), 0))
			if st.Starts > updateMaxStarts {
				return u.rollback(fmt.Sprintf("started %d times without reporting healthy", st.Starts-1))
			}
			if elapsed > u.healthTimeout {
				return u.rollback(fmt.Sprintf("not healthy within %s", u.healthTimeout))
			}
			u.logf("update: running candidate %s (start %d), confirming its health", u.version, st.Starts)
		case st.Previous:
			// The swap did not take effect (stopped mid-activation). Not the candidate's fault: retry, a few times.
			st.Interrupted++
			block := st.Interrupted >= updateMaxStarts
			u.finish(updFailed, st.Target, block, "activation of %s was interrupted", st.Target.Version)
			st.Phase = phaseIdle
			u.mustSave()
			u.logf("update: %s", st.Result.Error)
		default:
			u.installedExternally()
		}
	case phaseRollingBack:
		switch u.version {
		case st.Previous:
			st.Phase, st.Running, st.RunningSequence = phaseIdle, st.Previous, st.PreviousSequence
			u.mustSave()
			u.logf("update: back on %s after rolling back %s: %s", u.version, st.Target.Version, u.resultError())
		case st.Target.Version:
			return u.rollback(u.resultError()) // the restore did not take effect: try again
		default:
			u.installedExternally()
		}
	default:
		if st.Running != u.version {
			u.installedExternally()
		}
	}
	return false
}

func (u *updater) resultError() string {
	if u.st.Result == nil {
		return ""
	}
	return u.st.Result.Error
}

// installedExternally: this binary was put in place by the installer (or by hand), not by an update in progress.
func (u *updater) installedExternally() {
	if u.st.Running != "" || u.st.Phase != phaseIdle {
		u.logf("update: %s was installed outside an update; starting from it", u.version)
	}
	u.st = updateFile{Running: u.version, Result: u.st.Result}
	u.mustSave()
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
	case u.st.Phase == phaseConfirming:
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

// tick runs after each heartbeat. errRestartForUpdate means: exit now so the service manager runs <exe>.
func (u *updater) tick(a *Agent, reportErr error) error {
	if u.disabled != "" {
		return nil
	}
	if u.st.Phase == phaseConfirming {
		return u.confirm(a, reportErr)
	}
	if !u.lastCheck.IsZero() && u.now().Sub(u.lastCheck) < u.interval {
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
	if u.healthyCycles >= updateHealthy {
		st := &u.st
		st.Phase, st.Running, st.RunningSequence, st.Starts, st.Interrupted = phaseIdle, st.Target.Version, st.Target.Sequence, 0, 0
		u.finish(updUpdated, st.Target, false, "")
		u.mustSave()
		u.logf("update: %s (sequence %d) confirmed healthy; previous release %s stays at %s.previous",
			st.Target.Version, st.Target.Sequence, st.Previous, filepath.Base(u.exe))
		return nil
	}
	if u.now().Sub(time.Unix(int64(u.st.ActivatedAt), 0)) > u.healthTimeout {
		if problem == "" {
			problem = "not confirmed in time"
		}
		if u.rollback(fmt.Sprintf("not healthy within %s: %s", u.healthTimeout, problem)) {
			return errRestartForUpdate
		}
	}
	return nil
}

// rollback puts <exe>.previous back at <exe>. True when the agent must exit so the previous release starts.
func (u *updater) rollback(reason string) bool {
	st := &u.st
	u.logf("update: rolling back %s to %s: %s", st.Target.Version, st.Previous, reason)
	u.finish(updRolledBack, st.Target, true, "%s", reason)
	st.Phase = phaseRollingBack
	u.mustSave()
	if err := u.restorePrevious(); err != nil {
		// Keep running the candidate rather than leave no binary: report it and let the operator decide.
		st.Phase = phaseIdle
		st.Running, st.RunningSequence = st.Target.Version, st.Target.Sequence
		u.finish(updFailed, st.Target, true, "rollback failed (%v) after: %s", err, reason)
		u.mustSave()
		u.logf("update: %s", st.Result.Error)
		return false
	}
	return true
}

func (u *updater) restorePrevious() error {
	prev := u.exe + ".previous"
	if !isRegular(prev) {
		return fmt.Errorf("%s is missing", prev)
	}
	tmp := u.exe + ".restore"
	if err := copyFile(prev, tmp, 0o755); err != nil {
		return err
	}
	return replaceExecutable(tmp, u.exe)
}

// -- check, download, activate -------------------------------------------------------------------------------------

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
	t := &updateTarget{Rollout: o.Rollout}
	if err := release.Verify(u.keys, []byte(o.Record), o.Signature); err != nil {
		t.Version = "unverified"
		return &o, nil, t, err
	}
	r, err := release.Parse([]byte(o.Record))
	if err != nil {
		t.Version = "unverified"
		return &o, nil, t, err
	}
	t.Version, t.Sequence = r.Version, r.Sequence
	return &o, &r, t, nil
}

func (u *updater) check(a *Agent) error {
	o, r, t, err := u.offer()
	u.target = t
	if o == nil && err != nil {
		u.logf("update: cannot read the rollout target: %v", err)
		return nil
	}
	if o == nil {
		u.transient = ""
		return nil
	}
	if err != nil { // signature or record: never retried for this rollout
		if u.st.Result == nil || u.st.Result.Blocked != targetKey(*t) {
			u.finish(updRejected, *t, true, "release record refused: %v", err)
			u.mustSave()
			u.logf("update: %s", u.st.Result.Error)
		}
		return nil
	}
	if r.Version == u.version {
		if u.st.RunningSequence < r.Sequence {
			u.st.Running, u.st.RunningSequence = u.version, r.Sequence
			u.mustSave()
		}
		u.transient = ""
		return nil
	}
	if res := u.st.Result; res != nil && res.Blocked == targetKey(*t) {
		return nil // rolled back or rejected before: wait for the operator to change the rollout
	}
	if u.st.RunningSequence > 0 && r.Sequence <= u.st.RunningSequence {
		u.finish(updRejected, *t, true, "release sequence %d is not newer than the running release (%d)", r.Sequence, u.st.RunningSequence)
		u.mustSave()
		u.logf("update: %s", u.st.Result.Error)
		return nil
	}
	bin, ok := r.Binaries[u.platform]
	if !ok {
		u.finish(updRejected, *t, true, "incompatible: release %s has no build for %s", r.Version, u.platform)
		u.mustSave()
		u.logf("update: %s", u.st.Result.Error)
		return nil
	}
	u.transient, u.transientErr = updDownloading, ""
	staged := u.exe + ".candidate"
	if sum, size, err := release.HashFile(staged); err != nil || sum != bin.SHA256 || size != bin.Size {
		u.logf("update: downloading %s (sequence %d, rollout %d) for %s", r.Version, r.Sequence, t.Rollout, u.platform)
		if err := u.fetchBinary(r.Version, bin, staged); err != nil {
			u.transient, u.transientErr = updFailed, "download: "+err.Error()
			u.logf("update: download of %s failed, the current release keeps running: %v", r.Version, err)
			return nil
		}
	}
	if err := u.selfTest(staged, r.Version); err != nil {
		os.Remove(staged)
		u.finish(updRejected, *t, true, "incompatible: %v", err)
		u.mustSave()
		u.logf("update: candidate %s refused: %v", r.Version, err)
		return nil
	}
	// A rollout paused or changed while the binary downloaded is not activated.
	o2, _, t2, err := u.offer()
	if err != nil || o2 == nil || targetKey(*t2) != targetKey(*t) {
		u.transient = ""
		u.logf("update: rollout changed during the download; %s stays staged, not activated", r.Version)
		return nil
	}
	return u.activate(a, *t, staged)
}

// fetchBinary downloads into <exe>.download and renames it to dst once size and SHA-256 match.
func (u *updater) fetchBinary(ver string, bin release.Binary, dst string) error {
	tmp := u.exe + ".download"
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
		err = os.Rename(tmp, dst)
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

func (u *updater) activate(a *Agent, t updateTarget, staged string) error {
	st := &u.st
	st.Baseline = baselineOf(a)
	st.Phase, st.Target, st.Previous, st.PreviousSequence = phaseActivating, t, u.version, st.RunningSequence
	st.ActivatedAt, st.Starts = float64(u.now().Unix()), 0
	if err := u.save(); err != nil {
		st.Phase = phaseIdle
		u.transient, u.transientErr = updFailed, "cannot record the activation: "+err.Error()
		return nil
	}
	fail := func(err error) error {
		st.Phase = phaseIdle
		u.transient, u.transientErr = updFailed, "activation: "+err.Error()
		u.mustSave()
		u.logf("update: activation of %s failed, the current release keeps running: %v", t.Version, err)
		return nil
	}
	if err := copyFile(u.exe, u.exe+".previous.tmp", 0o755); err != nil {
		return fail(err)
	}
	if err := os.Rename(u.exe+".previous.tmp", u.exe+".previous"); err != nil {
		os.Remove(u.exe + ".previous.tmp")
		return fail(err)
	}
	if err := replaceExecutable(staged, u.exe); err != nil {
		return fail(err)
	}
	u.logf("update: activated %s (sequence %d, rollout %d) in place of %s; restarting through the service manager",
		t.Version, t.Sequence, t.Rollout, u.version)
	return errRestartForUpdate
}

// copyFile copies src to dst (replaced), synced, with mode.
func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(dst, mode)
	}
	if err != nil {
		os.Remove(dst)
	}
	return err
}

// replaceExecutable moves src to dst. A running image cannot be replaced on Windows, but it can be renamed:
// the old file moves aside to <dst>.replaced (removed at the next start) first.
func replaceExecutable(src, dst string) error {
	if isWindows() {
		os.Remove(dst + ".replaced")
		if err := os.Rename(dst, dst+".replaced"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			_ = os.Rename(dst+".replaced", dst) // put the old one back
			return err
		}
		return nil
	}
	return os.Rename(src, dst)
}

// restartForUpdate runs --update-restart-cmd detached (Windows: the scheduled task is ended and started again on the
// new file). Without it the exit status alone makes the service manager restart the agent.
func (u *updater) restartForUpdate() {
	if u.restartCmd == "" {
		return
	}
	argv, err := splitCommand(u.restartCmd)
	if err != nil {
		u.logf("update: --update-restart-cmd: %v", err)
		return
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	detach(cmd)
	if err := cmd.Start(); err != nil {
		u.logf("update: %s: %v", u.restartCmd, err)
		return
	}
	_ = cmd.Process.Release()
	u.logf("update: started %s", u.restartCmd)
}
