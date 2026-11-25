package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// activated returns an env whose agent has just activated "agent-new" (staged, not started yet).
func activated(t *testing.T) *updateEnv {
	t.Helper()
	e := newUpdateEnv(t)
	e.publish("agent-new", 7, 1, nil)
	if err := e.activate(); err != errRestartForUpdate {
		t.Fatalf("activation: %v", err)
	}
	return e
}

func (e *updateEnv) wantRolledBack(reason string) {
	e.t.Helper()
	st := loadUpdateFile(e.stateDir, e.t.Logf)
	if st.Phase != phaseIdle || st.Running != "agent-old" || st.RunningSequence != 1 || st.Result == nil ||
		st.Result.State != updRolledBack || !strings.Contains(st.Result.Error, reason) || st.Result.Blocked == "" {
		e.t.Fatalf("want a rollback to agent-old (%q), state %+v result %+v", reason, st, st.Result)
	}
	// The previous release reports it.
	e.u = e.updaterAs("agent-old", e.self)
	e.cycle()
	if got := e.lastUpdate(); got["state"] != updRolledBack || !strings.Contains(got["error"].(string), reason) {
		e.t.Fatalf("reported %v", got)
	}
}

// A candidate that dies before its own startup code (runtime or init crash) never records anything itself: the
// launcher counts the starts and restores the previous release.
func TestLauncherRollsBackCandidateThatNeverStarts(t *testing.T) {
	e := activated(t)
	l := e.launcher()
	for start := 1; start <= updateMaxStarts; start++ {
		path, ver := l.choose()
		if path != e.staged("agent-new") || ver != "agent-new" {
			t.Fatalf("start %d: chose %q", start, path)
		}
		// ... the process dies at once; the service manager starts the launcher again.
	}
	if path, ver := l.choose(); path != "" || ver != "agent-old" {
		t.Fatalf("after %d starts the launcher must run itself, chose %q", updateMaxStarts, path)
	}
	e.wantRolledBack("started 3 times without reporting healthy")
	e.launcherUnchanged()
}

func TestLauncherRollsBackCandidateThatCannotBeExecuted(t *testing.T) {
	e := activated(t)
	l := e.launcher()
	path, ver := l.choose()
	// exec(2) fails: a corrupt file, another platform's build ("exec format error").
	l.cannotStart(ver, errors.New("exec format error"))
	if p, v := l.choose(); p != "" || v != "agent-old" {
		t.Fatalf("after %s could not start the launcher must run itself, chose %q", path, p)
	}
	e.wantRolledBack("cannot start agent-new: exec format error")
}

// Stopped after recording the activation, with the candidate's file gone (a disk cleanup, a half-written
// directory): there is no rename to interrupt, and the launcher falls back at once.
func TestLauncherRollsBackWhenTheCandidateFileIsMissing(t *testing.T) {
	e := activated(t)
	os.RemoveAll(filepath.Dir(e.staged("agent-new")))
	if p, _ := e.launcher().choose(); p != "" {
		t.Fatalf("chose %q", p)
	}
	e.wantRolledBack("is missing")
}

func TestLauncherDoesNotStartAPendingCandidateWhenUpdatesAreDisabled(t *testing.T) {
	e := activated(t)
	l := e.launcher()
	l.skipPending = true
	if path, ver := l.choose(); path != "" || ver != "agent-old" {
		t.Fatalf("updates disabled, chose %q %q", path, ver)
	}
	e.wantRolledBack("automatic updates are disabled")
}

func TestLauncherKeepsConfirmedReleaseIfItCannotRecordAStart(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged test process")
	}
	e := activated(t)
	if err := os.Chmod(e.stateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.stateDir, 0o700) })
	if path, ver := e.launcher().choose(); path != "" || ver != "agent-old" {
		t.Fatalf("unrecorded candidate must not start: %q %q", path, ver)
	}
	if st := loadUpdateFile(e.stateDir, t.Logf); st.Starts != 0 || st.Phase != phaseActivating {
		t.Fatalf("recorded state changed after a failed write: %+v", st)
	}
}

func TestLauncherRollsBackAfterTheHealthDeadline(t *testing.T) {
	e := activated(t)
	e.launcher().choose()
	e.clock = e.clock.Add(11 * time.Minute) // the candidate hung, then the host restarted
	if p, _ := e.launcher().choose(); p != "" {
		t.Fatalf("chose %q", p)
	}
	e.wantRolledBack("not healthy within 10m0s")
}

func TestLauncherRunsTheConfirmedReleaseAndFallsBackWhenItIsGone(t *testing.T) {
	e := activated(t)
	e.launcher().choose()
	e.u = e.updaterAs("agent-new", e.staged("agent-new"))
	e.cycle()
	e.cycle()
	if p, v := e.launcher().choose(); p != e.staged("agent-new") || v != "agent-new" {
		t.Fatalf("confirmed release: chose %q", p)
	}
	os.RemoveAll(filepath.Join(e.home, "releases"))
	if p, v := e.launcher().choose(); p != "" || v != "agent-old" {
		t.Fatalf("missing release: chose %q", p)
	}
	if st := loadUpdateFile(e.stateDir, t.Logf); st.Running != "agent-old" || st.RunningSequence != 0 {
		t.Fatalf("state %+v", st)
	}
}

// The installer replaced the launcher (an operator's rerun): it runs, and staged releases go.
func TestLauncherStartsOverWhenTheInstallerReplacedIt(t *testing.T) {
	e := activated(t)
	l := e.launcher()
	l.version = "agent-installed-by-hand"
	if p, v := l.choose(); p != "" || v != "agent-installed-by-hand" {
		t.Fatalf("chose %q", p)
	}
	st := loadUpdateFile(e.stateDir, t.Logf)
	if st.Launcher != "agent-installed-by-hand" || st.Phase != phaseIdle || st.Running != "agent-installed-by-hand" {
		t.Fatalf("state %+v", st)
	}
	if _, err := os.Stat(filepath.Join(e.home, "releases")); err == nil {
		t.Fatal("staged releases kept after the launcher changed")
	}
}

func TestLaunchEnvironmentIsNotInherited(t *testing.T) {
	env := withoutLaunchEnv([]string{"PATH=/bin", envRelease + "=agent-x", envHome + "=/opt", "HOME=/root"})
	if strings.Join(env, " ") != "PATH=/bin HOME=/root" {
		t.Fatalf("env %v", env)
	}
}
