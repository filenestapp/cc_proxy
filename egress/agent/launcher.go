package main

// The stable launcher (docs/exit-agent-updates.md).
//
// The service (systemd unit, launchd daemon, Windows scheduled task) always runs the binary the installer put at
// <bin>/ccproxy-exit-agent. Automatic updates never replace that file: a new release goes to
// <bin>/releases/<version>/ and the launcher decides at every start which binary runs, from update-state.json:
//
//   - idle: the release in "running_version", or the launcher itself;
//   - a candidate being confirmed: the candidate, after counting this start. A candidate that was started more than
//     updateMaxStarts times, whose health deadline passed, whose file is missing, or that cannot be executed at all is
//     rolled back here, before it runs, so a candidate that dies before reaching its own startup code (a crash in the
//     Go runtime or in package initialization, a corrupt or foreign executable) is still restored.
//
// On Unix the launcher replaces itself with the chosen binary (exec: the service manager keeps the same main PID
// and restarts the launcher whenever the agent exits). Windows has no exec: the launcher runs the chosen binary as
// a child in a kill-on-close job object and starts the next choice itself when the child exits for an update, or
// after a crash (5 s later), so it does not rely on Task Scheduler restarting a failed task.
//
// The launcher's own version is recorded as "launcher_version". When the installer puts a different launcher in
// place, the state starts over from it (the operator's choice) and old releases are removed.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/filenestapp/cc_proxy/egress/agent/release"
)

const (
	envRelease = "CCPROXY_EXIT_AGENT_RELEASE" // set for a binary started by the launcher: run, do not launch again
	envHome    = "CCPROXY_EXIT_AGENT_HOME"    // the launcher's directory (where releases/ lives)
)

type launcher struct {
	stateDir, home, self, version, platform string
	healthTimeout                           time.Duration
	skipPending                             bool
	logf                                    func(string, ...any)
	now                                     func() time.Time
}

func releaseBinary(home, ver, platform string) string {
	return filepath.Join(home, "releases", ver, release.FileName(platform))
}

func (l *launcher) binary(ver string) string {
	if !release.ValidVersion(ver) {
		return ""
	}
	return releaseBinary(l.home, ver, l.platform)
}

func (l *launcher) load() updateFile { return loadUpdateFile(l.stateDir, l.logf) }

func (l *launcher) save(st updateFile) bool {
	if err := saveUpdateFile(l.stateDir, st); err != nil {
		l.logf("launcher: cannot write the update state: %v", err)
		return false
	}
	return true
}

// choose returns the binary to run now: "" for the launcher itself.
func (l *launcher) choose() (path, ver string) {
	st := l.load()
	if st.Launcher != l.version {
		previous := st.Launcher
		st = updateFile{Launcher: l.version, Running: l.version, Result: st.Result}
		if !l.save(st) {
			return "", l.version
		}
		if previous != "" {
			l.logf("launcher: %s replaced launcher %s; running it and removing staged releases", l.version, previous)
			if err := os.RemoveAll(filepath.Join(l.home, "releases")); err != nil {
				l.logf("launcher: cannot remove staged releases: %v", err)
			}
		}
	}
	if l.skipPending && (st.Phase == phaseActivating || st.Phase == phaseConfirming) {
		st.rollback(l.now(), "automatic updates are disabled")
		l.save(st)
	}
	switch st.Phase {
	case phaseActivating, phaseConfirming:
		st.Phase = phaseConfirming
		st.Starts++
		elapsed := l.now().Sub(time.Unix(int64(st.ActivatedAt), 0))
		switch {
		case !isRegular(l.binary(st.Target.Version)):
			st.rollback(l.now(), fmt.Sprintf("the candidate's file %s is missing", l.binary(st.Target.Version)))
		case st.Starts > updateMaxStarts:
			st.rollback(l.now(), fmt.Sprintf("started %d times without reporting healthy", st.Starts-1))
		case elapsed > l.healthTimeout:
			st.rollback(l.now(), fmt.Sprintf("not healthy within %s", l.healthTimeout))
		default:
			if !l.save(st) {
				return l.confirmedRelease(st)
			}
			l.logf("launcher: starting candidate %s (start %d of %d)", st.Target.Version, st.Starts, updateMaxStarts)
			return l.binary(st.Target.Version), st.Target.Version
		}
		l.logf("launcher: rolled back %s to %s: %s", st.Target.Version, st.Running, st.Result.Error)
		l.save(st)
	}
	return l.confirmedRelease(st)
}

func (l *launcher) confirmedRelease(st updateFile) (path, ver string) {
	if st.Running == "" || st.Running == l.version {
		return "", l.version
	}
	if p := l.binary(st.Running); isRegular(p) {
		return p, st.Running
	}
	l.logf("launcher: release %s is missing; running the launcher's own release %s", st.Running, l.version)
	st.Running, st.RunningSequence = l.version, 0
	l.save(st)
	return "", l.version
}

// cannotStart: executing ver failed outright (missing, corrupt, wrong platform). The next choice will differ.
func (l *launcher) cannotStart(ver string, err error) bool {
	st := l.load()
	reason := fmt.Sprintf("cannot start %s: %v", ver, err)
	switch {
	case st.Phase == phaseConfirming && st.Target.Version == ver:
		st.rollback(l.now(), reason)
	case st.Running == ver:
		st.Running, st.RunningSequence = l.version, 0
		st.Result = &updateResult{State: updFailed, Target: updateTarget{Version: ver}, Error: reason, At: float64(l.now().Unix())}
	}
	l.logf("launcher: %s", reason)
	return l.save(st)
}

// launch is the first thing a service start runs. It returns (code, true) when the caller should run the agent in
// this process (Unix: the launcher's own release, or the release it was started as), else the exit code.
func launch(argv []string) (int, bool) {
	if os.Getenv(envRelease) != "" {
		return 0, true
	}
	c, err := parseArgs(argv, io.Discard)
	if err != nil || c.Once {
		return 0, true // run reports the error; --once never updates
	}
	self, err := os.Executable()
	if err == nil {
		self, err = filepath.EvalSymlinks(self)
	}
	if err != nil {
		return 0, true
	}
	logw := io.Writer(os.Stderr)
	if c.logFile != "" {
		if f, err := os.OpenFile(c.logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err == nil {
			defer f.Close()
			logw = f
		}
	}
	l := &launcher{stateDir: c.StateDir, home: filepath.Dir(self), self: self, version: version,
		platform: currentPlatform(), healthTimeout: time.Duration(c.UpdateHealthTimeout * float64(time.Second)),
		skipPending: c.Update == "off", now: time.Now,
		logf: func(format string, a ...any) {
			fmt.Fprintf(logw, "%s %s\n", time.Now().Format("2006-01-02T15:04:05"), fmt.Sprintf(format, a...))
		}}
	if isWindows() {
		if err := enterKillJob(); err != nil {
			l.logf("launcher: cannot create a job object (a stopped task may leave the agent running): %v", err)
		}
	}
	for {
		path, ver := l.choose()
		env := append(withoutLaunchEnv(os.Environ()), envRelease+"="+ver, envHome+"="+l.home)
		if !isWindows() {
			if path == "" {
				return 0, true
			}
			err := syscall.Exec(path, append([]string{path}, argv...), env)
			if !l.cannotStart(ver, err) { // Exec returns only on failure.
				return 0, true
			}
			continue
		}
		own := path == ""
		if own {
			path = self
		}
		code, err := runChildWait(path, argv, env)
		switch {
		case err != nil && own:
			l.logf("launcher: cannot run the agent: %v", err)
			return 1, false
		case err != nil:
			if !l.cannotStart(ver, err) {
				return 0, true
			}
		case code == exitForUpdate:
		case code == 0:
			return 0, false
		case own:
			return code, false // the launcher's own release failing (bad flags...) behaves as before
		default:
			l.logf("launcher: %s exited with %d; starting again in 5 s", ver, code)
			time.Sleep(5 * time.Second)
		}
	}
}

func withoutLaunchEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, envRelease+"=") && !strings.HasPrefix(kv, envHome+"=") {
			out = append(out, kv)
		}
	}
	return out
}

var errNoHome = errors.New("unknown agent home")

// agentHome is the launcher's directory, as the launcher passed it, or this binary's directory.
func agentHome() (string, error) {
	if h := os.Getenv(envHome); h != "" {
		return h, nil
	}
	self, err := os.Executable()
	if err != nil {
		return "", errNoHome
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return "", errNoHome
	}
	return filepath.Dir(self), nil
}
