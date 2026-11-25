//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

const canHangup = true

func isWindows() bool { return false }

func (c *child) hangup() error { return c.cmd.Process.Signal(syscall.SIGHUP) }

func terminate(p *os.Process) error { return p.Signal(syscall.SIGTERM) }

func configureChild(cmd *exec.Cmd) { configureChildOS(cmd) }

// cleanupStaleChild: on Unix the --run mode is for containers and tests; Linux children die with the agent
// (Pdeathsig), so there is nothing to clean up.
func cleanupStaleChild(stateDir, singbox string, logf func(string, ...any)) {}

// enterKillJob and runChildWait are the Windows launcher's; on Unix the launcher execs the chosen release.
func enterKillJob() error { return nil }

func runChildWait(path string, argv, env []string) (int, error) {
	return 0, errors.New("the Unix launcher execs the release")
}
