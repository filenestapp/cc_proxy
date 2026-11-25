//go:build !windows

package main

import (
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

// detach: the restart helper outlives the agent (its own session, no controlling terminal).
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
