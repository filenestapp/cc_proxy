//go:build linux

package main

import (
	"os/exec"
	"syscall"
)

func configureChildOS(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}
