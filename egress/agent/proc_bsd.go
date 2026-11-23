//go:build !windows && !linux

package main

import "os/exec"

func configureChildOS(cmd *exec.Cmd) {}
