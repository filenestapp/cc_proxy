//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// Windows has no SIGHUP: --run applies a new config by stopping sing-box and starting it again.
const canHangup = false

func isWindows() bool { return true }

func (c *child) hangup() error { return errors.New("SIGHUP is not available on Windows") }

// terminate: Windows has no polite stop for a console process without a console; kill() follows at once.
func terminate(p *os.Process) error { return errors.New("no graceful stop on Windows") }

func configureChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	queryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
)

const (
	processTerminate               = 0x0001
	processQueryLimitedInformation = 0x1000
)

func imagePath(h syscall.Handle) string {
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	r, _, _ := queryFullProcessImageName.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

// cleanupStaleChild stops a sing-box left running by an earlier agent process (the scheduled task was ended, or
// the agent crashed): Windows does not end children with their parent, and the orphan would hold the ports.
// Only a process whose image is this --singbox is stopped, so a reused pid is never touched.
func cleanupStaleChild(stateDir, singbox string, logf func(string, ...any)) {
	data, err := os.ReadFile(filepath.Join(stateDir, "sing-box.pid"))
	if err != nil {
		return
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return
	}
	h, err := syscall.OpenProcess(processTerminate|processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return
	}
	defer syscall.CloseHandle(h)
	want, _ := filepath.Abs(singbox)
	if got := imagePath(h); got == "" || !strings.EqualFold(filepath.Clean(got), filepath.Clean(want)) {
		return
	}
	if syscall.TerminateProcess(h, 1) == nil {
		logf("stopped sing-box pid %d left over from an earlier agent run", pid)
	}
}
