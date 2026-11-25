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

var (
	createJobObject          = kernel32.NewProc("CreateJobObjectW")
	setInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	assignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
)

const (
	jobObjectExtendedLimitInformation = 9
	jobObjectLimitKillOnJobClose      = 0x2000
	jobObjectLimitBreakawayOK         = 0x800
)

type ioCounters struct {
	ReadOperationCount, WriteOperationCount, OtherOperationCount uint64
	ReadTransferCount, WriteTransferCount, OtherTransferCount    uint64
}

type jobBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobExtendedLimitInformation struct {
	BasicLimitInformation jobBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// enterKillJob puts the launcher in a job object that ends every process in it when its last handle closes: when
// the scheduled task is ended (or the launcher dies), the agent and its sing-box end too, as they did when the agent
// was the task's process. The handle is deliberately never closed.
func enterKillJob() error {
	job, _, err := createJobObject.Call(0, 0)
	if job == 0 {
		return err
	}
	info := jobExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose | jobObjectLimitBreakawayOK
	if r, _, err := setInformationJobObject.Call(job, jobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info)); r == 0 {
		return err
	}
	self, _ := syscall.GetCurrentProcess()
	if r, _, err := assignProcessToJobObject.Call(job, uintptr(self)); r == 0 {
		return err
	}
	return nil
}

// runChildWait runs the chosen release with the launcher's arguments and waits for it (Windows has no exec).
func runChildWait(path string, argv, env []string) (int, error) {
	cmd := exec.Command(path, argv...)
	cmd.Env, cmd.Stdout, cmd.Stderr = env, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	err := cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	return 0, err
}
