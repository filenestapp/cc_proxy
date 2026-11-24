package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// child is a sing-box started by --run. Wait runs in the background so alive() never blocks.
type child struct {
	cmd  *exec.Cmd
	done chan struct{}
	mu   sync.Mutex
	code int
}

func startChild(singbox, config, stateDir string, output io.Writer) (*child, error) {
	cmd := exec.Command(singbox, "run", "-c", config, "-D", stateDir)
	if output != nil {
		cmd.Stdout, cmd.Stderr = output, output
	} else {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	}
	configureChild(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan struct{})}
	// Remember the pid: a restarted agent stops an orphaned sing-box before starting its own.
	_ = os.WriteFile(filepath.Join(stateDir, "sing-box.pid"), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600)
	go func() {
		err := cmd.Wait()
		code := 0
		if err != nil {
			code = -1
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			}
		}
		c.mu.Lock()
		c.code = code
		c.mu.Unlock()
		close(c.done)
	}()
	return c, nil
}

func (c *child) pid() int { return c.cmd.Process.Pid }

func (c *child) alive() bool {
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}

func (c *child) exitCode() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.code
}

// stop asks the child to exit (SIGTERM where available), then kills it after grace.
func (c *child) stop(grace time.Duration) {
	if !c.alive() {
		return
	}
	if terminate(c.cmd.Process) == nil {
		select {
		case <-c.done:
			return
		case <-time.After(grace):
		}
	}
	_ = c.cmd.Process.Kill()
	<-c.done
}
