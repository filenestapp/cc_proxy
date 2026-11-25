package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/filenestapp/cc_proxy/egress/agent/release"
)

// TestUpdateWithRealBinaries runs compiled agents the way a service manager does (restart whenever the process
// exits) against the fake control plane, with sing-box as a separate long-lived process reloaded by --reload-cmd
// (the Linux and macOS installation). It checks that:
//
//   - v1 moves to v2 by itself, through the normal service loop, and reports agent_version v2 and "updated";
//   - sing-box is neither reloaded nor restarted by the upgrade (the new agent adopts the confirmed config);
//   - a v3 whose heartbeats fail is rolled back to v2 after --update-health-timeout, and v2 reports it.
func TestUpdateWithRealBinaries(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("builds three agents and waits for a health timeout (about 90 s); POSIX only")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	build := t.TempDir()
	bins := map[string][]byte{}
	for _, v := range []string{"agent-it-v1", "agent-it-v2", "agent-it-v3"} {
		out := filepath.Join(build, v)
		cmd := exec.Command("go", "build", "-trimpath", "-o", out, "-ldflags",
			"-X main.version="+v+" -X main.extraReleaseKeys="+release.FormatPublicKey(pub), ".")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if msg, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", v, err, msg)
		}
		bins[v], _ = os.ReadFile(out)
	}

	cp := newFakeCP(t)
	dir := t.TempDir()
	exe := filepath.Join(dir, "bin", "ccproxy-exit-agent")
	os.MkdirAll(filepath.Dir(exe), 0o755)
	os.WriteFile(exe, bins["agent-it-v1"], 0o755)
	os.WriteFile(filepath.Join(dir, "token"), []byte(testToken+"\n"), 0o600)
	fakeSingbox, _ := os.Executable()
	// --reload-cmd: start sing-box once, SIGHUP it after that; every reload is logged.
	reload := filepath.Join(dir, "reload.sh")
	os.WriteFile(reload, []byte(`#!/bin/sh
d=`+dir+`
echo reload >> "$d/reloads.log"
if [ -f "$d/sb.pid" ] && kill -0 "$(cat "$d/sb.pid")" 2>/dev/null; then kill -HUP "$(cat "$d/sb.pid")"; exit 0; fi
mkdir -p "$d/sb"
CCPROXY_FAKE_SINGBOX=1 nohup "`+fakeSingbox+`" run -c "$d/config.json" -D "$d/sb" >/dev/null 2>&1 &
echo $! > "$d/sb.pid"
`), 0o755)
	t.Cleanup(func() {
		if pid, err := os.ReadFile(filepath.Join(dir, "sb.pid")); err == nil {
			exec.Command("kill", strings.TrimSpace(string(pid))).Run()
		}
	})
	args := []string{"--cp", cp.srv.URL, "--token-file", filepath.Join(dir, "token"), "--config", filepath.Join(dir, "config.json"),
		"--state-dir", filepath.Join(dir, "state"), "--singbox", fakeSingbox, "--reload-cmd", "sh " + reload,
		"--confirm-api", freePort(t), "--usage-api", "off", "--interval", "0.3", "--settle", "0",
		"--probe-interval", "3600", "--update-interval", "30", "--update-health-timeout", "60", "--name", "it-host"}

	// The service manager: start the binary at exe again whenever it exits (systemd Restart=always).
	logPath := filepath.Join(dir, "agent.log")
	logFile, _ := os.Create(logPath)
	var mu sync.Mutex
	var exits []int
	stop := make(chan struct{})
	var current *exec.Cmd
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			cmd := exec.Command(exe, args...)
			cmd.Stdout, cmd.Stderr = logFile, logFile
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "CCPROXY_FAKE_SINGBOX=1"} // for "sing-box check" (the test binary)
			mu.Lock()
			err := cmd.Start()
			current = cmd
			mu.Unlock()
			if err != nil {
				t.Errorf("start agent: %v", err)
				return
			}
			err = cmd.Wait()
			code := 0
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			}
			mu.Lock()
			exits = append(exits, code)
			mu.Unlock()
			select {
			case <-stop:
				return
			case <-time.After(300 * time.Millisecond):
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		mu.Lock()
		if current != nil && current.Process != nil {
			current.Process.Signal(syscall.SIGTERM)
		}
		mu.Unlock()
		<-done
		logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Logf("agent log:\n%s", data)
		}
	})

	waitReport := func(what string, limit time.Duration, ok func(r map[string]any) bool) map[string]any {
		t.Helper()
		deadline := time.Now().Add(limit)
		for time.Now().Before(deadline) {
			cp.mu.Lock()
			var hit map[string]any
			for i := len(cp.reports) - 1; i >= 0 && hit == nil; i-- {
				if ok(cp.reports[i]) {
					hit = cp.reports[i]
				}
			}
			cp.mu.Unlock()
			if hit != nil {
				return hit
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
	update := func(r map[string]any) map[string]any { u, _ := r["update"].(map[string]any); return u }
	reloads := func() int {
		data, _ := os.ReadFile(filepath.Join(dir, "reloads.log"))
		return strings.Count(string(data), "reload")
	}
	sbPID := func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "sb.pid"))
		return strings.TrimSpace(string(data))
	}

	waitReport("v1 confirmed", 30*time.Second, func(r map[string]any) bool {
		return r["agent_version"] == "agent-it-v1" && r["apply_state"] == "confirmed"
	})
	reloadsBefore, pidBefore := reloads(), sbPID()
	if reloadsBefore != 1 || pidBefore == "" {
		t.Fatalf("v1 should have started sing-box once: %d reloads, pid %q", reloadsBefore, pidBefore)
	}

	publish := func(ver string, seq, rollout int64) {
		sum, size := sha256Hex(bins[ver]), int64(len(bins[ver]))
		r := release.Record{Schema: 1, Product: release.Product, Version: ver, Sequence: seq,
			Binaries: map[string]release.Binary{testPlatform: {File: release.FileName(testPlatform), SHA256: sum, Size: size}}}
		data, err := release.Encode(r)
		if err != nil {
			t.Fatal(err)
		}
		cp.mu.Lock()
		cp.offer = &updateOffer{Rollout: rollout, Record: string(data), Signature: release.Sign(priv, data)}
		cp.binaries = map[string][]byte{ver + "/" + testPlatform: bins[ver]}
		cp.mu.Unlock()
	}

	// 1. Upgrade v1 -> v2.
	start := time.Now()
	publish("agent-it-v2", 2, 1)
	r := waitReport("v2 updated", 60*time.Second, func(r map[string]any) bool {
		u := update(r)
		return r["agent_version"] == "agent-it-v2" && u != nil && u["state"] == updUpdated
	})
	t.Logf("v1 -> v2 confirmed in %s: update=%v", time.Since(start).Round(time.Millisecond), update(r))
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, bins["agent-it-v2"]) {
		t.Fatal("v2 is not at the executable path")
	}
	if got, _ := os.ReadFile(exe + ".previous"); !bytes.Equal(got, bins["agent-it-v1"]) {
		t.Fatal("v1 not kept as .previous")
	}
	if r["apply_state"] != "confirmed" {
		t.Fatalf("v2 heartbeat: %v", r)
	}
	if n, pid := reloads(), sbPID(); n != reloadsBefore || pid != pidBefore {
		t.Fatalf("the upgrade reloaded or restarted sing-box: %d reloads (was %d), pid %s (was %s)", n, reloadsBefore, pid, pidBefore)
	}

	// 2. A v3 that cannot report healthy is rolled back to v2.
	cp.mu.Lock()
	cp.reportFailFor = "agent-it-v3"
	cp.mu.Unlock()
	start = time.Now()
	publish("agent-it-v3", 3, 2)
	waitReport("v3 running", 60*time.Second, func(r map[string]any) bool { return r["agent_version"] == "agent-it-v3" })
	r = waitReport("rollback to v2", 120*time.Second, func(r map[string]any) bool {
		u := update(r)
		return r["agent_version"] == "agent-it-v2" && u != nil && u["state"] == updRolledBack && u["target_version"] == "agent-it-v3"
	})
	t.Logf("v3 rolled back to v2 in %s: update=%v", time.Since(start).Round(time.Millisecond), update(r))
	if got, _ := os.ReadFile(exe); !bytes.Equal(got, bins["agent-it-v2"]) {
		t.Fatal("v2 not restored at the executable path")
	}
	if n, pid := reloads(), sbPID(); n != reloadsBefore || pid != pidBefore {
		t.Fatalf("the rollback reloaded or restarted sing-box: %d reloads, pid %s", n, pid)
	}
	mu.Lock()
	t.Logf("agent exit codes seen by the service manager: %v", exits)
	mu.Unlock()
	// v2 stays: the rolled-back target is not retried for the same rollout.
	time.Sleep(2 * time.Second)
	if r := cp.last(); r["agent_version"] != "agent-it-v2" {
		t.Fatalf("after rollback: %v", r)
	}
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
