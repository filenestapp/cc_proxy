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

// TestUpdateWithRealBinaries runs launchd's stable launcher and compiled releases. It checks that the launcher
// remains at bin/ccproxy-exit-agent, releases stay below bin/releases/<version>/, and an unexecutable candidate
// is rolled back before it reaches main.
func TestUpdateWithRealBinaries(t *testing.T) {
	if testing.Short() || runtime.GOOS != "darwin" {
		t.Skip("builds four macOS agents and waits for update health checks")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	build := t.TempDir()
	binaries := map[string][]byte{}
	for _, version := range []string{"launcher-it", "agent-it-v1", "agent-it-v2", "agent-it-v3"} {
		path := filepath.Join(build, version)
		command := exec.Command("go", "build", "-trimpath", "-o", path, "-ldflags",
			"-X main.version="+version+" -X main.extraReleaseKeys="+release.FormatPublicKey(public), ".")
		command.Env = append(os.Environ(), "CGO_ENABLED=0")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v\n%s", version, err, output)
		}
		binaries[version], _ = os.ReadFile(path)
	}

	cp := newFakeCP(t)
	dir := t.TempDir()
	home := filepath.Join(dir, "bin")
	launcherPath := filepath.Join(home, "ccproxy-exit-agent")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcherPath, binaries["launcher-it"], 0o755); err != nil {
		t.Fatal(err)
	}
	stage := func(version string) string {
		path := releaseBinary(home, version, testPlatform)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, binaries[version], 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	v1Path := stage("agent-it-v1")
	stateDir := filepath.Join(dir, "state")
	if err := saveUpdateFile(stateDir, updateFile{Launcher: "launcher-it", Running: "agent-it-v1", RunningSequence: 1}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "token"), []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	fakeSingbox, _ := os.Executable()
	reload := filepath.Join(dir, "reload.sh")
	reloadScript := "#!/bin/sh\n" +
		"d=" + dir + "\n" +
		"echo reload >> \"$d/reloads.log\"\n" +
		"if [ -f \"$d/sb.pid\" ] && kill -0 \"$(cat \"$d/sb.pid\")\" 2>/dev/null; then kill -HUP \"$(cat \"$d/sb.pid\")\"; exit 0; fi\n" +
		"mkdir -p \"$d/sb\"\n" +
		"CCPROXY_FAKE_SINGBOX=1 nohup \"" + fakeSingbox + "\" run -c \"$d/config.json\" -D \"$d/sb\" >/dev/null 2>&1 &\n" +
		"echo $! > \"$d/sb.pid\"\n"
	if err := os.WriteFile(reload, []byte(reloadScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if pid, err := os.ReadFile(filepath.Join(dir, "sb.pid")); err == nil {
			exec.Command("kill", strings.TrimSpace(string(pid))).Run()
		}
	})
	args := []string{"--cp", cp.srv.URL, "--token-file", filepath.Join(dir, "token"), "--config", filepath.Join(dir, "config.json"),
		"--state-dir", stateDir, "--singbox", fakeSingbox, "--reload-cmd", "sh " + reload,
		"--confirm-api", freePort(t), "--usage-api", "off", "--interval", "0.3", "--settle", "0",
		"--probe-interval", "3600", "--update-interval", "30", "--update-health-timeout", "60", "--name", "it-host"}

	logPath := filepath.Join(dir, "agent.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	var current *exec.Cmd
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			command := exec.Command(launcherPath, args...)
			command.Stdout, command.Stderr = logFile, logFile
			command.Env = []string{"PATH=" + os.Getenv("PATH"), "CCPROXY_FAKE_SINGBOX=1"}
			mutex.Lock()
			err := command.Start()
			current = command
			mutex.Unlock()
			if err != nil {
				t.Errorf("start launcher: %v", err)
				return
			}
			err = command.Wait()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Errorf("wait launcher: %v", err)
				return
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	t.Cleanup(func() {
		close(stop)
		mutex.Lock()
		if current != nil && current.Process != nil {
			current.Process.Signal(syscall.SIGTERM)
		}
		mutex.Unlock()
		<-done
		logFile.Close()
		if t.Failed() {
			data, _ := os.ReadFile(logPath)
			t.Logf("agent log:\n%s", data)
		}
	})

	waitReport := func(what string, limit time.Duration, match func(map[string]any) bool) map[string]any {
		t.Helper()
		deadline := time.Now().Add(limit)
		for time.Now().Before(deadline) {
			cp.mu.Lock()
			var found map[string]any
			for i := len(cp.reports) - 1; i >= 0 && found == nil; i-- {
				if match(cp.reports[i]) {
					found = cp.reports[i]
				}
			}
			cp.mu.Unlock()
			if found != nil {
				return found
			}
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
	waitState := func(what string, limit time.Duration, match func(updateFile) bool) {
		t.Helper()
		deadline := time.Now().Add(limit)
		for time.Now().Before(deadline) {
			if state := loadUpdateFile(stateDir, t.Logf); match(state) {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", what)
	}
	update := func(report map[string]any) map[string]any {
		value, _ := report["update"].(map[string]any)
		return value
	}
	reloads := func() int {
		data, _ := os.ReadFile(filepath.Join(dir, "reloads.log"))
		return strings.Count(string(data), "reload")
	}
	singboxPID := func() string {
		data, _ := os.ReadFile(filepath.Join(dir, "sb.pid"))
		return strings.TrimSpace(string(data))
	}
	offer := func(version string, sequence, rollout int64) *updateOffer {
		hash := sha256.Sum256(binaries[version])
		record := release.Record{Schema: 1, Product: release.Product, Version: version, Sequence: sequence,
			Binaries: map[string]release.Binary{testPlatform: {File: release.FileName(testPlatform), SHA256: hex.EncodeToString(hash[:]), Size: int64(len(binaries[version]))}}}
		data, err := release.Encode(record)
		if err != nil {
			t.Fatal(err)
		}
		return &updateOffer{Rollout: rollout, Record: string(data), Signature: release.Sign(private, data)}
	}
	publish := func(version string, sequence, rollout int64) {
		cp.mu.Lock()
		cp.offer = offer(version, sequence, rollout)
		cp.binaries = map[string][]byte{version + "/" + testPlatform: binaries[version]}
		cp.mu.Unlock()
	}
	cp.mu.Lock()
	cp.releases = map[string]*updateOffer{"agent-it-v1": offer("agent-it-v1", 1, 0)}
	cp.mu.Unlock()

	waitReport("v1 confirmed", 30*time.Second, func(report map[string]any) bool {
		return report["agent_version"] == "agent-it-v1" && report["apply_state"] == "confirmed"
	})
	reloadsBefore, pidBefore := reloads(), singboxPID()
	if reloadsBefore != 1 || pidBefore == "" {
		t.Fatalf("v1 should start sing-box once: %d reloads, pid %q", reloadsBefore, pidBefore)
	}

	publish("agent-it-v2", 2, 1)
	report := waitReport("v2 updated", 75*time.Second, func(report map[string]any) bool {
		current := update(report)
		return report["agent_version"] == "agent-it-v2" && current != nil && current["state"] == updUpdated
	})
	t.Logf("v1 -> v2: %v", update(report))
	if got, _ := os.ReadFile(launcherPath); !bytes.Equal(got, binaries["launcher-it"]) {
		t.Fatal("the stable launcher was replaced")
	}
	if got, _ := os.ReadFile(v1Path); !bytes.Equal(got, binaries["agent-it-v1"]) {
		t.Fatal("v1 was not retained under releases/")
	}
	if got, _ := os.ReadFile(releaseBinary(home, "agent-it-v2", testPlatform)); !bytes.Equal(got, binaries["agent-it-v2"]) {
		t.Fatal("v2 was not staged under releases/")
	}
	if got, pid := reloads(), singboxPID(); got != reloadsBefore || pid != pidBefore {
		t.Fatalf("upgrade reloaded or restarted sing-box: %d/%s, want %d/%s", got, pid, reloadsBefore, pidBefore)
	}

	publish("agent-it-v3", 3, 2)
	waitState("v3 activation", 75*time.Second, func(state updateFile) bool {
		return state.Phase == phaseActivating && state.Target.Version == "agent-it-v3"
	})
	v3Path := releaseBinary(home, "agent-it-v3", testPlatform)
	if err := os.Chmod(v3Path, 0o600); err != nil {
		t.Fatal(err)
	}
	report = waitReport("pre-main rollback to v2", 75*time.Second, func(report map[string]any) bool {
		current := update(report)
		if current == nil {
			return false
		}
		errorText, _ := current["error"].(string)
		return report["agent_version"] == "agent-it-v2" && current["state"] == updRolledBack &&
			current["target_version"] == "agent-it-v3" && strings.Contains(errorText, "cannot start agent-it-v3")
	})
	t.Logf("pre-main rollback: %v", update(report))
	if got, _ := os.ReadFile(launcherPath); !bytes.Equal(got, binaries["launcher-it"]) {
		t.Fatal("the launcher changed after the pre-main rollback")
	}
	if got, pid := reloads(), singboxPID(); got != reloadsBefore || pid != pidBefore {
		t.Fatalf("pre-main rollback reloaded or restarted sing-box: %d/%s, want %d/%s", got, pid, reloadsBefore, pidBefore)
	}
}
