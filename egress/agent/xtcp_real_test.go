//go:build !windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestXTCPWithRealFrp runs the agent's XTCP sync against the official frps and frpc (the release pinned in
// controlplane/install/frpc.json), natively on this machine:
//
//	CCPROXY_FRP_DIR=/path/to/frp_0.72.0_<os>_<arch> go test -run TestXTCPWithRealFrp ./...
//
// frpc starts from a configuration installed before this change (no admin API). The agent adopts it with one
// restart, hot-reloads a second proxy without touching the primary one, confirms registration from frpc's live
// status (frps logs the registrations), restores the working proxies when frps refuses a new one, and removes a
// released proxy. The XTCP data path itself is covered by controlplane/test/shared-egress/run-e2e.sh.
func TestXTCPWithRealFrp(t *testing.T) {
	frp := os.Getenv("CCPROXY_FRP_DIR")
	if frp == "" {
		t.Skip("set CCPROXY_FRP_DIR to an unpacked frp release to run against the real frps and frpc")
	}
	dir := t.TempDir()
	caPEM, certPEM, keyPEM := realFrpPKI(t)
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("frps.pem", certPEM)
	write("frps.key", keyPEM)
	frpsPort := strings.Split(freePort(t), ":")[1]
	frpsConf := write("frps.toml", fmt.Sprintf("bindAddr = \"127.0.0.1\"\nbindPort = %s\nauth.method = \"token\"\n"+
		"auth.token = \"real-frps-token-0123456789\"\ntransport.tls.force = true\ntransport.tls.certFile = '%s'\n"+
		"transport.tls.keyFile = '%s'\n", frpsPort, filepath.Join(dir, "frps.pem"), filepath.Join(dir, "frps.key")))
	frpsLog, _ := os.Create(filepath.Join(dir, "frps.log"))
	frps := exec.Command(filepath.Join(frp, "frps"), "-c", frpsConf)
	frps.Stdout, frps.Stderr = frpsLog, frpsLog
	if err := frps.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { frps.Process.Kill(); frps.Wait() })
	waitPort(t, "127.0.0.1:"+frpsPort)

	// frpc under a tiny supervisor standing in for systemd / launchd: "restart" kills it and starts it again.
	conf, caFile := filepath.Join(dir, "frpc.toml"), write("frp-ca.pem", caPEM)
	ctl := write("frpc-ctl", fmt.Sprintf(`#!/bin/sh
pid=$(cat %[1]s/frpc.pid 2>/dev/null)
[ -n "$pid" ] && kill "$pid" 2>/dev/null && while kill -0 "$pid" 2>/dev/null; do sleep 0.05; done
%[2]s -c %[3]s >> %[1]s/frpc.log 2>&1 &
echo $! > %[1]s/frpc.pid
`, dir, filepath.Join(frp, "frpc"), conf))
	os.Chmod(ctl, 0o700)
	t.Cleanup(func() {
		if pid, err := os.ReadFile(filepath.Join(dir, "frpc.pid")); err == nil {
			exec.Command("kill", strings.TrimSpace(string(pid))).Run()
		}
	})

	e := &xtcpEnv{t: t, ca: caPEM, token: "real-frps-token-0123456789"}
	e.cp = newFakeCP(t)
	a, _ := newTestAgent(t, e.cp, func(o *Options) {
		o.FrpcBin, o.FrpcConfig, o.FrpcCA = filepath.Join(frp, "frpc"), conf, caFile
		o.FrpcAdmin, o.FrpcConfirmTimeout, o.FrpcRestartCmd = freePort(t), 15, ctl
	})
	e.a = a
	if err := a.xtcp.load(); err != nil {
		t.Fatal(err)
	}
	render := func(proxies ...string) *xtcpDesired {
		d := e.render(e.token, proxies...)
		d.FrpcTOML = strings.Replace(d.FrpcTOML, "serverPort = 7003", "serverPort = "+frpsPort, 1)
		return d
	}
	d := e.publish(render(primary))
	os.WriteFile(conf, []byte(d.FrpcTOML), 0o600) // installed before the admin API existed
	if out, err := exec.Command(ctl).CombinedOutput(); err != nil {
		t.Fatalf("start frpc: %v %s", err, out)
	}
	frpsSays := func(text string) bool {
		data, _ := os.ReadFile(filepath.Join(dir, "frps.log"))
		return strings.Contains(string(data), text)
	}
	waitFor(t, "frps registers the primary proxy", func() bool { return frpsSays("new proxy [ccproxy-t-direct] type [xtcp] success") })

	a.Cycle() // adopts the legacy frpc: one restart, admin API now on
	e.wantReport(xtcpApplied, e.gen, e.gen)
	pid, _ := os.ReadFile(filepath.Join(dir, "frpc.pid"))

	d = e.publish(render(primary, second))
	start := time.Now()
	a.Cycle()
	e.wantReport(xtcpApplied, d.Generation, d.Generation)
	t.Logf("second port: generation %d confirmed by live frpc status %v after the agent fetched it", d.Generation, time.Since(start).Round(time.Millisecond))
	if again, _ := os.ReadFile(filepath.Join(dir, "frpc.pid")); string(again) != string(pid) {
		t.Fatal("adding a proxy restarted frpc instead of hot-reloading it")
	}
	if !frpsSays("new proxy [ccproxy-t-direct-20444] type [xtcp] success") {
		t.Fatal("frps never saw the second proxy")
	}
	logText := func() string { data, _ := os.ReadFile(filepath.Join(dir, "frpc.log")); return string(data) }
	if primaryStopped(logText()) {
		t.Fatal("the hot reload stopped the primary proxy")
	}

	// A second frpc (another host by mistake) holds a name the next generation adds: frps refuses it.
	other := write("other.toml", fmt.Sprintf("serverAddr = \"127.0.0.1\"\nserverPort = %s\nauth.method = \"token\"\n"+
		"auth.token = \"real-frps-token-0123456789\"\ntransport.tls.enable = true\ntransport.tls.trustedCaFile = '%s'\n"+
		"transport.tls.serverName = \"frps\"\n\n[[proxies]]\nname = \"ccproxy-t-direct-20445\"\ntype = \"xtcp\"\n"+
		"secretKey = \"squatter-0123456789\"\nlocalPort = 1\n", frpsPort, caFile))
	squatter := exec.Command(filepath.Join(frp, "frpc"), "-c", other)
	if err := squatter.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { squatter.Process.Kill(); squatter.Wait() })
	waitFor(t, "the squatter registers", func() bool { return frpsSays("new proxy [ccproxy-t-direct-20445] type [xtcp] success") })
	confirmed := d.Generation
	working, _ := os.ReadFile(conf)
	a.opt.FrpcConfirmTimeout = 4
	d = e.publish(render(primary, second, "ccproxy-t-direct-20445:20445:third-secret-0123456789"))
	a.Cycle()
	r := e.wantReport(xtcpFailed, d.Generation, confirmed)
	if !strings.Contains(fmt.Sprint(r["error"]), "ccproxy-t-direct-20445") || !strings.Contains(fmt.Sprint(r["error"]), "already exists") {
		t.Fatalf("failure report: %v", r["error"])
	}
	if now, _ := os.ReadFile(conf); string(now) != string(working) {
		t.Fatal("the working configuration was not restored")
	}
	live, err := a.xtcp.liveProxies()
	if err != nil || registrationProblem([]xtcpProxy{{Name: "ccproxy-t-direct"}, {Name: "ccproxy-t-direct-20444"}}, live) != "" {
		t.Fatalf("after the restore frpc serves the previous proxies: %v %v", live, err)
	}

	// Release the second user: the retired proxy disappears, the primary stays.
	squatter.Process.Kill()
	d = e.publish(render(primary))
	a.Cycle()
	e.wantReport(xtcpApplied, d.Generation, d.Generation)
	live, _ = a.xtcp.liveProxies()
	if len(live) != 1 || live["ccproxy-t-direct"].Status != "running" {
		t.Fatalf("after release: %v", live)
	}
	if primaryStopped(logText()) {
		t.Fatal("the primary proxy was stopped at some point")
	}
}

// primaryStopped: frpc logged "proxy removed: [a b ...]" with the primary proxy in the list.
func primaryStopped(log string) bool {
	for _, m := range regexp.MustCompile(`proxy removed: \[([^\]]*)\]`).FindAllStringSubmatch(log, -1) {
		for _, name := range strings.Fields(m[1]) {
			if name == "ccproxy-t-direct" {
				return true
			}
		}
	}
	return false
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); !ok(); time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
	}
}

func waitPort(t *testing.T, addr string) {
	t.Helper()
	waitFor(t, addr, func() bool {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
}

// realFrpPKI makes a CA and an frps server certificate for the name "frps".
func realFrpPKI(t *testing.T) (caPEM, certPEM, keyPEM string) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "real frp test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "frps"}, DNSNames: []string{"frps"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

// The installer inserts the admin block itself (exit.sh add_frpc_admin) so that a fresh install already equals the
// agent's candidate. Run the installer's own function and compare byte for byte.
func TestInstallerAdminBlockMatchesTheAgent(t *testing.T) {
	script, err := os.ReadFile(filepath.Join("..", "..", "controlplane", "install", "exit.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(script)
	start := strings.Index(text, "add_frpc_admin() {")
	end := strings.Index(text[start:], "\n}\n")
	if start < 0 || end < 0 {
		t.Fatal("exit.sh has no add_frpc_admin function")
	}
	dir := t.TempDir()
	secret := "0123456789abcdef0123456789abcdef"
	os.WriteFile(filepath.Join(dir, "secret"), []byte(secret+"\n"), 0o600)
	toml := "# frpc\nserverAddr = \"x\"\nlog.maxDays = 7\n\n[[proxies]]\nname = \"a\"\n\n[[proxies]]\nname = \"b\"\nlocalPort = 1\n"
	conf := filepath.Join(dir, "frpc.toml")
	os.WriteFile(conf, []byte(toml), 0o600)
	cmd := exec.Command("sh", "-c", "set -eu; FRPC_ADMIN_SECRET=\"$1\"; FRPC_ADMIN_PORT=9097\n"+text[start:start+end+3]+"add_frpc_admin \"$2\"",
		"sh", filepath.Join(dir, "secret"), conf)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("add_frpc_admin: %v %s", err, out)
	}
	got, _ := os.ReadFile(conf)
	x := &xtcpSync{admin: "127.0.0.1:9097", password: secret}
	if want := spliceAdmin(toml, x.adminBlock()); string(got) != want {
		t.Fatalf("installer and agent differ:\n--- installer\n%s--- agent\n%s", got, want)
	}
}
