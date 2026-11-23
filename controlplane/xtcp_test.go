package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T, isCA bool) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test XTCP CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func testXTCP(t *testing.T) xtcpSettings {
	return xtcpSettings{Host: "macmini-sg-208", ServerAddr: "203.0.113.10", ServerPort: 7003, TLSServerName: "203.0.113.10",
		CAPEM: testCertPEM(t, true), AuthToken: "frps-token-0123456789abcdef", ProxyName: "ccproxy-208-direct",
		SecretKey: "xtcp-secret-0123456789abcdef", LocalPort: 20443}
}

func TestFrpcConfigIsDirectOnlyWithVerifiedTLS(t *testing.T) {
	x := testXTCP(t)
	conf := renderFrpcTOML(x, "/etc/ccproxy-exit/frp-ca.pem", "")
	for _, want := range []string{
		`serverAddr = "203.0.113.10"`, "serverPort = 7003", `auth.method = "token"`,
		`auth.token = "frps-token-0123456789abcdef"`, "transport.tls.enable = true",
		`transport.tls.trustedCaFile = '/etc/ccproxy-exit/frp-ca.pem'`, `transport.tls.serverName = "203.0.113.10"`,
		`log.to = "console"`, "[[proxies]]", `name = "ccproxy-208-direct"`, `type = "xtcp"`,
		`secretKey = "xtcp-secret-0123456789abcdef"`, `localIP = "127.0.0.1"`, "localPort = 20443", "loginFailExit = false",
	} {
		if !strings.Contains(conf, want+"\n") {
			t.Errorf("frpc.toml lacks %q", want)
		}
	}
	// No relay: no fallback, no stcp/tcp proxies, no visitor, no plain TCP/insecure TLS options.
	var settings strings.Builder // configuration lines only; the header comment explains the absence of a relay
	for _, line := range strings.Split(conf, "\n") {
		if !strings.HasPrefix(line, "#") {
			settings.WriteString(line + "\n")
		}
	}
	for _, banned := range []string{"fallback", "stcp", `type = "tcp"`, "visitors", "insecureSkipVerify", "tls.enable = false", "webServer"} {
		if strings.Contains(strings.ToLower(settings.String()), strings.ToLower(banned)) {
			t.Errorf("frpc.toml must not contain %q", banned)
		}
	}
	if strings.Count(conf, x.AuthToken) != 1 || strings.Count(conf, x.SecretKey) != 1 {
		t.Error("each secret appears exactly once")
	}
	win := renderFrpcTOML(x, `C:\ProgramData\CCProxyExit\frp-ca.pem`, `C:\ProgramData\CCProxyExit\logs\frpc.log`)
	if !strings.Contains(win, `transport.tls.trustedCaFile = 'C:\ProgramData\CCProxyExit\frp-ca.pem'`) ||
		!strings.Contains(win, `log.to = 'C:\ProgramData\CCProxyExit\logs\frpc.log'`) || !strings.Contains(win, "log.maxDays = 7") {
		t.Errorf("Windows paths must be TOML literal strings:\n%s", win)
	}
}

func TestInstallerPathsAreSafeInTOML(t *testing.T) {
	for _, ok := range []string{"/etc/ccproxy-exit/frp-ca.pem", `C:\ProgramData\CCProxyExit\frp-ca.pem`, "/private/var/folders/x y/root/etc/frp-ca.pem"} {
		if !xtcpPathPattern.MatchString(ok) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{"relative/ca.pem", "/etc/x'\nauth.token = \"x\"", "/etc/ca.pem\n", `/etc/"ca".pem`, "", "/etc/$(id)"} {
		if xtcpPathPattern.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestCAValidation(t *testing.T) {
	ca := testCertPEM(t, true)
	out, cert, err := normalizeCA("\n" + ca + "\n")
	if err != nil || out != ca || cert.Subject.CommonName != "Test XTCP CA" {
		t.Fatalf("valid CA refused: %v", err)
	}
	for name, bad := range map[string]string{
		"leaf certificate": testCertPEM(t, false), "garbage": "not a certificate", "empty": "",
		"private key":   "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"trailing text": ca + "extra",
	} {
		if _, _, err := normalizeCA(bad); err == nil || statusOf(err) != 400 {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSecretAndNamePatterns(t *testing.T) {
	if !xtcpSecretPattern.MatchString(newXTCPSecret()) || len(newXTCPSecret()) != 43 || newXTCPSecret() == newXTCPSecret() {
		t.Fatal("generated secret keys must be 43 random URL-safe characters")
	}
	for _, bad := range []string{"short", `with"quote-0123456789`, "with space 0123456789", "new\nline-0123456789"} {
		if xtcpSecretPattern.MatchString(bad) {
			t.Errorf("accepted secret %q", bad)
		}
	}
	for _, bad := range []string{"", "a b", `a"b`, strings.Repeat("x", 65)} {
		if xtcpNamePattern.MatchString(bad) {
			t.Errorf("accepted proxy name %q", bad)
		}
	}
	for _, bad := range []string{"-x.example", "x..example\n", "x example", `x"`} {
		if xtcpHostPattern.MatchString(bad) && bad != "x..example\n" {
			t.Errorf("accepted host %q", bad)
		}
	}
}

func TestScriptsCarryThePinnedFrpc(t *testing.T) {
	dist, _ := fakeDist(t)
	frpc, err := loadFrpcPins()
	if err != nil || frpc.Version != "0.72.0" {
		t.Fatalf("frpc pins: %v %v", frpc.Version, err)
	}
	sh, err := renderInstaller("exit.sh", dist)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := renderInstaller("exit.ps1", dist)
	if err != nil {
		t.Fatal(err)
	}
	for platform, asset := range frpc.Assets {
		if !strings.Contains(string(sh), platform+") echo '"+asset.SHA256+"' ;;") || !strings.Contains(string(ps), asset.SHA256) {
			t.Errorf("frpc %s digest missing from the scripts", platform)
		}
		if !strings.HasPrefix(asset.File, "frp_0.72.0_") {
			t.Errorf("unexpected asset %s", asset.File)
		}
	}
}

// With FRPC_TEST_BIN pointing at the official frpc, the rendered configuration must pass `frpc verify`.
func TestRealFrpcAcceptsTheConfiguration(t *testing.T) {
	bin := os.Getenv("FRPC_TEST_BIN")
	if bin == "" {
		t.Skip("set FRPC_TEST_BIN to an frpc binary")
	}
	dir := t.TempDir()
	x := testXTCP(t)
	ca := filepath.Join(dir, "frp-ca.pem")
	os.WriteFile(ca, []byte(x.CAPEM), 0o644)
	conf := filepath.Join(dir, "frpc.toml")
	os.WriteFile(conf, []byte(renderFrpcTOML(x, ca, "")), 0o600)
	out, err := exec.Command(bin, "verify", "-c", conf).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "syntax is ok") {
		t.Fatalf("frpc verify: %v %s", err, out)
	}
}
