package release

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeDist writes a build.sh-shaped directory with small fake binaries.
func fakeDist(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	var sums strings.Builder
	for _, p := range Platforms {
		data := []byte("binary for " + p + " " + version)
		if err := os.WriteFile(filepath.Join(dir, FileName(p)), data, 0o755); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(sum[:]), FileName(p))
	}
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(version+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestRecordRoundTripAndSignature(t *testing.T) {
	dir := fakeDist(t, "v0.1.0")
	r, err := FromDist(dir, 42, "0123456789abcdef", "2026-11-25T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	data, err := Encode(r)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if back.Version != "v0.1.0" || back.Sequence != 42 || len(back.Binaries) != len(Platforms) {
		t.Fatalf("round trip lost data: %+v", back)
	}
	if err := CheckDist(dir, back); err != nil {
		t.Fatal(err)
	}

	pub, priv := newKey(t)
	keys, err := ParsePublicKeys("# comment\n\n" + FormatPublicKey(pub) + "\n")
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys: %v %v", keys, err)
	}
	sig := Sign(priv, data)
	if err := Verify(keys, data, sig); err != nil {
		t.Fatal(err)
	}
	// One changed byte anywhere in the record invalidates the signature.
	tampered := bytes.Replace(data, []byte(`"sequence": 42`), []byte(`"sequence": 43`), 1)
	if err := Verify(keys, tampered, sig); err == nil {
		t.Fatal("tampered record verified")
	}
	other, _ := newKey(t)
	if err := Verify([]ed25519.PublicKey{other}, data, sig); err == nil {
		t.Fatal("signature verified with the wrong key")
	}
	if err := Verify(nil, data, sig); err == nil {
		t.Fatal("no keys must refuse")
	}
	if err := Verify(keys, data, "ed25519:AAAA"); err == nil {
		t.Fatal("malformed signature verified")
	}

	// A changed binary no longer matches the record.
	if err := os.WriteFile(filepath.Join(dir, FileName("linux-amd64")), []byte("evil"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckDist(dir, back); err == nil {
		t.Fatal("changed binary passed CheckDist")
	}
}

func TestPrivateKeyText(t *testing.T) {
	_, priv := newKey(t)
	back, err := ParsePrivateKey(FormatPrivateKey(priv) + "\n")
	if err != nil || !back.Equal(priv) {
		t.Fatalf("private key round trip: %v", err)
	}
	if _, err := ParsePrivateKey("ed25519:short"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestParseRefuses(t *testing.T) {
	good := Record{Schema: 1, Product: Product, Version: "agent-abc", Sequence: 1,
		Binaries: map[string]Binary{"linux-amd64": {File: FileName("linux-amd64"), SHA256: strings.Repeat("a", 64), Size: 10}}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(r *Record){
		"schema":   func(r *Record) { r.Schema = 2 },
		"product":  func(r *Record) { r.Product = "other" },
		"version":  func(r *Record) { r.Version = "bad version" },
		"dot path": func(r *Record) { r.Version = ".." },
		"dirty":    func(r *Record) { r.Version = "agent-abc-dirty" },
		"sequence": func(r *Record) { r.Sequence = 0 },
		"commit":   func(r *Record) { r.Commit = "XYZ" },
		"empty":    func(r *Record) { r.Binaries = nil },
		"platform": func(r *Record) {
			r.Binaries = map[string]Binary{"plan9-386": {File: "x", SHA256: strings.Repeat("a", 64), Size: 1}}
		},
		"file": func(r *Record) {
			r.Binaries["linux-amd64"] = Binary{File: "../../bin/sh", SHA256: strings.Repeat("a", 64), Size: 1}
		},
		"digest": func(r *Record) {
			r.Binaries["linux-amd64"] = Binary{File: FileName("linux-amd64"), SHA256: "abc", Size: 1}
		},
		"size": func(r *Record) {
			r.Binaries["linux-amd64"] = Binary{File: FileName("linux-amd64"), SHA256: strings.Repeat("a", 64)}
		},
		"oversized": func(r *Record) {
			r.Binaries["linux-amd64"] = Binary{File: FileName("linux-amd64"), SHA256: strings.Repeat("a", 64), Size: MaxBinaryBytes + 1}
		},
	}
	for name, change := range cases {
		r := good
		r.Binaries = map[string]Binary{}
		for k, v := range good.Binaries {
			r.Binaries[k] = v
		}
		change(&r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	data, _ := Encode(good)
	withExtra := bytes.Replace(data, []byte(`"schema": 1`), []byte(`"schema": 1, "install_script": "rm -rf /"`), 1)
	if _, err := Parse(withExtra); err == nil {
		t.Error("unknown field accepted")
	}
	if _, err := Parse(append(data, []byte(`{}`)...)); err == nil {
		t.Error("trailing data accepted")
	}
	if _, err := ParsePublicKeys("ssh-ed25519 AAAA"); err == nil {
		t.Error("non-ed25519 key line accepted")
	}
}

func TestFromDistRequiresEveryPlatform(t *testing.T) {
	dir := fakeDist(t, "agent-abc")
	os.Remove(filepath.Join(dir, FileName("windows-arm64")))
	if _, err := FromDist(dir, 1, "", ""); err == nil {
		t.Fatal("missing platform accepted")
	}
	dir = fakeDist(t, "agent-abc")
	os.WriteFile(filepath.Join(dir, FileName("darwin-arm64")), []byte("changed after build"), 0o755)
	if _, err := FromDist(dir, 1, "", ""); err == nil {
		t.Fatal("binary that differs from SHA256SUMS accepted")
	}
}
