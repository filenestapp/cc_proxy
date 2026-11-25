// Package release defines the signed release record of the exit agent.
//
// A release is the reproducible build directory written by egress/agent/build.sh (the binaries, SHA256SUMS and
// VERSION) plus two files added when an operator publishes it from the exit-agent workflow:
//
//	release.json      the record: version, release sequence, source commit and every binary's name, size and SHA-256
//	release.json.sig  an Ed25519 signature over the exact bytes of release.json, as "ed25519:<base64>"
//
// Agent versions are source hashes ("agent-<tree>"), so they carry no order. The sequence does: the workflow sets it
// from its run number, and an agent never moves to a record whose sequence is lower than the release it runs. The
// control plane only stores and serves these files; the agent checks the signature against the public keys compiled
// into it (release_keys.txt), so a control plane cannot make a host run a binary the release key did not sign.
package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
)

const (
	Schema        = 1
	Product       = "ccproxy-exit-agent"
	RecordFile    = "release.json"
	SignatureFile = "release.json.sig"
	signaturePre  = "ed25519:"
	// MaxRecordBytes bounds what an agent reads as a record.
	MaxRecordBytes = 64 << 10
	// MaxBinaryBytes bounds a binary an agent downloads.
	MaxBinaryBytes = 256 << 20
)

// Platforms are the targets of the build matrix (build.sh and the exit-agent workflow).
var Platforms = []string{"darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"}

var (
	versionPattern = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
	hexPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{7,64}$`)
)

// Binary is one platform's file in a release.
type Binary struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Record is release.json.
type Record struct {
	Schema      int               `json:"schema"`
	Product     string            `json:"product"`
	Version     string            `json:"version"`
	Sequence    int64             `json:"sequence"`
	Commit      string            `json:"commit,omitempty"`
	PublishedAt string            `json:"published_at,omitempty"`
	Binaries    map[string]Binary `json:"binaries"`
}

// FileName is the binary's name for a platform, as build.sh writes it.
func FileName(platform string) string {
	if strings.HasPrefix(platform, "windows-") {
		return Product + "-" + platform + ".exe"
	}
	return Product + "-" + platform
}

func knownPlatform(platform string) bool { return slices.Contains(Platforms, platform) }

// Validate checks every field. A record that passes names only known platforms with the build's file names.
func (r Record) Validate() error {
	switch {
	case r.Schema != Schema:
		return fmt.Errorf("unsupported release schema %d", r.Schema)
	case r.Product != Product:
		return fmt.Errorf("release is for %q, not %s", r.Product, Product)
	case !versionPattern.MatchString(r.Version):
		return fmt.Errorf("bad release version %q", r.Version)
	case strings.HasSuffix(r.Version, "-dirty"):
		return errors.New("a build with uncommitted changes cannot be released")
	case r.Sequence <= 0:
		return fmt.Errorf("release sequence must be positive, got %d", r.Sequence)
	case r.Commit != "" && !commitPattern.MatchString(r.Commit):
		return fmt.Errorf("bad release commit %q", r.Commit)
	case len(r.Binaries) == 0:
		return errors.New("release lists no binaries")
	}
	for platform, b := range r.Binaries {
		if !knownPlatform(platform) {
			return fmt.Errorf("release names unknown platform %q", platform)
		}
		if b.File != FileName(platform) {
			return fmt.Errorf("release file for %s must be %s, not %q", platform, FileName(platform), b.File)
		}
		if !hexPattern.MatchString(b.SHA256) {
			return fmt.Errorf("bad SHA-256 for %s", platform)
		}
		if b.Size <= 0 || b.Size > MaxBinaryBytes {
			return fmt.Errorf("bad size %d for %s", b.Size, platform)
		}
	}
	return nil
}

// Parse decodes and validates a record. Unknown fields are refused, so a signed record means exactly what it says.
func Parse(data []byte) (Record, error) {
	var r Record
	if len(data) > MaxRecordBytes {
		return r, errors.New("release record too large")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return r, fmt.Errorf("release record: %w", err)
	}
	if dec.More() {
		return r, errors.New("release record: trailing data")
	}
	return r, r.Validate()
}

// Encode is the canonical form written to release.json (sorted keys, two-space indent, final newline).
func Encode(r Record) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// -- keys and signatures ------------------------------------------------------------------------------------------

// FormatPublicKey is the line release_keys.txt holds for a key.
func FormatPublicKey(key ed25519.PublicKey) string {
	return signaturePre + base64.StdEncoding.EncodeToString(key)
}

// ParsePublicKeys reads "ed25519:<base64>" lines; blank lines and lines starting with # are ignored.
func ParsePublicKeys(text string) ([]ed25519.PublicKey, error) {
	var keys []ed25519.PublicKey
	scanner := bufio.NewScanner(strings.NewReader(text))
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw, ok := strings.CutPrefix(line, signaturePre)
		if !ok {
			return nil, fmt.Errorf("release key line %d: expected ed25519:<base64>", n)
		}
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("release key line %d: not an Ed25519 public key", n)
		}
		keys = append(keys, ed25519.PublicKey(key))
	}
	return keys, scanner.Err()
}

// ParsePrivateKey reads a private key as written by "agent-release keygen": the 32-byte seed in base64.
func ParsePrivateKey(text string) (ed25519.PrivateKey, error) {
	raw, _ := strings.CutPrefix(strings.TrimSpace(text), signaturePre)
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key must be a base64 Ed25519 seed (32 bytes)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// FormatPrivateKey is the text form of a private key (its seed).
func FormatPrivateKey(key ed25519.PrivateKey) string {
	return signaturePre + base64.StdEncoding.EncodeToString(key.Seed())
}

// Sign returns the contents of release.json.sig for the record bytes.
func Sign(key ed25519.PrivateKey, record []byte) string {
	return signaturePre + base64.StdEncoding.EncodeToString(ed25519.Sign(key, record)) + "\n"
}

// Verify checks the signature text against the record bytes with any of the keys.
func Verify(keys []ed25519.PublicKey, record []byte, signature string) error {
	if len(keys) == 0 {
		return errors.New("no release signing key is configured")
	}
	raw, ok := strings.CutPrefix(strings.TrimSpace(signature), signaturePre)
	if !ok {
		return errors.New("release signature must be ed25519:<base64>")
	}
	sig, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("release signature is malformed")
	}
	for _, key := range keys {
		if ed25519.Verify(key, record, sig) {
			return nil
		}
	}
	return errors.New("release signature does not match a trusted release key")
}

// -- build directories ---------------------------------------------------------------------------------------------

// HashFile returns a file's SHA-256 (hex) and size.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// readSums reads SHA256SUMS ("<hex>  <file>" lines, as sha256sum and shasum write them).
func readSums(dir string) (map[string]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return nil, err
	}
	sums := map[string]string{}
	for line := range strings.SplitSeq(string(data), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			sums[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	return sums, nil
}

// FromDist builds the record for a build.sh output directory. Every platform of the matrix must be present and match
// SHA256SUMS.
func FromDist(dir string, sequence int64, commit, publishedAt string) (Record, error) {
	version, err := os.ReadFile(filepath.Join(dir, "VERSION"))
	if err != nil {
		return Record{}, err
	}
	sums, err := readSums(dir)
	if err != nil {
		return Record{}, err
	}
	r := Record{Schema: Schema, Product: Product, Version: strings.TrimSpace(string(version)), Sequence: sequence,
		Commit: commit, PublishedAt: publishedAt, Binaries: map[string]Binary{}}
	for _, platform := range Platforms {
		name := FileName(platform)
		sum, size, err := HashFile(filepath.Join(dir, name))
		if err != nil {
			return Record{}, err
		}
		if sums[name] != sum {
			return Record{}, fmt.Errorf("%s does not match SHA256SUMS", name)
		}
		r.Binaries[platform] = Binary{File: name, SHA256: sum, Size: size}
	}
	return r, r.Validate()
}

// CheckDist verifies that every binary the record names is present in dir with its size and digest.
func CheckDist(dir string, r Record) error {
	platforms := make([]string, 0, len(r.Binaries))
	for p := range r.Binaries {
		platforms = append(platforms, p)
	}
	sort.Strings(platforms)
	for _, p := range platforms {
		b := r.Binaries[p]
		sum, size, err := HashFile(filepath.Join(dir, b.File))
		if err != nil {
			return err
		}
		if sum != b.SHA256 || size != b.Size {
			return fmt.Errorf("%s does not match the release record", b.File)
		}
	}
	return nil
}
