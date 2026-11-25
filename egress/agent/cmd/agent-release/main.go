// Command agent-release creates, signs and checks exit-agent release records (package release).
//
//	agent-release keygen PRIVATE_KEY_FILE
//	    New Ed25519 key pair. Writes the private key (0600) and prints the public key line for release_keys.txt.
//	agent-release record -dist DIR -sequence N [-commit SHA] [-published-at RFC3339]
//	    Write DIR/release.json for a build.sh output directory.
//	agent-release sign -dist DIR [-key-env NAME | -key-file FILE]
//	    Sign DIR/release.json into DIR/release.json.sig. The key is read from the environment variable NAME
//	    (default AGENT_RELEASE_SIGNING_KEY), never from the command line.
//	agent-release verify -dist DIR [-keys FILE]
//	    Check the record, its signature (against FILE, default the agent's release_keys.txt) and every binary.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/filenestapp/cc_proxy/egress/agent/release"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "record":
		err = record(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "agent-release:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: agent-release keygen FILE | record -dist DIR -sequence N | sign -dist DIR | verify -dist DIR")
	os.Exit(2)
}

func keygen(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: agent-release keygen PRIVATE_KEY_FILE")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(args[0], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, release.FormatPrivateKey(priv)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println(release.FormatPublicKey(pub))
	return nil
}

func record(args []string) error {
	fs := flag.NewFlagSet("record", flag.ContinueOnError)
	dist := fs.String("dist", "", "build.sh output directory")
	sequence := fs.Int64("sequence", 0, "release sequence (higher is newer)")
	commit := fs.String("commit", "", "source commit")
	published := fs.String("published-at", time.Now().UTC().Format(time.RFC3339), "publication time (RFC 3339)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dist == "" {
		return errors.New("-dist is required")
	}
	r, err := release.FromDist(*dist, *sequence, *commit, *published)
	if err != nil {
		return err
	}
	data, err := release.Encode(r)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dist, release.RecordFile), data, 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: %s sequence %d, %d platforms\n", release.RecordFile, r.Version, r.Sequence, len(r.Binaries))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	dist := fs.String("dist", "", "directory with release.json")
	keyEnv := fs.String("key-env", "AGENT_RELEASE_SIGNING_KEY", "environment variable holding the private key")
	keyFile := fs.String("key-file", "", "file holding the private key (instead of -key-env)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dist == "" {
		return errors.New("-dist is required")
	}
	text := os.Getenv(*keyEnv)
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		text = string(data)
	}
	if text == "" {
		return fmt.Errorf("no signing key: set %s or pass -key-file", *keyEnv)
	}
	key, err := release.ParsePrivateKey(text)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(*dist, release.RecordFile))
	if err != nil {
		return err
	}
	r, err := release.Parse(data)
	if err != nil {
		return err
	}
	if err := release.CheckDist(*dist, r); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dist, release.SignatureFile), []byte(release.Sign(key, data)), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s sequence %d with %s\n", r.Version, r.Sequence, release.FormatPublicKey(key.Public().(ed25519.PublicKey)))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	dist := fs.String("dist", "", "release directory")
	keysFile := fs.String("keys", "", "public keys (default: release_keys.txt next to this source tree's agent)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dist == "" {
		return errors.New("-dist is required")
	}
	if *keysFile == "" {
		*keysFile = "release_keys.txt"
	}
	keyText, err := os.ReadFile(*keysFile)
	if err != nil {
		return err
	}
	keys, err := release.ParsePublicKeys(string(keyText))
	if err != nil {
		return err
	}
	data, err := os.ReadFile(filepath.Join(*dist, release.RecordFile))
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(filepath.Join(*dist, release.SignatureFile))
	if err != nil {
		return err
	}
	if err := release.Verify(keys, data, string(sig)); err != nil {
		return err
	}
	r, err := release.Parse(data)
	if err != nil {
		return err
	}
	if err := release.CheckDist(*dist, r); err != nil {
		return err
	}
	fmt.Printf("ok: %s sequence %d, %d platforms, signature valid\n", r.Version, r.Sequence, len(r.Binaries))
	return nil
}
