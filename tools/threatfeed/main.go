// Command threatfeed signs the public threat feed
// (https://stackurity.ai/threats/feed.json), whose detached signature
// self-hosted and Cloud servers verify against the public keys embedded in
// internal/threats/keys before they use it (docs/threat-notices.md).
//
// The private key never leaves the signer's machine and is never printed:
//
//	go run ./tools/threatfeed genkey --key ~/.config/stackurity/threat-feed-signing.key \
//	  --pub internal/threats/keys/threat-feed.pub
//	go run ./tools/threatfeed sign --key ~/.config/stackurity/threat-feed-signing.key \
//	  --feed static/threats/feed.json
//	go run ./tools/threatfeed verify --feed static/threats/feed.json
//
// genkey refuses to overwrite an existing key. sign checks the feed parses
// as a catalogue this build reads, then writes feed.json.sig next to it and
// verifies the result with the embedded keys (so a feed signed with a key
// no release trusts yet is caught here).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stackurity/stackurity/internal/threats"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "genkey":
		err = genkey(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "threatfeed:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: threatfeed genkey --key FILE --pub FILE | sign --key FILE --feed feed.json [--sig FILE] | verify --feed feed.json [--sig FILE]")
	os.Exit(2)
}

func genkey(args []string) error {
	fs := flag.NewFlagSet("genkey", flag.ExitOnError)
	keyFile := fs.String("key", "", "where to write the private key (base64 Ed25519 seed, mode 0600)")
	pubFile := fs.String("pub", "", "where to write the public key (base64)")
	_ = fs.Parse(args)
	if *keyFile == "" || *pubFile == "" {
		usage()
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*keyFile), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(*keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists; refusing to overwrite a signing key", *keyFile)
		}
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.WriteFile(*pubFile, []byte(base64.StdEncoding.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote the private key to %s (0600) and the public key to %s; key id %s\n", *keyFile, *pubFile, threats.KeyID(pub))
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyFile := fs.String("key", "", "the private key (base64 Ed25519 seed)")
	feedFile := fs.String("feed", "", "feed.json to sign")
	sigFile := fs.String("sig", "", "where to write the signature (default: the feed's path + .sig)")
	_ = fs.Parse(args)
	if *keyFile == "" || *feedFile == "" {
		usage()
	}
	if *sigFile == "" {
		*sigFile = *feedFile + ".sig"
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	priv, err := threats.ParsePrivateKey(string(raw))
	if err != nil {
		return err
	}
	feed, err := os.ReadFile(*feedFile)
	if err != nil {
		return err
	}
	c, err := threats.Parse(feed)
	if err != nil {
		return err
	}
	sig := threats.Sign(feed, priv)
	if err := threats.Verify(feed, sig); err != nil {
		return fmt.Errorf("the signature does not verify against this build's embedded keys (%v): embed the public key in a release first", err)
	}
	if err := os.WriteFile(*sigFile, sig, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed %s (serial %d, %d threats) with key %s -> %s\n", *feedFile, c.Serial, len(c.Threats),
		threats.KeyID(priv.Public().(ed25519.PublicKey)), *sigFile)
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	feedFile := fs.String("feed", "", "feed.json")
	sigFile := fs.String("sig", "", "its signature (default: the feed's path + .sig)")
	_ = fs.Parse(args)
	if *feedFile == "" {
		usage()
	}
	if *sigFile == "" {
		*sigFile = *feedFile + ".sig"
	}
	feed, err := os.ReadFile(*feedFile)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(*sigFile)
	if err != nil {
		return err
	}
	if err := threats.Verify(feed, sig); err != nil {
		return err
	}
	c, err := threats.Parse(feed)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ok: serial %d, %d threats, signed by a trusted key\n", c.Serial, len(c.Threats))
	return nil
}
