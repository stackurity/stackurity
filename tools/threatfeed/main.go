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
//	  --feed static/threats/feed.json --valid-for 90d
//	go run ./tools/threatfeed verify --signed static/threats/feed.signed.json
//
// genkey refuses to overwrite an existing key. sign checks the feed parses
// as a catalogue this build reads, sets its generated_at and expires_at
// (servers refuse it after that), writes feed.signed.json (the catalogue
// and its signature in one file, threats.Envelope) next to it and
// verifies the result with the embedded keys (so a feed signed with a key
// no release trusts yet is caught here).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	fmt.Fprintln(os.Stderr, "usage: threatfeed genkey --key FILE --pub FILE | sign --key FILE --feed feed.json [--out feed.signed.json] [--valid-for 90d] | verify --signed feed.signed.json")
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
	feedFile := fs.String("feed", "", "feed.json to sign (rewritten with generated_at and expires_at)")
	out := fs.String("out", "", "where to write the signed feed (default: feed.signed.json next to feed.json)")
	validFor := fs.String("valid-for", "90d", "how long servers accept it, in days (90d) or a Go duration")
	_ = fs.Parse(args)
	if *keyFile == "" || *feedFile == "" {
		usage()
	}
	if *out == "" {
		*out = filepath.Join(filepath.Dir(*feedFile), "feed.signed.json")
	}
	valid, err := parseValidity(*validFor)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		return err
	}
	priv, err := threats.ParsePrivateKey(string(raw))
	if err != nil {
		return err
	}
	in, err := os.ReadFile(*feedFile)
	if err != nil {
		return err
	}
	c, err := threats.Parse(in)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	exp := now.Add(valid)
	c.GeneratedAt, c.ExpiresAt = now, &exp
	feed, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	feed = append(feed, '\n')
	if _, err := threats.Parse(feed); err != nil {
		return err
	}
	env := threats.SignEnvelope(feed, priv)
	if _, err := threats.OpenEnvelope(env); err != nil {
		return fmt.Errorf("the signature does not verify against this build's embedded keys (%v): embed the public key in a release first", err)
	}
	if err := os.WriteFile(*feedFile, feed, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(*out, env, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "signed %s (serial %d, %d threats, valid until %s) with key %s -> %s\n", *feedFile, c.Serial, len(c.Threats),
		exp.Format(time.DateOnly), threats.KeyID(priv.Public().(ed25519.PublicKey)), *out)
	return nil
}

func parseValidity(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 366 {
			return 0, fmt.Errorf("--valid-for %q: 1d to 366d", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--valid-for %q is not a duration", s)
	}
	return d, nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	envFile := fs.String("signed", "", "feed.signed.json")
	_ = fs.Parse(args)
	if *envFile == "" {
		usage()
	}
	env, err := os.ReadFile(*envFile)
	if err != nil {
		return err
	}
	feed, err := threats.OpenEnvelope(env)
	if err != nil {
		return err
	}
	c, err := threats.Parse(feed)
	if err != nil {
		return err
	}
	exp := "never (a feed must have expires_at)"
	if c.ExpiresAt != nil {
		exp = c.ExpiresAt.Format(time.DateOnly)
	}
	fmt.Fprintf(os.Stderr, "ok: serial %d, %d threats, expires %s, signed by a trusted key\n", c.Serial, len(c.Threats), exp)
	return nil
}
