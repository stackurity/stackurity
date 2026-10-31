// Command license issues Stackurity licence keys. It needs the issuer's
// private key, which never leaves the issuer's machine:
//
//	go run ./tools/license --key ~/.config/stackurity/license-signing.key \
//	  --customer "Acme Ltd" --email ops@acme.example --edition pro --assets 250 --months 12
//
// A free Community key (normally issued by the sign-up on Stackurity Cloud)
// takes --edition community and never expires in practice; sign it with the
// free-key issuer's key, or with the licence issuer's.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/license"
)

func main() {
	keyFile := flag.String("key", "", "issuer private key (base64 Ed25519 seed)")
	customer := flag.String("customer", "", "customer name")
	email := flag.String("email", "", "customer contact")
	edition := flag.String("edition", "pro", "community, pro or enterprise")
	name := flag.String("name", "", "the person a community key is for")
	assets := flag.Int("assets", 0, "asset limit (0 = unlimited)")
	months := flag.Int("months", 12, "validity in months")
	flag.Parse()
	if *keyFile == "" || *customer == "" {
		fmt.Fprintln(os.Stderr, "usage: license --key FILE --customer NAME [--edition community|pro|enterprise] [--name PERSON] [--assets N] [--months N]")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*keyFile)
	if err != nil {
		fail(err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		fail(fmt.Errorf("the key file must hold a base64 Ed25519 seed"))
	}
	id := make([]byte, 8)
	_, _ = rand.Read(id)
	now := time.Now().UTC().Truncate(time.Second)
	l := license.License{ID: "lic_" + hex.EncodeToString(id), Customer: *customer, Name: *name, Email: *email,
		Edition: license.Edition(*edition), MaxAssets: *assets, IssuedAt: now, ExpiresAt: now.AddDate(0, *months, 0)}
	if l.Edition == license.Community {
		l.ID, l.MaxAssets, l.ExpiresAt = "ck_"+hex.EncodeToString(id), 0, now.Add(license.CommunityValidity)
	}
	key, err := license.Issue(l, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		fail(err)
	}
	if _, err := license.Parse(key); err != nil {
		fail(fmt.Errorf("the issued licence does not verify against this build's public key: %w", err))
	}
	fmt.Fprintf(os.Stderr, "%s: %s for %s, %s, until %s\n", l.ID, l.Edition, l.Customer, assetText(l.MaxAssets), l.ExpiresAt.Format("2006-01-02"))
	fmt.Println(key)
}

func assetText(n int) string {
	if n == 0 {
		return "unlimited assets"
	}
	return fmt.Sprintf("%d assets", n)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
