package packs

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Signature is signature.json: an Ed25519 signature over Archive.Digest by
// the publisher's key.
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// Trust is how far a pack is trusted, shown to administrators.
type Trust string

const (
	TrustOfficial Trust = "official" // signed by the Stackurity project
	TrustVerified Trust = "verified" // signed by a publisher this server trusts
	TrustUnsigned Trust = "unsigned" // allowed only in developer mode
)

// Key is a publisher's public key.
type Key struct {
	ID        string
	Publisher string
	Public    ed25519.PublicKey
	Official  bool
}

// KeyID is the first 16 hex characters of the key's SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return fmt.Sprintf("%x", h[:8])
}

// Keyring holds the keys whose packs may be installed.
type Keyring struct {
	keys          map[string]Key
	AllowUnsigned bool
}

//go:embed keys/official.pub
var officialKey string

// DefaultKeyring trusts the official Stackurity key, any publisher keys listed
// in STACKURITY_PACK_TRUSTED_KEYS (a file of "publisher base64-key" lines),
// and unsigned packs only when STACKURITY_PACK_ALLOW_UNSIGNED=true.
func DefaultKeyring() (*Keyring, error) {
	k := &Keyring{keys: map[string]Key{}, AllowUnsigned: os.Getenv("STACKURITY_PACK_ALLOW_UNSIGNED") == "true"}
	if err := k.Add("stackurity", strings.TrimSpace(officialKey), true); err != nil {
		return nil, fmt.Errorf("official key: %w", err)
	}
	if f := os.Getenv("STACKURITY_PACK_TRUSTED_KEYS"); f != "" {
		file, err := os.Open(f)
		if err != nil {
			return nil, fmt.Errorf("trusted pack keys: %w", err)
		}
		defer file.Close()
		sc := bufio.NewScanner(file)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			publisher, key, ok := strings.Cut(line, " ")
			if !ok {
				return nil, fmt.Errorf("trusted pack keys: %q must be \"publisher base64-key\"", line)
			}
			if publisher == "stackurity" {
				return nil, errors.New("trusted pack keys: the publisher name stackurity is reserved for official packs")
			}
			if err := k.Add(publisher, strings.TrimSpace(key), false); err != nil {
				return nil, fmt.Errorf("trusted pack keys: %w", err)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	return k, nil
}

// Add trusts a base64-encoded Ed25519 public key for one publisher.
func (k *Keyring) Add(publisher, b64 string, official bool) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("a key must be a base64 Ed25519 public key")
	}
	if k.keys == nil {
		k.keys = map[string]Key{}
	}
	pub := ed25519.PublicKey(raw)
	k.keys[KeyID(pub)] = Key{ID: KeyID(pub), Publisher: publisher, Public: pub, Official: official}
	return nil
}

// Verify checks a pack's signature and that its manifest names the key's
// publisher, so nobody can sign a pack in another publisher's name.
func (k *Keyring) Verify(a *Archive) (Trust, error) {
	if a.Signature == nil {
		if k.AllowUnsigned {
			return TrustUnsigned, nil
		}
		return "", errors.New("the pack is not signed; unsigned packs are refused (STACKURITY_PACK_ALLOW_UNSIGNED=true allows them for development)")
	}
	key, ok := k.keys[a.Signature.KeyID]
	if !ok {
		return "", fmt.Errorf("the pack is signed by key %s, which this server does not trust", a.Signature.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature.Signature)
	if err != nil || !ed25519.Verify(key.Public, a.Digest(), sig) {
		return "", errors.New("the pack's signature does not match its contents")
	}
	if a.Manifest.Publisher != key.Publisher {
		return "", fmt.Errorf("the pack says it is published by %q but is signed by %q", a.Manifest.Publisher, key.Publisher)
	}
	if key.Official {
		return TrustOfficial, nil
	}
	return TrustVerified, nil
}

// Sign signs the archive in place with a publisher's private key.
func Sign(a *Archive, priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	a.Signature = &Signature{KeyID: KeyID(pub), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, a.Digest()))}
}
