package threats

import (
	"crypto/ed25519"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Signature is feed.json.sig: a detached Ed25519 signature over the exact
// bytes of feed.json, by the key whose id is KeyID. It is JSON so that the
// key can be rotated: a new key is embedded in a release before the feed is
// signed with it.
type Signature struct {
	Algorithm string `json:"algorithm"` // always "ed25519"
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64 (standard encoding)
}

// KeyID is the first 16 hex characters of the public key's SHA-256, as for
// stack packs (internal/packs).
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return fmt.Sprintf("%x", h[:8])
}

//go:embed keys/*.pub
var keyFiles embed.FS

// trusted are the public keys a feed may be signed with, by key id.
var trusted = func() map[string]ed25519.PublicKey {
	out := map[string]ed25519.PublicKey{}
	entries, err := keyFiles.ReadDir("keys")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		b, err := keyFiles.ReadFile("keys/" + e.Name())
		if err != nil {
			panic(err)
		}
		pub, err := ParsePublicKey(string(b))
		if err != nil {
			panic(fmt.Sprintf("threat feed key %s: %v", e.Name(), err))
		}
		out[KeyID(pub)] = pub
	}
	return out
}()

// TrustedKeyIDs lists the ids of the embedded feed keys.
func TrustedKeyIDs() []string {
	var ids []string
	for id := range trusted {
		ids = append(ids, id)
	}
	return ids
}

// ParsePublicKey reads a base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("not a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads a base64 Ed25519 seed (the format of the licence
// and pack signing keys).
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the key file must hold a base64 Ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign returns feed.json.sig for feed.
func Sign(feed []byte, priv ed25519.PrivateKey) []byte {
	pub := priv.Public().(ed25519.PublicKey)
	b, _ := json.MarshalIndent(Signature{Algorithm: "ed25519", KeyID: KeyID(pub),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, feed))}, "", "  ")
	return append(b, '\n')
}

// ErrBadSignature means the feed is unsigned, signed by a key this server
// does not trust, or changed after it was signed.
var ErrBadSignature = errors.New("threat feed signature is not valid")

// Verify checks feed against its detached signature with the embedded keys.
func Verify(feed, sig []byte) error {
	return verifyWith(trusted, feed, sig)
}

func verifyWith(keys map[string]ed25519.PublicKey, feed, sig []byte) error {
	if len(sig) == 0 {
		return fmt.Errorf("%w: the feed is not signed", ErrBadSignature)
	}
	var s Signature
	if err := json.Unmarshal(sig, &s); err != nil {
		return fmt.Errorf("%w: unreadable signature file", ErrBadSignature)
	}
	if s.Algorithm != "ed25519" {
		return fmt.Errorf("%w: algorithm %q", ErrBadSignature, s.Algorithm)
	}
	pub, ok := keys[s.KeyID]
	if !ok {
		return fmt.Errorf("%w: signed by key %q, which this server does not trust", ErrBadSignature, s.KeyID)
	}
	raw, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(pub, feed, raw) {
		return fmt.Errorf("%w: it does not match the feed", ErrBadSignature)
	}
	return nil
}
