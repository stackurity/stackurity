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

// Signature is an Ed25519 signature over the exact bytes of a catalogue,
// by the key whose id is KeyID, so that the key can be rotated: a new key
// is embedded in a release before the feed is signed with it. The feed is
// published as an Envelope holding both, so a cache can never pair a new
// catalogue with an old signature.
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

// Sign returns the detached signature of feed, as JSON (Signature).
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

// EnvelopeFormat names the signed feed's format.
const EnvelopeFormat = "stackurity-threat-feed/1"

// Envelope is the published feed (threats/feed.signed.json): the catalogue's
// exact bytes, base64-encoded, with their detached signature, in one file.
type Envelope struct {
	Format string `json:"format"`
	Signature
	Feed string `json:"feed"`
}

// SignEnvelope returns feed.signed.json for the catalogue bytes feed.
func SignEnvelope(feed []byte, priv ed25519.PrivateKey) []byte {
	var s Signature
	_ = json.Unmarshal(Sign(feed, priv), &s)
	b, _ := json.MarshalIndent(Envelope{Format: EnvelopeFormat, Signature: s, Feed: base64.StdEncoding.EncodeToString(feed)}, "", "  ")
	return append(b, '\n')
}

// OpenEnvelope checks a published feed's signature with the embedded keys
// and returns the catalogue bytes.
func OpenEnvelope(b []byte) ([]byte, error) { return openWith(trusted, b) }

func openWith(keys map[string]ed25519.PublicKey, b []byte) ([]byte, error) {
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil || e.Format != EnvelopeFormat {
		return nil, fmt.Errorf("%w: not a signed threat feed", ErrBadSignature)
	}
	feed, err := base64.StdEncoding.DecodeString(e.Feed)
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable feed", ErrBadSignature)
	}
	sig, _ := json.Marshal(e.Signature)
	if err := verifyWith(keys, feed, sig); err != nil {
		return nil, err
	}
	return feed, nil
}
