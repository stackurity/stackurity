// Package evidencesig signs and verifies the manifest of a compliance
// evidence pack (the ZIP export of the audit evidence pack).
//
// The pack's manifest.json lists every file in the ZIP with its SHA-256. A
// server with an evidence signing key adds manifest.json.sig, a detached
// Ed25519 signature over the exact bytes of manifest.json, which names the
// key that made it. Anyone can check a pack against the published key set
// (KeySetURL) with `stackurity evidence verify`: the signature proves the
// manifest came from the key's holder, and the manifest's hashes prove every
// file is the one it listed.
//
// The key set holds every key ever used, so rotating a key never breaks a
// pack signed earlier: a retired key still verifies the packs it signed
// while it was in use (until its not_after), and only a revoked key stops
// verifying altogether. Signing and verifying are both open source; the
// evidence pack itself is in the licensed build.
package evidencesig

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	// Alg is the only signature algorithm.
	Alg = "Ed25519"
	// ManifestName and SignatureName are the files' names in the ZIP.
	ManifestName  = "manifest.json"
	SignatureName = "manifest.json.sig"
	// KeySetURL is where Stackurity publishes the public keys that sign the
	// packs of Stackurity Cloud. Its address never changes.
	KeySetURL = "https://stackurity.ai/.well-known/stackurity-evidence-keys.json"
	// EnvKeyFile is the setting that names the private key file (PKCS#8 PEM).
	EnvKeyFile = "STACKURITY_EVIDENCE_SIGNING_KEY_FILE"
)

// Key statuses in a key set.
const (
	StatusActive  = "active"  // signs new packs
	StatusRetired = "retired" // no longer signs; still verifies what it signed
	StatusRevoked = "revoked" // compromised: verifies nothing
)

var (
	ErrUnsigned     = errors.New("the pack is not signed")
	ErrUnknownKey   = errors.New("the pack was signed with a key that is not in the key set")
	ErrRevokedKey   = errors.New("the pack was signed with a revoked key")
	ErrKeyWindow    = errors.New("the pack's date is outside the period its key was in use")
	ErrBadSignature = errors.New("the signature does not match manifest.json: the manifest was changed or not signed by this key")
	ErrTampered     = errors.New("a file does not match manifest.json")
)

// KeyID names a public key: "ed25519:" and the first 16 hex digits of the
// SHA-256 of its 32 bytes.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(h[:8])
}

// Signature is the content of manifest.json.sig.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	// Signature is the base64 Ed25519 signature of manifest.json's bytes.
	Signature string `json:"signature"`
}

// Signer signs manifests with one private key.
type Signer struct {
	key ed25519.PrivateKey
	id  string
}

// NewSigner wraps a private key.
func NewSigner(key ed25519.PrivateKey) *Signer {
	return &Signer{key: key, id: KeyID(key.Public().(ed25519.PublicKey))}
}

// LoadSigner reads a PKCS#8 PEM Ed25519 private key (as made by
// `openssl genpkey -algorithm ed25519`).
func LoadSigner(path string) (*Signer, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return NewSigner(key), nil
}

// SignerFromEnv loads the key named by EnvKeyFile; nil, nil when it is not
// set (packs are then unsigned).
func SignerFromEnv() (*Signer, error) {
	path := os.Getenv(EnvKeyFile)
	if path == "" {
		return nil, nil
	}
	return LoadSigner(path)
}

// ParsePrivateKey reads a PKCS#8 PEM Ed25519 private key.
func ParsePrivateKey(b []byte) (ed25519.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("not a PEM file")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 key")
	}
	return key, nil
}

// KeyID of the signer's public key.
func (s *Signer) KeyID() string { return s.id }

// PublicKey of the signer.
func (s *Signer) PublicKey() ed25519.PublicKey { return s.key.Public().(ed25519.PublicKey) }

// Sign signs the exact bytes of manifest.json.
func (s *Signer) Sign(manifest []byte) Signature {
	return Signature{Alg: Alg, KeyID: s.id, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(s.key, manifest))}
}

// Key is one public key of a key set.
type Key struct {
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	// PublicKey is the key's 32 bytes in base64.
	PublicKey string `json:"public_key"`
	Status    string `json:"status"`
	// NotBefore and NotAfter bound the packs (by their generated_at) the key
	// verifies; NotAfter is set when the key is retired.
	NotBefore time.Time  `json:"not_before"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
	Comment   string     `json:"comment,omitempty"`
}

// KeySet is the published list of keys.
type KeySet struct {
	Keys []Key `json:"keys"`
}

// Entry is the key set entry for a new active key.
func Entry(pub ed25519.PublicKey, notBefore time.Time) Key {
	return Key{KeyID: KeyID(pub), Alg: Alg, PublicKey: base64.StdEncoding.EncodeToString(pub), Status: StatusActive,
		NotBefore: notBefore.UTC()}
}

// ParseKeySet reads a key set and checks every key's id matches its key.
func ParseKeySet(b []byte) (*KeySet, error) {
	var ks KeySet
	if err := json.Unmarshal(b, &ks); err != nil {
		return nil, fmt.Errorf("key set: %w", err)
	}
	for _, k := range ks.Keys {
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize || k.Alg != Alg {
			return nil, fmt.Errorf("key set: key %s is not an Ed25519 public key", k.KeyID)
		}
		if KeyID(pub) != k.KeyID {
			return nil, fmt.Errorf("key set: key id %s does not match its public key", k.KeyID)
		}
		switch k.Status {
		case StatusActive, StatusRetired, StatusRevoked:
		default:
			return nil, fmt.Errorf("key set: key %s has unknown status %q", k.KeyID, k.Status)
		}
	}
	return &ks, nil
}

// Verify checks sig over manifest, made at generatedAt (the manifest's own
// date), and returns the key that verified it.
func (ks *KeySet) Verify(manifest []byte, sig Signature, generatedAt time.Time) (*Key, error) {
	if sig.Alg != Alg {
		return nil, fmt.Errorf("unsupported signature algorithm %q", sig.Alg)
	}
	for i := range ks.Keys {
		k := &ks.Keys[i]
		if k.KeyID != sig.KeyID {
			continue
		}
		if k.Status == StatusRevoked {
			return k, ErrRevokedKey
		}
		if generatedAt.Before(k.NotBefore) || (k.NotAfter != nil && generatedAt.After(*k.NotAfter)) {
			return k, ErrKeyWindow
		}
		pub, _ := base64.StdEncoding.DecodeString(k.PublicKey)
		raw, err := base64.StdEncoding.DecodeString(sig.Signature)
		if err != nil || !ed25519.Verify(pub, manifest, raw) {
			return k, ErrBadSignature
		}
		return k, nil
	}
	return nil, ErrUnknownKey
}

// Manifest is manifest.json.
type Manifest struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	// Signed says whether the server signed this manifest, and KeyID with
	// which key; an unsigned pack says so in its manifest, its pack.json and
	// its PDF.
	Signed bool           `json:"signed"`
	KeyID  string         `json:"signing_key_id,omitempty"`
	Files  []ManifestFile `json:"files"`
}

// ManifestFile is one file the manifest lists.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Result is what VerifyZIP found.
type Result struct {
	Manifest Manifest
	// Key verified the signature; nil for an unsigned pack.
	Key *Key
	// Files is the number of files whose hash was checked.
	Files int
}

// VerifyZIP checks an evidence pack ZIP: every file against manifest.json,
// then manifest.json's signature against ks. An unsigned pack whose files
// all match returns ErrUnsigned with the result filled in.
func VerifyZIP(r io.ReaderAt, size int64, ks *KeySet) (*Result, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	read := func(f *zip.File) ([]byte, error) {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	byName := map[string]*zip.File{}
	for _, f := range zr.File {
		if _, dup := byName[f.Name]; dup {
			return nil, fmt.Errorf("%w: %s is in the ZIP twice", ErrTampered, f.Name)
		}
		byName[f.Name] = f
	}
	mf := byName[ManifestName]
	if mf == nil {
		return nil, errors.New("not an evidence pack: no manifest.json")
	}
	mb, err := read(mf)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	if err := json.Unmarshal(mb, &res.Manifest); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	listed := map[string]bool{ManifestName: true, SignatureName: true}
	for _, e := range res.Manifest.Files {
		listed[e.Path] = true
		f := byName[e.Path]
		if f == nil {
			return res, fmt.Errorf("%w: %s is missing", ErrTampered, e.Path)
		}
		b, err := read(f)
		if err != nil {
			return res, err
		}
		h := sha256.Sum256(b)
		if hex.EncodeToString(h[:]) != e.SHA256 || int64(len(b)) != e.Bytes {
			return res, fmt.Errorf("%w: %s was changed", ErrTampered, e.Path)
		}
		res.Files++
	}
	for name := range byName {
		if !listed[name] {
			return res, fmt.Errorf("%w: %s is not in the manifest", ErrTampered, name)
		}
	}
	sf := byName[SignatureName]
	switch {
	case sf == nil && !res.Manifest.Signed:
		return res, ErrUnsigned
	case sf == nil:
		return res, fmt.Errorf("%w: manifest.json says it is signed but manifest.json.sig is missing", ErrTampered)
	case !res.Manifest.Signed:
		return res, fmt.Errorf("%w: manifest.json says it is unsigned but has a signature", ErrTampered)
	}
	sb, err := read(sf)
	if err != nil {
		return res, err
	}
	var sig Signature
	if err := json.Unmarshal(bytes.TrimSpace(sb), &sig); err != nil {
		return res, fmt.Errorf("manifest.json.sig: %w", err)
	}
	if sig.KeyID != res.Manifest.KeyID {
		return res, fmt.Errorf("%w: the signature's key %s is not the key manifest.json names (%s)", ErrTampered, sig.KeyID, res.Manifest.KeyID)
	}
	res.Key, err = ks.Verify(mb, sig, res.Manifest.GeneratedAt)
	return res, err
}
