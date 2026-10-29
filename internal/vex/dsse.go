package vex

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Envelope is a DSSE envelope (https://github.com/secure-systems-lab/dsse),
// the signed wrapper cosign attest and in-toto use for attestations.
type Envelope struct {
	PayloadType string
	Payload     []byte
	Signatures  []EnvelopeSignature
}

// EnvelopeSignature is one signature over the envelope's payload.
type EnvelopeSignature struct {
	KeyID string
	Sig   []byte
}

const maxSignatures = 16

func parseEnvelope(data []byte) (*Envelope, error) {
	var raw struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse DSSE envelope: %w", err)
	}
	payload, err := b64(raw.Payload)
	if err != nil {
		return nil, errors.New("the envelope's payload is not base64")
	}
	if len(raw.Signatures) > maxSignatures {
		return nil, errors.New("too many signatures on the envelope")
	}
	env := &Envelope{PayloadType: raw.PayloadType, Payload: payload}
	for _, s := range raw.Signatures {
		sig, err := b64(s.Sig)
		if err != nil {
			return nil, errors.New("a signature is not base64")
		}
		env.Signatures = append(env.Signatures, EnvelopeSignature{KeyID: clip(s.KeyID, 200), Sig: sig})
	}
	return env, nil
}

func b64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64")
}

// PAE is DSSE's pre-authentication encoding of a payload: what is signed.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// Verifier checks an envelope's signature. KeyVerifier checks it with a
// public key; keyless signatures (a Fulcio certificate and a Rekor entry,
// cosign's default) would be another Verifier, which this release does not
// have: an envelope signed that way is reported as signed but unverified.
type Verifier interface {
	Verify(env *Envelope) error
}

// KeyVerifier verifies with one PEM public key (ECDSA P-256 or P-384,
// Ed25519 or RSA), as `cosign generate-key-pair` writes in cosign.pub.
type KeyVerifier struct {
	key crypto.PublicKey
}

// ParsePublicKey reads a PEM "PUBLIC KEY" block and returns a verifier
// and the key's fingerprint (the SHA-256 of its DER encoding, in hex).
func ParsePublicKey(pemText string) (*KeyVerifier, string, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemText)))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, "", errors.New(`the key must be a PEM "PUBLIC KEY" block (cosign.pub)`)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("read public key: %w", err)
	}
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if n := k.Curve.Params().Name; n != "P-256" && n != "P-384" {
			return nil, "", fmt.Errorf("ECDSA curve %s is not supported; use P-256 or P-384", n)
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, "", errors.New("RSA keys must have at least 2048 bits")
		}
	default:
		return nil, "", fmt.Errorf("unsupported key type %T", key)
	}
	sum := sha256.Sum256(block.Bytes)
	return &KeyVerifier{key: key}, hex.EncodeToString(sum[:]), nil
}

// Verify succeeds when any signature on the envelope verifies with the key.
func (v *KeyVerifier) Verify(env *Envelope) error {
	if env == nil || len(env.Signatures) == 0 {
		return errors.New("the document is not signed")
	}
	msg := PAE(env.PayloadType, env.Payload)
	for _, s := range env.Signatures {
		if v.verifyOne(msg, s.Sig) {
			return nil
		}
	}
	return errors.New("no signature on the envelope verifies with the source's key")
}

func (v *KeyVerifier) verifyOne(msg, sig []byte) bool {
	switch k := v.key.(type) {
	case *ecdsa.PublicKey:
		var h []byte
		if k.Curve.Params().Name == "P-384" {
			s := sha512.Sum384(msg)
			h = s[:]
		} else {
			s := sha256.Sum256(msg)
			h = s[:]
		}
		return ecdsa.VerifyASN1(k, h, sig)
	case ed25519.PublicKey:
		return ed25519.Verify(k, msg, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		if rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil {
			return true
		}
		return rsa.VerifyPSS(k, crypto.SHA256, h[:], sig, nil) == nil
	}
	return false
}
