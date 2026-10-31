// Package webauthntest is a virtual WebAuthn authenticator for tests: it
// answers the options the server sends for navigator.credentials.create()
// and .get() the way a browser and a platform authenticator would (P-256
// keys, "none" attestation), so registration and sign-in can be tested end
// to end without a browser. It is never part of the server binary.
package webauthntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// Authenticator flags (WebAuthn §6.1).
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// Authenticator is a virtual authenticator for one origin.
type Authenticator struct {
	// Origin is what the browser puts in clientDataJSON
	// ("https://app.example").
	Origin string
	// NoUV leaves user verification out (a security key without a PIN).
	NoUV bool
	// Synced marks credentials as backed up (a synced passkey).
	Synced bool
	// Creds are the credentials made so far.
	Creds []*Credential
}

// Credential is a key pair the authenticator holds.
type Credential struct {
	ID         []byte
	UserHandle []byte
	RPID       string
	Key        *ecdsa.PrivateKey
	// Counter is the signature counter, sent incremented with each
	// assertion; a test sets it lower to imitate a cloned key.
	Counter uint32
}

var b64 = base64.RawURLEncoding

type options struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		RPID string `json:"rpId"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		Exclude []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
		Allow []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

func (a *Authenticator) flags() byte {
	f := byte(flagUP)
	if !a.NoUV {
		f |= flagUV
	}
	if a.Synced {
		f |= flagBE | flagBS
	}
	return f
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

// Create answers creation options (the "options" a server's begin step
// returns: {"publicKey": {...}}) with the JSON a browser sends for a new
// credential.
func (a *Authenticator) Create(opts json.RawMessage) (json.RawMessage, *Credential, error) {
	var o options
	if err := json.Unmarshal(opts, &o); err != nil {
		return nil, nil, err
	}
	pk := o.PublicKey
	for _, ex := range pk.Exclude {
		for _, c := range a.Creds {
			if b64.EncodeToString(c.ID) == ex.ID {
				return nil, nil, errors.New("InvalidStateError: the authenticator already holds an excluded credential")
			}
		}
	}
	handle, err := b64.DecodeString(pk.User.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("user.id: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	c := &Credential{ID: id, UserHandle: handle, RPID: pk.RP.ID, Key: key}
	x, y := key.PublicKey.X.FillBytes(make([]byte, 32)), key.PublicKey.Y.FillBytes(make([]byte, 32))
	cose, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{KeyType: int64(webauthncose.EllipticKey), Algorithm: int64(webauthncose.AlgES256)},
		Curve:         1, XCoord: x, YCoord: y,
	})
	if err != nil {
		return nil, nil, err
	}
	rpHash := sha256.Sum256([]byte(pk.RP.ID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, a.flags()|flagAT)
	auth = binary.BigEndian.AppendUint32(auth, 0)
	auth = append(auth, make([]byte, 16)...) // AAGUID: none
	auth = binary.BigEndian.AppendUint16(auth, uint16(len(id)))
	auth = append(auth, id...)
	auth = append(auth, cose...)
	att, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth})
	if err != nil {
		return nil, nil, err
	}
	out, err := json.Marshal(map[string]any{
		"id": b64.EncodeToString(id), "rawId": b64.EncodeToString(id), "type": "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData("webauthn.create", pk.Challenge, a.Origin)),
			"attestationObject": b64.EncodeToString(att),
			"transports":        []string{"internal", "hybrid"},
		},
		"clientExtensionResults": map[string]any{"credProps": map[string]any{"rk": true}},
	})
	if err != nil {
		return nil, nil, err
	}
	a.Creds = append(a.Creds, c)
	return out, c, nil
}

// Get answers request options with an assertion from c (nil: the first
// credential the options allow, or for a discoverable request the first
// one for the relying party).
func (a *Authenticator) Get(opts json.RawMessage, c *Credential) (json.RawMessage, error) {
	var o options
	if err := json.Unmarshal(opts, &o); err != nil {
		return nil, err
	}
	pk := o.PublicKey
	if c == nil {
		for _, cand := range a.Creds {
			if cand.RPID != pk.RPID {
				continue
			}
			if len(pk.Allow) == 0 {
				c = cand
				break
			}
			for _, al := range pk.Allow {
				if b64.EncodeToString(cand.ID) == al.ID {
					c = cand
				}
			}
			if c != nil {
				break
			}
		}
	}
	if c == nil {
		return nil, errors.New("NotAllowedError: no credential for this request")
	}
	return a.Assert(pk.Challenge, pk.RPID, c)
}

// Assert signs challenge for rpID with c, as Get does, without options.
func (a *Authenticator) Assert(challenge, rpID string, c *Credential) (json.RawMessage, error) {
	c.Counter++
	rpHash := sha256.Sum256([]byte(rpID))
	auth := append([]byte{}, rpHash[:]...)
	auth = append(auth, a.flags())
	auth = binary.BigEndian.AppendUint32(auth, c.Counter)
	cd := clientData("webauthn.get", challenge, a.Origin)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, c.Key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id": b64.EncodeToString(c.ID), "rawId": b64.EncodeToString(c.ID), "type": "public-key",
		"authenticatorAttachment": "platform",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(auth),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(c.UserHandle),
		},
		"clientExtensionResults": map[string]any{},
	})
}
