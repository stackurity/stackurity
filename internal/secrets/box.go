package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Box encrypts stored secrets with AES-256-GCM. Each value is bound to its
// workspace and name, so a ciphertext copied to another row does not open.
type Box struct{ aead cipher.AEAD }

// ErrNoKey means stored secrets are disabled because no key is configured.
var ErrNoKey = errors.New("stored secrets need STACKURITY_SECRET_KEY (32 random bytes, base64)")

// BoxFromEnv reads STACKURITY_SECRET_KEY or STACKURITY_SECRET_KEY_FILE. It
// returns ErrNoKey when neither is set.
func BoxFromEnv() (*Box, error) {
	raw := os.Getenv("STACKURITY_SECRET_KEY")
	if f := os.Getenv("STACKURITY_SECRET_KEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read secret key: %w", err)
		}
		raw = string(b)
	}
	if strings.TrimSpace(raw) == "" {
		return nil, ErrNoKey
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(key) != 32 {
		return nil, errors.New("STACKURITY_SECRET_KEY must be 32 bytes, base64-encoded (openssl rand -base64 32)")
	}
	return NewBox(key)
}

func NewBox(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func aad(workspace int64, name string) []byte {
	return []byte(strconv.FormatInt(workspace, 10) + "/" + name)
}

// Seal returns nonce||ciphertext.
func (b *Box) Seal(workspace int64, name, value string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, []byte(value), aad(workspace, name)), nil
}

func (b *Box) Open(workspace int64, name string, sealed []byte) (string, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return "", errors.New("stored secret is corrupt")
	}
	out, err := b.aead.Open(nil, sealed[:n], sealed[n:], aad(workspace, name))
	if err != nil {
		return "", errors.New("stored secret cannot be decrypted (wrong STACKURITY_SECRET_KEY?)")
	}
	return string(out), nil
}
