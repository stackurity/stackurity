package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is HMAC-SHA1, which every authenticator app uses
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Time-based one-time passwords (RFC 6238): HMAC-SHA1, 30-second steps,
// six digits, the parameters every authenticator app supports.

const (
	totpPeriod = 30
	totpDigits = 6
	// totpSkew is how many steps before and after the current one are
	// accepted, for clocks that drift (RFC 6238 section 5.2 recommends one).
	totpSkew = 1
)

// NewTOTPSecret returns a random 160-bit secret, base32 without padding,
// as authenticator apps expect it.
func NewTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// TOTPURL is the otpauth:// URL an authenticator app reads from a QR code.
func TOTPURL(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprint(totpDigits))
	v.Set("period", fmt.Sprint(totpPeriod))
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// TOTPStep is the RFC 6238 time step t falls in.
func TOTPStep(t time.Time) int64 { return t.Unix() / totpPeriod }

func totpAt(key []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1000000
	return fmt.Sprintf("%06d", code)
}

// TOTPCode is the code for secret at t (for tests and enrolment checks).
func TOTPCode(secret string, t time.Time) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	return totpAt(key, TOTPStep(t)), nil
}

// CheckTOTP reports the time step code matches for secret at now, within
// one step either side, or 0 when it matches none. Callers reject a step
// at or before the last one accepted, so a code is never accepted twice.
func CheckTOTP(secret, code string, now time.Time) int64 {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return 0
	}
	cur := TOTPStep(now)
	var match int64
	// Every candidate is computed, so the time taken does not depend on
	// which step matched.
	for s := cur - totpSkew; s <= cur+totpSkew; s++ {
		if subtle.ConstantTimeCompare([]byte(totpAt(key, s)), []byte(code)) == 1 {
			match = s
		}
	}
	return match
}

// RecoveryCodeCount is how many one-time recovery codes are issued.
const RecoveryCodeCount = 10

// NewRecoveryCodes returns n random codes shown once, as xxxx-xxxx-xxxx-xxxx
// (80 bits each), and their hashes to store.
func NewRecoveryCodes(n int) (codes []string, hashes [][]byte, err error) {
	for i := 0; i < n; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, err
		}
		s := strings.ToLower(b32.EncodeToString(b)) // 16 characters
		code := s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
		codes = append(codes, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return codes, hashes, nil
}

// HashRecoveryCode hashes a recovery code as typed: case, spaces and
// dashes do not matter. The codes carry 80 random bits, so a fast hash is
// enough.
func HashRecoveryCode(code string) []byte {
	c := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	h := sha256.Sum256([]byte("stackurity-recovery:" + c))
	return h[:]
}

// LooksLikeRecoveryCode tells a recovery code from a six-digit TOTP code.
func LooksLikeRecoveryCode(code string) bool {
	c := strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code))
	return len(c) == 16
}
