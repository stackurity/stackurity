package auth

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 column (the eight-digit codes, last six).
func TestTOTPVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	for _, c := range []struct {
		unix int64
		want string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
	} {
		got, err := TOTPCode(secret, time.Unix(c.unix, 0))
		if err != nil || got != c.want {
			t.Errorf("t=%d: %q %v, want %q", c.unix, got, err, c.want)
		}
	}
}

func TestCheckTOTPWindow(t *testing.T) {
	secret, err := NewTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		code, _ := TOTPCode(secret, now.Add(d))
		if CheckTOTP(secret, code, now) != TOTPStep(now.Add(d)) {
			t.Errorf("offset %v refused", d)
		}
	}
	for _, d := range []time.Duration{-90 * time.Second, 90 * time.Second} {
		code, _ := TOTPCode(secret, now.Add(d))
		if CheckTOTP(secret, code, now) != 0 {
			t.Errorf("offset %v accepted", d)
		}
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if CheckTOTP(secret, bad, now) != 0 {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes, hashes, err := NewRecoveryCodes(RecoveryCodeCount)
	if err != nil || len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("%d codes, %v", len(codes), err)
	}
	seen := map[string]bool{}
	for i, c := range codes {
		if len(c) != 19 || !LooksLikeRecoveryCode(c) || seen[c] {
			t.Fatalf("bad code %q", c)
		}
		seen[c] = true
		if string(HashRecoveryCode(" "+c[:4]+c[5:9]+" "+c[10:]+"\n")) != string(hashes[i]) {
			t.Errorf("code %q does not match typed loosely", c)
		}
	}
	if LooksLikeRecoveryCode("123456") {
		t.Error("TOTP code taken for a recovery code")
	}
}
