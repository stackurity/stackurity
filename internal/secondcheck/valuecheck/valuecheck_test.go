package valuecheck

import (
	"hash/crc32"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
)

// Sample values are built from parts so this file does not look like it
// holds keys.
func ghToken(random string) string {
	n := crc32.ChecksumIEEE([]byte(random))
	var b [6]byte
	for i := 5; i >= 0; i-- {
		b[i] = base62[n%62]
		n /= 62
	}
	return "gh" + "p_" + random + string(b[:])
}

func randomString(r *rand.Rand, alphabet string, n int) string {
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

func TestCheck(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	real := ghToken(randomString(r, base62, 30))
	edited := real[:len(real)-1] + "a"
	if strings.HasSuffix(real, "a") {
		edited = real[:len(real)-1] + "b"
	}
	for _, c := range []struct {
		name, rule, value string
		want              []string
	}{
		{"real GitHub token", "github-token", real, []string{ChecksumValid}},
		{"edited GitHub token", "github-token", edited, []string{ChecksumInvalid}},
		{"made-up GitHub token", "github-token", "gh" + "p_" + strings.Repeat("a", 36), []string{Placeholder, LowEntropy, ChecksumInvalid}},
		{"run", "github-token", "gh" + "p_1234567890abcdefghij1234567890abcdef", []string{Placeholder, ChecksumInvalid}},
		{"AWS documentation key", "aws-access-key-id", "AKIA" + "IOSFODNN7" + "EXAMPLE", []string{KnownSample, Placeholder}},
		{"Stripe documentation test key", "password-assignment", "sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc", []string{KnownSample, TestModeKey}},
		{"Stripe test key", "password-assignment", "sk_" + "test_" + randomString(r, base62, 24), []string{TestModeKey}},
		{"template", "password-assignment", "<your-api-key>", []string{Placeholder}},
		{"stars", "openai-key", "sk-" + "proj-****************T3BlbkFJ" + randomString(r, base62, 20), []string{Placeholder}},
		{"repeated unit", "slack-token", "xox" + "b-" + strings.Repeat("ab12", 8), []string{Placeholder, LowEntropy}},
		{"weak password is still a password", "password-assignment", "Summer2024!", nil},
		{"real-looking password", "password-assignment", "h7#Kq9!vLm2@", nil},
		{"private key body", "private-key", strings.Repeat("A", 64), []string{Placeholder, LowEntropy}},
	} {
		got := Check(c.rule, c.value)
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
		for _, s := range got {
			if !Valid(s) {
				t.Errorf("%s: %q is not in Signals", c.name, s)
			}
		}
	}
}

// Generated keys of every format the detector reports must come out with
// no signal that would call them false positives: a missed real key is far
// worse than noise.
func TestGeneratedKeysAreNotFlagged(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	const hexDigits = "0123456789abcdef"
	const base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	formats := []struct {
		rule string
		gen  func() string
	}{
		{"github-token", func() string { return ghToken(randomString(r, base62, 30)) }},
		{"aws-access-key-id", func() string { return "AKIA" + randomString(r, base32, 16) }},
		{"aws-secret-key", func() string { return randomString(r, base62+"/+", 40) }},
		{"gitlab-token", func() string { return "glpat-" + randomString(r, base62+"_-", 20) }},
		{"stripe-live-key", func() string { return "sk_" + "live_" + randomString(r, base62, 24) }},
		{"openrouter-key", func() string { return "sk-or-v1-" + randomString(r, hexDigits, 64) }},
		{"anthropic-key", func() string { return "sk-ant-api03-" + randomString(r, base62+"_-", 93) }},
		{"npm-token", func() string { return "npm_" + randomString(r, base62, 36) }},
		{"private-key", func() string { return "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + randomString(r, base62+"+/", 32) }},
		{"password-assignment", func() string { return randomString(r, base62+"!@#%^&*", 16) }},
	}
	for _, f := range formats {
		flagged := 0
		for range 20_000 {
			v := f.gen()
			for _, s := range Check(f.rule, v) {
				if s != ChecksumValid {
					flagged++
					if flagged <= 3 {
						t.Logf("%s: %s flagged %v", f.rule, v, s)
					}
				}
			}
		}
		// Allow at most one in 10,000 (a chance "0123456789" or a word).
		if flagged > 2 {
			t.Errorf("%s: %d of 20,000 generated keys flagged", f.rule, flagged)
		}
	}
}
