// Package valuecheck is the part of the second check of leaked keys that
// needs the value itself: whether it is a placeholder, a provider's
// test-mode key, a sample published in documentation, too plain to be a
// generated key, or a token whose built-in checksum does not match.
//
// It runs in the collector, which has the value while it reads the file,
// and returns only signals from a fixed list (Signals). Nothing derived from
// the value's characters leaves it, so the server still never holds the
// key, and the database refuses any other text in the column that keeps
// them (migration 0119). The server's second check (internal/secondcheck)
// turns the signals, the file and the scan history into a verdict.
//
// It is deliberately separate from the detector (internal/collect/leaks),
// which already drops some placeholders on its own: a defect or a gap in
// one is not repeated in the other. It imports nothing but the standard
// library.
package valuecheck

import (
	"crypto/sha256"
	"encoding/hex"
	"hash/crc32"
	"math"
	"regexp"
	"strings"
)

// Checker is the version of these rules, stored with the signals. Change
// it whenever a rule changes, so verdicts made under older rules can be
// told apart.
const Checker = "value/1"

// The signals. Each is a fact about the value, never the value.
const (
	// Placeholder: the value is a template's or a document's stand-in
	// (xxxx, <your-key>, changeme, EXAMPLE, one character repeated, a run
	// such as 0123456789).
	Placeholder = "placeholder"
	// LowEntropy: a key with a provider's format whose random part is far
	// too plain to have been generated. Not used for passwords: a weak
	// password is still a password.
	LowEntropy = "low_entropy"
	// TestModeKey: a provider's test-mode key (Stripe sk_test_, Razorpay
	// rzp_test_), which cannot move real money.
	TestModeKey = "test_mode_key"
	// KnownSample: a key published in a provider's documentation.
	KnownSample = "known_sample"
	// ChecksumValid and ChecksumInvalid: the token's built-in checksum
	// (GitHub's classic tokens end in a CRC32 of their random part)
	// matches, or does not, so the provider never issued it.
	ChecksumValid   = "checksum_valid"
	ChecksumInvalid = "checksum_invalid"
)

// Signals is every signal Check can return; the server refuses others.
var Signals = []string{Placeholder, LowEntropy, TestModeKey, KnownSample, ChecksumValid, ChecksumInvalid}

// Valid reports whether s is one of Signals.
func Valid(s string) bool {
	for _, x := range Signals {
		if x == s {
			return true
		}
	}
	return false
}

// knownSamples are SHA-256 hashes of keys published in providers'
// documentation, kept as hashes so this file does not trip secret scanners:
// AWS's AKIAIOSFODNN7EXAMPLE and its secret key, Stripe's documented
// test-mode keys (two secret, one publishable) and the bot token in Slack's
// API documentation.
var knownSamples = map[string]bool{
	"1a5d44a2dca19669d72edf4c4f1c27c4c1ca4b4408fbb17f6ce4ad452d78ddb3": true,
	"78314b11be2e581549ac1c4f616563fad3fdf0c3b71678f6e2299182080e0598": true,
	"2cafc0970149a84f3b9e62eaf169f36f59907a3b3e31f7b82e68c69cd27f7326": true,
	"b1471f544ceeea31333bde7e1ecbaad6eac0d4a749412ad29bd66ef895b81c6b": true,
	"f2d6ca16515033e5dce14eba840b979d27b5cbae24bb3e5bf484339667f86397": true,
	"2ddc147f3a3b5a1722b8ed6be3c45c49a7156b17fca5d11410137a6d04def6eb": true,
}

// placeholderWords appear in stand-ins, never by chance in a generated key
// of the lengths the detector reports.
var placeholderWords = []string{"xxxx", "****", "....", "example", "placeholder", "changeme", "change_me", "change-me",
	"your_", "your-", "yourkey", "yourtoken", "yoursecret", "yourpassword", "<", ">", "{{", "${", "dummy", "fake",
	"sample", "redacted", "insert_", "insert-", "replace_me", "replaceme", "replace-me", "notreal", "not_real", "not-real",
	"todo", "fixme", "secret123", "password123", "test1234"}

// strongWord reports whether w is a placeholder word even in a key with
// its own format: six or more letters, or symbols and repeats no
// generated key holds by chance. "fake" or "todo" turn up in about one
// long generated key in ten thousand.
func strongWord(w string) bool {
	return len(w) >= 6 || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" || w == "xxxx"
}

// runs are keyboard and counting sequences a person types into a template.
var runs = []string{"0123456789", "1234567890", "abcdefghij", "qwertyuiop", "asdfghjkl"}

// testPrefixes are the prefixes of test-mode keys.
var testPrefixes = []string{"sk_test_", "rk_test_", "pk_test_", "rzp_test_"}

// githubClassic is a GitHub classic token: a prefix, 30 random
// characters and 6 characters of checksum.
var githubClassic = regexp.MustCompile(`^gh[pousr]_[A-Za-z0-9]{36}$`)

// prefixRe is a provider's prefix, dropped before the random part is read:
// sk-ant-api03-, ghp_, glpat-, sk_live_, xoxb-.
var prefixRe = regexp.MustCompile(`^(?:[A-Za-z]{2,7}[_-]){1,3}(?:[a-z]{2,5}\d\d-)?`)

// Check returns the signals for one value found by rule (the detector's
// rule id: github-token, password-assignment, private-key...). For a
// private key the value is the start of the key's body. The value is not
// kept.
func Check(rule, value string) []string {
	var out []string
	sum := sha256.Sum256([]byte(value))
	if knownSamples[hex.EncodeToString(sum[:])] {
		out = append(out, KnownSample)
	}
	for _, p := range testPrefixes {
		if strings.HasPrefix(value, p) {
			out = append(out, TestModeKey)
			break
		}
	}
	body := value
	if formatted(rule) {
		if m := prefixRe.FindString(value); m != "" && len(value)-len(m) >= 16 {
			body = value[len(m):]
		}
	}
	if placeholder(value, body, formatted(rule)) {
		out = append(out, Placeholder)
	}
	if formatted(rule) && len(body) >= 16 && entropy(body) < 0.55*math.Log2(float64(len(body))) {
		out = append(out, LowEntropy)
	}
	if rule == "github-token" && githubClassic.MatchString(value) {
		if githubChecksum(value) {
			out = append(out, ChecksumValid)
		} else {
			out = append(out, ChecksumInvalid)
		}
	}
	return out
}

// formatted reports whether a rule finds a key by its own format, whose
// random part has a known length and alphabet. Passwords and database
// addresses are chosen by people and are not.
func formatted(rule string) bool {
	return rule != "password-assignment" && rule != "database-url"
}

// placeholder reports whether the value is a stand-in. In a key with its
// own format only strong words count, in one case (xxxx or XXXX); a
// password is read for every word, in any case.
func placeholder(value, body string, formatted bool) bool {
	low := strings.ToLower(value)
	for _, w := range placeholderWords {
		if formatted && (!strongWord(w) || !strings.Contains(value, w) && !strings.Contains(value, strings.ToUpper(w))) {
			continue
		}
		if strings.Contains(low, w) {
			return true
		}
	}
	lowBody := strings.ToLower(body)
	for _, r := range runs {
		if strings.Contains(lowBody, r) {
			return true
		}
	}
	if len(body) < 8 {
		return false
	}
	// One character makes most of it (0000000000, aaaaaaaa1).
	counts := map[rune]int{}
	most, n := 0, 0
	for _, c := range body {
		counts[c]++
		most = max(most, counts[c])
		n++
	}
	if most*10 >= n*6 {
		return true
	}
	// A short unit repeated (abcabcabc, 12341234).
	for unit := 2; unit <= 4; unit++ {
		repeated := true
		for i := unit; i < len(body); i++ {
			if body[i] != body[i%unit] {
				repeated = false
				break
			}
		}
		if repeated {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of s in bits per character. A generated
// key of n characters comes close to log2(n) (for n up to its alphabet's
// size): a base62 key of 36 characters about 4.7, a hex one of 64 about
// 3.9. Check flags a key below 0.55 of log2(n).
func entropy(s string) float64 {
	counts := map[rune]float64{}
	n := 0.0
	for _, c := range s {
		counts[c]++
		n++
	}
	h := 0.0
	for _, c := range counts {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// githubChecksum checks a classic GitHub token: its last six characters
// are the CRC32 (IEEE) of the 30 random characters after the prefix, in
// base 62, padded with zeros.
func githubChecksum(token string) bool {
	random, check := token[4:34], token[34:]
	n := crc32.ChecksumIEEE([]byte(random))
	var b [6]byte
	for i := 5; i >= 0; i-- {
		b[i] = base62[n%62]
		n /= 62
	}
	return n == 0 && string(b[:]) == check
}
