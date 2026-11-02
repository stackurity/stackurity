//go:build ee && cloud && !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Stackurity Cloud refuses to start without its configuration (the
// licensed overlay's internal/cloud ConfigFromEnv). This is the least it
// accepts: billing off (no Razorpay keys, so no plans and no Razorpay
// requests), sign-up and email settings that are only used when someone
// signs up or mail is sent, and the Turnstile secret from a file, as a
// deployment passes it. None of the host names is ever looked up at start:
// if one were, the egress tests would record it.
func init() {
	editionEnv = func(t *testing.T) map[string]string {
		secret := filepath.Join(t.TempDir(), "turnstile-secret")
		if err := os.WriteFile(secret, []byte("egress-test-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return map[string]string{
			"STACKURITY_BASE_URL":              "https://stackurity.example",
			"STACKURITY_TURNSTILE_SITE_KEY":    "egress-test-site-key",
			"STACKURITY_TURNSTILE_SECRET_FILE": secret,
			"STACKURITY_CLOUD_TERMS_URL":       "https://stackurity.example/terms",
			"STACKURITY_CLOUD_PRIVACY_URL":     "https://stackurity.example/privacy",
			"STACKURITY_CLOUD_TERMS_VERSION":   "1",
			"STACKURITY_CLOUD_PRIVACY_VERSION": "1",
			"STACKURITY_CLOUD_SMTP_HOST":       "smtp.stackurity.example",
			"STACKURITY_CLOUD_SMTP_FROM":       "Stackurity <no-reply@stackurity.example>",
		}
	}
}
