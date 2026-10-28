package api_test

import (
	"regexp"
	"strings"
	"testing"
)

// parsePermissionsPolicy reads the header (a structured-field dictionary of
// inner lists) into feature -> allowlist, failing on anything malformed.
func parsePermissionsPolicy(t *testing.T, h string) map[string]string {
	t.Helper()
	item := regexp.MustCompile(`^([a-z][a-z0-9-]*)=\(((?:self|"https://[a-z0-9.-]+")(?: (?:self|"https://[a-z0-9.-]+"))*)?\)$`)
	out := map[string]string{}
	for _, p := range strings.Split(h, ", ") {
		m := item.FindStringSubmatch(p)
		if m == nil {
			t.Fatalf("malformed Permissions-Policy item %q in %q", p, h)
		}
		if _, dup := out[m[1]]; dup {
			t.Fatalf("feature %s twice", m[1])
		}
		out[m[1]] = m[2]
	}
	return out
}

// TestPermissionsPolicy: every response turns off the browser features the
// dashboard does not use; payment and WebAuthn (publickey-credentials-*)
// keep the browser's default (this origin), and the payment page delegates
// what Razorpay Checkout's frame asks for to Razorpay's origins only.
func TestPermissionsPolicy(t *testing.T) {
	e := newEnv(t)
	get := func(path string) map[string]string {
		t.Helper()
		resp := e.anon().req("GET", path, nil, nil)
		resp.Body.Close()
		return parsePermissionsPolicy(t, resp.Header.Get("Permissions-Policy"))
	}
	for _, path := range []string{"/", "/login", "/api/v1/auth/me", "/healthz", "/billing", "/billing/payments"} {
		pp := get(path)
		for _, f := range []string{"camera", "microphone", "geolocation", "usb", "serial", "hid", "bluetooth", "midi",
			"display-capture", "browsing-topics", "otp-credentials", "web-share"} {
			if v, ok := pp[f]; !ok || v != "" {
				t.Errorf("%s: %s=(%s), want denied", path, f, v)
			}
		}
		for _, f := range []string{"payment", "publickey-credentials-get", "publickey-credentials-create", "clipboard-write", "fullscreen"} {
			if v, ok := pp[f]; ok {
				t.Errorf("%s: %s=(%s), want the browser's default", path, f, v)
			}
		}
	}
	const rzp = `self "https://api.razorpay.com" "https://checkout.razorpay.com"`
	pay := get("/billing/pay/sub_test")
	for _, f := range []string{"payment", "publickey-credentials-get", "publickey-credentials-create", "camera", "otp-credentials", "web-share"} {
		if pay[f] != rzp {
			t.Errorf("payment page: %s=(%s), want (%s)", f, pay[f], rzp)
		}
	}
	for _, f := range []string{"microphone", "geolocation", "usb"} {
		if v, ok := pay[f]; !ok || v != "" {
			t.Errorf("payment page: %s=(%s), want denied", f, v)
		}
	}
}
