package api

import (
	"net/http/httptest"
	"testing"
)

// Per-address limits on registration and wrong tokens count an IPv6 /64
// as one address, since one client usually holds all of it.
func TestAddressKey(t *testing.T) {
	for remote, want := range map[string]string{
		"203.0.113.7:4000":            "203.0.113.7",
		"[2001:db8:1:2:3:4:5:6]:4000": "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff::1]:4000": "2001:db8:1:2::/64",
		"[2001:db8:1:3::1]:4000":      "2001:db8:1:3::/64",
		"[::ffff:203.0.113.7]:4000":   "203.0.113.7",
	} {
		r := httptest.NewRequest("POST", "/oauth/register", nil)
		r.RemoteAddr = remote
		if got := addressKey(r); got != want {
			t.Errorf("addressKey(%s) = %s, want %s", remote, got, want)
		}
	}
}

func TestCheckRedirectURI(t *testing.T) {
	for uri, ok := range map[string]bool{
		"https://claude.ai/api/mcp/auth_callback": true,
		"http://localhost:8765/callback":          true,
		"http://127.0.0.1/cb":                     true,
		"http://[::1]:9000/cb":                    true,
		"com.example.app:/oauth":                  true,
		"cursor://anysphere.cursor-retrieval/cb":  false,
		"http://example.com/cb":                   false,
		"intent://x#Intent;end":                   false,
		"ms-settings:privacy":                     false,
		"ms-word.x:ofe":                           false,
		"javascript:alert(1)":                     false,
		"data:text/html,x":                        false,
		"file:///etc/passwd":                      false,
		"https://x.example/cb#f":                  false,
	} {
		if err := checkRedirectURI(uri); (err == nil) != ok {
			t.Errorf("checkRedirectURI(%q) = %v", uri, err)
		}
	}
}
