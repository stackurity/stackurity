package api_test

import (
	"strings"
	"testing"
)

// The dashboard's styles come only from its own files: no inline style
// elements or attributes (React sets styles through the CSSOM, which CSP
// allows). Nothing names the server software or its version.
func TestCSPHasNoUnsafeInline(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/", "/api/v1/meta", "/settings/users"} {
		resp := e.anon().req("GET", path, nil, nil)
		resp.Body.Close()
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "style-src 'self';") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
			t.Errorf("%s: Content-Security-Policy %q", path, csp)
		}
		for _, h := range []string{"Server", "X-Powered-By"} {
			if v := resp.Header.Get(h); v != "" {
				t.Errorf("%s: %s: %q", path, h, v)
			}
		}
	}
}
