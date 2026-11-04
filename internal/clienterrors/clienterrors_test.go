package clienterrors

import (
	"strings"
	"testing"
)

func TestScrub(t *testing.T) {
	cases := []struct{ in, want string }{
		{"not found", "not found"},
		{"no account for jane.doe+test@example.co.uk here", "no account for [email] here"},
		{"asset 3f2b8c1e-9a4d-4e2f-b1c3-0d9e8f7a6b5c is gone", "asset [uuid] is gone"},
		{"Authorization: Bearer stk_live_abcdefghijklmnop", "Authorization [redacted] [token]"},
		{"token=abc123", "token [redacted]"},
		{"key eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl leaked", "key [token] leaked"},
		{"session 9f8e7d6c5b4a39281706f5e4d3c2b1a0 expired", "session [token] expired"},
		{"card 4111111111111111 refused", "card [number] refused"},
		{"from 203.0.113.42 refused", "from [ip] refused"},
		{"GET https://acme.example.com/api/v1/assets/42?q=secret failed", "GET [url] failed"},
		{"line 12 of 300", "line 12 of 300"},
		{`duplicate key value violates unique constraint "assets_name" Key (name)=(acme-prod)`, `duplicate key value violates unique constraint "[text]" Key (name)=[value]`},
		{`asset "web-prod" not found`, `asset "[text]" not found`},
		{"Cannot read properties of undefined (reading 'name')", "Cannot read properties of undefined (reading 'name')"},
	}
	for _, c := range cases {
		if got := Scrub(c.in); got != c.want {
			t.Errorf("Scrub(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	long := Scrub(strings.Repeat("word ", 200))
	if n := len([]rune(long)); n != MaxMessage {
		t.Errorf("long message is %d characters, want %d", n, MaxMessage)
	}
}

func TestPathDropsIDs(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/settings/billing", "/settings/billing"},
		{"/assets/:id", "/assets/:id"},
		{"/assets/1234", "/assets/:id"},
		{"/findings/3f2b8c1e-9a4d-4e2f-b1c3-0d9e8f7a6b5c/events", "/findings/:id/events"},
		{"/users/jane@example.com", "/users/:id"},
		{"/components/pkg:npm%2Flodash@4.17.21", "/components/:id"},
		{"/fixes/issues?asset=42&q=openssl", "/fixes/issues"},
		{"https://acme.example.com/assets/42#top", "/assets/:id"},
		{"/help/getting-started", "/help/getting-started"},
		{"relative/path", ""},
	}
	for _, c := range cases {
		if got := Path(c.in, ":id"); got != c.want {
			t.Errorf("Path(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := Path("/api/v1/assets/77/stack", "{id}"); got != "/api/v1/assets/{id}/stack" {
		t.Errorf("API path: %q", got)
	}
}

func TestFrameKeepsOnlyOurBundle(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://app.stackurity.com/static/index-Dk3x_a9Q.js:12:345", "static/index.js:12:345"},
		{"/static/Settings-a1B2c3D4.js:7", "static/Settings.js:7"},
		{"chrome-extension://abcdef/content.js:1:2", ""},
		{"https://cdn.example.net/lib.js:1:1", ""},
		{"eval at foo (eval:1:1)", ""},
	}
	for _, c := range cases {
		if got := Frame(c.in); got != c.want {
			t.Errorf("Frame(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCheckAndFingerprint(t *testing.T) {
	r := Report{Source: "api", Route: "/settings/billing", Method: "GET", APIRoute: "/api/v1/billing?x=1", Status: 404,
		Code: "not_found", Name: "ApiError", Message: "not found for ops@acme.example", Version: "0.15.0", Browser: "Chrome 131",
		PageID: "k3j4h5g6f7d8s9a0", Stack: []string{"https://x/static/index-AbCdEf12.js:1:2", "https://evil/x.js:1:1"}}
	c, ok := Check(r)
	if !ok {
		t.Fatal("refused a good report")
	}
	if c.Message != "not found for [email]" || c.APIRoute != "/api/v1/billing" || len(c.Stack) != 1 || c.Kind != KindClient {
		t.Errorf("clean: %+v", c)
	}
	// The same fault with another message and another page load is the
	// same fingerprint; another status or route is not.
	r2 := r
	r2.Message, r2.PageID = "something else", "zzzzzzzzzzzz"
	c2, _ := Check(r2)
	if c.Fingerprint() != c2.Fingerprint() {
		t.Error("message changed the fingerprint")
	}
	r3 := r
	r3.Status = 500
	c3, _ := Check(r3)
	r4 := r
	r4.Route = "/settings/usage"
	c4, _ := Check(r4)
	if c3.Fingerprint() == c.Fingerprint() || c4.Fingerprint() == c.Fingerprint() {
		t.Error("status or route did not change the fingerprint")
	}
	// The same route with different ids is one fingerprint.
	a, _ := Check(Report{Source: "error", Route: "/assets/12", Name: "TypeError"})
	b, _ := Check(Report{Source: "error", Route: "/assets/9981", Name: "TypeError"})
	if a.Fingerprint() != b.Fingerprint() || a.Route != "/assets/:id" {
		t.Errorf("ids split the fingerprint: %q %q", a.Route, b.Route)
	}

	bad := []Report{
		{Source: "nope", Route: "/x"},
		{Source: "api", Route: "no-slash"},
	}
	for _, b := range bad {
		if _, ok := Check(b); ok {
			t.Errorf("accepted %+v", b)
		}
	}
	// Junk in the optional fields is dropped, not stored.
	j, ok := Check(Report{Source: "api", Route: "/x", Method: "BREW", Code: "Not Found!", Name: "<script>", Browser: "x<y> 1", Version: "1 2", PageID: "short"})
	if !ok || j.Method != "" || j.Code != "" || j.Name != "" || j.Browser != "" || j.Version != "" || j.PageID != "" {
		t.Errorf("junk kept: %+v", j)
	}
}

func TestServerFrame(t *testing.T) {
	stack := []byte(`goroutine 7 [running]:
runtime/debug.Stack()
	/usr/local/go/src/runtime/debug/stack.go:26 +0x5e
github.com/stackurity/stackurity/internal/api.(*Server).recoverer.func1.1()
	/src/internal/api/middleware.go:400 +0x45
panic({0x1, 0x2})
	/usr/local/go/src/runtime/panic.go:787 +0x132
github.com/stackurity/stackurity/internal/api.(*Server).billing(...)
	/home/runner/work/stackurity/stackurity/internal/api/billing.go:42 +0x1d
net/http.HandlerFunc.ServeHTTP(...)
`)
	if got := ServerFrame(stack, "github.com/stackurity/stackurity"); got != "internal/api/billing.go:42" {
		t.Errorf("frame %q", got)
	}
}
