package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/tenant"
)

// outbound records every connection the process tries to open to anything
// but loopback, through http.DefaultTransport (every http.Client without a
// Transport of its own) and the resolver (any dial by host name), and
// refuses it. It proves itself first. While it is installed, tests in this
// package must not run in parallel (none do).
type outbound struct {
	mu   sync.Mutex
	seen []string
}

func (o *outbound) record(s string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, s)
}

func (o *outbound) attempts() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.seen)
}

var errOutbound = errors.New("outbound connection refused by the test")

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.Unmap().IsLoopback()
}

func guardOutbound(t *testing.T) *outbound {
	t.Helper()
	o := &outbound{}
	oldTransport, oldResolver := http.DefaultTransport, net.DefaultResolver
	tr := oldTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	d := &net.Dialer{Timeout: 10 * time.Second}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, _, err := net.SplitHostPort(addr); err != nil || !isLoopback(host) {
			o.record("http " + addr)
			return nil, errOutbound
		}
		return d.DialContext(ctx, network, addr)
	}
	http.DefaultTransport = tr
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		o.record("dns " + address)
		return nil, errOutbound
	}}
	t.Cleanup(func() { http.DefaultTransport, net.DefaultResolver = oldTransport, oldResolver })

	// The guard must see a deliberate attempt through each path, or it
	// proves nothing.
	if resp, err := (&http.Client{}).Get("https://app.stackurity.dev/"); err == nil {
		resp.Body.Close()
		t.Fatal("the guard let a request through http.DefaultTransport")
	}
	if _, err := net.DefaultResolver.LookupHost(context.Background(), "app.stackurity.dev"); err == nil {
		t.Fatal("the guard let a DNS lookup through")
	}
	got := o.attempts()
	if !slices.Contains(got, "http app.stackurity.dev:443") || !slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, "dns ") }) {
		t.Fatalf("the guard is blind (recorded %v): fix the test before trusting it", got)
	}
	o.mu.Lock()
	o.seen = nil
	o.mu.Unlock()
	return o
}

// keyLinkEnv is a self-hosted server waiting for its key, with test
// issuer keys: lic signs paid licences, com free Community keys.
type keyLinkEnv struct {
	*env
	licPriv, comPriv ed25519.PrivateKey
}

func newKeyLinkEnv(t *testing.T, baseURL string) *keyLinkEnv {
	licPub, licPriv, _ := ed25519.GenerateKey(rand.Reader)
	comPub, comPriv, _ := ed25519.GenerateKey(rand.Reader)
	e := newEnvWith(t, func(s *api.Server) {
		s.KeyRequirement = &license.Requirement{From: time.Now().Add(-time.Minute), Licence: s.Licence}
		s.ParseLicence = func(k string) (*license.License, error) { return license.ParseWithKeys(k, licPub, comPub) }
		s.BaseURL = baseURL
	})
	e.api.Licence.Set(nil)
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	e.user("other@x.io", auth.RoleAdmin)
	e.instanceAdmin("other@x.io")
	e.user("view@x.io", auth.RoleViewer)
	return &keyLinkEnv{env: e, licPriv: licPriv, comPriv: comPriv}
}

func (k *keyLinkEnv) key(edition license.Edition, priv ed25519.PrivateKey) string {
	now := time.Now().UTC().Truncate(time.Second)
	s, err := license.Issue(license.License{ID: "ck_test" + string(edition), Customer: "Acme", Name: "Asha", Email: "asha@acme.example",
		Edition: edition, IssuedAt: now, ExpiresAt: now.Add(license.CommunityValidity)}, priv)
	if err != nil {
		k.t.Fatal(err)
	}
	return s
}

// start asks for a link and returns its state, after checking the address.
func (k *keyLinkEnv) start(s *session) string {
	k.t.Helper()
	var out struct {
		URL string `json:"url"`
	}
	if code := s.do("POST", "/api/v1/admin/license/link", nil, &out); code != 201 {
		k.t.Fatalf("start a key link: %d", code)
	}
	u, err := url.Parse(out.URL)
	if err != nil || !strings.HasPrefix(out.URL, license.KeyLinkURL+"#") || u.RawQuery != "" || strings.Contains(out.URL, "?") {
		k.t.Fatalf("key link address (values only in the fragment): %q", out.URL)
	}
	f, _ := url.ParseQuery(u.Fragment)
	return f.Get("state")
}

func (k *keyLinkEnv) claim(s *session, key, state string) (int, string) {
	k.t.Helper()
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	code := s.do("POST", "/api/v1/admin/license/link/claim", map[string]string{"key": key, "state": state}, &out)
	return code, out.Error.Code
}

// TestKeyLink: "Get a free key" sends the administrator's browser to
// Stackurity Cloud with a one-time state bound to their session; the key
// that comes back is installed only with that state, once, within its
// time, and only if it verifies offline as a free Community key. The
// server opens no outbound connection at any step.
func TestKeyLink(t *testing.T) {
	k := newKeyLinkEnv(t, "https://stackurity.example.com/")
	out := guardOutbound(t)
	owner := k.login("owner@x.io")

	var info struct {
		KeyLink bool `json:"key_link"`
	}
	if code := owner.do("GET", "/api/v1/admin/license", nil, &info); code != 200 || !info.KeyLink {
		t.Fatalf("licence page offers the button: %d %+v", code, info)
	}

	// The address: Cloud's page, this server's base URL, a random state, a
	// hash of the server's id (never the id).
	var link struct {
		URL string `json:"url"`
	}
	if code := owner.do("POST", "/api/v1/admin/license/link", nil, &link); code != 201 {
		t.Fatalf("start: %d", code)
	}
	u, _ := url.Parse(link.URL)
	// Everything in the fragment, nothing in a query string (the Cloud's
	// proxy logs failed requests' full URL).
	if u.RawQuery != "" || strings.Contains(link.URL, "?") {
		t.Fatalf("key link has a query string: %s", link.URL)
	}
	q, _ := url.ParseQuery(u.Fragment)
	serverID, err := k.st.ServerID(context.Background())
	if err != nil || serverID == "" {
		t.Fatalf("server id: %q %v", serverID, err)
	}
	if u.Scheme+"://"+u.Host+u.Path != license.KeyLinkURL || q.Get("return") != "https://stackurity.example.com" ||
		!regexp.MustCompile(`^cks_[a-z2-7]{52}$`).MatchString(q.Get("state")) ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(q.Get("server_id")) || strings.Contains(link.URL, serverID) ||
		strings.Contains(link.URL, strings.ReplaceAll(serverID, "-", "")) {
		t.Fatalf("key link: %s (server id %s)", link.URL, serverID)
	}
	if other := k.start(owner); other == q.Get("state") {
		t.Fatal("two links got the same state")
	}

	// Only instance administrators, and only in a browser session.
	if code := k.login("view@x.io").do("POST", "/api/v1/admin/license/link", nil, nil); code != 403 {
		t.Errorf("a viewer starts a key link: %d", code)
	}
	var ownerID int64
	if err := k.st.Pool.QueryRow(context.Background(), `SELECT id FROM users WHERE email = 'owner@x.io'`).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	// The instance administrator's own admin token: allowed on /admin/license
	// itself, but not to start a browser round trip.
	_, adminToken, err := k.st.CreateToken(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "ci", auth.RoleAdmin, &ownerID, ownerID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := bearer(k.env, adminToken, "GET", "/api/v1/admin/license", nil, nil); code != 200 {
		t.Fatalf("the admin token reads the licence (control): %d", code)
	}
	if code := bearer(k.env, adminToken, "POST", "/api/v1/admin/license/link", nil, nil); code != 403 {
		t.Errorf("an API token starts a key link: %d", code)
	}

	valid := k.key(license.Community, k.comPriv)

	// A state from another session of the same administrator, or another
	// administrator's, is refused, and used up by the try.
	st := k.start(owner)
	if code, c := k.claim(k.login("owner@x.io"), valid, st); code != 410 || c != "key_link_invalid" {
		t.Errorf("state from another session: %d %s", code, c)
	}
	if code, _ := k.claim(owner, valid, st); code != 410 {
		t.Errorf("state used by another session, then by its own: %d (must be used up)", code)
	}
	st = k.start(owner)
	if code, _ := k.claim(k.login("other@x.io"), valid, st); code != 410 {
		t.Errorf("another administrator's state: %d", code)
	}

	// Made-up, missing and expired states.
	for _, bad := range []string{"", "cks_", "cks_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "not-a-state", strings.Repeat("cks_a", 50)} {
		if code, _ := k.claim(owner, valid, bad); code != 410 {
			t.Errorf("state %q: %d", bad, code)
		}
	}
	st = k.start(owner)
	if _, err := k.st.Pool.Exec(tenant.System(context.Background()), `UPDATE license_key_links SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if code, _ := k.claim(owner, valid, st); code != 410 {
		t.Errorf("expired state: %d", code)
	}

	// Keys that do not verify, or are not free Community keys, are refused
	// (the state is used up all the same).
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	for name, bad := range map[string]string{
		"foreign issuer":                  k.key(license.Community, otherPriv),
		"paid edition by the free issuer": k.key(license.Pro, k.comPriv),
		"paid licence":                    k.key(license.Pro, k.licPriv),
		"not a key":                       "hello",
		"tampered":                        valid[:len(valid)-4] + "AAAA",
	} {
		st := k.start(owner)
		if code, _ := k.claim(owner, bad, st); code != 400 {
			t.Errorf("%s: %d, want 400", name, code)
		}
		if code, _ := k.claim(owner, valid, st); code != 410 {
			t.Errorf("%s: the state worked again after a refused key: %d", name, code)
		}
	}
	if k.api.Licence.License() != nil {
		t.Fatal("a refused key was installed")
	}
	if code := owner.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Fatalf("still gated before a key: %d", code)
	}

	// The real thing: installed, the gate lifts, and the state is spent.
	st = k.start(owner)
	if code, c := k.claim(owner, valid, st); code != 200 {
		t.Fatalf("valid claim: %d %s", code, c)
	}
	if l := k.api.Licence.License(); l == nil || l.Edition != license.Community || l.Email != "asha@acme.example" {
		t.Fatalf("installed: %+v", l)
	}
	if code := owner.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("gate after the key: %d", code)
	}
	if stored, err := k.st.LicenseKey(context.Background()); err != nil || stored != valid {
		t.Errorf("stored key: %v", err)
	}
	var via string
	if err := k.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT detail->>'via' FROM audit_events
		WHERE action = 'license.install' ORDER BY id DESC LIMIT 1`).Scan(&via); err != nil || via != "key_link" {
		t.Errorf("audit: %q %v", via, err)
	}
	if code, _ := k.claim(owner, valid, st); code != 410 {
		t.Errorf("state used twice: %d", code)
	}

	// A paid licence is never replaced by the button.
	pst := k.start(owner)
	k.api.Licence.Set(&license.License{Version: 1, Customer: "Acme", Edition: license.Pro, ExpiresAt: time.Now().AddDate(1, 0, 0)})
	if code := owner.do("POST", "/api/v1/admin/license/link", nil, nil); code != 409 {
		t.Errorf("start with a paid licence: %d", code)
	}
	if code, _ := k.claim(owner, valid, pst); code != 409 || k.api.Licence.License().Edition != license.Pro {
		t.Errorf("claim with a paid licence: %d (the paid licence must stay)", code)
	}
	if code := owner.do("GET", "/api/v1/admin/license", nil, &info); code != 200 || info.KeyLink {
		t.Errorf("licence page with a paid licence offers the button: %+v", info)
	}

	if got := out.attempts(); len(got) != 0 {
		t.Errorf("the server opened outbound connections during the key link: %v", got)
	}
}

// TestKeyLinkGate: both steps work while the server waits for its key,
// and nothing else does.
func TestKeyLinkGate(t *testing.T) {
	k := newKeyLinkEnv(t, "http://10.0.0.5:8080")
	owner := k.login("owner@x.io")
	st := k.start(owner) // the gate lets it through
	if code, _ := k.claim(owner, k.key(license.Community, k.comPriv), st); code != 200 {
		t.Fatalf("claim through the gate: %d", code)
	}
	k.api.Licence.Set(nil)
	if code := owner.do("GET", "/api/v1/admin/license/link", nil, nil); code != 403 && code != 405 {
		t.Errorf("GET on the link route through the gate: %d", code)
	}
}

// TestKeyLinkNoBaseURL: without STACKURITY_BASE_URL the server cannot be
// sent back to, so the dashboard offers the paste flow only.
func TestKeyLinkNoBaseURL(t *testing.T) {
	for _, base := range []string{"", "ftp://x.example", "https://user:pw@x.example", "https://x.example/?a=b", "https://x.example/#f"} {
		k := newKeyLinkEnv(t, base)
		owner := k.login("owner@x.io")
		var info struct {
			KeyLink bool `json:"key_link"`
		}
		if code := owner.do("GET", "/api/v1/admin/license", nil, &info); code != 200 || info.KeyLink {
			t.Errorf("%q: licence page offers the button: %d %+v", base, code, info)
		}
		var e struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if code := owner.do("POST", "/api/v1/admin/license/link", nil, &e); code != 409 || e.Error.Code != "no_base_url" {
			t.Errorf("%q: start: %d %s", base, code, e.Error.Code)
		}
	}
}
