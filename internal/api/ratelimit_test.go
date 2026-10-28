package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// replicaServers starts n API servers, each with its own database pool, over
// one database: replicas behind a load balancer. They trust CF-Connecting-IP
// from loopback (the test client), so a test can play several client
// addresses.
func replicaServers(t *testing.T, n int) ([]*httptest.Server, *store.Store) {
	t.Helper()
	pool := testdb.New(t)
	first := store.New(pool)
	var out []*httptest.Server
	for i := range n {
		st := first
		if i > 0 {
			p, err := pgxpool.NewWithConfig(context.Background(), pool.Config())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(p.Close)
			st = store.New(p)
		}
		s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test", SetupToken: "setup-123", TrustProxy: true}
		srv := httptest.NewServer(s.Handler())
		t.Cleanup(srv.Close)
		out = append(out, srv)
	}
	return out, first
}

// freshWindow waits for the next fixed window of length d when the current
// one ends within ten seconds, so a test's attempts all land in one window.
func freshWindow(d time.Duration) {
	if left := d - time.Since(time.Now().Truncate(d)); left < 10*time.Second {
		time.Sleep(left + 100*time.Millisecond)
	}
}

func post(t *testing.T, srv *httptest.Server, path, addr string, body any) int {
	t.Helper()
	code, _, _ := postFull(t, srv, path, map[string]string{"CF-Connecting-IP": addr}, body)
	return code
}

// postFull is post with any headers, returning the Retry-After header and
// the body too. Empty header values are not sent.
func postFull(t *testing.T, srv *httptest.Server, path string, hdr map[string]string, body any) (int, string, string) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Stackurity-CSRF", "1")
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("Retry-After"), string(rb)
}

// One address gets ten sign-in attempts a minute in total, however the load
// balancer spreads them over replicas; other addresses are unaffected.
func TestSignInLimitPerAddressAcrossReplicas(t *testing.T) {
	srv, st := replicaServers(t, 2)
	if _, err := st.CreateUser(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "a@x.io", "", auth.RoleAdmin, pw); err != nil {
		t.Fatal(err)
	}
	// Each attempt names another account, so the per-account backoff stays
	// out of the way.
	wrong := func(i int) map[string]string {
		return map[string]string{"email": fmt.Sprintf("n%d@x.io", i), "password": "not the password"}
	}
	freshWindow(time.Minute)
	for i := range 10 {
		if code := post(t, srv[i%2], "/api/v1/auth/login", "192.0.2.1", wrong(i)); code != 401 {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	for i := range 2 {
		if code := post(t, srv[i], "/api/v1/auth/login", "192.0.2.1", map[string]string{"email": "a@x.io", "password": pw}); code != 429 {
			t.Errorf("11th attempt on replica %d: %d; want 429", i, code)
		}
	}
	if code := post(t, srv[1], "/api/v1/auth/login", "192.0.2.2", map[string]string{"email": "a@x.io", "password": pw}); code != 200 {
		t.Errorf("another address: %d", code)
	}
	// Enrollment codes are limited the same way.
	freshWindow(time.Minute)
	for i := range 10 {
		if code := post(t, srv[i%2], "/api/v1/enroll", "192.0.2.3", map[string]string{"code": "stke_nope"}); code != 403 {
			t.Fatalf("enroll attempt %d: %d", i+1, code)
		}
	}
	if code := post(t, srv[0], "/api/v1/enroll", "192.0.2.3", map[string]string{"code": "stke_nope"}); code != 429 {
		t.Errorf("11th enroll attempt: %d; want 429", code)
	}
}

// auditCount counts audit events with action.
func auditCount(t *testing.T, st *store.Store, action string) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM audit_events WHERE action = $1`, action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Failed sign-ins back off per account and address: five are free, then the
// guesser waits. The account's owner, signing in from another address, is
// not held up, and an account that does not exist answers exactly like one
// that does.
func TestSignInBackoff(t *testing.T) {
	srv, st := replicaServers(t, 3)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if _, err := st.CreateUser(ctx, "victim@x.io", "", auth.RoleViewer, pw); err != nil {
		t.Fatal(err)
	}
	freshWindow(time.Minute)
	var bodies [2][2]string
	for k, c := range []struct{ email, attacker string }{{"victim@x.io", "198.51.100.66"}, {"nobody@x.io", "198.51.100.67"}} {
		for i := range 5 {
			code, _, body := postFull(t, srv[i%3], "/api/v1/auth/login", map[string]string{"CF-Connecting-IP": c.attacker},
				map[string]string{"email": c.email, "password": fmt.Sprintf("guess %d", i)})
			if code != 401 {
				t.Fatalf("%s failure %d: %d", c.email, i+1, code)
			}
			bodies[k][0] = body
		}
		// The sixth attempt waits, even with the right password.
		code, retry, body := postFull(t, srv[1], "/api/v1/auth/login", map[string]string{"CF-Connecting-IP": c.attacker},
			map[string]string{"email": c.email, "password": pw})
		if s, _ := strconv.Atoi(retry); code != 429 || s < 1 || s > 30 {
			t.Errorf("%s after five failures: %d, Retry-After %q; want 429 within 30s", c.email, code, retry)
		}
		bodies[k][1] = body
	}
	if bodies[0] != bodies[1] {
		t.Errorf("an existing and a missing account answer differently: %q vs %q", bodies[0], bodies[1])
	}
	// The owner, from their own address, during the guessing.
	if code := post(t, srv[2], "/api/v1/auth/login", "203.0.113.50", map[string]string{"email": " Victim@X.io", "password": pw}); code != 200 {
		t.Errorf("owner from another address: %d; want 200", code)
	}
	if n := auditCount(t, st, "auth.login_backoff"); n != 2 {
		t.Errorf("auth.login_backoff events: %d; want 2", n)
	}
	// An IPv6 guesser is counted by /64.
	for i := range 5 {
		if code := post(t, srv[0], "/api/v1/auth/login", "2001:db8:1::1", map[string]string{"email": "victim@x.io", "password": fmt.Sprintf("v6 %d", i)}); code != 401 {
			t.Fatalf("v6 failure %d: %d", i+1, code)
		}
	}
	if code := post(t, srv[0], "/api/v1/auth/login", "2001:db8:1::2", map[string]string{"email": "victim@x.io", "password": pw}); code != 429 {
		t.Errorf("same /64: %d; want 429", code)
	}
	if code := post(t, srv[0], "/api/v1/auth/login", "2001:db8:2::1", map[string]string{"email": "victim@x.io", "password": pw}); code != 200 {
		t.Errorf("another /64: %d; want 200", code)
	}
}

// Successful sign-ins never count towards a lockout, and one clears the
// failures from its address.
func TestSignInSuccessNeverLocks(t *testing.T) {
	srv, st := replicaServers(t, 2)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if _, err := st.CreateUser(ctx, "busy@x.io", "", auth.RoleViewer, pw); err != nil {
		t.Fatal(err)
	}
	freshWindow(time.Minute)
	ok := map[string]string{"email": "busy@x.io", "password": pw}
	for i := range 25 {
		if code := post(t, srv[i%2], "/api/v1/auth/login", fmt.Sprintf("192.0.2.%d", 10+i%3), ok); code != 200 {
			t.Fatalf("sign-in %d: %d", i+1, code)
		}
	}
	addr := "192.0.2.77"
	fail := func(n int) {
		for i := range n {
			if code := post(t, srv[i%2], "/api/v1/auth/login", addr, map[string]string{"email": "busy@x.io", "password": "wrong"}); code != 401 {
				t.Fatalf("failure %d: %d", i+1, code)
			}
		}
	}
	fail(4)
	if code := post(t, srv[0], "/api/v1/auth/login", addr, ok); code != 200 {
		t.Fatalf("sign-in after four failures: %d", code)
	}
	fail(5) // would have been the ninth failure in a row without the reset
}

// Guessing spread over many addresses stops at the per-account cap; other
// accounts are unaffected.
func TestSignInAccountCap(t *testing.T) {
	srv, st := replicaServers(t, 3)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	for _, e := range []string{"victim@x.io", "bystander@x.io"} {
		if _, err := st.CreateUser(ctx, e, "", auth.RoleViewer, pw); err != nil {
			t.Fatal(err)
		}
	}
	freshWindow(15 * time.Minute)
	for i := range 100 {
		addr := fmt.Sprintf("198.51.%d.%d", 100+i/200, 1+i%200)
		if code := post(t, srv[i%3], "/api/v1/auth/login", addr, map[string]string{"email": "victim@x.io", "password": "guess " + addr}); code != 401 {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	if code := post(t, srv[2], "/api/v1/auth/login", "203.0.113.50", map[string]string{"email": "victim@x.io", "password": pw}); code != 429 {
		t.Errorf("after the cap, with the right password: %d; want 429", code)
	}
	if code := post(t, srv[0], "/api/v1/auth/login", "203.0.113.52", map[string]string{"email": "bystander@x.io", "password": pw}); code != 200 {
		t.Errorf("another account: %d", code)
	}
	if n := auditCount(t, st, "auth.login_locked"); n != 1 {
		t.Errorf("auth.login_locked events: %d; want 1", n)
	}
}

// Rotating client-written address headers does not escape the per-address
// limit: True-Client-IP, X-Real-IP and X-Forwarded-For are never read, and
// CF-Connecting-IP only from a trusted proxy.
func TestSpoofedClientIPCannotBypassLimits(t *testing.T) {
	srv, _ := replicaServers(t, 1)
	untrusted := &api.Server{Store: store.New(testdb.New(t)), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test",
		TrustProxy: true, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}
	srvU := httptest.NewServer(untrusted.Handler())
	t.Cleanup(srvU.Close)
	for _, c := range []struct {
		name string
		srv  *httptest.Server
		hdr  func(i int) map[string]string
	}{
		{"spoofed headers from a trusted peer", srv[0], func(i int) map[string]string {
			a := fmt.Sprintf("203.0.113.%d", i+1)
			return map[string]string{"True-Client-IP": a, "X-Real-IP": a, "X-Forwarded-For": a}
		}},
		{"CF-Connecting-IP from an untrusted peer", srvU, func(i int) map[string]string {
			return map[string]string{"CF-Connecting-IP": fmt.Sprintf("203.0.113.%d", i+1)}
		}},
	} {
		freshWindow(time.Minute)
		for i := range 10 {
			// A different unknown account each time, so only the
			// per-address limit is in play.
			if code, _, _ := postFull(t, c.srv, "/api/v1/auth/login", c.hdr(i), map[string]string{"email": fmt.Sprintf("n%d@x.io", i), "password": "x"}); code != 401 {
				t.Fatalf("%s: attempt %d: %d", c.name, i+1, code)
			}
		}
		if code, _, _ := postFull(t, c.srv, "/api/v1/auth/login", c.hdr(10), map[string]string{"email": "n10@x.io", "password": "x"}); code != 429 {
			t.Errorf("%s: 11th attempt: %d; want 429", c.name, code)
		}
	}
}

// Setup attempts are limited per address across replicas.
func TestSetupLimitAcrossReplicas(t *testing.T) {
	srv, _ := replicaServers(t, 2)
	bad := map[string]string{"setup_token": "guess", "email": "a@x.io", "password": pw}
	freshWindow(time.Minute)
	for i := range 10 {
		if code := post(t, srv[i%2], "/api/v1/setup", "192.0.2.9", bad); code != 403 {
			t.Fatalf("setup attempt %d: %d", i+1, code)
		}
	}
	if code := post(t, srv[1], "/api/v1/setup", "192.0.2.9", map[string]string{"setup_token": "setup-123", "email": "a@x.io", "password": pw}); code != 429 {
		t.Errorf("11th setup attempt: %d; want 429", code)
	}
}

// When the database cannot count, sign-in is refused (503), not let through.
func TestSignInLimitFailsClosed(t *testing.T) {
	pool := testdb.New(t)
	down, err := pgxpool.NewWithConfig(context.Background(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	down.Close()
	s := &api.Server{Store: store.New(down), Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/setup", "/api/v1/enroll"} {
		if code := post(t, srv, path, "", map[string]string{"email": "a@x.io", "password": pw}); code != 503 {
			t.Errorf("%s with the database down: %d; want 503", path, code)
		}
	}
}
