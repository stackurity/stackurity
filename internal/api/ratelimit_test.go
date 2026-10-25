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
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// replicaServers starts n API servers, each with its own database pool, over
// one database: replicas behind a load balancer. They trust X-Real-IP so a
// test can play several client addresses.
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

func post(t *testing.T, srv *httptest.Server, path, addr string, body any) int {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Stackurity-CSRF", "1")
	if addr != "" {
		req.Header.Set("X-Real-IP", addr)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// One address gets ten sign-in attempts a minute in total, however the load
// balancer spreads them over replicas; other addresses are unaffected.
func TestSignInLimitPerAddressAcrossReplicas(t *testing.T) {
	srv, st := replicaServers(t, 2)
	if _, err := st.CreateUser(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "a@x.io", "", auth.RoleAdmin, pw); err != nil {
		t.Fatal(err)
	}
	wrong := map[string]string{"email": "a@x.io", "password": "not the password"}
	for i := range 10 {
		if code := post(t, srv[i%2], "/api/v1/auth/login", "192.0.2.1", wrong); code != 401 {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	for i := range 2 {
		if code := post(t, srv[i], "/api/v1/auth/login", "192.0.2.1", wrong); code != 429 {
			t.Errorf("11th attempt on replica %d: %d; want 429", i, code)
		}
	}
	if code := post(t, srv[1], "/api/v1/auth/login", "192.0.2.2", map[string]string{"email": "a@x.io", "password": pw}); code != 200 {
		t.Errorf("another address: %d", code)
	}
	// Enrollment codes are limited the same way.
	for i := range 10 {
		if code := post(t, srv[i%2], "/api/v1/enroll", "192.0.2.3", map[string]string{"code": "stke_nope"}); code != 403 {
			t.Fatalf("enroll attempt %d: %d", i+1, code)
		}
	}
	if code := post(t, srv[0], "/api/v1/enroll", "192.0.2.3", map[string]string{"code": "stke_nope"}); code != 429 {
		t.Errorf("11th enroll attempt: %d; want 429", code)
	}
}

// Guessing one account's password from many addresses stops after twenty
// attempts in fifteen minutes, even with the right password, whether or not
// the account exists. Other accounts are unaffected.
func TestSignInLimitPerAccount(t *testing.T) {
	srv, st := replicaServers(t, 3)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	for _, e := range []string{"victim@x.io", "bystander@x.io"} {
		if _, err := st.CreateUser(ctx, e, "", auth.RoleViewer, pw); err != nil {
			t.Fatal(err)
		}
	}
	for _, email := range []string{"victim@x.io", "nobody@x.io"} {
		for i := range 20 {
			addr := fmt.Sprintf("198.51.100.%d", i+1)
			if code := post(t, srv[i%3], "/api/v1/auth/login", addr, map[string]string{"email": email, "password": "guess " + addr}); code != 401 {
				t.Fatalf("%s attempt %d: %d", email, i+1, code)
			}
		}
	}
	// The account key ignores case and spaces, so " Victim@X.io" is the same account.
	if code := post(t, srv[2], "/api/v1/auth/login", "203.0.113.50", map[string]string{"email": " Victim@X.io", "password": pw}); code != 429 {
		t.Errorf("21st attempt with the right password: %d; want 429", code)
	}
	if code := post(t, srv[1], "/api/v1/auth/login", "203.0.113.51", map[string]string{"email": "nobody@x.io", "password": "x"}); code != 429 {
		t.Errorf("21st attempt on an unknown account: %d; want 429", code)
	}
	if code := post(t, srv[0], "/api/v1/auth/login", "203.0.113.52", map[string]string{"email": "bystander@x.io", "password": pw}); code != 200 {
		t.Errorf("another account: %d", code)
	}
}

// Setup attempts are limited per address across replicas.
func TestSetupLimitAcrossReplicas(t *testing.T) {
	srv, _ := replicaServers(t, 2)
	bad := map[string]string{"setup_token": "guess", "email": "a@x.io", "password": pw}
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
