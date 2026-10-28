package api_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A botnet failing on purpose cannot keep the owner out: an address the
// account signed in from recently is exempt from the per-account cap, and
// any other address is still held at it.
func TestSignInAccountCapSparesKnownAddress(t *testing.T) {
	srv, st := replicaServers(t, 3)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if _, err := st.CreateUser(ctx, "owner@x.io", "", auth.RoleViewer, pw); err != nil {
		t.Fatal(err)
	}
	const home = "203.0.113.10"
	if code := post(t, srv[0], "/api/v1/auth/login", home, map[string]string{"email": "owner@x.io", "password": pw}); code != 200 {
		t.Fatalf("first sign-in: %d", code)
	}
	freshWindow(15 * time.Minute)
	for i := range 100 {
		addr := fmt.Sprintf("198.51.%d.%d", 100+i/200, 1+i%200)
		if code := post(t, srv[i%3], "/api/v1/auth/login", addr, map[string]string{"email": "owner@x.io", "password": "guess " + addr}); code != 401 {
			t.Fatalf("attempt %d: %d", i+1, code)
		}
	}
	if code := post(t, srv[1], "/api/v1/auth/login", home, map[string]string{"email": "owner@x.io", "password": pw}); code != 200 {
		t.Errorf("owner from a known address after the cap: %d; want 200", code)
	}
	if code := post(t, srv[2], "/api/v1/auth/login", "203.0.113.99", map[string]string{"email": "owner@x.io", "password": pw}); code != 429 {
		t.Errorf("an unknown address after the cap: %d; want 429", code)
	}
}
