package api_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A botnet failing on purpose cannot keep the owner out: an address the
// account signed in from recently is exempt from the per-account cap, and
// any other address is still held at it.
//
// The cap counts per fixed window of the database clock (15 minutes; 2 in
// this test, so any wait below stays short). A run that crosses a window
// boundary (100 password checks can take longer than any margin on a
// loaded machine) counts in two windows and proves nothing, so it is
// detected by the database clock and run again, with a fresh account, once
// the window has room for twice the first run: at most one window's wait.
func TestSignInAccountCapSparesKnownAddress(t *testing.T) {
	srv, st := replicaServers(t, 3)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	const window = 2 * time.Minute
	t.Cleanup(api.SetAccountFailureWindow(window))
	dbNow := func() time.Time {
		now, err := st.DBNow(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return now
	}
	var took time.Duration // the first run's length, by the database clock
	for run := range 2 {
		email := fmt.Sprintf("owner%d@x.io", run)
		if _, err := st.CreateUser(ctx, email, "", auth.RoleViewer, pw); err != nil {
			t.Fatal(err)
		}
		const home = "203.0.113.10"
		if code := post(t, srv[0], "/api/v1/auth/login", home, map[string]string{"email": email, "password": pw}); code != 200 {
			t.Fatalf("first sign-in: %d", code)
		}
		if run > 0 {
			// Room for twice the first run, or the next window.
			now := dbNow()
			if left := now.Truncate(window).Add(window).Sub(now); left < 2*took+10*time.Second {
				waitForWindow(t, st, window)
			}
		}
		begin := dbNow()
		started := begin.Truncate(window)
		for i := range 100 {
			addr := fmt.Sprintf("198.51.%d.%d", 100+i/200, 1+i%200)
			if code := post(t, srv[i%3], "/api/v1/auth/login", addr, map[string]string{"email": email, "password": "guess " + addr}); code != 401 {
				t.Fatalf("attempt %d: %d", i+1, code)
			}
		}
		known := post(t, srv[1], "/api/v1/auth/login", home, map[string]string{"email": email, "password": pw})
		unknown := post(t, srv[2], "/api/v1/auth/login", "203.0.113.99", map[string]string{"email": email, "password": pw})
		end := dbNow()
		if end.Truncate(window) != started {
			took = end.Sub(begin)
			t.Logf("run %d crossed a %s window boundary (it took %s); running again", run, window, took)
			continue
		}
		if known != 200 {
			t.Errorf("owner from a known address after the cap: %d; want 200", known)
		}
		if unknown != 429 {
			t.Errorf("an unknown address after the cap: %d; want 429", unknown)
		}
		return
	}
	t.Fatal("both runs crossed a window boundary")
}

// waitForWindow waits, by the database clock, for the next fixed window of
// length d to begin.
func waitForWindow(t *testing.T, st *store.Store, d time.Duration) {
	t.Helper()
	now, err := st.DBNow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(now.Truncate(d).Add(d).Sub(now) + 100*time.Millisecond)
}
