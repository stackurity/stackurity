package store_test

import (
	"context"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// replicas returns two stores on separate pools over one database, like two
// server replicas.
func replicas(t *testing.T) (*store.Store, *store.Store) {
	t.Helper()
	pool := testdb.New(t)
	other, err := pgxpool.NewWithConfig(context.Background(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	return store.New(pool), store.New(other)
}

// Hits on two replicas, concurrent or not, land on one counter: each hit is
// counted exactly once.
func TestRateLimitSharedAcrossReplicas(t *testing.T) {
	a, b := replicas(t)
	ctx := context.Background()
	const n = 40
	var mu sync.Mutex
	var got []int
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := a
			if i%2 == 1 {
				st = b
			}
			hits, err := st.RateLimitHit(ctx, "login", "203.0.113.7", time.Hour)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			got = append(got, hits)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Ints(got)
	for i, h := range got {
		if h != i+1 {
			t.Fatalf("counts %v; want 1..%d, each once", got, n)
		}
	}
	// Other subjects and buckets have their own counters.
	if h, err := b.RateLimitHit(ctx, "login", "203.0.113.8", time.Hour); err != nil || h != 1 {
		t.Errorf("other address: %d %v", h, err)
	}
	if h, err := b.RateLimitHit(ctx, "enroll", "203.0.113.7", time.Hour); err != nil || h != 1 {
		t.Errorf("other bucket: %d %v", h, err)
	}
	if _, err := a.RateLimitHit(ctx, "login", "x", time.Millisecond); err == nil {
		t.Error("a sub-second window was accepted")
	}
}

// A counter starts again in the next window, and ended windows are purged.
func TestRateLimitWindowAndPurge(t *testing.T) {
	a, b := replicas(t)
	ctx := context.Background()
	// Start just after a window boundary so both hits share a window.
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 50*time.Millisecond)))
	if h, _ := a.RateLimitHit(ctx, "setup", "198.51.100.1", time.Second); h != 1 {
		t.Fatalf("first hit: %d", h)
	}
	if h, _ := b.RateLimitHit(ctx, "setup", "198.51.100.1", time.Second); h != 2 {
		t.Fatalf("second hit: %d", h)
	}
	if _, err := a.RateLimitHit(ctx, "setup", "198.51.100.2", time.Hour); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if h, _ := b.RateLimitHit(ctx, "setup", "198.51.100.1", time.Second); h != 1 {
		t.Errorf("next window: %d; want a fresh count", h)
	}
	time.Sleep(1100 * time.Millisecond)
	n, err := a.PurgeRateLimits(ctx)
	if err != nil || n != 2 {
		t.Errorf("purged %d (%v); want the two ended windows", n, err)
	}
	var left int
	if err := a.Pool.QueryRow(tenant.System(ctx), `SELECT count(*) FROM rate_limits`).Scan(&left); err != nil || left != 1 {
		t.Errorf("%d windows left (%v); want the open hour-long one", left, err)
	}
}

// Workspaces never see the counters, and the counters never hold the address
// or email they count.
func TestRateLimitPlatformIsolation(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := context.Background()
	if _, err := st.RateLimitHit(ctx, "login-account", "victim@example.com", time.Minute); err != nil {
		t.Fatal(err)
	}
	ws := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	var n int
	if err := st.Pool.QueryRow(ws, `SELECT count(*) FROM rate_limits`).Scan(&n); err != nil || n != 0 {
		t.Errorf("workspace scope sees %d rate limit rows (%v)", n, err)
	}
	if _, err := st.Pool.Exec(ws, `INSERT INTO rate_limits (key, window_start, expires_at) VALUES ('x', now(), now())`); err == nil {
		t.Error("a workspace wrote a rate limit")
	}
	var key string
	if err := st.Pool.QueryRow(tenant.System(ctx), `SELECT key FROM rate_limits`).Scan(&key); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(key, "victim") || !strings.HasPrefix(key, "login-account:") {
		t.Errorf("key %q", key)
	}
}
