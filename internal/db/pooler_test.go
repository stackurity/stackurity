package db_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Connected straight to PostgreSQL, each pool connection keeps its session.
func TestCheckSessionPinnedDirect(t *testing.T) {
	pool := testdb.New(t)
	for i := 0; i < 20; i++ {
		if err := db.CheckSessionPinned(context.Background(), pool); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

// Behind PgBouncer in transaction mode (issues #539, #540) the check fails.
// STACKURITY_TEST_POOLER_URL points at such a pooler; CI has none, so the
// test runs only where one is set up (docs/operations.md#connection-poolers
// says how). STACKURITY_TEST_SESSION_POOLER_URL, a pooler in session mode,
// must pass.
func TestCheckSessionPinnedPooler(t *testing.T) {
	ctx := context.Background()
	if url := os.Getenv("STACKURITY_TEST_POOLER_URL"); url != "" {
		pool, err := db.Open(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		for i := 0; i < 10; i++ {
			if err := db.CheckSessionPinned(ctx, pool); !errors.Is(err, db.ErrSessionNotPinned) {
				t.Fatalf("transaction pooler, run %d: %v, want ErrSessionNotPinned", i, err)
			}
		}
	}
	if url := os.Getenv("STACKURITY_TEST_SESSION_POOLER_URL"); url != "" {
		pool, err := db.Open(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		for i := 0; i < 10; i++ {
			if err := db.CheckSessionPinned(ctx, pool); err != nil {
				t.Fatalf("session pooler, run %d: %v", i, err)
			}
		}
	}
	if os.Getenv("STACKURITY_TEST_POOLER_URL") == "" && os.Getenv("STACKURITY_TEST_SESSION_POOLER_URL") == "" {
		t.Skip("STACKURITY_TEST_POOLER_URL is not set")
	}
}
