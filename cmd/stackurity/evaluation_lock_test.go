package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/worker"
)

// waitingForEvaluationLock reports whether a session waits for the
// workspace's evaluation lock (an advisory lock not granted).
func waitingForEvaluationLock(t *testing.T, st *store.Store, ws int64) bool {
	t.Helper()
	var waiting bool
	if err := st.Pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM pg_locks
		WHERE locktype = 'advisory' AND NOT granted
		  AND ((classid::bigint << 32) | objid::bigint) = hashtextextended('stackurity.evaluate:' || current_schema() || ':' || $1::bigint, 0))`,
		ws).Scan(&waiting); err != nil {
		t.Fatal(err)
	}
	return waiting
}

// An evaluation job waits in line for the evaluation lock that the
// dispatcher's tick holds, and gets it when the tick releases it. Before, it
// only tried the lock and was deferred 5 to 15 seconds, and a tick every
// second could keep it from ever running.
func TestEvaluationWaitsInLineForTheLock(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	held, err := st.LockEvaluations(ctx) // the dispatcher's upkeep
	if err != nil {
		t.Fatal(err)
	}
	tick := sync.OnceFunc(held)
	t.Cleanup(tick) // released on every path, or the schema cannot be dropped
	type result struct {
		release func()
		err     error
	}
	got := make(chan result, 1)
	go func() {
		release, err := lockForEvaluation(ctx, st, evaluationLockWait)
		got <- result{release, err}
	}()
	deadline := time.Now().Add(30 * time.Second)
	for !waitingForEvaluationLock(t, st, tenant.DefaultWorkspace) {
		select {
		case r := <-got:
			t.Fatalf("the evaluation did not wait for the lock: %v", r.err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the evaluation never waited for the lock")
		}
		time.Sleep(10 * time.Millisecond)
	}
	tick()
	r := <-got
	if r.err != nil {
		t.Fatalf("the evaluation was not given the lock when the tick released it: %v", r.err)
	}
	evaluated := sync.OnceFunc(r.release)
	t.Cleanup(evaluated)
	evaluated()

	// Held longer than the wait (another long evaluation): deferred.
	other, err := st.LockEvaluations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sync.OnceFunc(other))
	_, err = lockForEvaluation(ctx, st, 100*time.Millisecond)
	var deferred *worker.Deferred
	if !errors.As(err, &deferred) {
		t.Fatalf("a lock held past the wait must defer the job: %v", err)
	}
}
