package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func newWorker(st *store.Store) *Worker {
	w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.Lease = time.Second
	return w
}

func task(t *testing.T, st *store.Store, name string) *store.PeriodicTask {
	t.Helper()
	list, err := st.ListPeriodicTasks(tenant.System(context.Background()))
	if err != nil {
		t.Fatal(err)
	}
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	t.Fatalf("task %s not registered", name)
	return nil
}

// Replicas racing for the same task: exactly one runs it, never two at once.
func TestPeriodicRunsOncePerIntervalAcrossReplicas(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	var runs, running, overlap atomic.Int32
	fn := func(ctx context.Context) error {
		if !tenant.IsSystem(ctx) {
			t.Error("periodic tasks run in system scope")
		}
		if running.Add(1) > 1 {
			overlap.Add(1)
		}
		runs.Add(1)
		time.Sleep(50 * time.Millisecond)
		running.Add(-1)
		return nil
	}
	var workers []*Worker
	for i := 0; i < 4; i++ {
		w := newWorker(st)
		w.Every("race", time.Hour, fn)
		if !w.register(ctx) {
			t.Fatal("register")
		}
		workers = append(workers, w)
	}
	var wg sync.WaitGroup
	for round := 0; round < 3; round++ {
		for _, w := range workers {
			wg.Add(1)
			go func(w *Worker) {
				defer wg.Done()
				w.runPeriodic(ctx, w.periodic[0])
			}(w)
		}
		wg.Wait()
	}
	if runs.Load() != 1 || overlap.Load() != 0 {
		t.Fatalf("runs = %d, overlapping = %d; want 1 run in the interval", runs.Load(), overlap.Load())
	}
	tk := task(t, st, "race")
	if tk.LastSuccessAt == nil || tk.LockedBy != nil || tk.Running || tk.ConsecutiveFailures != 0 || tk.EverySeconds != 3600 {
		t.Errorf("after a successful run: %+v", tk)
	}
}

// A replica that dies holding a task keeps it only until the lease expires.
func TestPeriodicLeaseExpiryHandsTaskOver(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	if err := st.RegisterPeriodic(ctx, "crashy", time.Hour); err != nil {
		t.Fatal(err)
	}
	// Replica A claims the task and dies without finishing or renewing.
	if ok, err := st.ClaimPeriodic(ctx, "crashy", "replica-a", time.Hour, 500*time.Millisecond); err != nil || !ok {
		t.Fatalf("claim: %v %v", ok, err)
	}
	var runs atomic.Int32
	b := newWorker(st)
	b.Every("crashy", time.Hour, func(context.Context) error { runs.Add(1); return nil })
	b.runPeriodic(ctx, b.periodic[0])
	if runs.Load() != 0 {
		t.Fatal("ran while another replica held the lease")
	}
	time.Sleep(700 * time.Millisecond)
	b.runPeriodic(ctx, b.periodic[0])
	if runs.Load() != 1 {
		t.Fatal("an unfinished run whose lease expired should be taken over at once, not after the interval")
	}
	// A cannot record an outcome for a run it no longer owns.
	if err := st.FinishPeriodic(ctx, "crashy", "replica-a", errors.New("late")); err != nil {
		t.Fatal(err)
	}
	if tk := task(t, st, "crashy"); tk.LastError != "" || tk.LastSuccessAt == nil {
		t.Errorf("stale owner overwrote the outcome: %+v", tk)
	}
	if ok, _ := st.RenewPeriodic(ctx, "crashy", "replica-a", time.Minute); ok {
		t.Error("a lost lease must not be renewable")
	}
}

// A task that runs longer than its lease keeps it by renewing.
func TestPeriodicHeartbeatKeepsLongTask(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	a, b := newWorker(st), newWorker(st)
	a.Lease, b.Lease = 400*time.Millisecond, 400*time.Millisecond
	started := make(chan struct{})
	var bRuns atomic.Int32
	a.Every("long", time.Millisecond, func(ctx context.Context) error {
		close(started)
		select {
		case <-time.After(1500 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	b.Every("long", time.Millisecond, func(context.Context) error { bRuns.Add(1); return nil })
	a.register(ctx)
	done := make(chan struct{})
	go func() { a.runPeriodic(ctx, a.periodic[0]); close(done) }()
	<-started
	deadline := time.After(1200 * time.Millisecond)
loop:
	for {
		b.runPeriodic(ctx, b.periodic[0])
		select {
		case <-deadline:
			break loop
		case <-time.After(100 * time.Millisecond):
		}
	}
	<-done
	if bRuns.Load() != 0 {
		t.Fatalf("second replica ran %d times while the first still held the task", bRuns.Load())
	}
	if tk := task(t, st, "long"); tk.LastSuccessAt == nil || tk.LastError != "" {
		t.Errorf("long task outcome: %+v", tk)
	}
}

func TestPeriodicFailuresAndShutdown(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	w := newWorker(st)
	calls := 0
	w.Every("flaky", time.Millisecond, func(context.Context) error {
		calls++
		if calls == 3 {
			panic("boom")
		}
		return errors.New("upstream down")
	})
	w.register(ctx)
	for i := 0; i < 3; i++ {
		time.Sleep(5 * time.Millisecond)
		w.runPeriodic(ctx, w.periodic[0])
	}
	tk := task(t, st, "flaky")
	if tk.ConsecutiveFailures != 3 || tk.LastSuccessAt != nil || tk.LastError != "panic: boom" {
		t.Errorf("failures: %+v", tk)
	}

	// Shutdown mid-run releases the task without an outcome, so the next
	// replica runs it at once instead of waiting a whole interval.
	sctx, cancel := context.WithCancel(ctx)
	s := newWorker(st)
	s.Every("slow", time.Hour, func(ctx context.Context) error {
		cancel()
		<-ctx.Done()
		return ctx.Err()
	})
	s.register(ctx)
	s.runPeriodic(sctx, s.periodic[0])
	tk = task(t, st, "slow")
	if tk.LockedBy != nil || tk.ConsecutiveFailures != 0 || tk.LastFinishedAt != nil {
		t.Errorf("after shutdown: %+v", tk)
	}
	if ok, err := st.ClaimPeriodic(ctx, "slow", "other", time.Hour, time.Minute); err != nil || !ok {
		t.Errorf("interrupted task should be due at once: %v %v", ok, err)
	}
}

// EveryWorkspace runs the task in each active workspace's scope.
func TestEveryWorkspaceScopes(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	w := newWorker(st)
	var seen []int64
	w.EveryWorkspace("per-ws", time.Hour, func(ctx context.Context) error {
		id, ok := tenant.Workspace(ctx)
		if !ok {
			t.Error("not workspace scoped")
		}
		seen = append(seen, id)
		return nil
	})
	w.register(ctx)
	w.runPeriodic(ctx, w.periodic[0])
	if len(seen) != 1 || seen[0] != tenant.DefaultWorkspace {
		t.Errorf("workspaces = %v", seen)
	}
}

// claimJob enqueues one job of kind and claims it as owner.
func claimJob(t *testing.T, st *store.Store, kind, owner string) *store.Job {
	t.Helper()
	ctx := tenant.System(context.Background())
	if _, err := st.Enqueue(ctx, kind, map[string]string{}, "", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	j, err := st.Claim(ctx, owner)
	if err != nil || j == nil {
		t.Fatalf("claim %s: %v %v", kind, j, err)
	}
	return j
}

// Jobs registered with HandleTimeout get their own deadline; others keep
// JobTimeout.
func TestJobTimeoutPerKind(t *testing.T) {
	st := store.New(testdb.New(t))
	w := newWorker(st)
	deadlines := map[string]time.Duration{}
	record := func(kind string) Handler {
		return func(ctx context.Context, _ json.RawMessage) error {
			d, _ := ctx.Deadline()
			deadlines[kind] = time.Until(d)
			return nil
		}
	}
	w.Handle("fast", record("fast"))
	w.HandleTimeout("slow", 3*time.Hour, record("slow"))
	ctx := tenant.System(context.Background())
	for _, k := range []string{"fast", "slow"} {
		w.run(ctx, claimJob(t, st, k, "a"), "a")
	}
	if d := deadlines["slow"]; d < 2*time.Hour+50*time.Minute || d > 3*time.Hour {
		t.Errorf("slow job deadline = %v, want about 3h", d)
	}
	if d := deadlines["fast"]; d < 19*time.Minute || d > 20*time.Minute {
		t.Errorf("fast job deadline = %v, want about 20m", d)
	}
}

// A running job renews its lock, so a job running longer than the store's
// lock timeout is not claimed a second time.
func TestRunningJobKeepsItsLock(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	w := newWorker(st)
	w.JobRenew = 50 * time.Millisecond
	started, release := make(chan struct{}), make(chan struct{})
	w.Handle("long", func(ctx context.Context, _ json.RawMessage) error {
		close(started)
		<-release
		return ctx.Err()
	})
	j := claimJob(t, st, "long", "a")
	finished := make(chan struct{})
	go func() { w.run(ctx, j, "a"); close(finished) }()
	<-started
	// Pretend the job has run for 31 minutes, past the lock timeout.
	if _, err := st.Pool.Exec(ctx, `UPDATE jobs SET locked_at = now() - interval '31 minutes' WHERE id = $1`, j.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond) // several renewals
	if other, err := st.Claim(ctx, "b"); err != nil || other != nil {
		t.Errorf("a running job must not be claimed again: %+v %v", other, err)
	}
	close(release)
	<-finished
	var done bool
	if err := st.Pool.QueryRow(ctx, `SELECT done_at IS NOT NULL FROM jobs WHERE id = $1`, j.ID).Scan(&done); err != nil || !done {
		t.Errorf("job should complete: %v %v", done, err)
	}
}

// A job whose lock another worker took over is stopped.
func TestJobStopsWhenLockIsLost(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	w := newWorker(st)
	w.JobRenew = 50 * time.Millisecond
	started := make(chan struct{})
	stopped := make(chan error, 1)
	w.Handle("long", func(ctx context.Context, _ json.RawMessage) error {
		close(started)
		select {
		case <-ctx.Done():
			stopped <- ctx.Err()
		case <-time.After(5 * time.Second):
			stopped <- nil
		}
		return ctx.Err()
	})
	j := claimJob(t, st, "long", "a")
	go w.run(ctx, j, "a")
	<-started
	if _, err := st.Pool.Exec(ctx, `UPDATE jobs SET locked_by = 'b' WHERE id = $1`, j.ID); err != nil {
		t.Fatal(err)
	}
	if err := <-stopped; err == nil {
		t.Error("the job should be cancelled once its lock is lost")
	}
}

// A worker that dies mid-job (crash, kill) stops renewing the lock. The job is
// claimed again once the lock times out, with the interrupted attempt as its
// last error, and after max_attempts it fails instead of running forever.
func TestJobInterruptedEveryAttemptFails(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	j := claimJob(t, st, "crashy", "dead-1")
	for attempt := 2; ; attempt++ {
		// The worker died: its lock is older than the lock timeout.
		if _, err := st.Pool.Exec(ctx, `UPDATE jobs SET locked_at = now() - interval '31 minutes' WHERE id = $1`, j.ID); err != nil {
			t.Fatal(err)
		}
		next, err := st.Claim(ctx, fmt.Sprintf("dead-%d", attempt))
		if err != nil {
			t.Fatal(err)
		}
		if attempt > j.MaxAttempts {
			if next != nil {
				t.Fatalf("attempt %d of %d claimed", next.Attempts, next.MaxAttempts)
			}
			break
		}
		want := fmt.Sprintf("attempt %d of %d was interrupted: worker dead-%d stopped", attempt-1, j.MaxAttempts, attempt-1)
		if next == nil || next.ID != j.ID || next.Attempts != attempt || !strings.HasPrefix(next.LastError, want) {
			t.Fatalf("attempt %d: claimed %+v; want the job again with %q", attempt, next, want)
		}
	}
	got, err := st.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.FailedAt == nil || got.Attempts != got.MaxAttempts || !strings.Contains(got.LastError, "was interrupted") {
		t.Errorf("job = %+v; want failed after %d interrupted attempts", got, got.MaxAttempts)
	}
}
