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
	// The lease is renewed every quarter of it, so it survives a stall of
	// up to three quarters (from the claim to the first renewal, or
	// between renewals). With a database under heavy load, round trips of
	// over 300 ms (all a 400 ms lease allowed) were seen to lose it.
	const lease = 2 * time.Second
	a.Lease, b.Lease = lease, lease
	started, release := make(chan struct{}), make(chan struct{})
	var bRuns atomic.Int32
	var aStopped atomic.Bool
	a.Every("long", time.Millisecond, func(ctx context.Context) error {
		close(started)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			aStopped.Store(true)
			return ctx.Err()
		}
	})
	b.Every("long", time.Millisecond, func(context.Context) error { bRuns.Add(1); return nil })
	a.register(ctx)
	done := make(chan struct{})
	go func() { a.runPeriodic(ctx, a.periodic[0]); close(done) }()
	<-started
	// The task runs until the test releases it, so the second replica's
	// attempts all fall while the first holds it, however slowly this
	// goroutine is scheduled. They go on until, by the database clock the
	// lease is kept in, the first lease and one more have ended: the task
	// has then outlived its lease twice over, which only renewal allows.
	var firstLease time.Time
	if err := st.Pool.QueryRow(ctx, `SELECT locked_until FROM periodic_tasks WHERE name = 'long'`).Scan(&firstLease); err != nil {
		t.Fatal(err)
	}
	for {
		b.runPeriodic(ctx, b.periodic[0])
		var past bool
		if err := st.Pool.QueryRow(ctx, `SELECT now() > $1`, firstLease.Add(lease)).Scan(&past); err != nil {
			t.Fatal(err)
		}
		if past {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	close(release)
	<-done
	if bRuns.Load() != 0 || aStopped.Load() {
		t.Fatalf("second replica ran %d times while the first still held the task (first stopped for a lost lease: %v)",
			bRuns.Load(), aStopped.Load())
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
	// Wait for a renewal (every 50 ms) to move the lock back to now. A fixed
	// sleep assumed one had happened, and under load another worker could
	// then claim a job whose lock still looked 31 minutes old.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		var renewed bool
		if err := st.Pool.QueryRow(ctx, `SELECT locked_at > now() - interval '1 minute' FROM jobs WHERE id = $1`, j.ID).Scan(&renewed); err != nil {
			t.Fatal(err)
		}
		if renewed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the running job's lock was not renewed")
		}
	}
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

// A job that cannot start yet (Defer) frees its slot: on a one-slot worker,
// while an evaluation of the workspace holds the evaluation lock, a second
// evaluation is deferred and another job kind runs meanwhile; the deferred
// evaluation runs once the lock is released, without using up an attempt or
// recording an error.
func TestDeferredJobFreesItsSlot(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	w := newWorker(st)
	w.Concurrency, w.Poll = 1, 20*time.Millisecond
	// The first evaluation, holding the lock (as a long full evaluation would).
	unlock, err := st.LockEvaluations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Release on failure too: the lock holds a pool connection, and closing
	// the pool waits for it (a failed check used to hang the package).
	var once sync.Once
	release := func() { once.Do(unlock) }
	t.Cleanup(release)
	var tries, ran atomic.Int64
	// As the server's evaluate handler: busy means defer.
	w.Handle("evaluate", func(ctx context.Context, _ json.RawMessage) error {
		tries.Add(1)
		rel, err := st.LockEvaluations(ctx)
		if errors.Is(err, store.ErrEvaluationBusy) {
			return Defer(50*time.Millisecond, "another evaluation of this workspace is running")
		}
		if err != nil {
			return err
		}
		defer rel()
		ran.Add(1)
		return nil
	})
	other := make(chan struct{})
	w.Handle("feed.sync", func(context.Context, json.RawMessage) error { close(other); return nil })
	evalID, err := st.Enqueue(ctx, "evaluate", map[string]any{"all": true}, "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Enqueue(ctx, "feed.sync", map[string]any{"feed": "x"}, "", time.Now().Add(100*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	rctx, stop := context.WithCancel(context.Background())
	defer stop()
	go w.Run(rctx)
	select {
	case <-other:
	case <-time.After(10 * time.Second):
		t.Fatal("the other job did not run while the evaluation was deferred")
	}
	if ran.Load() != 0 || tries.Load() < 1 {
		t.Fatalf("evaluation tries %d, ran %d", tries.Load(), ran.Load())
	}
	// The deferred evaluation comes back and is deferred again while the
	// lock is held. (Whether its second try comes before or after the other
	// job depends on scheduling: under load the first try can start after
	// the other job is due.)
	for deadline := time.Now().Add(10 * time.Second); tries.Load() < 2; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the deferred evaluation was not tried again: tries %d", tries.Load())
		}
	}
	if ran.Load() != 0 {
		t.Fatalf("the evaluation ran while another held the lock")
	}
	release()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		j, err := st.GetJob(tenant.System(context.Background()), evalID)
		if err != nil {
			t.Fatal(err)
		}
		if j.DoneAt != nil {
			if ran.Load() != 1 || j.Attempts != 1 || j.LastError != "" || j.FailedAt != nil {
				t.Errorf("after the lock was released: ran %d, job %+v", ran.Load(), j)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the deferred evaluation did not run after the lock was released")
}

// startWorker runs w until the test ends or the returned stop is called;
// stop returns once Run has returned.
func startWorker(t *testing.T, w *Worker) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	stop = func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	return stop
}

// A task that is stuck does not hold up another: the fast task keeps its
// pace (one check per Tick) the whole time the slow one runs. Before, the
// scheduler ran tasks one after another and the fast one waited.
func TestSlowTaskDoesNotDelayFastOne(t *testing.T) {
	st := store.New(testdb.New(t))
	w := newWorker(st)
	w.Tick = 50 * time.Millisecond
	slowStarted, release := make(chan struct{}), make(chan struct{})
	w.Every("slow", time.Millisecond, func(ctx context.Context) error {
		select {
		case <-slowStarted:
		default:
			close(slowStarted)
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	var mu sync.Mutex
	var runs []time.Time
	w.Every("fast", time.Millisecond, func(context.Context) error {
		mu.Lock()
		runs = append(runs, time.Now())
		mu.Unlock()
		return nil
	})
	startWorker(t, w)
	<-slowStarted
	from := time.Now()
	time.Sleep(1500 * time.Millisecond)
	close(release)
	mu.Lock()
	defer mu.Unlock()
	var during []time.Time
	for _, r := range runs {
		if r.After(from) {
			during = append(during, r)
		}
	}
	// 30 ticks in 1.5 s; allow for a slow test machine.
	if len(during) < 15 {
		t.Fatalf("fast task ran %d times in 1.5 s while the slow one was stuck; want about 30", len(during))
	}
	prev := from
	for _, r := range during {
		if gap := r.Sub(prev); gap > 500*time.Millisecond {
			t.Errorf("fast task paused %v while the slow one ran", gap)
		}
		prev = r
	}
}

// A task never runs twice at once in one process: not when it is due again
// while still running, not when it is registered twice, and not when a run
// that lost its lease (and ignores cancellation) is still going and the task
// could be claimed again.
func TestTaskNeverRunsTwiceInOneProcess(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())

	w := newWorker(st)
	w.Tick = 5 * time.Millisecond
	var runs, running, overlap atomic.Int32
	fn := func(context.Context) error {
		if running.Add(1) > 1 {
			overlap.Add(1)
		}
		runs.Add(1)
		time.Sleep(30 * time.Millisecond)
		running.Add(-1)
		return nil
	}
	w.Every("busy", time.Millisecond, fn)
	w.Every("busy", time.Millisecond, fn)
	stop := startWorker(t, w)
	time.Sleep(time.Second)
	stop()
	if runs.Load() < 5 || overlap.Load() != 0 {
		t.Fatalf("runs = %d, overlapping = %d; want many runs, none overlapping", runs.Load(), overlap.Load())
	}

	// A run that lost its lease but has not returned: the row is free, yet
	// this process does not start the task again.
	s := newWorker(st)
	s.Lease = 400 * time.Millisecond
	started, release := make(chan struct{}), make(chan struct{})
	var stuckRuns atomic.Int32
	s.Every("stuck", time.Millisecond, func(context.Context) error {
		if stuckRuns.Add(1) == 1 {
			close(started)
		}
		<-release // ignores cancellation
		return nil
	})
	s.register(ctx)
	first := make(chan struct{})
	go func() { s.runPeriodic(ctx, s.periodic[0]); close(first) }()
	<-started
	if _, err := st.Pool.Exec(ctx, `UPDATE periodic_tasks SET locked_by = NULL, locked_until = NULL WHERE name = 'stuck'`); err != nil {
		t.Fatal(err)
	}
	if err := s.runPeriodic(ctx, s.periodic[0]); err != nil {
		t.Fatal(err)
	}
	if n := stuckRuns.Load(); n != 1 {
		t.Errorf("task started %d times while its first run was still going", n)
	}
	close(release)
	<-first
}

// A running task whose lease is taken (this replica lost it) is cancelled
// within a renewal, and its outcome is not recorded.
func TestPeriodicLeaseLossCancelsTask(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	w := newWorker(st)
	w.Lease, w.Tick = 400*time.Millisecond, 20*time.Millisecond
	started := make(chan struct{})
	cancelled := make(chan time.Time, 1)
	var n atomic.Int32
	w.Every("victim", time.Hour, func(ctx context.Context) error {
		if n.Add(1) > 1 {
			return nil
		}
		close(started)
		select {
		case <-ctx.Done():
			cancelled <- time.Now()
		case <-time.After(10 * time.Second):
		}
		return ctx.Err()
	})
	startWorker(t, w)
	<-started
	taken := time.Now()
	if _, err := st.Pool.Exec(ctx, `UPDATE periodic_tasks SET locked_by = 'other-replica' WHERE name = 'victim'`); err != nil {
		t.Fatal(err)
	}
	select {
	case at := <-cancelled:
		if d := at.Sub(taken); d > w.Lease {
			t.Errorf("cancelled %v after the lease was lost; want within a renewal (%v)", d, w.Lease/4)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the task was not cancelled when its lease was lost")
	}
	time.Sleep(100 * time.Millisecond)
	if tk := task(t, st, "victim"); tk.LastFinishedAt != nil || tk.LockedBy == nil || *tk.LockedBy != "other-replica" {
		t.Errorf("a lost run must not record an outcome or touch the new owner's lease: %+v", tk)
	}
}

// On shutdown no task starts, a running task that finishes within the grace
// records its outcome, and one that does not is cancelled at the end of the
// grace and released without an outcome. Run returns after that.
func TestPeriodicShutdownWaitsThenCancels(t *testing.T) {
	st := store.New(testdb.New(t))
	w := newWorker(st)
	w.Tick, w.ShutdownGrace = 20*time.Millisecond, 600*time.Millisecond
	var wg sync.WaitGroup
	wg.Add(2)
	finishing, finished := make(chan struct{}), make(chan error, 1)
	w.Every("finishes", time.Hour, func(ctx context.Context) error {
		wg.Done()
		<-finishing
		time.Sleep(200 * time.Millisecond) // past the start of shutdown
		finished <- ctx.Err()
		return nil
	})
	cancelledAfter := make(chan time.Duration, 1)
	var shutdownAt atomic.Int64
	w.Every("hangs", time.Hour, func(ctx context.Context) error {
		wg.Done()
		<-ctx.Done()
		cancelledAfter <- time.Since(time.Unix(0, shutdownAt.Load()))
		return ctx.Err()
	})
	var lastFast atomic.Int64
	w.Every("fast", time.Millisecond, func(context.Context) error { lastFast.Store(time.Now().UnixNano()); return nil })
	stop := startWorker(t, w)
	wg.Wait()
	time.Sleep(100 * time.Millisecond)
	shutdownAt.Store(time.Now().UnixNano())
	close(finishing)
	stop()
	took := time.Since(time.Unix(0, shutdownAt.Load()))
	if err := <-finished; err != nil {
		t.Errorf("a task finishing within the grace was cancelled: %v", err)
	}
	if d := <-cancelledAfter; d < 500*time.Millisecond || d > 1500*time.Millisecond {
		t.Errorf("hanging task cancelled %v after shutdown; want at the 600ms grace", d)
	}
	if took < 500*time.Millisecond || took > 2*time.Second {
		t.Errorf("Run returned %v after shutdown; want just after the 600ms grace", took)
	}
	if tk := task(t, st, "finishes"); tk.LastSuccessAt == nil || tk.LockedBy != nil {
		t.Errorf("a task that finished during shutdown should record success: %+v", tk)
	}
	if tk := task(t, st, "hangs"); tk.LastFinishedAt != nil || tk.LockedBy != nil {
		t.Errorf("a cancelled task should be released without an outcome: %+v", tk)
	}
	// A claim already under way when shutdown began may still start.
	if d := time.Duration(lastFast.Load() - shutdownAt.Load()); d > 100*time.Millisecond {
		t.Errorf("a task started %v after shutdown began", d)
	}
}
