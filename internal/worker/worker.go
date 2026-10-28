// Package worker runs background jobs from the PostgreSQL queue and the
// periodic scheduler. Handlers must be idempotent: a job can run twice if a
// worker dies after finishing but before recording completion.
//
// Any number of server replicas can run a worker against one database. Jobs
// are claimed row by row; periodic tasks are claimed in periodic_tasks with a
// lease, so each runs at most once per interval across replicas and never on
// two replicas at the same time.
//
// Each periodic task has its own loop, so a slow or stuck task does not hold
// up the others (the notification task in particular). At most
// PeriodicSlots tasks run at once in one process, which bounds the database
// connections they use, and a task never runs twice at once in one process.
package worker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type Handler func(ctx context.Context, payload json.RawMessage) error

// Deferred is what a handler returns when its job cannot start yet, for
// example because another job holds a lock it needs: the job goes back to
// the queue and runs again after After, its slot is free for other jobs
// meanwhile, and the attempt is neither counted nor logged as a failure.
type Deferred struct {
	After  time.Duration
	Reason string
}

func (d *Deferred) Error() string { return "deferred: " + d.Reason }

// Defer returns a Deferred error for a handler to return.
func Defer(after time.Duration, reason string) error { return &Deferred{After: after, Reason: reason} }

type Worker struct {
	Store       *store.Store
	Log         *slog.Logger
	Concurrency int
	Poll        time.Duration
	JobTimeout  time.Duration
	// JobRenew is how often a running job's lock is renewed; it must be well
	// under the store's lock timeout (Store.JobLockTimeout, 30 minutes by
	// default).
	JobRenew time.Duration
	// Lease is how long a periodic task stays claimed without renewal. The
	// running replica renews it; when a replica dies, another takes the task
	// over once the lease has expired.
	Lease time.Duration
	// Tick is how often each periodic task checks whether it is due.
	Tick time.Duration
	// PeriodicSlots is how many periodic tasks may run at the same time in
	// this process. Each run uses at most one database connection at a time
	// for its queries and one for a moment while it renews its lease, so
	// periodic work holds at most 2*PeriodicSlots of the pool's connections.
	// The default of 4 leaves at least 12 of the 20 to the API and the job
	// workers, and three tasks can be slow or stuck at once while the
	// others keep their pace.
	PeriodicSlots int
	// ShutdownGrace is how long periodic tasks that are running when Run's
	// context ends may take to finish before they are cancelled (and their
	// lease released). No task starts after the context ends.
	ShutdownGrace time.Duration
	// HeapWarn is the growth of the Go heap during one job or periodic task
	// above which a warning names it (zero: DefaultHeapWarn; negative: off).
	HeapWarn int64
	heap     *heapWatch
	handlers map[string]Handler
	timeouts map[string]time.Duration
	periodic []periodic
	running  map[string]*atomic.Bool
	id       string
}

type periodic struct {
	name  string
	every time.Duration
	fn    func(ctx context.Context) error
	// running is shared by the tasks of one name in this process.
	running *atomic.Bool
}

func New(s *store.Store, log *slog.Logger) *Worker {
	host, _ := os.Hostname()
	// Containers often share a pid (1) and sometimes a hostname, so the id
	// also carries a random part.
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return &Worker{
		Store: s, Log: log, Concurrency: 2, Poll: 2 * time.Second, JobTimeout: 20 * time.Minute, JobRenew: 5 * time.Minute,
		Lease: 2 * time.Minute, Tick: 15 * time.Second, PeriodicSlots: 4, ShutdownGrace: 30 * time.Second,
		handlers: map[string]Handler{}, timeouts: map[string]time.Duration{}, running: map[string]*atomic.Bool{},
		id: fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(b)),
	}
}

func (w *Worker) Handle(kind string, h Handler) { w.handlers[kind] = h }

// HandleTimeout registers a handler whose jobs may run longer than
// JobTimeout, such as a full vulnerability archive download.
func (w *Worker) HandleTimeout(kind string, timeout time.Duration, h Handler) {
	w.handlers[kind] = h
	w.timeouts[kind] = timeout
}

// Every registers a periodic platform task, run in system scope.
func (w *Worker) Every(name string, every time.Duration, fn func(ctx context.Context) error) {
	w.add(name, every, func(ctx context.Context) error {
		return fn(tenant.System(ctx))
	})
}

func (w *Worker) add(name string, every time.Duration, fn func(ctx context.Context) error) {
	r, ok := w.running[name]
	if !ok {
		r = new(atomic.Bool)
		w.running[name] = r
	}
	w.periodic = append(w.periodic, periodic{name, every, fn, r})
}

// EveryWorkspace registers a periodic task that runs once for each enabled
// workspace, scoped to it. A failure in one workspace does not stop the rest.
func (w *Worker) EveryWorkspace(name string, every time.Duration, fn func(ctx context.Context) error) {
	w.everyWorkspace(name, every, w.Store.ActiveWorkspaceIDs, fn)
}

// EveryCollectingWorkspace is EveryWorkspace for the workspaces that are
// not read-only: collection, evaluation and notifications stop while a
// workspace is read-only (docs/asset-limits.md).
func (w *Worker) EveryCollectingWorkspace(name string, every time.Duration, fn func(ctx context.Context) error) {
	w.everyWorkspace(name, every, w.Store.CollectingWorkspaceIDs, fn)
}

func (w *Worker) everyWorkspace(name string, every time.Duration, list func(context.Context) ([]int64, error), fn func(ctx context.Context) error) {
	w.add(name, every, func(ctx context.Context) error {
		ids, err := list(tenant.System(ctx))
		if err != nil {
			return err
		}
		var errs []error
		for _, id := range ids {
			if ctx.Err() != nil {
				break
			}
			if err := fn(tenant.WithWorkspace(ctx, id)); err != nil {
				errs = append(errs, fmt.Errorf("workspace %d: %w", id, err))
			}
		}
		return errors.Join(errs...)
	})
}

// Run blocks until ctx is cancelled and in-flight work has stopped. Jobs are
// claimed in system scope and each runs in its own workspace; a running job
// is cancelled when ctx ends. A running periodic task gets ShutdownGrace to
// finish and record its outcome, and is then cancelled and released.
func (w *Worker) Run(ctx context.Context) {
	ctx = tenant.System(ctx)
	if w.Lease <= 0 {
		w.Lease = 2 * time.Minute
	}
	if w.Tick <= 0 {
		w.Tick = 15 * time.Second
	}
	if w.PeriodicSlots <= 0 {
		w.PeriodicSlots = 4
	}
	var wg sync.WaitGroup
	if w.HeapWarn >= 0 {
		limit := w.HeapWarn
		if limit == 0 {
			limit = DefaultHeapWarn
		}
		w.heap = newHeapWatch(limit, w.Log)
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.heap.run(ctx)
		}()
	}
	for i := 0; i < w.Concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			w.loop(ctx, fmt.Sprintf("%s/%d", w.id, n))
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		w.schedule(ctx)
	}()
	wg.Wait()
}

func (w *Worker) loop(ctx context.Context, id string) {
	for {
		if ctx.Err() != nil {
			return
		}
		job, err := w.Store.Claim(ctx, id)
		if err != nil {
			if ctx.Err() == nil {
				w.Log.Error("claim job", "err", err)
			}
			sleep(ctx, w.Poll*5)
			continue
		}
		if job == nil {
			sleep(ctx, w.Poll)
			continue
		}
		w.run(ctx, job, id)
	}
}

func (w *Worker) run(ctx context.Context, job *store.Job, owner string) {
	log := w.Log.With("job", job.ID, "kind", job.Kind, "attempt", job.Attempts)
	h, ok := w.handlers[job.Kind]
	// Finishing bookkeeping must survive shutdown of the parent context.
	bg := context.WithoutCancel(ctx)
	if !ok {
		_ = w.Store.FailJob(bg, &store.Job{ID: job.ID, Attempts: job.MaxAttempts, MaxAttempts: job.MaxAttempts},
			fmt.Errorf("no handler for job kind %q", job.Kind))
		return
	}
	timeout := w.JobTimeout
	if t, ok := w.timeouts[job.Kind]; ok {
		timeout = t
	}
	jctx, cancel := context.WithTimeout(ctx, timeout)
	if job.WorkspaceID != nil {
		jctx = tenant.WithWorkspace(jctx, *job.WorkspaceID)
	}
	defer cancel()
	// Renew the lock while the job runs; stop it if another worker took it.
	done := make(chan struct{})
	defer close(done)
	go func() {
		renew := w.JobRenew
		if renew <= 0 {
			renew = 5 * time.Minute
		}
		t := time.NewTicker(renew)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if held, err := w.Store.TouchJob(bg, job.ID, owner); err == nil && !held {
					log.Warn("job lock lost; stopping")
					cancel()
					return
				}
			}
		}
	}()
	start := time.Now()
	endHeap := w.heap.begin("job "+job.Kind, "job", job.ID)
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return h(jctx, job.Payload)
	}()
	endHeap()
	var deferred *Deferred
	if errors.As(err, &deferred) {
		log.Debug("job deferred", "reason", deferred.Reason, "after", deferred.After)
		if derr := w.Store.DeferJob(bg, job.ID, deferred.After); derr != nil {
			log.Error("defer job", "err", derr)
		}
		return
	}
	if err != nil {
		log.Warn("job failed", "err", err, "took", time.Since(start))
		if ferr := w.Store.FailJob(bg, job, err); ferr != nil {
			log.Error("record job failure", "err", ferr)
		}
		return
	}
	log.Info("job done", "took", time.Since(start))
	if err := w.Store.CompleteJob(bg, job.ID); err != nil {
		log.Error("complete job", "err", err)
	}
}

// registerEvery is how often a running scheduler refreshes its tasks' rows,
// which tells health checks the tasks are still expected to run.
const registerEvery = 5 * time.Minute

// schedule gives each periodic task its own loop and keeps the tasks
// registered. A task that another replica holds or ran recently is skipped.
// It returns when ctx has ended and every task's loop has stopped: a run in
// progress may finish within ShutdownGrace, then its context is cancelled.
func (w *Worker) schedule(ctx context.Context) {
	runCtx, stopRuns := context.WithCancel(context.WithoutCancel(ctx))
	defer stopRuns()
	stop := context.AfterFunc(ctx, func() { time.AfterFunc(w.ShutdownGrace, stopRuns) })
	defer stop()

	var registered time.Time
	if w.register(ctx) {
		registered = time.Now()
	}
	slots := make(chan struct{}, w.PeriodicSlots)
	var failures claimFailures
	var wg sync.WaitGroup
	for _, p := range w.periodic {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.loopPeriodic(ctx, runCtx, p, slots, &failures)
		}()
	}
	defer wg.Wait()

	tick := time.NewTicker(w.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if time.Since(registered) >= registerEvery && w.register(ctx) {
			registered = time.Now()
		}
		// While the database is unreachable every claim fails: log the
		// first error and how many tasks it affected once a tick, not one
		// line per task.
		if n, err := failures.take(); n > 0 {
			w.Log.Error("claim periodic tasks", "failed", n, "of", len(w.periodic), "err", err)
		}
	}
}

// loopPeriodic runs p every Tick, if it is due, in a free slot, until ctx
// ends. Runs get runCtx, which outlives ctx by the shutdown grace.
func (w *Worker) loopPeriodic(ctx, runCtx context.Context, p periodic, slots chan struct{}, failures *claimFailures) {
	tick := time.NewTicker(w.Tick)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case slots <- struct{}{}:
		}
		if ctx.Err() != nil {
			<-slots
			return
		}
		err := w.runPeriodic(runCtx, p)
		<-slots
		if err != nil {
			failures.add(p.name, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// claimFailures collects the tasks whose claim failed since the last report.
type claimFailures struct {
	mu    sync.Mutex
	tasks map[string]bool
	first error
}

func (c *claimFailures) add(name string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tasks == nil {
		c.tasks = map[string]bool{}
	}
	if c.first == nil {
		c.first = fmt.Errorf("task %s: %w", name, err)
	}
	c.tasks[name] = true
}

// take returns how many tasks failed to claim and the first error, and
// starts over.
func (c *claimFailures) take() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := len(c.tasks), c.first
	c.tasks, c.first = nil, nil
	return n, err
}

func (w *Worker) register(ctx context.Context) bool {
	for _, p := range w.periodic {
		if err := w.Store.RegisterPeriodic(ctx, p.name, p.every); err != nil {
			if ctx.Err() == nil {
				w.Log.Error("register periodic task", "task", p.name, "err", err)
			}
			return false
		}
	}
	return true
}

// runPeriodic claims p and runs it if it is due, renewing the lease while it
// runs. If the lease is lost (this replica could not reach the database for
// most of a lease), the task's context is cancelled so that it does not
// overlap with the replica that takes it over. A run of p that is still in
// progress in this process (one that lost its lease and has not returned yet)
// means p is skipped. It returns the error of a claim that failed (not of the
// task, which is recorded).
func (w *Worker) runPeriodic(ctx context.Context, p periodic) error {
	if !p.running.CompareAndSwap(false, true) {
		return nil
	}
	defer p.running.Store(false)
	ok, err := w.Store.ClaimPeriodic(ctx, p.name, w.id, p.every, w.Lease)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if !ok {
		return nil
	}
	log := w.Log.With("task", p.name)
	tctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{})
	lost := make(chan struct{})
	var hb sync.WaitGroup
	hb.Add(1)
	go func() {
		defer hb.Done()
		w.heartbeat(ctx, p.name, done, func() { close(lost); cancel() })
	}()
	start := time.Now()
	endHeap := w.heap.begin("task " + p.name)
	runErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return p.fn(tctx)
	}()
	endHeap()
	close(done)
	hb.Wait()
	// Recording the outcome must survive shutdown of the parent context.
	bg := context.WithoutCancel(ctx)
	select {
	case <-lost:
		log.Error("periodic task lost its lease and was stopped", "took", time.Since(start), "err", runErr)
		return nil
	default:
	}
	if ctx.Err() != nil {
		// Interrupted by shutdown: release without an outcome so another
		// replica runs it again instead of waiting a whole interval.
		if err := w.Store.ReleasePeriodic(bg, p.name, w.id); err != nil {
			log.Error("release periodic task", "err", err)
		}
		return nil
	}
	if runErr != nil {
		log.Error("periodic task failed", "err", runErr, "took", time.Since(start))
	} else {
		log.Debug("periodic task done", "took", time.Since(start))
	}
	if err := w.Store.FinishPeriodic(bg, p.name, w.id, runErr); err != nil {
		log.Error("record periodic task", "err", err)
	}
	return nil
}

// heartbeat renews the lease on a task until done is closed. It calls lose
// when the lease is gone or about to expire without a successful renewal.
func (w *Worker) heartbeat(ctx context.Context, name string, done <-chan struct{}, lose func()) {
	t := time.NewTicker(w.Lease / 4)
	defer t.Stop()
	renewed := time.Now()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		ok, err := w.Store.RenewPeriodic(context.WithoutCancel(ctx), name, w.id, w.Lease)
		switch {
		case err == nil && ok:
			renewed = time.Now()
			continue
		case err == nil:
			lose()
			return
		}
		w.Log.Warn("renew periodic task lease", "task", name, "err", err)
		if time.Since(renewed) > w.Lease*3/4 {
			lose()
			return
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
