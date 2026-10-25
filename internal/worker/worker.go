// Package worker runs background jobs from the PostgreSQL queue and the
// periodic scheduler. Handlers must be idempotent: a job can run twice if a
// worker dies after finishing but before recording completion.
//
// Any number of server replicas can run a worker against one database. Jobs
// are claimed row by row; periodic tasks are claimed in periodic_tasks with a
// lease, so each runs at most once per interval across replicas and never on
// two replicas at the same time.
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
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type Handler func(ctx context.Context, payload json.RawMessage) error

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
	// Tick is how often the scheduler looks for due periodic tasks.
	Tick     time.Duration
	handlers map[string]Handler
	timeouts map[string]time.Duration
	periodic []periodic
	id       string
}

type periodic struct {
	name  string
	every time.Duration
	fn    func(ctx context.Context) error
}

func New(s *store.Store, log *slog.Logger) *Worker {
	host, _ := os.Hostname()
	// Containers often share a pid (1) and sometimes a hostname, so the id
	// also carries a random part.
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return &Worker{
		Store: s, Log: log, Concurrency: 2, Poll: 2 * time.Second, JobTimeout: 20 * time.Minute, JobRenew: 5 * time.Minute,
		Lease: 2 * time.Minute, Tick: 15 * time.Second,
		handlers: map[string]Handler{}, timeouts: map[string]time.Duration{}, id: fmt.Sprintf("%s-%d-%s", host, os.Getpid(), hex.EncodeToString(b)),
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
	w.periodic = append(w.periodic, periodic{name, every, func(ctx context.Context) error {
		return fn(tenant.System(ctx))
	}})
}

// EveryWorkspace registers a periodic task that runs once for each enabled
// workspace, scoped to it. A failure in one workspace does not stop the rest.
func (w *Worker) EveryWorkspace(name string, every time.Duration, fn func(ctx context.Context) error) {
	w.periodic = append(w.periodic, periodic{name, every, func(ctx context.Context) error {
		ids, err := w.Store.ActiveWorkspaceIDs(tenant.System(ctx))
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
	}})
}

// Run blocks until ctx is cancelled and in-flight jobs have finished. Jobs
// are claimed in system scope and each runs in its own workspace.
func (w *Worker) Run(ctx context.Context) {
	ctx = tenant.System(ctx)
	if w.Lease <= 0 {
		w.Lease = 2 * time.Minute
	}
	if w.Tick <= 0 {
		w.Tick = 15 * time.Second
	}
	var wg sync.WaitGroup
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
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return h(jctx, job.Payload)
	}()
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

// schedule runs due periodic tasks one after another. A task that another
// replica holds or ran recently is skipped.
func (w *Worker) schedule(ctx context.Context) {
	tick := time.NewTicker(w.Tick)
	defer tick.Stop()
	var registered time.Time
	for {
		if time.Since(registered) >= registerEvery && w.register(ctx) {
			registered = time.Now()
		}
		for _, p := range w.periodic {
			if ctx.Err() != nil {
				return
			}
			w.runPeriodic(ctx, p)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
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
// overlap with the replica that takes it over.
func (w *Worker) runPeriodic(ctx context.Context, p periodic) {
	ok, err := w.Store.ClaimPeriodic(ctx, p.name, w.id, p.every, w.Lease)
	if err != nil {
		if ctx.Err() == nil {
			w.Log.Error("claim periodic task", "task", p.name, "err", err)
		}
		return
	}
	if !ok {
		return
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
	runErr := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return p.fn(tctx)
	}()
	close(done)
	hb.Wait()
	// Recording the outcome must survive shutdown of the parent context.
	bg := context.WithoutCancel(ctx)
	select {
	case <-lost:
		log.Error("periodic task lost its lease and was stopped", "took", time.Since(start), "err", runErr)
		return
	default:
	}
	if ctx.Err() != nil {
		// Interrupted by shutdown: release without an outcome so another
		// replica runs it again instead of waiting a whole interval.
		if err := w.Store.ReleasePeriodic(bg, p.name, w.id); err != nil {
			log.Error("release periodic task", "err", err)
		}
		return
	}
	if runErr != nil {
		log.Error("periodic task failed", "err", runErr, "took", time.Since(start))
	} else {
		log.Debug("periodic task done", "took", time.Since(start))
	}
	if err := w.Store.FinishPeriodic(bg, p.name, w.id, runErr); err != nil {
		log.Error("record periodic task", "err", err)
	}
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
