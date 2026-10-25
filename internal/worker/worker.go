// Package worker runs background jobs from the PostgreSQL queue and the
// periodic scheduler. Handlers must be idempotent: a job can run twice if a
// worker dies after finishing but before recording completion.
package worker

import (
	"context"
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
	handlers    map[string]Handler
	periodic    []periodic
	id          string
}

type periodic struct {
	name  string
	every time.Duration
	fn    func(ctx context.Context) error
}

func New(s *store.Store, log *slog.Logger) *Worker {
	host, _ := os.Hostname()
	return &Worker{
		Store: s, Log: log, Concurrency: 2, Poll: 2 * time.Second, JobTimeout: 20 * time.Minute,
		handlers: map[string]Handler{}, id: fmt.Sprintf("%s-%d", host, os.Getpid()),
	}
}

func (w *Worker) Handle(kind string, h Handler) { w.handlers[kind] = h }

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
		w.run(ctx, job)
	}
}

func (w *Worker) run(ctx context.Context, job *store.Job) {
	log := w.Log.With("job", job.ID, "kind", job.Kind, "attempt", job.Attempts)
	h, ok := w.handlers[job.Kind]
	// Finishing bookkeeping must survive shutdown of the parent context.
	bg := context.WithoutCancel(ctx)
	if !ok {
		_ = w.Store.FailJob(bg, &store.Job{ID: job.ID, Attempts: job.MaxAttempts, MaxAttempts: job.MaxAttempts},
			fmt.Errorf("no handler for job kind %q", job.Kind))
		return
	}
	jctx, cancel := context.WithTimeout(ctx, w.JobTimeout)
	if job.WorkspaceID != nil {
		jctx = tenant.WithWorkspace(jctx, *job.WorkspaceID)
	}
	defer cancel()
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

func (w *Worker) schedule(ctx context.Context) {
	last := make([]time.Time, len(w.periodic))
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		now := time.Now()
		for i, p := range w.periodic {
			if now.Sub(last[i]) < p.every {
				continue
			}
			last[i] = now
			if err := p.fn(ctx); err != nil && ctx.Err() == nil {
				w.Log.Error("periodic task failed", "task", p.name, "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
