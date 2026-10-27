package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Periodic tasks running side by side must not exhaust the connection pool
// or slow the API. Several replicas, each with a production-sized pool of 20
// connections, run 40 periodic tasks on intervals scaled down from
// production's (100 ms for the alerts task, 100 ms to 1 s for the rest; 2 of
// them hold a connection for half a second, 1 waits on the network for a
// second, the rest make short queries), job workers busy with a steady
// stream of jobs, and 5 API clients each. The API is measured first without
// the workers, then under that load.
//
// It opens over 80 connections, so it runs only when asked:
//
//	STACKURITY_LOAD_SECONDS=10 go test -race -run TestPeriodicLoad -v ./internal/worker
//
// STACKURITY_LOAD_SECONDS is how long each phase lasts, STACKURITY_LOAD_SLOTS
// the periodic slots (default 4; 1 runs one task at a time, as before).
func TestPeriodicLoad(t *testing.T) {
	secs, err := strconv.Atoi(os.Getenv("STACKURITY_LOAD_SECONDS"))
	if err != nil || secs <= 0 {
		t.Skip("set STACKURITY_LOAD_SECONDS to run the load test")
	}
	phase := time.Duration(secs) * time.Second
	base := testdb.New(t)
	const replicas, tasks, apiClients = 4, 40, 5
	ctx := tenant.System(context.Background())

	type replica struct {
		pool    *pgxpool.Pool
		st      *store.Store
		w       *Worker
		inQuery atomic.Int32 // periodic task queries in flight
		peakQ   atomic.Int32
		peak    atomic.Int32 // connections acquired
	}
	var reps []*replica
	for range replicas {
		cfg := base.Config()
		cfg.MaxConns = 20
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		st := store.New(pool)
		w := New(st, slog.New(slog.NewTextHandler(io.Discard, nil)))
		w.Tick, w.Poll, w.Lease = 20*time.Millisecond, 20*time.Millisecond, 2*time.Second
		if s, err := strconv.Atoi(os.Getenv("STACKURITY_LOAD_SLOTS")); err == nil && s > 0 {
			w.PeriodicSlots = s
		}
		reps = append(reps, &replica{pool: pool, st: st, w: w})
	}

	// The alerts task's runs, on whichever replica: its cadence under load.
	var alertsMu sync.Mutex
	var alertRuns []time.Time
	for _, r := range reps {
		query := func(ctx context.Context, sleep time.Duration) error {
			n := r.inQuery.Add(1)
			defer r.inQuery.Add(-1)
			for p := r.peakQ.Load(); n > p && !r.peakQ.CompareAndSwap(p, n); p = r.peakQ.Load() {
			}
			_, err := r.st.Pool.Exec(ctx, `SELECT pg_sleep($1)`, sleep.Seconds())
			return err
		}
		r.w.Every("alerts", 100*time.Millisecond, func(ctx context.Context) error {
			alertsMu.Lock()
			alertRuns = append(alertRuns, time.Now())
			alertsMu.Unlock()
			return query(ctx, time.Millisecond)
		})
		for i := range tasks - 1 {
			name := fmt.Sprintf("task-%02d", i)
			every := time.Duration(100+i*900/tasks) * time.Millisecond // the same on every replica
			switch {
			case i < 2: // a slow query
				r.w.Every(name, time.Millisecond, func(ctx context.Context) error { return query(ctx, 500*time.Millisecond) })
			case i == 2: // stuck on the network, no connection held
				r.w.Every(name, time.Millisecond, func(ctx context.Context) error { sleep(ctx, time.Second); return nil })
			case i%5 == 0:
				r.w.EveryWorkspace(name, every, func(ctx context.Context) error { return query(ctx, 2*time.Millisecond) })
			default:
				r.w.Every(name, every, func(ctx context.Context) error {
					if err := query(ctx, time.Duration(rand.IntN(5))*time.Millisecond); err != nil {
						return err
					}
					return query(ctx, time.Millisecond)
				})
			}
		}
		r.w.Handle("load", func(ctx context.Context, _ json.RawMessage) error {
			_, err := r.st.Pool.Exec(ctx, `SELECT pg_sleep(0.01)`)
			return err
		})
	}

	// api runs the API clients for d and returns each request's total time
	// and the time it waited for a connection.
	api := func(d time.Duration) (total, wait []time.Duration, errs int) {
		var mu sync.Mutex
		var wg sync.WaitGroup
		end := time.Now().Add(d)
		for _, r := range reps {
			for range apiClients {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for time.Now().Before(end) {
						start := time.Now()
						c, err := r.pool.Acquire(ctx)
						acquired := time.Since(start)
						if err == nil {
							var n int
							err = c.QueryRow(ctx, `SELECT count(*) FROM periodic_tasks WHERE locked_until > now() OR last_error <> ''`).Scan(&n)
							c.Release()
						}
						took := time.Since(start)
						mu.Lock()
						if err != nil {
							errs++
						} else {
							total, wait = append(total, took), append(wait, acquired)
						}
						mu.Unlock()
						time.Sleep(5 * time.Millisecond) // between requests
					}
				}()
			}
		}
		wg.Wait()
		return total, wait, errs
	}
	pct := func(d []time.Duration, p float64) time.Duration {
		if len(d) == 0 {
			return 0
		}
		slices.Sort(d)
		return d[min(len(d)-1, int(float64(len(d))*p))]
	}

	baseTotal, baseWait, baseErrs := api(phase)

	// Load: workers, a job producer and a sampler of each pool's connections.
	wctx, stopWork := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	for _, r := range reps {
		wg.Add(1)
		go func() { defer wg.Done(); r.w.Run(wctx) }()
	}
	var jobs atomic.Int64
	wg.Add(2)
	go func() {
		defer wg.Done()
		for wctx.Err() == nil {
			if _, err := reps[0].st.Enqueue(ctx, "load", map[string]int{}, "", time.Time{}); err == nil {
				jobs.Add(1)
			}
			sleep(wctx, 10*time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for wctx.Err() == nil {
			for _, r := range reps {
				n := r.pool.Stat().AcquiredConns()
				for p := r.peak.Load(); n > p && !r.peak.CompareAndSwap(p, n); p = r.peak.Load() {
				}
			}
			sleep(wctx, time.Millisecond)
		}
	}()
	time.Sleep(500 * time.Millisecond) // every task has started
	alertsMu.Lock()
	alertRuns = alertRuns[:0]
	alertsMu.Unlock()
	loadTotal, loadWait, loadErrs := api(phase)
	alertsMu.Lock()
	runs := slices.Clone(alertRuns)
	alertsMu.Unlock()
	stopWork()
	wg.Wait()

	var done int
	if err := reps[0].pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind = 'load' AND done_at IS NOT NULL`).Scan(&done); err != nil {
		t.Fatal(err)
	}
	var maxGap time.Duration
	for i := 1; i < len(runs); i++ {
		maxGap = max(maxGap, runs[i].Sub(runs[i-1]))
	}
	t.Logf("%d replicas x %d periodic tasks (%d slots each), 2 job workers and %d API clients each; %v per phase",
		replicas, tasks, reps[0].w.PeriodicSlots, apiClients, phase)
	t.Logf("API without workers: %d requests, p50 %v, p99 %v, max %v; connection wait p99 %v, max %v; %d errors",
		len(baseTotal), pct(baseTotal, .5), pct(baseTotal, .99), pct(baseTotal, 1), pct(baseWait, .99), pct(baseWait, 1), baseErrs)
	t.Logf("API under load:      %d requests, p50 %v, p99 %v, max %v; connection wait p99 %v, max %v; %d errors",
		len(loadTotal), pct(loadTotal, .5), pct(loadTotal, .99), pct(loadTotal, 1), pct(loadWait, .99), pct(loadWait, 1), loadErrs)
	for i, r := range reps {
		s := r.pool.Stat()
		t.Logf("replica %d: peak %d of %d connections in use, peak %d periodic queries at once, %d acquires waited %v in all for an empty pool",
			i, r.peak.Load(), s.MaxConns(), r.peakQ.Load(), s.EmptyAcquireCount(), s.EmptyAcquireWaitTime().Round(time.Millisecond))
	}
	t.Logf("alerts ran %d times, longest gap %v; %d of %d jobs done", len(runs), maxGap.Round(time.Millisecond), done, jobs.Load())

	if baseErrs+loadErrs > 0 {
		t.Errorf("%d API requests failed", baseErrs+loadErrs)
	}
	for i, r := range reps {
		if p := r.peak.Load(); p >= r.pool.Stat().MaxConns() {
			t.Errorf("replica %d used all %d connections", i, p)
		}
		if q := r.peakQ.Load(); int(q) > r.w.PeriodicSlots {
			t.Errorf("replica %d ran %d periodic queries at once, more than its %d slots", i, q, r.w.PeriodicSlots)
		}
	}
	// The API never waits for a connection behind periodic work.
	if w := pct(loadWait, .99); w > 20*time.Millisecond {
		t.Errorf("API connection wait p99 %v under load", w)
	}
	// Query time also depends on how busy PostgreSQL is (here far busier
	// than in production, with every replica checking 40 tasks 50 times a
	// second), so this bound is loose; the wait above is what the pool adds.
	if p := pct(loadTotal, .99); p > 250*time.Millisecond {
		t.Errorf("API p99 %v under load, %v without", p, pct(baseTotal, .99))
	}
	// Due every 100 ms and checked every 20 ms: about 8 runs a second.
	if maxGap > 500*time.Millisecond || len(runs) < int(phase/(250*time.Millisecond)) {
		t.Errorf("alerts ran %d times with a longest gap of %v while other tasks were slow", len(runs), maxGap)
	}
	if done == 0 {
		t.Error("no job ran under periodic load")
	}
}
