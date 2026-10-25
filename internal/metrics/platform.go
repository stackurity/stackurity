package metrics

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Handler serves /metrics: build information, HTTP and database pool
// statistics from this replica, and platform state read from the database
// (jobs, periodic tasks, feeds, stale assets, health problems), which is
// the same on every replica.
type Handler struct {
	Store   *store.Store
	Health  *health.Checker
	HTTP    *HTTP
	Log     *slog.Logger
	Version string
	Edition string // community or ee
	Started time.Time
}

func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(tenant.System(r.Context()), 10*time.Second)
	defer cancel()
	var buf bytes.Buffer
	h.Write(ctx, NewWriter(&buf))
	rw.Header().Set("Content-Type", ContentType)
	_, _ = rw.Write(buf.Bytes())
}

// Write writes every metric. Database sections that fail are left out and
// counted in stackurity_scrape_errors, so a scrape still succeeds while the
// database is down.
func (h *Handler) Write(ctx context.Context, w *Writer) {
	ctx = tenant.System(ctx)
	w.Family("stackurity_build_info", "gauge", "Build information; always 1.")
	w.Sample("stackurity_build_info", 1, "version", h.Version, "edition", h.Edition, "go_version", runtime.Version())
	if !h.Started.IsZero() {
		w.Gauge("stackurity_start_time_seconds", "When this server process started, as a Unix timestamp.", float64(h.Started.Unix()))
	}
	w.Gauge("go_goroutines", "Goroutines that currently exist.", float64(runtime.NumGoroutine()))
	if h.HTTP != nil {
		h.HTTP.Write(w)
	}
	errs := 0
	fail := func(section string, err error) {
		errs++
		if h.Log != nil && ctx.Err() == nil {
			h.Log.Warn("metrics: read failed", "section", section, "err", err)
		}
	}

	pool := h.Store.Pool.Stat()
	w.Family("stackurity_db_pool_connections", "gauge", "Database pool connections by state.")
	w.Sample("stackurity_db_pool_connections", float64(pool.AcquiredConns()), "state", "acquired")
	w.Sample("stackurity_db_pool_connections", float64(pool.IdleConns()), "state", "idle")
	w.Sample("stackurity_db_pool_connections", float64(pool.ConstructingConns()), "state", "constructing")
	w.Gauge("stackurity_db_pool_max_connections", "Largest size the database pool may grow to.", float64(pool.MaxConns()))
	w.Family("stackurity_db_pool_acquires_total", "counter", "Connections acquired from the database pool.")
	w.Sample("stackurity_db_pool_acquires_total", float64(pool.AcquireCount()))
	w.Family("stackurity_db_pool_empty_acquires_total", "counter", "Acquires that had to wait for a connection.")
	w.Sample("stackurity_db_pool_empty_acquires_total", float64(pool.EmptyAcquireCount()))
	w.Family("stackurity_db_pool_canceled_acquires_total", "counter", "Acquires cancelled before a connection was available.")
	w.Sample("stackurity_db_pool_canceled_acquires_total", float64(pool.CanceledAcquireCount()))
	w.Family("stackurity_db_pool_acquire_wait_seconds_total", "counter", "Total time spent acquiring connections.")
	w.Sample("stackurity_db_pool_acquire_wait_seconds_total", pool.AcquireDuration().Seconds())

	pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
	err := h.Store.Pool.Ping(pctx)
	pcancel()
	w.Gauge("stackurity_database_up", "Whether the database answered a ping.", boolValue(err == nil))
	if err != nil {
		fail("ping", err)
		w.Gauge("stackurity_scrape_errors", "Database sections of this scrape that could not be read.", float64(errs))
		return
	}

	if rep, err := h.Health.Check(ctx); err != nil {
		fail("health", err)
	} else {
		writeHealth(w, rep)
	}
	if feeds, err := h.Store.ListFeeds(ctx); err != nil {
		fail("feeds", err)
	} else {
		writeFeeds(w, feeds)
	}
	if n, err := h.Store.CountStaleAssets(ctx); err != nil {
		fail("assets", err)
	} else {
		w.Gauge("stackurity_assets_stale", "Assets that have stopped reporting, across all workspaces.", float64(n))
	}
	w.Gauge("stackurity_scrape_errors", "Database sections of this scrape that could not be read.", float64(errs))
}

func writeHealth(w *Writer, r *health.Report) {
	crit, warn := 0, 0
	for _, p := range r.Problems {
		if p.Severity == health.Critical {
			crit++
		} else {
			warn++
		}
	}
	w.Family("stackurity_health_problems", "gauge", "Platform problems found by the health check, by severity.")
	w.Sample("stackurity_health_problems", float64(crit), "severity", "critical")
	w.Sample("stackurity_health_problems", float64(warn), "severity", "warning")

	w.Family("stackurity_jobs", "gauge", "Background jobs by kind and state (queued, scheduled, running, failed in the last 24 hours).")
	for _, j := range r.Jobs {
		w.Sample("stackurity_jobs", float64(j.Count), "kind", j.Kind, "state", j.State)
	}
	w.Gauge("stackurity_jobs_oldest_queued_age_seconds", "How long the oldest due job has waited for a worker.", r.OldestQueuedSeconds)

	w.Family("stackurity_periodic_task_interval_seconds", "gauge", "How often each periodic task runs.")
	for _, t := range r.Tasks {
		w.Sample("stackurity_periodic_task_interval_seconds", t.EverySeconds, "task", t.Name)
	}
	w.Family("stackurity_periodic_task_last_success_timestamp_seconds", "gauge", "When each periodic task last succeeded (0 if never), as a Unix timestamp.")
	for _, t := range r.Tasks {
		v := 0.0
		if t.LastSuccessAt != nil {
			v = float64(t.LastSuccessAt.Unix())
		}
		w.Sample("stackurity_periodic_task_last_success_timestamp_seconds", v, "task", t.Name)
	}
	w.Family("stackurity_periodic_task_consecutive_failures", "gauge", "Failed runs of each periodic task since its last success.")
	for _, t := range r.Tasks {
		w.Sample("stackurity_periodic_task_consecutive_failures", float64(t.ConsecutiveFailures), "task", t.Name)
	}
	w.Family("stackurity_periodic_task_last_duration_seconds", "gauge", "How long each periodic task's last finished run took.")
	for _, t := range r.Tasks {
		if t.LastDuration != nil {
			w.Sample("stackurity_periodic_task_last_duration_seconds", t.LastDuration.Seconds(), "task", t.Name)
		}
	}
	w.Family("stackurity_periodic_task_running", "gauge", "Whether a replica is running each periodic task now.")
	for _, t := range r.Tasks {
		w.Sample("stackurity_periodic_task_running", boolValue(t.Running), "task", t.Name)
	}
}

func writeFeeds(w *Writer, feeds []store.Feed) {
	var on []store.Feed
	for _, f := range feeds {
		if f.Enabled {
			on = append(on, f)
		}
	}
	w.Family("stackurity_feed_last_success_timestamp_seconds", "gauge", "When each enabled intelligence feed last synced (0 if never), as a Unix timestamp.")
	for _, f := range on {
		v := 0.0
		if f.LastSuccess != nil {
			v = float64(f.LastSuccess.Unix())
		}
		w.Sample("stackurity_feed_last_success_timestamp_seconds", v, "feed", f.Name, "kind", f.Kind)
	}
	w.Family("stackurity_feed_stale", "gauge", "Whether each enabled feed is older than its stale threshold.")
	for _, f := range on {
		w.Sample("stackurity_feed_stale", boolValue(f.Stale), "feed", f.Name, "kind", f.Kind)
	}
	w.Family("stackurity_feed_failing", "gauge", "Whether each enabled feed's last sync attempt failed.")
	for _, f := range on {
		w.Sample("stackurity_feed_failing", boolValue(f.LastError != ""), "feed", f.Name, "kind", f.Kind)
	}
	w.Family("stackurity_feed_records", "gauge", "Records held for each enabled feed.")
	for _, f := range on {
		w.Sample("stackurity_feed_records", float64(f.Records), "feed", f.Name, "kind", f.Kind)
	}
}
