package health

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func find(r *Report, kind, key string) *Problem {
	for i := range r.Problems {
		if r.Problems[i].Kind == kind && r.Problems[i].Key == key {
			return &r.Problems[i]
		}
	}
	return nil
}

func TestCheck(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := tenant.System(context.Background())
	c := &Checker{Store: st, FeedsEnabled: true}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := st.Pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}

	// A new installation: nothing synced yet, a warning while the first
	// sync runs.
	r, err := c.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if p := find(r, "intelligence", "vulnerability"); p == nil || p.Severity != Warning || r.Status != "warning" {
		t.Fatalf("empty intelligence: %+v", r.Problems)
	}
	exec(`INSERT INTO feeds (name, kind, last_attempt) VALUES ('osv:npm', 'vulnerability', now())`)
	r, _ = c.Check(ctx)
	if p := find(r, "intelligence", "vulnerability"); p == nil || p.Severity != Warning {
		t.Fatalf("first sync: %+v", r.Problems)
	}
	// Started long ago and never completed: critical.
	exec(`UPDATE feeds SET last_attempt = now() - interval '2 hours'`)
	r, _ = c.Check(ctx)
	if p := find(r, "intelligence", "vulnerability"); p == nil || p.Severity != Critical || r.Status != "critical" {
		t.Fatalf("first sync never completed: %+v", r.Problems)
	}
	incs, err := c.PlatformIncidents(ctx)
	if err != nil || len(incs) != 1 || incs[0].Kind != "platform" || incs[0].Key != "intelligence:vulnerability" {
		t.Fatalf("platform incidents: %+v %v", incs, err)
	}
	off := (&Checker{Store: st}).mustCheck(t)
	if p := find(off, "intelligence", "vulnerability"); p == nil || p.Severity != Warning || !strings.Contains(p.Title, "turned off") {
		t.Fatalf("feeds off: %+v", off.Problems)
	}

	// Feeds: synced and fresh is fine; stale is critical for vulnerability
	// data; failing within the freshness limit is a warning.
	exec(`UPDATE feeds SET last_success = now() WHERE name = 'osv:npm'`)
	exec(`INSERT INTO feeds (name, kind, stale_after, last_attempt, last_success, last_error) VALUES
		('osv:Debian', 'vulnerability', '6 hours', now(), now() - interval '2 days', 'connection refused'),
		('releases:npm', 'release', '72 hours', now(), now() - interval '1 hour', 'HTTP 503'),
		('kev', 'vulnerability', '72 hours', now(), NULL, 'TLS handshake timeout'),
		('lifecycle:endoflife', 'lifecycle', '7 days', NULL, NULL, '')`)
	// Periodic tasks: one healthy, one overdue, one failing recently, one
	// that no running server registers any more.
	exec(`INSERT INTO periodic_tasks (name, every, created_at, last_success_at, last_error, consecutive_failures, seen_at) VALUES
		('alerts', '1 minute', now() - interval '1 day', now(), '', 0, now()),
		('housekeeping', '1 hour', now() - interval '1 day', now() - interval '5 hours', 'disk full', 4, now()),
		('mark-stale-assets', '10 minutes', now() - interval '1 day', now() - interval '11 minutes', 'timeout', 1, now()),
		('retired', '1 minute', now() - interval '30 days', NULL, '', 0, now() - interval '1 day')`)
	exec(`INSERT INTO jobs (kind, payload, attempts, max_attempts, failed_at, last_error) VALUES ('feed.sync', '{}', 5, 5, now(), 'boom')`)
	exec(`INSERT INTO jobs (kind, payload, run_at) VALUES ('evaluate', '{}', now() - interval '2 hours')`)

	r, err = c.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[[2]string]Severity{
		{"feed", "osv:Debian"}:        Critical,
		{"feed", "releases:npm"}:      Warning,
		{"feed", "kev"}:               Critical,
		{"task", "housekeeping"}:      Critical,
		{"task", "mark-stale-assets"}: Warning,
		{"jobs", "feed.sync"}:         Warning,
		{"jobs", "backlog"}:           Warning,
	}
	for k, sev := range want {
		if p := find(r, k[0], k[1]); p == nil || p.Severity != sev {
			t.Errorf("%v: got %+v, want %s", k, p, sev)
		}
	}
	if len(r.Problems) != len(want) {
		t.Errorf("unexpected problems: %+v", r.Problems)
	}
	if p := find(r, "task", "housekeeping"); p != nil && !strings.Contains(p.Detail, "disk full") {
		t.Errorf("task detail: %q", p.Detail)
	}
	if r.Status != "critical" || r.Problems[0].Severity != Critical {
		t.Errorf("status %s, first %+v", r.Status, r.Problems[0])
	}
	if len(r.Tasks) != 3 {
		t.Errorf("tasks no server registers should be left out: %+v", r.Tasks)
	}
	if len(r.RecentFailures) != 1 || r.RecentFailures[0].LastError != "boom" {
		t.Errorf("recent failures: %+v", r.RecentFailures)
	}
	// Only critical, non-feed problems become incidents, without errors
	// that could name another workspace.
	incs, _ = c.PlatformIncidents(ctx)
	if len(incs) != 1 || incs[0].Key != "task:housekeeping" || strings.Contains(fmt.Sprint(incs[0]), "disk full") {
		t.Errorf("platform incidents: %+v", incs)
	}

	// Fixed: back to ok.
	exec(`UPDATE feeds SET last_success = now(), last_error = ''`)
	exec(`UPDATE periodic_tasks SET last_success_at = now(), consecutive_failures = 0, last_error = ''`)
	exec(`DELETE FROM jobs`)
	if r = c.mustCheck(t); r.Status != "ok" || len(r.Problems) != 0 {
		t.Errorf("after fixing: %s %+v", r.Status, r.Problems)
	}
}

func (c *Checker) mustCheck(t *testing.T) *Report {
	t.Helper()
	r, err := c.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestDeliveryProblems(t *testing.T) {
	r := &Report{}
	if p := deliveryProblems(r); len(p) != 0 {
		t.Fatalf("no deliveries: %+v", p)
	}
	r = &Report{
		Deliveries: []store.DeliveryCount{{Kind: "webhook", State: "failed", Count: 2}, {Kind: "slack", State: "failed", Count: 1},
			{Kind: "webhook", State: "retrying", Count: 5}},
		FailingChannels:          []store.ChannelCount{{Kind: "webhook", Count: 1}},
		OldestDueDeliverySeconds: (20 * time.Minute).Seconds(),
	}
	ps := deliveryProblems(r)
	byKey := map[string]Problem{}
	for _, p := range ps {
		if p.Severity != Warning || p.Kind != "notifications" {
			t.Errorf("%+v: want a notifications warning", p)
		}
		byKey[p.Key] = p
	}
	// Failed deliveries and failing channels are reported per channel by the
	// notification problems (objects.go); only the backlog is reported here.
	if len(ps) != 1 {
		t.Errorf("want only the backlog problem, got %+v", ps)
	}
	if b := byKey["backlog"]; b.NextStep == "" || b.Docs == "" {
		t.Errorf("backlog needs a next step and docs: %+v", b)
	}
	if !strings.Contains(byKey["backlog"].Detail, "20m") {
		t.Errorf("backlog: %+v", byKey["backlog"])
	}
	r.OldestDueDeliverySeconds = 60
	r.FailingChannels, r.Deliveries = nil, r.Deliveries[2:]
	if p := deliveryProblems(r); len(p) != 0 {
		t.Errorf("retries alone and a short wait are not problems: %+v", p)
	}
}
