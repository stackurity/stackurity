//go:build crash

package crashtest

import (
	"context"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/store"
)

// The operational drills of docs/operations.md, run against the real server:
// an upstream outage long enough for a feed to go stale, a notification
// provider that refuses every message, and an agent that stops reporting.
// Each checks that what an operator watches (the metrics the recommended
// alerts use, Platform health, incidents, coverage) reports the problem,
// that nothing good is thrown away while it lasts, and that it clears once
// the cause is gone.

// metric returns the value of one series in a scrape (the full series text,
// with labels in the order the server writes them).
func metric(scrape, series string) (float64, bool) {
	for _, line := range strings.Split(scrape, "\n") {
		if v, ok := strings.CutPrefix(line, series+" "); ok {
			f, err := strconv.ParseFloat(v, 64)
			return f, err == nil
		}
	}
	return 0, false
}

func (e *env) problem(kind, key string) *health.Problem {
	e.t.Helper()
	r, err := (&health.Checker{Store: e.st, FeedsEnabled: true}).Check(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	for _, p := range r.Problems {
		if p.Kind == kind && p.Key == key {
			return &p
		}
	}
	return nil
}

func (e *env) incident(kind, key string) string {
	return e.str(`SELECT status FROM incidents WHERE kind = $1 AND key = $2 ORDER BY id DESC LIMIT 1`, kind, key)
}

// reportingIncident is the status of the latest reporting incident that
// lists an asset (store/reporting_incidents.go), and its title.
func (e *env) reportingIncident(asset int64) (status, title string) {
	return e.str(`SELECT status FROM incidents WHERE kind = 'collection' AND key LIKE 'reporting:%' AND detail->'asset_ids' @> to_jsonb($1::bigint)
		ORDER BY id DESC LIMIT 1`, asset),
		e.str(`SELECT title FROM incidents WHERE kind = 'collection' AND key LIKE 'reporting:%' AND detail->'asset_ids' @> to_jsonb($1::bigint)
		ORDER BY id DESC LIMIT 1`, asset)
}

// OSV stops answering for longer than the Debian feed's freshness limit
// (6 hours; the last success is moved back instead of waiting). The feed is
// reported failing and stale in metrics, Platform health and a feed
// incident, the host's coverage says its findings rest on stale
// intelligence, and its findings stay open: nothing is cleared because
// intelligence is missing. Once OSV answers again, the next sync clears it
// all.
func TestUpstreamOutage(t *testing.T) {
	e := newEnv(t)
	t0 := time.Now().Add(-time.Hour)
	host := e.ingest(hostBatch("web-1", debPurl("openssl", "3.0.11-1~deb12u2")))
	advs := append([]advisory{{id: "DSA-0001-1", cve: "CVE-2024-0001", pkg: "openssl", fixed: "3.0.15-1~deb12u1", modified: t0}},
		fillers("OLD", 20, t0)...)
	e.serveIntel(advs, "CVE-2024-0001")
	e.up.set("/osv/Debian/modified_id.csv", modifiedCSV(advs, t0))
	s := e.start()
	waitFor(t, firstEvaluation, "first Debian sync and evaluation", func() bool {
		return e.when(`SELECT last_success FROM feeds WHERE name = 'osv:Debian'`) != nil && len(e.findings(host)) == 1 && e.evaluationsDone()
	})
	before := e.findings(host)

	e.up.down.Store(true)
	e.exec(`UPDATE feeds SET last_success = last_success - interval '7 hours', last_attempt = last_attempt - interval '7 hours'
		WHERE name = 'osv:Debian'`)
	if _, err := e.st.Enqueue(sys, "feed.sync", map[string]string{"feed": "osv:Debian"}, "feed:osv:Debian", time.Time{}); err != nil {
		t.Fatal(err)
	}
	sync := `kind = 'feed.sync' AND payload->>'feed' = 'osv:Debian' AND done_at IS NULL`
	waitFor(t, 30*time.Second, "the sync attempt to fail", func() bool {
		j := e.job(sync)
		return j != nil && j.LastError != "" && j.LockedBy == ""
	})
	j := e.job(sync)
	feedErr := e.str(`SELECT last_error FROM feeds WHERE name = 'osv:Debian'`)
	e.logf("OSV down: attempt %d failed (%q), retried with backoff; feed error %q", j.Attempts, j.LastError, feedErr)
	if !strings.Contains(j.LastError, "503") || !strings.Contains(feedErr, "503") {
		t.Errorf("job error %q, feed error %q: want the upstream's 503 in both", j.LastError, feedErr)
	}

	waitFor(t, 30*time.Second, "metrics to report the feed stale and failing", func() bool {
		m := s.scrape()
		stale, _ := metric(m, `stackurity_feed_stale{feed="osv:Debian",kind="vulnerability"}`)
		failing, _ := metric(m, `stackurity_feed_failing{feed="osv:Debian",kind="vulnerability"}`)
		crit, _ := metric(m, `stackurity_health_problems{severity="critical"}`)
		return stale == 1 && failing == 1 && crit >= 1
	})
	if p := e.problem("feed", "osv:Debian"); p == nil || p.Severity != health.Critical || !strings.Contains(p.Title, "stale") {
		t.Errorf("platform health: %+v, want a critical stale-feed problem", p)
	}
	waitFor(t, 30*time.Second, "a feed incident", func() bool { return e.incident("feed", "osv:Debian") == "open" })
	cov, err := e.st.AssetCoverage(ws, host)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cov.StaleFeeds, "osv:Debian") || cov.Components.StaleIntelligence == 0 {
		t.Errorf("coverage %+v: want the host's components marked as checked against stale intelligence", cov)
	}
	if after := e.findings(host); !maps.Equal(after, before) {
		t.Errorf("findings changed during the outage: %v, before %v", after, before)
	}
	e.logf("stale and failing in metrics, critical in platform health, feed incident open, coverage %q, findings kept %v", cov.State, before)

	// OSV is back: the retried sync clears everything.
	e.up.down.Store(false)
	e.exec(`UPDATE jobs SET run_at = now() WHERE kind = 'feed.sync' AND done_at IS NULL AND failed_at IS NULL`)
	waitFor(t, 60*time.Second, "the feed to recover and its incident to resolve", func() bool {
		return e.str(`SELECT last_error FROM feeds WHERE name = 'osv:Debian'`) == "" &&
			e.int(`SELECT count(*) FROM feeds WHERE name = 'osv:Debian' AND last_success > now() - interval '1 minute'`) == 1 &&
			e.incident("feed", "osv:Debian") == "resolved"
	})
	m := s.scrape()
	if v, _ := metric(m, `stackurity_feed_stale{feed="osv:Debian",kind="vulnerability"}`); v != 0 {
		t.Errorf("feed still stale in metrics:\n%s", grep(m, "osv:Debian"))
	}
	if p := e.problem("feed", "osv:Debian"); p != nil {
		t.Errorf("platform health still reports %+v", p)
	}
	if after := e.findings(host); !maps.Equal(after, before) {
		t.Errorf("findings after recovery: %v, before %v", after, before)
	}
}

// The webhook receiver answers 500 to everything. Deliveries are retried
// and show as retrying, the channel as failing; once they run out of
// attempts they are failed, counted in metrics and in Platform health, and
// nothing is lost: sent again by hand after the provider recovers, each is
// received once.
func TestNotificationProviderOutage(t *testing.T) {
	e, _ := notifyEnv(t)
	e.hook.fail.Store(true)
	s := e.start()
	waitFor(t, 60*time.Second, "a failed send to be retried", func() bool {
		return e.int(`SELECT count(*) FROM deliveries WHERE status = 'pending' AND attempts > 0 AND last_error <> ''`) > 0
	})
	e.logf("provider down: delivery error %q", e.str(`SELECT last_error FROM deliveries WHERE last_error <> '' LIMIT 1`))
	waitFor(t, 30*time.Second, "metrics to show retries and a failing channel", func() bool {
		m := s.scrape()
		retrying, _ := metric(m, `stackurity_notification_deliveries{kind="webhook",state="retrying"}`)
		failing, _ := metric(m, `stackurity_notification_channels_failing{kind="webhook"}`)
		return retrying > 0 && failing == 1
	})
	// A channel is reported once a delivery to it has failed twice, so one
	// passing glitch does not raise a problem.
	waitFor(t, 60*time.Second, "platform health to report the failing channel", func() bool {
		p := e.problem("notification", "delivery")
		return p != nil && p.NextStep != "" && p.Scope.Count == 1
	})

	// Skip the backoff: the next attempt is the last.
	e.exec(`UPDATE deliveries SET attempts = 7, next_attempt = now() WHERE status = 'pending'`)
	waitFor(t, 30*time.Second, "the deliveries to fail", func() bool {
		return e.int(`SELECT count(*) FROM deliveries WHERE status = 'pending'`) == 0 &&
			e.int(`SELECT count(*) FROM deliveries WHERE status = 'failed'`) > 0
	})
	failed := e.int(`SELECT count(*) FROM deliveries WHERE status = 'failed'`)
	m := s.scrape()
	if v, _ := metric(m, `stackurity_notification_deliveries{kind="webhook",state="failed"}`); v != float64(failed) {
		t.Errorf("%d failed deliveries, metrics:\n%s", failed, grep(m, "stackurity_notification"))
	}
	// The summary counts channels whose deliveries were given up: here one.
	if p := e.problem("notification", "delivery"); p == nil || !strings.Contains(p.Scope.Summary, "failed in the last 7 days (1)") {
		t.Errorf("platform health: %+v, want the channel with its %d failed deliveries", p, failed)
	}
	e.logf("%d deliveries failed after 8 attempts; metrics and platform health report them", failed)
	if n := len(e.hook.counts()); n != 0 {
		t.Errorf("the receiver processed %d deliveries while failing", n)
	}

	// The provider recovers; the failed deliveries are sent again by hand.
	e.hook.fail.Store(false)
	rows, err := e.db.Query(context.Background(), `SELECT id FROM deliveries WHERE status = 'failed'`)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if err := e.st.RetryDelivery(ws, id); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, 30*time.Second, "every delivery to be sent", e.allSent)
	waitFor(t, 30*time.Second, "metrics to clear", func() bool {
		m := s.scrape()
		f, _ := metric(m, `stackurity_notification_deliveries{kind="webhook",state="failed"}`)
		c, _ := metric(m, `stackurity_notification_channels_failing{kind="webhook"}`)
		return f == 0 && c == 0
	})
	if p := e.problem("notifications", "failed"); p != nil {
		t.Errorf("platform health still reports %+v", p)
	}
	e.checkDeliveries(nil)
}

// An agent stops reporting for longer than STACKURITY_STALE_AFTER (48
// hours; its last report is moved back instead of waiting). The asset is
// marked stale, counted in metrics, its coverage says the inventory may be
// out of date, and a reporting incident opens ("Server web-1: the
// Stackurity agent hasn't reported since ..."); its findings stay. When the
// agent reports again, all of that clears.
func TestAgentStopsReporting(t *testing.T) {
	e := newEnv(t)
	e.serveIntel([]advisory{{id: "DSA-0001-1", cve: "CVE-2024-0001", pkg: "openssl", fixed: "3.0.15-1~deb12u1", modified: time.Now().Add(-time.Hour)}}, "CVE-2024-0001")
	batch := hostBatch("web-1", debPurl("openssl", "3.0.11-1~deb12u2"))
	host := e.ingest(batch)
	token := e.collectorToken()
	e.exec(`UPDATE assets SET last_seen = now() - interval '3 days' WHERE id = $1`, host)
	s := e.start()
	waitFor(t, 60*time.Second, "the finding, the stale asset and its incident", func() bool {
		v, _ := metric(s.scrape(), "stackurity_assets_stale")
		status, _ := e.reportingIncident(host)
		return v == 1 && len(e.findings(host)) == 1 && status == "open"
	})
	if _, title := e.reportingIncident(host); !strings.HasPrefix(title, "Server web-1: the Stackurity agent hasn't reported since ") {
		t.Errorf("incident title %q", title)
	}
	cov, err := e.st.AssetCoverage(ws, host)
	if err != nil {
		t.Fatal(err)
	}
	if cov.State != store.StateFailedCollection {
		t.Errorf("coverage state %q, want %s", cov.State, store.StateFailedCollection)
	}
	before := e.findings(host)
	e.logf("asset stale: metrics count it, coverage %q, collection incident open, findings kept %v", cov.State, before)

	if _, err := post(context.Background(), s.addr, token, batch); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 30*time.Second, "the asset to be current and its incident to resolve", func() bool {
		v, _ := metric(s.scrape(), "stackurity_assets_stale")
		status, _ := e.reportingIncident(host)
		return v == 0 && status == "resolved"
	})
	if after := e.findings(host); !maps.Equal(after, before) {
		t.Errorf("findings after the agent came back: %v, before %v", after, before)
	}
}
