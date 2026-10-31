package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func TestCadence(t *testing.T) {
	at := func(h ...float64) []time.Time {
		base := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
		var out []time.Time
		for _, x := range h {
			out = append(out, base.Add(-time.Duration(x*float64(time.Hour))))
		}
		return out
	}
	for _, c := range []struct {
		name  string
		times []time.Time
		runs  int
		usual time.Duration
	}{
		{"none", nil, 0, 0},
		{"one report", at(10), 1, 0},
		// The agent's OS and software batches, and a scan's lockfiles,
		// arrive minutes apart: one run.
		{"one run of several batches", at(10, 10.1, 10.5), 1, 0},
		{"daily", at(0, 24, 48, 72.2, 96), 5, 24 * time.Hour},
		{"daily with batches", at(0, 0.1, 24, 24.2, 48, 48.1), 3, 24 * time.Hour},
		// Only the latest 6 runs count: an old weekly habit is forgotten.
		{"latest six runs", at(0, 6, 12, 18, 24, 30, 200, 400), 6, 6 * time.Hour},
		{"unordered", at(48, 0, 24), 3, 24 * time.Hour},
	} {
		runs, usual := store.Cadence(c.times)
		if runs != c.runs || usual.Round(time.Minute) != c.usual.Round(time.Minute) {
			t.Errorf("%s: runs %d usual %s, want %d %s", c.name, runs, usual, c.runs, c.usual)
		}
	}
}

func TestLearned(t *testing.T) {
	h := time.Hour
	for _, c := range []struct {
		runs int
		span time.Duration
		ok   bool
	}{{1, 0, false}, {2, 72 * h, false}, {3, 5 * h, false}, {4, 23 * h, false}, {3, 24 * h, true}, {6, 30 * 24 * h, true}} {
		if got := store.Learned(c.runs, c.span); got != c.ok {
			t.Errorf("Learned(%d, %s) = %v", c.runs, c.span, got)
		}
	}
}

func TestDueAfter(t *testing.T) {
	h := time.Hour
	for _, c := range []struct {
		source, override string
		runs             int
		usual, schedule  time.Duration
		due              time.Duration
		ok               bool
	}{
		{store.SourceAgent, "auto", 1, 0, 0, 48 * h, true},
		{store.SourceScan, "auto", 1, 0, 0, 0, false},         // scanned once: one-off
		{store.SourceManual, "auto", 1, 0, 0, 0, false},       // uploaded once
		{store.SourceScan, "auto", 3, 6 * h, 0, 48 * h, true}, // twice 6 hours is under the minimum
		{store.SourceScan, "auto", 4, 7 * 24 * h, 0, 14 * 24 * h, true},
		{store.SourceManual, "auto", 3, 5 * 24 * h, 0, 10 * 24 * h, true},
		{store.SourceScan, "auto", 2, 5 * h, 0, 0, false}, // two runs: no cadence to learn
		{store.SourceScan, "auto", 3, 0, 0, 0, false},     // three runs on one day: Learned says no
		{store.SourceIntegration, "auto", 9, 0, 6 * h, 48 * h, true},
		{store.SourceIntegration, "auto", 9, 0, 3 * 24 * h, 6 * 24 * h, true},
		{store.SourceScan, "daily", 1, 0, 0, 48 * h, true},
		{store.SourceScan, "weekly", 1, 0, 0, 8 * 24 * h, true},
		{store.SourceAgent, "weekly", 9, 0, 0, 8 * 24 * h, true},
		{store.SourceAgent, "one_off", 9, 0, 0, 0, false},
		{"", "auto", 0, 0, 0, 0, false},
	} {
		due, ok := store.DueAfter(c.source, c.override, c.runs, c.usual, 48*h, c.schedule)
		if ok != c.ok || due != c.due {
			t.Errorf("%+v: %s %v", c, due, ok)
		}
	}
}

// scan uploads a repository scan the way the CLI or a CI job does.
func scanRepo(t *testing.T, s *store.Store, ctx context.Context, name string) int64 {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "lockfile-scanner", Version: "0.13.9", Method: "lockfile"},
		model.AssetRef{Kind: model.AssetRepository, Name: name, Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://git.example/" + name}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Location: "package-lock.json", Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := s.Ingest(store.WithReportSource(ctx, store.ReportSource{Source: store.SourceScan}), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

// backdate moves an asset's reports into the past, hoursAgo for each of its
// collections from the newest, and its last_seen with them.
func backdate(t *testing.T, s *store.Store, ctx context.Context, id int64, hoursAgo ...float64) {
	t.Helper()
	sys := tenant.System(ctx)
	rows, err := s.Pool.Query(sys, `SELECT id FROM collections WHERE asset_id = $1 ORDER BY id DESC`, id)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for rows.Next() {
		var c int64
		_ = rows.Scan(&c)
		ids = append(ids, c)
	}
	rows.Close()
	if len(ids) != len(hoursAgo) {
		t.Fatalf("asset %d has %d collections, %d times given", id, len(ids), len(hoursAgo))
	}
	for i, c := range ids {
		if _, err := s.Pool.Exec(sys, `UPDATE collections SET received_at = now() - make_interval(secs => $2), observed_at = now() - make_interval(secs => $2)
			WHERE id = $1`, c, hoursAgo[i]*3600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Pool.Exec(sys, `UPDATE assets SET last_seen = now() - make_interval(secs => $2) WHERE id = $1`, id, hoursAgo[0]*3600); err != nil {
		t.Fatal(err)
	}
	if err := s.RefreshReporting(ctx, []int64{id}); err != nil {
		t.Fatal(err)
	}
}

func reportingIncidents(t *testing.T, s *store.Store, ctx context.Context) []store.SystemIncident {
	t.Helper()
	if _, err := s.MarkStaleAssets(ctx, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	all, err := s.DetectSystemProblems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.SystemIncident
	for _, c := range all {
		if strings.HasPrefix(c.Key, "reporting:") {
			out = append(out, c)
		}
	}
	return out
}

// The owner's case: five repositories scanned once, five days ago, by a CLI
// scan. Before 0.13.10 each opened "Asset X has stopped reporting". Now they
// are one-off: not stale, no incident, and their old incidents resolve
// without a recovery message.
func TestScannedOnceIsNotStoppedReporting(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	names := []string{"analytics", "commmerceblog", "commmerce_chat", "commmerce_connect", "help-centre"}
	var ids []int64
	for _, n := range names {
		id := scanRepo(t, s, ctx, n)
		backdate(t, s, ctx, id, 5*24)
		ids = append(ids, id)
	}
	// As the old rule left them: stale, each with an announced incident,
	// and not yet worked out (migration 0064 leaves that to the server).
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'stale', report_runs = NULL`); err != nil {
		t.Fatal(err)
	}
	for i, id := range ids {
		if _, err := s.Pool.Exec(ctx, `INSERT INTO incidents (kind, key, title, priority, detail, notified_priority, notified_at)
			VALUES ('collection', $1, $2, 'P3', jsonb_build_object('asset_id', $3::bigint), 'P3', now() - interval '3 days')`,
			"asset:"+itoa64(id), "Asset "+names[i]+" has stopped reporting", id); err != nil {
			t.Fatal(err)
		}
	}

	if got := reportingIncidents(t, s, ctx); len(got) != 0 {
		t.Fatalf("one-off repositories opened incidents: %+v", got)
	}
	sys, err := s.DetectSystemProblems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SyncSystemIncidents(ctx, sys); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE status = 'open' AND kind = 'collection'`).Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 0 {
		t.Errorf("%d collection incidents still open", open)
	}
	rows, err := s.Pool.Query(ctx, `SELECT key, status, resolved_notified, detail->>'resolution' FROM incidents WHERE kind = 'collection'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var key, status string
		var quiet bool
		var why *string
		_ = rows.Scan(&key, &status, &quiet, &why)
		if status != "resolved" || !quiet || why == nil || *why != "one_off" {
			t.Errorf("%s: %s, resolved_notified %v, resolution %v", key, status, quiet, why)
		}
	}
	rows.Close()
	// Not stale, so not scored as stale, and shown "as of" their scan.
	for _, id := range ids {
		a, err := s.GetAsset(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if a.CollectionStatus != "ok" || a.Reporting.Mode != "one_off" || a.Reporting.AsOf == nil || a.Reporting.Source != store.SourceScan {
			t.Errorf("%s: status %s, reporting %+v", a.Name, a.CollectionStatus, a.Reporting)
		}
	}
	groups, err := s.OneOffAssets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Kind != "repository" || groups[0].Count != 5 {
		t.Errorf("one-off groups = %+v", groups)
	}
	o, err := s.Overview(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.OneOff) != 1 || o.OneOff[0].Count != 5 || o.AssetStatus["stale"] != 0 {
		t.Errorf("overview: one-off %+v, status %+v", o.OneOff, o.AssetStatus)
	}
	// Their findings say "as of".
	rows2, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: ids[1]})
	if err != nil || len(rows2) != 1 {
		t.Fatalf("inventory: %d, %v", len(rows2), err)
	}
	in := []store.FindingInput{{Kind: "vulnerability", Key: "CVE-2021-23337", InventoryID: rows2[0].ID, AssetID: ids[1], ComponentID: rows2[0].ComponentID,
		Verification: "confirmed", Severity: "high", FixedVersion: "4.17.21", Title: "lodash", Sources: []string{"GHSA-35jh-r3h4-6jhm"}}}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, []int64{rows2[0].ID}, in); err != nil {
		t.Fatal(err)
	}
	fs, _, err := s.ListFindings(ctx, store.FindingFilter{Status: "all"})
	if err != nil || len(fs) != 1 {
		t.Fatalf("findings: %d, %v", len(fs), err)
	}
	if fs[0].AsOf == nil || fs[0].AsOf.Sub(time.Now().Add(-5*24*time.Hour)).Abs() > time.Minute {
		t.Errorf("finding as_of = %v", fs[0].AsOf)
	}

	// A second scan is not yet a cadence; a third, days after the first,
	// makes it a scheduled repository. A person can set one back to
	// one-off.
	scanRepo(t, s, ctx, "analytics")
	a, _ := s.GetAsset(ctx, ids[0])
	if a.Reporting.Mode != "one_off" || a.Reporting.Runs != 2 {
		t.Errorf("after a second scan: %+v", a.Reporting)
	}
	scanRepo(t, s, ctx, "analytics")
	backdate(t, s, ctx, ids[0], 0, 2*24, 5*24)
	a, _ = s.GetAsset(ctx, ids[0])
	if a.Reporting.Mode != "scheduled" || a.Reporting.Runs != 3 || a.Reporting.UsualSeconds == nil || a.Reporting.DueAfterSeconds == nil {
		t.Errorf("after a third scan: %+v", a.Reporting)
	}
	if err := s.SetReportOverride(ctx, ids[0], store.ReportOneOff); err != nil {
		t.Fatal(err)
	}
	a, _ = s.GetAsset(ctx, ids[0])
	if a.Reporting.Mode != "one_off" || a.Reporting.DueAfterSeconds != nil {
		t.Errorf("set to one-off: %+v", a.Reporting)
	}
	if err := s.SetReportOverride(ctx, ids[0], "hourly"); err == nil {
		t.Error("an unknown override was accepted")
	}
}

// Servers are grouped by the day they went quiet, with the applications
// read on them; scans past their usual cadence are grouped apart, P4 and
// for the digest unless production with a set cadence.
func TestReportingIncidentsGrouped(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	web := appHost(t, s, ctx, "web-1", []string{"/var/www/shop"})
	appReport(t, s, ctx, web, "web-1", "shop", "/var/www/shop", []model.CoverageItem{{Scope: "app:/var/www/shop", Status: "checked"}},
		pkg{"pkg:npm/lodash@4.17.15", "/var/www/shop/package-lock.json"})
	db := appHost(t, s, ctx, "db-1", nil)
	fine := appHost(t, s, ctx, "fine-1", nil)
	_ = fine
	var app int64
	if err := s.Pool.QueryRow(ctx, `SELECT id FROM assets WHERE kind = 'application'`).Scan(&app); err != nil {
		t.Fatal(err)
	}
	// The agent's batches of one run, 3 days ago.
	if _, err := s.Pool.Exec(ctx, `UPDATE collections SET received_at = now() - interval '3 days' WHERE asset_id = ANY($1)`, []int64{web, app, db}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET last_seen = (date_trunc('day', now() AT TIME ZONE 'UTC') - interval '3 days' + interval '9 hours') AT TIME ZONE 'UTC',
		environment = 'production' WHERE id = ANY($1)`, []int64{web, app, db}); err != nil {
		t.Fatal(err)
	}

	daily := scanRepo(t, s, ctx, "shop")
	for i := 0; i < 4; i++ {
		scanRepo(t, s, ctx, "shop")
	}
	backdate(t, s, ctx, daily, 72, 96, 120, 144, 168)
	once := scanRepo(t, s, ctx, "notes")
	backdate(t, s, ctx, once, 300)

	got := reportingIncidents(t, s, ctx)
	if len(got) != 2 {
		t.Fatalf("incidents = %+v", got)
	}
	var servers, scans store.SystemIncident
	for _, c := range got {
		if strings.HasPrefix(c.Key, "reporting:agent:host:") {
			servers = c
		}
		if strings.HasPrefix(c.Key, "reporting:scan:repository:") {
			scans = c
		}
	}
	day := time.Now().UTC().AddDate(0, 0, -3)
	if !strings.HasSuffix(servers.Key, day.Format("2006-01-02")) || servers.Priority != "P3" || servers.Detail["digest_only"] != nil {
		t.Errorf("servers: %+v", servers)
	}
	wantTitle := "2 servers and their 1 application: the Stackurity agent hasn't reported since " + store.ReportDate(day, time.Now())
	if servers.Title != wantTitle {
		t.Errorf("servers title %q, want %q", servers.Title, wantTitle)
	}
	if len(servers.Members) != 3 {
		t.Errorf("servers members %v", servers.Members)
	}
	if strings.Contains(strings.ToLower(servers.Title), "asset") || strings.Contains(strings.ToLower(scans.Title), "asset") {
		t.Errorf("titles name assets: %q, %q", servers.Title, scans.Title)
	}
	if scans.Priority != "P4" || scans.Detail["digest_only"] != true ||
		scans.Title != "Repository shop hasn't been scanned since "+store.ReportDate(time.Now().Add(-72*time.Hour), time.Now())+" (usually every day)" {
		t.Errorf("scans: %+v", scans)
	}

	// One server alone is named, with the time.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET last_seen = now() WHERE id = $1`, db); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'ok' WHERE id = $1`, db); err != nil {
		t.Fatal(err)
	}
	for _, c := range reportingIncidents(t, s, ctx) {
		if strings.HasPrefix(c.Key, "reporting:agent:") && !strings.HasPrefix(c.Title, "Server web-1 and its 1 application: the Stackurity agent hasn't reported since ") ||
			strings.HasPrefix(c.Key, "reporting:agent:") && !strings.HasSuffix(c.Title, " UTC") {
			t.Errorf("one server: %q", c.Title)
		}
	}

	// Production with a set cadence makes a quiet repository urgent; a
	// learned cadence alone never does.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET environment = 'production' WHERE id = $1`, daily); err != nil {
		t.Fatal(err)
	}
	for _, c := range reportingIncidents(t, s, ctx) {
		if strings.HasPrefix(c.Key, "reporting:scan:") && (c.Priority != "P4" || c.Detail["digest_only"] != true) {
			t.Errorf("learned cadence, production: %+v", c)
		}
	}
	if err := s.SetReportOverride(ctx, daily, store.ReportDaily); err != nil {
		t.Fatal(err)
	}
	for _, c := range reportingIncidents(t, s, ctx) {
		if strings.HasPrefix(c.Key, "reporting:scan:") && (c.Priority != "P3" || c.Detail["digest_only"] != nil || !strings.HasSuffix(c.Title, "(expected daily)")) {
			t.Errorf("daily, production: %+v", c)
		}
	}
	// A weekly override is overdue after 8 days, not 3.
	if err := s.SetReportOverride(ctx, daily, store.ReportWeekly); err != nil {
		t.Fatal(err)
	}
	for _, c := range reportingIncidents(t, s, ctx) {
		if strings.HasPrefix(c.Key, "reporting:scan:") {
			t.Errorf("weekly, 3 days quiet: %+v", c)
		}
	}
}

// Assets an integration reports never open a reporting incident: a failing
// integration has its own.
func TestIntegrationAssetsHaveNoReportingIncident(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	var integ int64
	if err := s.Pool.QueryRow(ctx, `INSERT INTO integrations (kind, name, schedule) VALUES ('plugin', 'k8s', '1 hour') RETURNING id`).Scan(&integ); err != nil {
		t.Fatal(err)
	}
	b := model.NewBatch(model.Collector{ID: "plugin:kubernetes", Version: "1", Method: "plugin"},
		model.AssetRef{Kind: model.AssetWorkload, Name: "shop", Identifiers: []model.Identifier{{Scheme: "k8s-workload", Value: "prod/shop"}}})
	b.Complete = true
	r, err := s.Ingest(store.WithReportSource(ctx, store.ReportSource{Source: store.SourceIntegration, IntegrationID: integ}), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	backdate(t, s, ctx, r.AssetID, 72)
	if got := reportingIncidents(t, s, ctx); len(got) != 0 {
		t.Errorf("integration asset opened %+v", got)
	}
	a, _ := s.GetAsset(ctx, r.AssetID)
	if a.CollectionStatus != "stale" || a.Reporting.Mode != "integration" {
		t.Errorf("integration asset: %s %+v", a.CollectionStatus, a.Reporting)
	}
	var linked *int64
	_ = s.Pool.QueryRow(ctx, `SELECT report_integration_id FROM assets WHERE id = $1`, r.AssetID).Scan(&linked)
	if linked == nil || *linked != integ {
		t.Errorf("integration link = %v", linked)
	}
}

// A server back for less than a day that goes quiet again reopens its last
// incident (already announced, so nobody is told again) instead of opening
// a new one for the new day.
func TestReportingFlapReopens(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	host := appHost(t, s, ctx, "flaky-1", nil)
	quiet := func(lastSeen string) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, `UPDATE assets SET last_seen = now() - $2::interval WHERE id = $1`, host, lastSeen); err != nil {
			t.Fatal(err)
		}
	}
	sync := func() []store.SystemIncident {
		t.Helper()
		got := reportingIncidents(t, s, ctx)
		all, err := s.DetectSystemProblems(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.SyncSystemIncidents(ctx, all); err != nil {
			t.Fatal(err)
		}
		return got
	}
	openIDs := func() []int64 {
		t.Helper()
		rows, _ := s.Pool.Query(ctx, `SELECT id FROM incidents WHERE kind = 'collection' AND status = 'open' ORDER BY id`)
		defer rows.Close()
		var out []int64
		for rows.Next() {
			var id int64
			_ = rows.Scan(&id)
			out = append(out, id)
		}
		return out
	}

	quiet("3 days")
	sync()
	first := openIDs()
	if len(first) != 1 {
		t.Fatalf("open = %v", first)
	}
	// Announced; then the agent reports again and the incident resolves.
	if err := s.MarkIncidentsNotified(ctx, first); err != nil {
		t.Fatal(err)
	}
	appHost(t, s, ctx, "flaky-1", nil)
	sync()
	if len(openIDs()) != 0 {
		t.Fatal("recovered server still has an open incident")
	}
	// It reported for a few hours, then stopped: 49 hours ago, an hour
	// after the incident closed.
	if _, err := s.Pool.Exec(ctx, `UPDATE incidents SET resolved_at = now() - interval '50 hours' WHERE id = $1`, first[0]); err != nil {
		t.Fatal(err)
	}
	quiet("49 hours")
	sync()
	if got := openIDs(); len(got) != 1 || got[0] != first[0] {
		t.Fatalf("flap: open %v, want the first incident %d reopened", got, first[0])
	}
	// It stays the server's incident on the next cycles, though the server
	// went quiet on another day than the one its key names.
	sync()
	sync()
	if got := openIDs(); len(got) != 1 || got[0] != first[0] {
		t.Fatalf("after the flap, open %v, want %d alone", got, first[0])
	}
	announce, err := s.IncidentsToAnnounce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range announce {
		if in.ID == first[0] {
			t.Error("the reopened incident is announced again")
		}
	}

	// Back for longer than a day before going quiet: a new incident.
	appHost(t, s, ctx, "flaky-1", nil)
	sync()
	if _, err := s.Pool.Exec(ctx, `UPDATE incidents SET resolved_at = now() - interval '5 days' WHERE id = $1`, first[0]); err != nil {
		t.Fatal(err)
	}
	quiet("3 days")
	sync()
	if got := openIDs(); len(got) != 1 || got[0] == first[0] {
		t.Errorf("after a long recovery: open %v, want a new incident", got)
	}
}

// Detail round-trips through JSON as the notifier reads it.
func TestReportingDetailJSON(t *testing.T) {
	a := []store.ReportingAsset{{ID: 1, Name: "web-1", Kind: "host", LastSeen: time.Date(2026, 10, 29, 14, 5, 0, 0, time.UTC), Applications: []string{"shop"}}}
	raw, _ := json.Marshal(map[string]any{"assets": a})
	if !strings.Contains(string(raw), `"applications":["shop"]`) {
		t.Errorf("detail = %s", raw)
	}
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	if got := store.ReportingTitle("agent", "host", a, a[0].LastSeen, 0, now); got != "Server web-1: the Stackurity agent hasn't reported since 29 Oct 14:05 UTC" {
		t.Errorf("title = %q", got)
	}
	five := make([]store.ReportingAsset, 5)
	if got := store.ReportingTitle("scan", "repository", five, time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC), 0, now); got != "5 repositories haven't been scanned since 26 Oct" {
		t.Errorf("title = %q", got)
	}
	if got := store.ReportingTitle("upload", "sbom", a[:1], time.Date(2025, 10, 26, 10, 0, 0, 0, time.UTC), 0, now); got != "SBOM web-1 hasn't been uploaded since 26 Oct 2025" {
		t.Errorf("title = %q", got)
	}
}

// The owner's real case, from production: of five repositories scanned by
// hand on 26 Oct, two were scanned again that day (commmerce_connect four
// times, lighthouse twice). Re-runs on one day are not a cadence: all five
// are one-off, with no incident, and Home counts five scanned once.
func TestSameDayRescansAreOneOff(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	day := func(hm ...string) []time.Time {
		var out []time.Time
		for _, x := range hm {
			tm, err := time.Parse("2006-01-02 15:04", "2026-10-26 "+x)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, tm)
		}
		return out
	}
	timelines := map[string][]time.Time{
		"commmerce_connect": day("09:42", "09:30", "09:15", "04:34"),
		"lighthouse":        day("09:01", "04:34"),
		"analytics":         day("04:34"),
		"commmerceblog":     day("04:35"),
		"commmerce_chat":    day("04:36"),
	}
	sys := tenant.System(ctx)
	for name, times := range timelines {
		var id int64
		for range times {
			id = scanRepo(t, s, ctx, name)
		}
		rows, _ := s.Pool.Query(sys, `SELECT id FROM collections WHERE asset_id = $1 ORDER BY id DESC`, id)
		var cids []int64
		for rows.Next() {
			var c int64
			_ = rows.Scan(&c)
			cids = append(cids, c)
		}
		rows.Close()
		for i, c := range cids {
			if _, err := s.Pool.Exec(sys, `UPDATE collections SET received_at = $2 WHERE id = $1`, c, times[i]); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.Pool.Exec(sys, `UPDATE assets SET last_seen = $2 WHERE id = $1`, id, times[0]); err != nil {
			t.Fatal(err)
		}
		if err := s.RefreshReporting(ctx, []int64{id}); err != nil {
			t.Fatal(err)
		}
		a, _ := s.GetAsset(ctx, id)
		if a.Reporting.Mode != "one_off" || a.Reporting.DueAfterSeconds != nil || a.Reporting.UsualSeconds != nil {
			t.Errorf("%s (%d reports): %+v", name, len(times), a.Reporting)
		}
	}
	if got := reportingIncidents(t, s, ctx); len(got) != 0 {
		t.Errorf("incidents: %+v", got)
	}
	groups, err := s.OneOffAssets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || groups[0].Kind != "repository" || groups[0].Count != 5 ||
		store.AsOf(groups[0].Oldest, groups[0].Newest, time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)) != "26 Oct" {
		t.Errorf("one-off = %+v", groups)
	}
}

// A server the agent reports cannot be set to one-off: it would never say
// if the agent stopped.
func TestAgentCannotBeOneOff(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	host := appHost(t, s, ctx, "web-1", nil)
	one := store.ReportOneOff
	if err := s.UpdateAsset(ctx, host, store.AssetUpdate{ReportOverride: &one}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("update: %v", err)
	}
	if err := s.SetReportOverride(ctx, host, store.ReportOneOff); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("set: %v", err)
	}
	weekly := store.ReportWeekly
	if err := s.UpdateAsset(ctx, host, store.AssetUpdate{ReportOverride: &weekly}); err != nil {
		t.Errorf("weekly: %v", err)
	}
}

func itoa64(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
