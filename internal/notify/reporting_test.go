package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// reportHost ingests a server as the Linux agent does and backdates it, so
// it went quiet daysAgo days ago.
func (f *fixture) reportHost(ctx context.Context, name, env string, daysAgo int) int64 {
	f.t.Helper()
	b := model.NewBatch(model.Collector{ID: "linux-agent", Version: "0.13.9", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Environment: env, Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Location: "/var/lib/dpkg/status"}}
	b.Complete = true
	r, err := f.st.Ingest(ctx, b, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.backdate(ctx, r.AssetID, daysAgo)
	return r.AssetID
}

// scanOnce uploads a repository scan as the CLI does, daysAgo days ago.
func (f *fixture) scanOnce(ctx context.Context, name string, daysAgo int) int64 {
	f.t.Helper()
	b := model.NewBatch(model.Collector{ID: "lockfile-scanner", Version: "0.13.9", Method: "lockfile"},
		model.AssetRef{Kind: model.AssetRepository, Name: name, Identifiers: []model.Identifier{{Scheme: "git-url", Value: "https://git.example/" + name}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Location: "package-lock.json"}}
	b.Complete = true
	r, err := f.st.Ingest(store.WithReportSource(ctx, store.ReportSource{Source: store.SourceScan}), b, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	f.backdate(ctx, r.AssetID, daysAgo)
	return r.AssetID
}

func (f *fixture) backdate(ctx context.Context, id int64, daysAgo int) {
	f.t.Helper()
	sys := tenant.System(ctx)
	if _, err := f.st.Pool.Exec(sys, `UPDATE collections SET received_at = now() - make_interval(days => $2) WHERE asset_id = $1`, id, daysAgo); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(sys, `UPDATE assets SET last_seen = now() - make_interval(days => $2) WHERE id = $1`, id, daysAgo); err != nil {
		f.t.Fatal(err)
	}
}

// legacyIncident is an "Asset X has stopped reporting" incident as 0.13.9
// left it: open, announced, and (with jira) with a Jira issue.
func (f *fixture) legacyIncident(ctx context.Context, asset int64, name string) int64 {
	f.t.Helper()
	var id int64
	if err := f.st.Pool.QueryRow(ctx, `INSERT INTO incidents (kind, key, title, priority, detail, notified_priority, notified_at)
		VALUES ('collection', $1, $2, 'P3', jsonb_build_object('asset_id', $3::bigint), 'P3', now() - interval '2 days') RETURNING id`,
		fmt.Sprintf("asset:%d", asset), "Asset "+name+" has stopped reporting", asset).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

// The owner's case: five repositories scanned once on 26 Oct by a CLI scan,
// each with an open "Asset X has stopped reporting" incident from 0.13.9.
// After the upgrade nothing is announced, the incidents resolve quietly,
// and nothing opens again.
func TestReportingOwnerCaseIsQuiet(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	// The route the owner had: everything from P4 up, right away.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE routes SET min_priority = 'P4'`); err != nil {
		t.Fatal(err)
	}
	var legacy []int64
	for _, n := range []string{"analytics", "commmerceblog", "commmerce_chat", "commmerce_connect", "help-centre"} {
		id := f.scanOnce(ctx, n, 5)
		legacy = append(legacy, f.legacyIncident(ctx, id, n))
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'stale', report_runs = NULL`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := f.st.MarkStaleAssets(ctx, 48*time.Hour); err != nil {
			t.Fatal(err)
		}
		f.tick()
	}
	for _, m := range f.hook.got {
		if strings.Contains(m.Title, "reporting") || strings.Contains(m.Title, "scanned") || strings.Contains(m.Title, "needs attention") ||
			m.Event == "resolved" {
			t.Errorf("people were told: %s %q %+v", m.Event, m.Title, m.Sections)
		}
	}
	incs, _, err := f.st.ListIncidents(ctx, store.IncidentFilter{Status: "all", Kind: "collection"})
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != len(legacy) {
		t.Fatalf("incidents = %+v", incs)
	}
	for _, in := range incs {
		var d struct{ Resolution string }
		_ = json.Unmarshal(in.Detail, &d)
		if in.Status != "resolved" || d.Resolution != "one_off" {
			t.Errorf("%s: %s %s", in.Title, in.Status, in.Detail)
		}
	}
}

// Servers people were told about one by one before 0.13.10 are regrouped:
// the old Jira issues close saying "Replaced by #N", the grouped incident
// gets its own issue, and Slack and email hear nothing new.
func TestReportingRegroupOnUpgrade(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE routes SET min_priority = 'P4'`); err != nil {
		t.Fatal(err)
	}
	fj, srv := newFakeJira(t, true)
	ch := f.addJira(ctx, srv.URL, true, nil)

	web := f.reportHost(ctx, "web-1", "production", 3)
	db := f.reportHost(ctx, "db-1", "production", 3)
	var old []int64
	for i, a := range []struct {
		id   int64
		name string
	}{{web, "web-1"}, {db, "db-1"}} {
		in := f.legacyIncident(ctx, a.id, a.name)
		old = append(old, in)
		key := fmt.Sprintf("SEC-%d", i+1)
		fj.issues = append(fj.issues, &fakeIssue{Key: key, Summary: "[P3] Asset " + a.name + " has stopped reporting",
			Labels: []string{"security", "stackurity", IncidentLabel(tenant.DefaultWorkspace, in)}, Status: "To Do"})
		if err := f.st.RecordIssue(ctx, ch.ID, in, key, srv.URL+"/browse/"+key, "P3", 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'stale', report_runs = NULL`); err != nil {
		t.Fatal(err)
	}
	before := len(f.hook.got)
	for i := 0; i < 3; i++ {
		f.tick()
	}

	open, _, err := f.st.ListIncidents(ctx, store.IncidentFilter{Kind: "collection"})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 1 || !strings.HasPrefix(open[0].Key, "reporting:agent:host:") ||
		!strings.HasPrefix(open[0].Title, "2 servers: the Stackurity agent hasn't reported since ") || open[0].Priority != "P3" {
		t.Fatalf("open = %+v", open)
	}
	grouped := open[0]

	// No Slack or email message: both servers were announced before.
	for _, m := range f.hook.got[before:] {
		t.Errorf("people were told again: %s %q", m.Event, m.Title)
	}

	issues := fj.snapshot()
	if len(issues) != 3 {
		t.Fatalf("issues = %+v", issues)
	}
	for _, is := range issues[:2] {
		if is.Status != "Done" || len(is.Comments) != 1 || !strings.Contains(commentText(is.Comments[0]), fmt.Sprintf("Replaced by #%d", grouped.ID)) {
			t.Errorf("old issue %s: %s %s", is.Key, is.Status, is.Comments)
		}
	}
	is := issues[2]
	if is.Status != "To Do" || !strings.Contains(is.Summary, "2 servers: the Stackurity agent hasn't reported since") ||
		!strings.Contains(strings.Join(is.Labels, ","), IncidentLabel(tenant.DefaultWorkspace, grouped.ID)) {
		t.Errorf("grouped issue: %+v", is)
	}
	desc := string(is.Description)
	for _, want := range []string{"Your services may be fine", "At risk: findings for these servers are not refreshed",
		"Likely causes: the servers are off or were rebuilt", "systemctl status stackurity-agent", "web-1: last report", "db-1: last report",
		"https://stk.example/help/asset-reporting#servers"} {
		if !strings.Contains(desc, want) {
			t.Errorf("grouped issue lacks %q: %s", want, desc)
		}
	}
	for _, id := range old {
		in, err := f.st.GetIncident(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if in.Status != "resolved" {
			t.Errorf("old incident %d: %s", id, in.Status)
		}
	}

	// A server that goes quiet later is told, in its own incident.
	f.reportHost(ctx, "api-1", "production", 0)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assets SET last_seen = now() - interval '50 hours' WHERE name = 'api-1'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.MarkStaleAssets(ctx, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	f.tick()
	told := false
	for _, m := range f.hook.got[before:] {
		for _, s := range m.Sections {
			for _, it := range s.Items {
				if strings.HasPrefix(it.Text, "Server api-1: the Stackurity agent hasn't reported since ") {
					told = told || s.Title == "Not reporting to Stackurity (your services may be fine)"
				}
			}
		}
	}
	if !told {
		t.Errorf("api-1 not announced: %+v", f.hook.got[before:])
	}
}

// A repository past its usual scan is P4 and waits for the summary: no
// urgent message, no tracker issue.
func TestReportingScansAreDigestOnly(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE routes SET min_priority = 'P4'`); err != nil {
		t.Fatal(err)
	}
	fj, srv := newFakeJira(t, true)
	f.addJira(ctx, srv.URL, true, nil)
	id := f.scanOnce(ctx, "shop", 0)
	for i := 0; i < 3; i++ {
		f.scanOnce(ctx, "shop", 0)
	}
	sys := tenant.System(ctx)
	if _, err := f.st.Pool.Exec(sys, `UPDATE collections c SET received_at = now() - make_interval(days => 3 + n.rn::int)
		FROM (SELECT id, row_number() OVER (ORDER BY id DESC) - 1 AS rn FROM collections WHERE asset_id = $1) n WHERE n.id = c.id`, id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(sys, `UPDATE assets SET last_seen = now() - interval '3 days' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RefreshReporting(ctx, []int64{id}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.MarkStaleAssets(ctx, 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	before := len(f.hook.got)
	f.tick()
	f.tick()
	open, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{Kind: "collection"})
	if len(open) != 1 || open[0].Priority != "P4" || !strings.Contains(open[0].Title, "Repository shop hasn't been scanned since") ||
		!strings.Contains(open[0].Title, "(usually every day)") {
		t.Fatalf("open = %+v", open)
	}
	for _, m := range f.hook.got[before:] {
		if m.Event == EventUrgent {
			t.Errorf("urgent message for a quiet repository: %q", m.Title)
		}
	}
	if len(fj.snapshot()) != 0 {
		t.Errorf("tracker issue for a quiet repository: %+v", fj.snapshot())
	}
	// The message, as a summary or an incident page would build it.
	m := f.d.message(open[0], "opened")
	body := strings.Join(m.Summary, "\n") + "\n" + m.Action
	for _, want := range []string{"Your services may be fine", "At risk: findings for this repository are not refreshed",
		"Likely cause: the CI job or scheduled scan", "Settings → Integrations → CI pipeline", "shop: last report", "usually every day",
		"/help/asset-reporting#scans"} {
		if !strings.Contains(body, want) {
			t.Errorf("message lacks %q:\n%s", want, body)
		}
	}
}

// Summaries list reporting problems apart, and the weekly one nudges about
// assets scanned once.
func TestReportingSummarySections(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example", Now: func() time.Time { return time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC) }}
	rep, _ := json.Marshal(map[string]any{"cause": "agent", "asset_kind": "host", "asset_ids": []int64{1}})
	feed, _ := json.Marshal(map[string]any{"last_error": "timeout"})
	list := []store.Incident{
		{ID: 1, Kind: "collection", Key: "reporting:agent:host:2026-10-29", Title: "Server web-1: the Stackurity agent hasn't reported since 29 Oct 14:05 UTC", Detail: rep},
		{ID: 2, Kind: "feed", Key: "osv:npm", Title: "Intelligence feed osv:npm is stale", Detail: feed},
	}
	secs := d.systemSections(list)
	if len(secs) != 2 || secs[0].Title != "Stackurity needs attention" || secs[1].Title != "Not reporting to Stackurity (your services may be fine)" {
		t.Errorf("sections = %+v", secs)
	}
	if got := systemTitle(list[:1]); got != list[0].Title {
		t.Errorf("one reporting problem: %q", got)
	}
	if got := systemTitle(list); got != "Stackurity needs attention: 2 problems" {
		t.Errorf("mixed: %q", got)
	}
	data := &summaryData{oneOffRead: true, oneOff: []store.OneOffGroup{{Kind: "repository", Count: 5,
		Oldest: time.Date(2026, 10, 26, 10, 0, 0, 0, time.UTC), Newest: time.Date(2026, 10, 26, 10, 4, 0, 0, time.UTC)}}}
	it, ok := d.oneOffItem(data)
	if !ok || it.Text != "5 repositories scanned once, results as of 26 Oct. Set up a scheduled scan to keep them current." ||
		it.Link != "https://stk.example/help/asset-reporting#one-off" {
		t.Errorf("one-off nudge = %+v", it)
	}
}

// A production server goes quiet, recovers, and goes quiet again the same
// day. Slack and email are told once, but the trackers treat the second
// time as new: PagerDuty pages under the next dedup key, Jira and
// ServiceNow get a new record naming the previous one. When it recovers
// again, each is resolved again.
func TestReportingFlapReopensTrackers(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE routes SET min_priority = 'P4'`); err != nil {
		t.Fatal(err)
	}
	fp, pdSrv := newFakePagerDuty(t)
	f.d.Sender.PagerDutyURL = pdSrv.URL + "/v2/enqueue"
	pd := f.addTracker(ctx, KindPagerDuty, ChannelConfig{}, fp.key)
	fj, jSrv := newFakeJira(t, true)
	jira := f.addJira(ctx, jSrv.URL, true, nil)
	fs, snSrv := newFakeServiceNow(t)
	sn := f.addTracker(ctx, KindServiceNow, snConfig(snSrv.URL), fs.password)
	ticks := func() {
		t.Helper()
		if _, err := f.st.MarkStaleAssets(ctx, 48*time.Hour); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			f.tick()
		}
	}

	f.reportHost(ctx, "web-1", "production", 3)
	ticks()
	inc := f.onlyIncident(ctx)
	base := IncidentLabel(tenant.DefaultWorkspace, inc.ID)
	if inc.Priority != "P3" || fp.state(base) != "triggered" || len(fj.snapshot()) != 1 || len(fs.all()) != 1 {
		t.Fatalf("down: %+v, pagerduty %q, jira %d, servicenow %d", inc, fp.state(base), len(fj.snapshot()), len(fs.all()))
	}
	people := len(f.hook.got)
	if people == 0 {
		t.Fatal("people were not told the server went down")
	}

	// Back: everything resolves.
	f.reportHost(ctx, "web-1", "production", 0)
	ticks()
	if fp.state(base) != "resolved" || fj.snapshot()[0].Status != "Done" || fs.all()[0].fields["state"] == "1" {
		t.Fatalf("recovered: pagerduty %q, jira %+v, servicenow %+v", fp.state(base), fj.snapshot()[0], fs.all()[0].fields)
	}

	// Down again an hour after it closed.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE incidents SET resolved_at = now() - interval '50 hours' WHERE id = $1`, inc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assets SET last_seen = now() - interval '49 hours' WHERE name = 'web-1'`); err != nil {
		t.Fatal(err)
	}
	ticks()
	again := f.onlyIncident(ctx)
	if again.ID != inc.ID || again.Status != "open" {
		t.Fatalf("flap: %+v, want #%d reopened", again, inc.ID)
	}
	for _, m := range f.hook.got[people:] {
		t.Errorf("people told again on the flap: %s %q", m.Event, m.Title)
	}
	if fp.state(base+"-2") != "triggered" || fp.state(base) != "resolved" {
		t.Errorf("pagerduty after the flap: %q %q, events %+v", fp.state(base), fp.state(base+"-2"), fp.actions(base+"-2"))
	}
	issues := fj.snapshot()
	if len(issues) != 2 || issues[1].Status != "To Do" || !strings.Contains(strings.Join(issues[1].Labels, ","), base+"-2") ||
		!strings.Contains(string(issues[1].Description), "the previous record was SEC-1") {
		t.Errorf("jira after the flap: %+v", issues)
	}
	recs := fs.all()
	if len(recs) != 2 || recs[1].fields["correlation_id"] != base+"-2" ||
		!strings.Contains(recs[1].fields["description"], "the previous record was "+recs[0].fields["number"]) {
		t.Errorf("servicenow after the flap: %+v", recs)
	}
	inc2, _ := f.st.GetIncident(ctx, inc.ID)
	if len(inc2.Issues) != 3 {
		t.Errorf("issues = %+v", inc2.Issues)
	}

	// Back again: the new records resolve too.
	f.reportHost(ctx, "web-1", "production", 0)
	ticks()
	if fp.state(base+"-2") != "resolved" {
		t.Errorf("pagerduty second resolve: %v", fp.actions(base+"-2"))
	}
	if is := fj.snapshot(); is[1].Status != "Done" {
		t.Errorf("jira second resolve: %+v", is[1])
	}
	if r := fs.all()[1].fields; r["state"] == fs.all()[0].fields["state"] && r["state"] == "1" || r["close_notes"] == "" {
		t.Errorf("servicenow second resolve: %+v", r)
	}
	for _, ch := range []int64{pd.ID, jira.ID, sn.ID} {
		f.allSent(ctx, ch)
	}
}
