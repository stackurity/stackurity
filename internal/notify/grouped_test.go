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

// findingsOn replaces the vulnerability findings of the fixture's assets:
// each asset gets the listed CVEs on its lodash, known exploited.
func (f *fixture) findingsOn(perAsset map[string][]string) {
	f.t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var want []store.FindingInput
	var all []int64
	for name, inv := range f.inv {
		all = append(all, inv)
		rows, _, _ := f.st.ListInventory(ctx, store.InventoryFilter{AssetID: f.asset[name]})
		for _, key := range perAsset[name] {
			score := float32(7.2)
			want = append(want, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: inv, AssetID: f.asset[name],
				ComponentID: rows[0].ComponentID, Verification: "confirmed", Severity: "high", Score: &score,
				Title: "Command injection in lodash", FixedVersion: "4.17.21", Sources: []string{"GHSA-35jh"},
				Evidence: map[string]any{"known_exploited": true}})
		}
	}
	if _, _, err := f.st.SyncFindings(ctx, []string{"vulnerability"}, all, want); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.st.Pool.QueryRow(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), q, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// An asset's first scan raises no urgent alert for its backlog: one
// "connected" message describes it once its first complete collection has
// been evaluated. Issues found after that are urgent as usual.
func TestFirstScanIsQuiet(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addNewAsset("web-1", "production", true)
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337", "CVE-2020-8203"}})

	// Not evaluated yet: nothing is said, and the incidents wait.
	f.tick()
	if ev := f.hook.events(); len(ev) != 0 {
		t.Fatalf("messages before the first scan finished: %v", ev)
	}
	if n := f.count(`SELECT count(*) FROM incidents WHERE notified_at IS NULL`); n != 2 {
		t.Fatalf("%d incidents waiting, want 2", n)
	}

	// Evaluated (the job ingest queued has run): one "connected" message,
	// no urgent alert.
	if err := f.st.MarkEvaluated(ctx, f.asset["web-1"], time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE dedupe_key = $1`, fmt.Sprintf("evaluate:asset:%d", f.asset["web-1"])); err != nil {
		t.Fatal(err)
	}
	f.tick()
	f.tick()
	ev := f.hook.events()
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "connected") {
		t.Fatalf("want one connected message: %v", ev)
	}
	m := f.hook.got[0]
	if m.Title != "web-1 connected: 1 package checked, 2 issues found, 1 fix needs you" || m.SOS ||
		len(m.Sections) != 1 || len(m.Sections[0].Items) != 1 {
		t.Fatalf("connected = %+v", m)
	}
	it := m.Sections[0].Items[0]
	if it.Link != fmt.Sprintf("https://stk.example/assets/%d", f.asset["web-1"]) || len(it.Items) != 1 ||
		!strings.HasPrefix(it.Items[0].Text, "Upgrade lodash") || !strings.HasSuffix(it.Items[0].Text, "(clears 2 issues)") {
		t.Errorf("connected item = %+v", it)
	}
	if n := f.count(`SELECT count(*) FROM incidents WHERE notified_at IS NULL`); n != 0 {
		t.Errorf("%d first-scan incidents still to announce", n)
	}

	// A new issue after the first scan is urgent.
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337", "CVE-2020-8203", "CVE-2026-0001"}})
	f.tick()
	ev = f.hook.events()
	if len(ev) != 2 || ev[1] != "urgent:P1" || f.hook.got[1].Title != "web-1: 1 new urgent issue" {
		t.Fatalf("after the first scan: %v %+v", ev, f.hook.got[len(f.hook.got)-1])
	}

	// A collector that never sends a complete batch does not silence the
	// asset for ever: after six hours it is announced anyway.
	f.addNewAsset("ci-1", "staging", false)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assets SET created_at = now() - interval '7 hours' WHERE id = $1`, f.asset["ci-1"]); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if ev := f.hook.events(); len(ev) != 3 || !strings.HasPrefix(ev[2], "connected") || f.hook.got[2].Title != "ci-1 connected: 1 package checked, nothing needs fixing" {
		t.Errorf("stale first scan: %v %+v", ev, f.hook.got[len(f.hook.got)-1])
	}
}

// A daily summary says what is new, what was fixed and by what, and the
// top fixes still open, at the route's time; a summary-only route sends no
// urgent alerts; nothing changed, no summary.
func TestSummaryContents(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	r.Mode, r.SummaryTime = store.ModeDaily, "09:00"
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.addAsset("web-1", "production", true)
	f.addAsset("web-2", "production", true)
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337"}})
	f.tick()
	// web-1 is fixed (upgraded), web-2 has a new issue.
	f.findingsOn(map[string][]string{"web-2": {"CVE-2020-8203"}})
	f.tick()
	// The finding was dropped with the version unchanged; an upgrade
	// records it as remediated (only remediation counts as fixed).
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET resolution_kind = 'remediated' WHERE status = 'resolved'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	if ev := f.hook.events(); len(ev) != 0 {
		t.Fatalf("a summary-only route sent %v", ev)
	}
	f.d.Now = func() time.Time { return nextAt(9, 5) }
	f.tick()
	ev := f.hook.events()
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "summary") {
		t.Fatalf("want one summary: %v", ev)
	}
	m := f.hook.got[0]
	if m.Title != "Daily summary: 1 new issue, 1 fixed" || m.Period == nil || m.Counts["new"] != 1 || m.Counts["fixed"] != 1 {
		t.Fatalf("summary = %+v", m)
	}
	sections := map[string][]Item{}
	for _, s := range m.Sections {
		sections[s.Title] = s.Items
	}
	if it := sections["New issues"]; len(it) != 1 || it[0].Text != "web-2: 1 new issue (1 urgent)" ||
		!strings.HasPrefix(it[0].Link, fmt.Sprintf("https://stk.example/fixes/issues?asset_id=%d&new_within=", f.asset["web-2"])) {
		t.Errorf("new issues = %+v", it)
	}
	if it := sections["Fixed"]; len(it) != 1 || !strings.HasPrefix(it[0].Text, "web-1: 1 closed after Upgrade lodash") ||
		!strings.Contains(it[0].Link, "resolved_within=") || !strings.Contains(it[0].Link, "status=resolved") {
		t.Errorf("fixed = %+v", it)
	}
	if it := sections["Top fixes still open"]; len(it) != 1 || !strings.Contains(it[0].Text, "on web-2 (clears 1 issue)") ||
		!strings.HasPrefix(it[0].Link, "https://stk.example/fixes/") {
		t.Errorf("top fixes = %+v", it)
	}
	// A day on, the new issue is not acknowledged in time (licensed
	// build); nothing is past its fix deadline.
	for _, it := range sections["Overdue"] {
		if !escalationBuilt || strings.Contains(it.Text, "fix deadline") {
			t.Errorf("overdue = %+v", sections["Overdue"])
		}
	}

	// The next day nothing changed: no summary, but the period moves on.
	f.d.Now = func() time.Time { return nextAt(9, 5).AddDate(0, 0, 1) }
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 {
		t.Errorf("summary without changes: %v", ev)
	}
	after, _ := f.st.GetRoute(ctx, r.ID)
	if !after.LastSummaryAt.Equal(f.d.Now()) {
		t.Errorf("last summary at %s, want %s", after.LastSummaryAt, f.d.Now())
	}
}

// Regression: 2,000 incidents pass their fix deadline in the same cycle
// (24 Oct 2026: 2,869 escalation messages to one Slack channel in a day).
// Each route gets at most one message about it; the escalation levels are
// still recorded.
func TestManyIncidentsEscalateAtOnce(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	chs, _ := f.st.ListChannels(ctx)
	if _, err := f.st.SaveRoute(ctx, store.Route{Name: "leads", ChannelID: chs[0].ID, Enabled: true, MinPriority: "P1",
		Escalation: true, Timezone: "Europe/Berlin", MaxPerHour: 20}); err != nil {
		t.Fatal(err)
	}
	f.addAsset("web-1", "production", true)
	keys := make([]string, 2000)
	for i := range keys {
		keys[i] = fmt.Sprintf("CVE-2026-%05d", i)
	}
	f.findingsOn(map[string][]string{"web-1": keys})
	f.tick()
	if n := f.count(`SELECT count(*) FROM incidents WHERE status = 'open'`); n != 2000 {
		t.Fatalf("%d incidents, want 2000", n)
	}
	if n := f.count(`SELECT count(*) FROM deliveries`); n != 2 {
		t.Fatalf("%d urgent messages for 2 routes, want 2", n)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '60 days'`); err != nil {
		t.Fatal(err)
	}
	f.tick()
	f.tick()
	want := 0
	if escalationBuilt {
		want = 1
		if n := f.count(`SELECT count(*) FROM incidents WHERE escalation_level = 2`); n != 2000 {
			t.Errorf("%d incidents at escalation level 2, want 2000", n)
		}
	}
	for _, r := range []string{"main", "leads"} {
		if n := f.count(`SELECT count(*) FROM deliveries d JOIN routes r ON r.id = d.route_id WHERE r.name = $1 AND d.event <> 'urgent'`, r); n != want {
			t.Errorf("route %s: %d overdue messages, want %d", r, n, want)
		}
	}
	if n := f.count(`SELECT count(*) FROM deliveries WHERE event = 'escalated'`); n != 0 {
		t.Errorf("%d per-incident escalation messages", n)
	}
	if escalationBuilt {
		var m Message
		for _, got := range f.hook.got {
			if got.Event == EventOverdue {
				m = got
			}
		}
		if m.Title != "2,000 urgent issues past their deadline across 1 fix" || len(m.Sections[0].Items) != 2 {
			t.Errorf("overdue message = %+v", m)
		}
	}
}

func TestSummaryDue(t *testing.T) {
	ist := store.Route{Mode: store.ModeDaily, SummaryTime: "09:00", Timezone: "Asia/Kolkata",
		LastSummaryAt: time.Date(2026, 3, 9, 3, 30, 0, 0, time.UTC)} // 09:00 IST on Monday 9 March
	for _, c := range []struct {
		now  time.Time
		due  bool
		desc string
	}{
		{time.Date(2026, 3, 10, 3, 20, 0, 0, time.UTC), false, "08:50 IST the next day"},
		{time.Date(2026, 3, 10, 3, 31, 0, 0, time.UTC), true, "09:01 IST the next day"},
		{time.Date(2026, 3, 12, 20, 0, 0, 0, time.UTC), true, "days later"},
	} {
		if _, due := summaryDue(ist, false, c.now); due != c.due {
			t.Errorf("daily, %s: due = %v", c.desc, due)
		}
	}
	weekly := store.Route{Mode: store.ModeWeekly, SummaryTime: "08:00", SummaryDay: "friday", Timezone: "UTC",
		LastSummaryAt: time.Date(2026, 3, 6, 8, 0, 0, 0, time.UTC)} // Friday 6 March
	if _, due := summaryDue(weekly, true, time.Date(2026, 3, 12, 9, 0, 0, 0, time.UTC)); due {
		t.Error("weekly: due on Thursday")
	}
	stamp, due := summaryDue(weekly, true, time.Date(2026, 3, 13, 8, 1, 0, 0, time.UTC))
	if !due || stamp != "2026-03-13T08:00" {
		t.Errorf("weekly on Friday: %s %v", stamp, due)
	}
}

// syntheticUrgent is an urgent cycle over many assets, each with many fixes.
func syntheticUrgent(assets, fixes int, name func(int) string) (store.Route, []store.Incident, map[int64][]store.IssueCount, map[string]store.FixInfo) {
	r := store.Route{ID: 1, Name: "ops", Enabled: true, MinPriority: "P1"}
	in := store.Incident{ID: 9, Kind: "vulnerability", Priority: "P1", Detail: json.RawMessage(`{}`)}
	rows := map[int64][]store.IssueCount{}
	infos := map[string]store.FixInfo{}
	for a := 1; a <= assets; a++ {
		for g := 0; g < fixes; g++ {
			id := fmt.Sprintf("%d:package_upgrade:%d", a, g)
			infos[id] = store.FixInfo{ID: id, AssetID: int64(a), Title: fmt.Sprintf("Upgrade package-%d to 2.0", g), FindingCount: 100 + g, SortOrder: g}
			rows[9] = append(rows[9], store.IssueCount{IncidentID: 9, AssetID: int64(a), AssetName: name(a), Kind: "vulnerability",
				Priority: "P1", FixGroup: id, Count: 20 - g})
		}
	}
	return r, []store.Incident{in}, rows, infos
}

// However much happens, a message lists at most 5 assets and 3 fixes each,
// links every item, and stays inside Slack's limits.
func TestUrgentMessageLimits(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	r, incs, rows, infos := syntheticUrgent(40, 12, func(a int) string { return fmt.Sprintf("host-%02d.%s", a, strings.Repeat("very-long-name.", 20)) })
	m, ok := d.urgentMessage(r, incs, rows, nil, infos, nil)
	if !ok {
		t.Fatal("no message")
	}
	items := m.Sections[0].Items
	if len(items) != maxAssetItems+1 || !strings.HasPrefix(items[maxAssetItems].Text, "+35 more assets with new urgent issues") {
		t.Fatalf("asset items = %d, last %+v", len(items), items[len(items)-1])
	}
	for _, it := range items[:maxAssetItems] {
		if len(it.Items) != maxFixItems+1 || !strings.HasPrefix(it.Items[0].Text, "Top fix: Upgrade package-0 to 2.0 (clears 100 issues)") ||
			it.Items[maxFixItems].Text != "+9 more fixes" {
			t.Errorf("fix items = %+v", it.Items)
		}
	}
	var walk func([]Item)
	walk = func(list []Item) {
		for _, it := range list {
			if !strings.HasPrefix(it.Link, "https://stk.example/") {
				t.Errorf("item without a dashboard link: %+v", it)
			}
			walk(it.Items)
		}
	}
	walk(items)
	if m.Title != "6,960 new urgent issues on 40 assets" {
		t.Errorf("title = %q", m.Title)
	}
	payload := slackPayload(m)
	blocks := payload["blocks"].([]map[string]any)
	if len(blocks) > slackBlocksMax {
		t.Errorf("%d blocks", len(blocks))
	}
	for _, b := range blocks {
		txt, _ := b["text"].(map[string]any)
		s, _ := txt["text"].(string)
		if b["type"] == "header" && len([]rune(s)) > slackHeaderMax || len(s) > slackSectionMax {
			t.Errorf("block over the limit: %d chars", len(s))
		}
		if b["type"] == "header" && s != m.Subject() {
			t.Errorf("header cut: %q", s)
		}
	}
	if strings.Contains(fmt.Sprint(payload), "—") || strings.Contains(m.Text(), "—") {
		t.Error("em dash in a message")
	}
}

// Email is plain text and HTML with every item linked; Teams cards link
// items; the webhook JSON keeps its fields and adds sections and counts.
func TestGroupedPayloads(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	r, incs, rows, infos := syntheticUrgent(2, 4, func(a int) string { return []string{"", "commmerceblog", "pos-api"}[a] })
	m, _ := d.urgentMessage(r, incs, rows, nil, infos, nil)
	e := string(buildEmail("a@x.io", []string{"b@x.io"}, m))
	headers, body, _ := strings.Cut(e, "\r\n\r\n")
	if !strings.Contains(headers, "Subject: 148 new urgent issues on 2 assets") || !strings.Contains(headers, "multipart/alternative") {
		t.Errorf("headers = %q", headers)
	}
	if !strings.Contains(body, "- commmerceblog: 74 new urgent issues\r\n  https://stk.example/fixes/issues?asset_id=1&priority=P1\r\n") ||
		!strings.Contains(body, `<a href="https://stk.example/fixes/1:package_upgrade:0">Top fix: Upgrade package-0 to 2.0 (clears 100 issues)</a>`) ||
		!strings.Contains(body, "Change these notifications: https://stk.example/settings/notifications?tab=routes") {
		t.Errorf("email body = %s", body)
	}
	if strings.Contains(strings.ReplaceAll(body, "\r\n", ""), "\n") {
		t.Error("bare LF in the email body")
	}
	tm, _ := json.Marshal(teamsPayload(m))
	if !strings.Contains(string(tm), "[commmerceblog: 74 new urgent issues](https://stk.example/fixes/issues?asset_id=1\\u0026priority=P1)") {
		t.Errorf("teams: %s", tm)
	}
	wh, _ := json.Marshal(m)
	var shape map[string]any
	_ = json.Unmarshal(wh, &shape)
	for _, k := range []string{"event", "title", "sos", "summary", "link", "at", "route", "counts", "sections", "settings_link"} {
		if _, ok := shape[k]; !ok {
			t.Errorf("webhook JSON lacks %q: %s", k, wh)
		}
	}
	if shape["event"] != "urgent" || len(shape["summary"].([]any)) != 2+2*4 {
		t.Errorf("webhook JSON = %s", wh)
	}
}

// An issue that comes back after a fix is urgent whatever its priority:
// one urgent message says so, once, and the summary has a section for it.
func TestRegressedIsUrgent(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("web-1", "staging", false)
	report := func(purls ...string) {
		b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
			model.AssetRef{Kind: model.AssetHost, Name: "web-1", Identifiers: []model.Identifier{{Scheme: "test", Value: "web-1"}}})
		for _, p := range purls {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed, Scope: "runtime"})
		}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.Ingest(ctx, b, 0); err != nil {
			t.Fatal(err)
		}
		rows, _, _ := f.st.ListInventory(ctx, store.InventoryFilter{AssetID: f.asset["web-1"]})
		var ids []int64
		var want []store.FindingInput
		for _, r := range rows {
			if r.RemovedAt != nil {
				continue
			}
			ids = append(ids, r.ID)
			want = append(want, store.FindingInput{Kind: "vulnerability", Key: "CVE-2099-0007", InventoryID: r.ID, AssetID: f.asset["web-1"],
				ComponentID: r.ComponentID, Verification: "confirmed", Severity: "low", Title: "Minor issue in lodash",
				FixedVersion: "4.17.21", Sources: []string{"GHSA-low"}, Evidence: map[string]any{}})
		}
		if _, _, err := f.st.SyncFindings(ctx, []string{"vulnerability"}, ids, want); err != nil {
			t.Fatal(err)
		}
		if _, err := f.st.ResolveRemovedFindings(ctx); err != nil {
			t.Fatal(err)
		}
	}
	report("pkg:npm/lodash@4.17.15")
	f.tick()
	if ev := f.hook.events(); len(ev) != 0 {
		t.Fatalf("a low-priority issue raised %v", ev)
	}
	before := time.Now().Add(-time.Second)
	report() // lodash removed: fixed
	f.tick()
	report("pkg:npm/lodash@4.17.15") // and back
	f.tick()
	f.tick()
	ev := f.hook.events()
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "urgent") {
		t.Fatalf("want one urgent message: %v", ev)
	}
	m := f.hook.got[0]
	if m.Title != "web-1: 1 issue came back after a fix" || m.Counts["regressed"] != 1 || len(m.Sections) != 1 ||
		m.Sections[0].Title != "Came back after a fix" {
		t.Fatalf("urgent = %+v", m)
	}
	if it := m.Sections[0].Items[0]; it.Link != fmt.Sprintf("https://stk.example/fixes/issues?asset_id=%d&state=regressed", f.asset["web-1"]) {
		t.Errorf("item = %+v", it)
	}

	// The summary has the section, and the issue is not also "new".
	routes, _ := f.st.ListRoutes(ctx)
	data := &summaryData{d: f.d, ctx: ctx, cache: map[string][]store.IssueCount{}}
	sm, changed, err := f.d.summaryMessage(routes[0], false, data, before, time.Now().Add(time.Minute), false)
	if err != nil || !changed {
		t.Fatalf("summary: %v %v", changed, err)
	}
	var titles []string
	for _, s := range sm.Sections {
		titles = append(titles, s.Title)
	}
	if sm.Counts["regressed"] != 1 || sm.Counts["new"] != 0 || !strings.Contains(sm.Title, "1 came back") ||
		!strings.Contains(strings.Join(titles, "|"), "Came back after a fix") {
		t.Errorf("summary %q counts %v sections %v", sm.Title, sm.Counts, titles)
	}
}
