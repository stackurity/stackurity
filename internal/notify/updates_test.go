package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Updates available in summaries: off by default; when a route turns it
// on, its weekly summary lists the installs behind their latest stable
// release, within the route's scope. Daily summaries never carry them.
// Updates alone send the weekly summary, and never raise findings or
// incidents.
func TestSummaryUpdates(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("web-1", "production", true)
	f.addAsset("ci-runner", "staging", false)
	rows, _, err := f.st.ListInventory(ctx, store.InventoryFilter{AssetID: f.asset["web-1"]})
	if err != nil || len(rows) != 1 {
		t.Fatalf("inventory %v %v", rows, err)
	}
	lodash := rows[0].ComponentID
	if err := f.st.UpsertRelease(ctx, store.Release{ComponentID: lodash, Latest: "4.17.21", LatestStable: "4.17.21",
		Source: "releases:npm", CheckedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	if r.SummaryUpdates {
		t.Fatal("updates are on by default")
	}
	morning := nextAt(9, 30)
	r.Mode, r.Events, r.SummaryDay = "", []string{store.EventWeeklySummary}, store.Weekdays[morning.Weekday()]
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}

	// Off: nothing happened, so no weekly summary.
	f.d.Now = func() time.Time { return morning }
	f.tick()
	if ev := f.hook.events(); len(ev) != 0 {
		t.Fatalf("updates are off, but sent %v", ev)
	}
	routes, _ = f.st.ListRoutes(ctx)
	data := &summaryData{d: f.d, ctx: ctx, cache: map[string][]store.IssueCount{}}
	off, _, err := f.d.summaryMessage(routes[0], true, data, morning.AddDate(0, 0, -7), morning, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := off.Counts["updates"]; ok || sectionItems(off, "Updates available") != nil {
		t.Errorf("updates are off, but the summary has them: %+v", off)
	}

	// On: next week's summary lists them.
	r = routes[0]
	r.SummaryUpdates = true
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	f.d.Now = func() time.Time { return morning.AddDate(0, 0, 7) }
	f.tick()
	ev := f.hook.events()
	if len(ev) != 1 || !strings.HasPrefix(ev[0], "summary") {
		t.Fatalf("want one weekly summary: %v", ev)
	}
	m := f.hook.got[0]
	if m.Title != "Weekly summary: 2 updates available" || m.Counts["updates"] != 2 || m.Counts["updates_patch"] != 2 ||
		m.Counts["updates_minor"] != 0 || m.Counts["updates_major"] != 0 || m.Counts["new"] != 0 {
		t.Fatalf("summary = %q %v", m.Title, m.Counts)
	}
	items := sectionItems(m, "Updates available")
	if len(items) != 2 ||
		items[0].Text != "2 installs behind the latest stable release (2 patch), in 1 package; none fixes a known vulnerability" ||
		items[0].Link != "https://stk.example/components/updates" ||
		items[1].Text != "lodash 4.17.15 → 4.17.21 (patch) on 2 assets" ||
		items[1].Link != fmt.Sprintf("https://stk.example/components/%d", lodash) {
		t.Errorf("updates = %+v", items)
	}
	if n := f.count(`SELECT count(*) FROM findings`) + f.count(`SELECT count(*) FROM incidents`); n != 0 {
		t.Errorf("updates raised %d findings or incidents", n)
	}

	// A route limited to production counts web-1 only; a daily summary
	// has no section and is not sent for them.
	routes, _ = f.st.ListRoutes(ctx)
	r = routes[0]
	r.Environments = []string{"production"}
	data = &summaryData{d: f.d, ctx: ctx, cache: map[string][]store.IssueCount{}}
	weekly, _, err := f.d.summaryMessage(r, true, data, f.d.Now().AddDate(0, 0, -7), f.d.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if items := sectionItems(weekly, "Updates available"); weekly.Counts["updates"] != 1 || len(items) != 2 ||
		items[1].Text != "lodash 4.17.15 → 4.17.21 (patch) on 1 asset" {
		t.Errorf("production updates = %v %+v", weekly.Counts, items)
	}
	daily, changed, err := f.d.summaryMessage(r, false, data, f.d.Now().AddDate(0, 0, -1), f.d.Now(), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := daily.Counts["updates"]; changed || ok || sectionItems(daily, "Updates available") != nil {
		t.Errorf("daily: changed %v, counts %v, sections %+v", changed, daily.Counts, daily.Sections)
	}

	// A daily summary sent for a new issue still has no section; a
	// weekly one over the same period has it.
	f.setFindings("web-1")
	r = routes[0]
	from, to := time.Now().Add(-time.Hour), time.Now().Add(time.Minute)
	data = &summaryData{d: f.d, ctx: ctx, cache: map[string][]store.IssueCount{}}
	daily, changed, err = f.d.summaryMessage(r, false, data, from, to, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || daily.Counts["new"] != 1 || sectionItems(daily, "Updates available") != nil {
		t.Errorf("daily with a new issue: changed %v, counts %v, sections %+v", changed, daily.Counts, daily.Sections)
	}
	weekly, changed, err = f.d.summaryMessage(r, true, data, from, to, false)
	if err != nil {
		t.Fatal(err)
	}
	if !changed || weekly.Counts["new"] != 1 || weekly.Counts["updates"] != 2 || sectionItems(weekly, "Updates available") == nil {
		t.Errorf("weekly with a new issue: changed %v, counts %v", changed, weekly.Counts)
	}
}

func sectionItems(m Message, title string) []Item {
	for _, s := range m.Sections {
		if s.Title == title {
			return s.Items
		}
	}
	return nil
}

// updateText names the versions installed (at most three) and where.
func TestUpdateText(t *testing.T) {
	c := store.ComponentUpdate{Namespace: "@babel", Name: "core", InstalledVersions: []string{"7.1.0", "7.2.0", "7.3.0", "7.4.0"},
		LatestStable: "7.26.0", UpdateType: "minor", Installs: 9, Assets: 4}
	if got := updateText(c); got != "@babel/core 7.1.0, 7.2.0, 7.3.0 +1 → 7.26.0 (minor), 9 installs on 4 assets" {
		t.Errorf("updateText = %q", got)
	}
}
