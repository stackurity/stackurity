package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A route limited to a project tells its channel about the project's assets
// only: urgent alerts, summaries and "connected" messages never name an
// asset outside it, even when one issue spans both.
func TestProjectRoute(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("shop-web", "production", true)
	f.addAsset("other-web", "production", true)
	p, err := f.st.CreateProject(ctx, "Shop", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.AddProjectAssets(ctx, p.ID, []int64{f.asset["shop-web"]}); err != nil {
		t.Fatal(err)
	}
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	r.ProjectIDs = []int64{p.ID}
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		t.Fatal(err)
	}
	if routes, _ = f.st.ListRoutes(ctx); !routes[0].ProjectAssets[f.asset["shop-web"]] || routes[0].ProjectAssets[f.asset["other-web"]] {
		t.Fatalf("route assets: %v", routes[0].ProjectAssets)
	}

	// One issue on both assets, one on the other asset only.
	f.findingsOn(map[string][]string{"shop-web": {"CVE-2021-23337"}, "other-web": {"CVE-2021-23337", "CVE-2020-8203"}})
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 || !strings.HasPrefix(ev[0], "urgent") {
		t.Fatalf("want one urgent alert: %v", ev)
	}
	if m := f.hook.got[0]; m.Title != "shop-web: 1 new urgent issue" {
		t.Errorf("urgent alert: %q", m.Title)
	}

	// An issue on the other asset only: nothing for this route.
	f.findingsOn(map[string][]string{"shop-web": {"CVE-2021-23337"}, "other-web": {"CVE-2021-23337", "CVE-2020-8203", "CVE-2026-0002"}})
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 {
		t.Fatalf("an issue outside the project was announced: %v", ev)
	}

	// An issue on the other asset that comes back after a fix: nothing.
	f.findingsOn(map[string][]string{"shop-web": {"CVE-2021-23337"}, "other-web": {"CVE-2021-23337", "CVE-2026-0002"}})
	f.tick()
	f.findingsOn(map[string][]string{"shop-web": {"CVE-2021-23337"}, "other-web": {"CVE-2021-23337", "CVE-2020-8203", "CVE-2026-0002"}})
	f.tick()
	// A new asset outside the project is not announced to the route.
	f.addNewAsset("other-new", "production", true)
	if err := f.st.MarkEvaluated(ctx, f.asset["other-new"], time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE dedupe_key = $1`, fmt.Sprintf("evaluate:asset:%d", f.asset["other-new"])); err != nil {
		t.Fatal(err)
	}
	f.tick()
	f.tick()
	if ev := f.hook.events(); len(ev) != 1 {
		t.Fatalf("a route limited to a project heard about another asset: %v", ev)
	}
	// Issues outside the project past their deadline stay out of the summary.
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET fix_due = now() - interval '2 days' WHERE asset_id <> $1`, f.asset["shop-web"]); err != nil {
		t.Fatal(err)
	}

	// The daily summary. No message of any kind may name an asset outside
	// the project.
	f.d.Now = func() time.Time { return nextAt(9, 5) }
	f.tick()
	f.tick()
	for _, m := range f.hook.got {
		b, _ := json.Marshal(m)
		if strings.Contains(string(b), "other-web") || strings.Contains(string(b), "other-new") {
			t.Errorf("%s message names an asset outside the project: %s", m.Event, b)
		}
	}
	if ev := f.hook.events(); len(ev) < 2 || !strings.HasPrefix(ev[len(ev)-1], "summary") {
		t.Errorf("want a summary: %v", ev)
	}

	// A route limited to an archived project matches nothing.
	archived := true
	if err := f.st.UpdateProject(ctx, p.ID, store.ProjectUpdate{Archived: &archived}); err != nil {
		t.Fatal(err)
	}
	if routes, _ = f.st.ListRoutes(ctx); len(routes[0].ProjectAssets) != 0 {
		t.Errorf("archived project's assets still routed: %v", routes[0].ProjectAssets)
	}
}

// Routes limited to projects hear about collection and coverage problems
// of the project's assets only, and never about tracker issues.
func TestProjectRouteScope(t *testing.T) {
	r := store.Route{Enabled: true, ProjectIDs: []int64{7}, ProjectAssets: map[int64]bool{3: true}}
	for _, c := range []struct {
		in   store.Incident
		want bool
	}{
		{store.Incident{Kind: "vulnerability", Key: "CVE-1"}, true},
		{store.Incident{Kind: "collection", Key: "asset:3"}, true},
		{store.Incident{Kind: "coverage", Key: "asset:3:agent"}, true},
		{store.Incident{Kind: "collection", Key: "asset:4"}, false},
		{store.Incident{Kind: "collection", Key: "integration:3"}, false},
		{store.Incident{Kind: "feed", Key: "osv:npm"}, false},
	} {
		if got := inScope(r, c.in); got != c.want {
			t.Errorf("%s %s: %v, want %v", c.in.Kind, c.in.Key, got, c.want)
		}
	}
	if routeMatches(r, store.Incident{Kind: "vulnerability", Key: "CVE-1", Priority: "P1"}) {
		t.Error("a route limited to projects matched a tracker incident")
	}
	// Issues that came back after a fix (0.7) are counted per asset too.
	if issueInScope(r, store.IssueCount{AssetID: 4, Kind: "vulnerability"}) || !issueInScope(r, store.IssueCount{AssetID: 3, Kind: "vulnerability"}) {
		t.Error("issueInScope ignores the project")
	}
	if !assetInScope(r, 3, "", nil) || assetInScope(r, 4, "", nil) {
		t.Error("assetInScope ignores the project")
	}
}

// The second lock: a message to a route limited to projects that links to
// another asset is withheld.
func TestProjectRouteWithholdsOtherAssets(t *testing.T) {
	r := store.Route{ProjectIDs: []int64{7}, ProjectAssets: map[int64]bool{3: true}}
	d := &Dispatcher{BaseURL: "https://stk.example"}
	ok := Message{Sections: []Section{{Items: []Item{{Text: "web", Link: d.assetURL(3), Items: []Item{{Link: d.fixURL("3:package_upgrade:9")}}}}}}}
	if bad := outsideProjects(r, ok); len(bad) != 0 {
		t.Errorf("own asset flagged: %v", bad)
	}
	for _, link := range []string{d.assetURL(4), d.findingsURL(4, nil), d.planURL(4), d.fixURL("4:package_upgrade:9"),
		d.findingsURL(4, url.Values{"state": {"regressed"}})} {
		m := Message{Sections: []Section{{Items: []Item{{Text: "x", Link: link}}}}}
		if bad := outsideProjects(r, m); len(bad) != 1 || bad[0] != 4 {
			t.Errorf("%s: %v, want asset 4", link, bad)
		}
	}
	if bad := outsideProjects(store.Route{}, Message{Sections: []Section{{Items: []Item{{Link: d.assetURL(4)}}}}}); bad != nil {
		t.Errorf("a route for every asset: %v", bad)
	}
}

// A route limited to projects is stored switched off for releases before
// 0.8, which ignore project_ids and would send it every project's alerts.
func TestProjectRouteOffForOlderReleases(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	p, err := f.st.CreateProject(ctx, "Client A", "")
	if err != nil {
		t.Fatal(err)
	}
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	stored := func() (enabled, projectEnabled bool) {
		t.Helper()
		if err := f.st.Pool.QueryRow(ctx, `SELECT enabled, project_enabled FROM routes WHERE id = $1`, r.ID).Scan(&enabled, &projectEnabled); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, c := range []struct {
		on       bool
		projects []int64
		enabled  bool // what a release before 0.8 reads
		project  bool
	}{
		{true, []int64{p.ID}, false, true},
		{false, []int64{p.ID}, false, false},
		{true, nil, true, false},
		{false, nil, false, false},
	} {
		r.Enabled, r.ProjectIDs = c.on, c.projects
		saved, err := f.st.SaveRoute(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		if saved.Enabled != c.on {
			t.Errorf("on %v, projects %v: reads back enabled %v", c.on, c.projects, saved.Enabled)
		}
		if en, pe := stored(); en != c.enabled || pe != c.project {
			t.Errorf("on %v, projects %v: stored enabled %v, project_enabled %v", c.on, c.projects, en, pe)
		}
	}
}
