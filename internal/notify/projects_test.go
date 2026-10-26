package notify

import (
	"context"
	"encoding/json"
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

	// The daily summary.
	f.d.Now = func() time.Time { return nextAt(9, 5) }
	f.tick()
	f.tick()
	for _, m := range f.hook.got {
		b, _ := json.Marshal(m)
		if strings.Contains(string(b), "other-web") {
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
