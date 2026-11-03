package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// The planner's no-fix advice is read from stored data: another package the
// advisory fixes (babel-traverse → @babel/traverse, preferring a release
// over a pre-release), the registry's deprecation notice, the advisory's
// workaround, and where in the application each package was found.
func TestNoFixContext(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	sys := tenant.System(context.Background())
	const dir = "/var/www/ghost/versions/6.52.0"
	pnpm := func(name, ver string) string {
		return dir + "/node_modules/.pnpm/" + name + "@" + ver + "/node_modules/" + name
	}
	b := model.NewBatch(model.Collector{ID: "linux-apps", Version: "1", Method: "agent"}, model.AssetRef{
		Kind: model.AssetApplication, Name: "ghost (/6.52.0) on blog",
		Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: dir}},
		Attributes:  map[string]string{"app_dir": dir, "host": "blog", "app_version": "6.52.0"},
	})
	for _, p := range []struct{ purl, loc string }{
		{"pkg:npm/babel-traverse@6.26.0", pnpm("babel-traverse", "6.26.0")},
		{"pkg:npm/request@2.88.2", pnpm("request", "2.88.2")},
		{"pkg:npm/node-forge@1.4.0", dir + "/content/themes/source/yarn.lock"},
		{"pkg:npm/html-minifier@4.0.0", pnpm("html-minifier", "4.0.0")},
	} {
		b.Observations = append(b.Observations, model.Observation{Purl: p.purl, Location: p.loc, Confidence: model.ConfidenceConfirmed,
			Evidence: map[string]string{"app_dir": dir}})
	}
	b.Complete = true
	host := ingestHost(t, s, ctx, "blog")
	b.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: "blog"}}}}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	b.Asset.Identifiers[0].Value = fmt.Sprintf("host:%d:%s", host, dir)
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	mod := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	if err := s.EnsureFeed(sys, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	semver := func(events ...osv.Event) []osv.Range { return []osv.Range{{Type: "SEMVER", Events: events}} }
	vulns := []*osv.Vulnerability{
		{ID: "GHSA-67hx-6x53-jw92", Aliases: []string{"CVE-2023-45133"}, Modified: mod, Affected: []osv.Affected{
			{Package: osv.Package{Ecosystem: "npm", Name: "@babel/traverse"}, Ranges: semver(osv.Event{Introduced: "0"}, osv.Event{Fixed: "7.23.2"},
				osv.Event{Introduced: "8.0.0-alpha.0"}, osv.Event{Fixed: "8.0.0-alpha.4"})},
			{Package: osv.Package{Ecosystem: "npm", Name: "babel-traverse"}, Ranges: semver(osv.Event{Introduced: "0"})},
			// Another package with no fix is no way out.
			{Package: osv.Package{Ecosystem: "npm", Name: "babel-core"}, Ranges: semver(osv.Event{Introduced: "0"})},
		}},
		{ID: "GHSA-p8p7-x288-28g6", Aliases: []string{"CVE-2023-28155"}, Modified: mod, Affected: []osv.Affected{
			{Package: osv.Package{Ecosystem: "npm", Name: "request"}, Ranges: semver(osv.Event{Introduced: "0"})},
		}},
		{ID: "GHSA-pfq8-rq6v-vf5m", Aliases: []string{"CVE-2022-37620"}, Modified: mod, Affected: []osv.Affected{
			{Package: osv.Package{Ecosystem: "npm", Name: "html-minifier"}, Ranges: semver(osv.Event{Introduced: "0"})},
		}},
		{ID: "GHSA-forg-xxxx-xxxx", Aliases: []string{"CVE-2026-33894"}, Modified: mod,
			Details:  "### Impact\nForged signatures.\n\n### Workarounds\nDo not verify RSA signatures from untrusted sources with forge.\n\n### References\nx",
			Affected: []osv.Affected{{Package: osv.Package{Ecosystem: "npm", Name: "node-forge"}, Ranges: semver(osv.Event{Introduced: "0"})}}},
	}
	if _, err := s.UpsertAdvisories(sys, "osv:npm", vulns); err != nil {
		t.Fatal(err)
	}
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: r.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	sources := map[string][2]string{"babel-traverse": {"CVE-2023-45133", "GHSA-67hx-6x53-jw92"},
		"request": {"CVE-2023-28155", "GHSA-p8p7-x288-28g6"}, "node-forge": {"CVE-2026-33894", "GHSA-forg-xxxx-xxxx"},
		"html-minifier": {"CVE-2022-37620", "GHSA-pfq8-rq6v-vf5m"}}
	for _, row := range rows {
		ids = append(ids, row.ID)
		src := sources[row.Name]
		in = append(in, store.FindingInput{Kind: "vulnerability", Key: src[0], InventoryID: row.ID, AssetID: r.AssetID,
			ComponentID: row.ComponentID, Verification: "confirmed", Severity: "high", Title: src[0], Sources: []string{src[1]},
			Evidence: map[string]any{"osv_package": row.Name, "target_ecosystem": "npm"}})
		if row.Name == "html-minifier" {
			pub := time.Date(2019, 4, 1, 0, 0, 0, 0, time.UTC)
			if err := s.UpsertRelease(sys, store.Release{ComponentID: row.ComponentID, Latest: "4.0.0", LatestStable: "4.0.0",
				LatestPublished: &pub, Source: "releases:npm", CheckedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
		}
		if row.Name == "request" {
			pub := time.Date(2020, 2, 11, 0, 0, 0, 0, time.UTC)
			if err := s.UpsertRelease(sys, store.Release{ComponentID: row.ComponentID, Latest: "2.88.2", LatestStable: "2.88.2",
				LatestPublished: &pub, Deprecated: "request has been deprecated, see https://github.com/request/request/issues/3142",
				Source: "releases:npm", CheckedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	plan := func() (fixplan.Group, map[string]fixplan.NoFixItem, map[string]string) {
		t.Helper()
		if _, err := planner.Rebuild(ctx, s, time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
		list, _, err := s.ListFixGroups(ctx, store.FixGroupFilter{Kind: fixplan.NoFix})
		if err != nil || len(list) != 1 {
			t.Fatalf("no-fix groups: %d, %v", len(list), err)
		}
		var g fixplan.Group
		if err := json.Unmarshal(list[0], &g); err != nil {
			t.Fatal(err)
		}
		if g.NoFixAdvice == nil || len(g.NoFixAdvice.Sections) != 3 {
			t.Fatalf("advice %s", list[0])
		}
		items, titles := map[string]fixplan.NoFixItem{}, map[string]string{}
		for _, s := range g.NoFixAdvice.Sections {
			titles[s.Kind] = s.Title
			for _, it := range s.Items {
				items[s.Kind+":"+it.Component] = it
			}
		}
		return g, items, titles
	}
	g, items, titles := plan()
	a := g.NoFixAdvice
	if it := items["renamed:babel-traverse"]; it.MoveTo != "@babel/traverse" || it.FixedVersion != "7.23.2" {
		t.Errorf("babel-traverse: %+v", it)
	}
	if it := items["unmaintained:request"]; !strings.Contains(it.Text, "request has been deprecated") {
		t.Errorf("request: %+v", it)
	}
	if it := items["no_fix_yet:node-forge"]; it.Workaround != "Do not verify RSA signatures from untrusted sources with forge." ||
		it.WorkaroundSource != "GHSA-forg-xxxx-xxxx" {
		t.Errorf("node-forge: %+v", it)
	}
	bd := a.Bundled
	if bd == nil || bd.App != "ghost" || bd.AppVersion != "6.52.0" || len(bd.Commands) != 2 ||
		bd.Commands[0] != "cd "+dir+" && pnpm why babel-traverse html-minifier request" ||
		bd.Commands[1] != "cd "+dir+"/content/themes/source && yarn why node-forge" {
		t.Errorf("bundled %+v", bd)
	}
	if !strings.Contains(g.Action, "babel-traverse → @babel/traverse 7.23.2") || !strings.Contains(g.Action, "only a ghost upgrade") {
		t.Errorf("action %q", g.Action)
	}
	// The cutoff is the workspace's risk policy: html-minifier (no release
	// since April 2019) is unmaintained under the default 24 months, and
	// waits for a fix under 120.
	if _, ok := items["unmaintained:html-minifier"]; !ok ||
		titles[fixplan.NoFixUnmaintained] != "Deprecated, or no release for 24 months or more (your risk policy)" {
		t.Errorf("24 months: %v, %q", items, titles[fixplan.NoFixUnmaintained])
	}
	pol, err := s.RiskPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pol.UnmaintainedMonths = 120
	if err := s.SetRiskPolicy(ctx, pol); err != nil {
		t.Fatal(err)
	}
	if _, items, titles = plan(); items["no_fix_yet:html-minifier"].Component == "" ||
		titles[fixplan.NoFixUnmaintained] != "Deprecated by the maintainers" {
		t.Errorf("120 months: %v, %q", items, titles[fixplan.NoFixUnmaintained])
	}
	// Storing the same records again changes nothing; a record without a
	// workaround keeps its hash (only those with one are rewritten).
	if n, err := s.UpsertAdvisories(sys, "osv:npm", vulns); err != nil || n != 0 {
		t.Errorf("stored again: %d changed, %v", n, err)
	}
}
