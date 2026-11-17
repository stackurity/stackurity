package notify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func gateRows() []store.GateAssetViolations {
	team := int64(7)
	return []store.GateAssetViolations{
		{PolicyID: 1, PolicyName: "No known exploited", Mode: "enforce", AssetID: 10, AssetName: "web-1", Environment: "production", OwnerTeamID: &team, Count: 1},
		{PolicyID: 1, PolicyName: "No known exploited", Mode: "enforce", AssetID: 11, AssetName: "web-2", Environment: "staging", Count: 3},
		{PolicyID: 2, PolicyName: "No old criticals", Mode: "warn", AssetID: 10, AssetName: "web-1", Environment: "production", OwnerTeamID: &team, Count: 2},
	}
}

// The weekly summary's Policy gates section: one item per policy with its
// violations on the route's assets, the assets with most first, each
// linking to the Violations page narrowed to it.
func TestGateSection(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	sec, n, ok := d.gateSection(store.Route{}, gateRows())
	if !ok || n != 6 || sec.Title != "Policy gates" || len(sec.Items) != 2 {
		t.Fatalf("section = %+v (%d, %v)", sec, n, ok)
	}
	first := sec.Items[0]
	if first.Text != "No known exploited [enforce]: 4 violations on 2 assets" || first.Link != "https://stk.example/fixes/policy-violations?policy_id=1" {
		t.Errorf("first = %+v", first)
	}
	if len(first.Items) != 2 || first.Items[0].Text != "web-2: 3 violations" || first.Items[0].Link != "https://stk.example/fixes/policy-violations?asset_id=11&policy_id=1" ||
		first.Items[1].Text != "web-1: 1 violation" {
		t.Errorf("assets = %+v", first.Items)
	}
	if sec.Items[1].Text != "No old criticals [warn]: 2 violations on 1 asset" {
		t.Errorf("second = %+v", sec.Items[1])
	}

	// Scoped like the rest of the summary: environment and team filters.
	if sec, n, ok := d.gateSection(store.Route{Environments: []string{"staging"}}, gateRows()); !ok || n != 3 || len(sec.Items) != 1 ||
		sec.Items[0].Text != "No known exploited [enforce]: 3 violations on 1 asset" {
		t.Errorf("staging = %+v (%d)", sec, n)
	}
	if _, n, _ := d.gateSection(store.Route{TeamIDs: []int64{7}}, gateRows()); n != 3 {
		t.Errorf("team 7 = %d violations, want 3", n)
	}
	// A route limited to a project hears only of its assets.
	r := store.Route{ProjectIDs: []int64{5}, ProjectAssets: map[int64]bool{11: true}, AssetProject: map[int64]int64{11: 5}}
	sec, n, ok = d.gateSection(r, gateRows())
	if !ok || n != 3 {
		t.Fatalf("project = %+v (%d)", sec, n)
	}
	scopeItems(r, sec.Items)
	if !strings.Contains(sec.Items[0].Items[0].Link, "project=5") {
		t.Errorf("link not opened in the project: %s", sec.Items[0].Items[0].Link)
	}
	if _, _, ok := d.gateSection(store.Route{Environments: []string{"dev"}}, gateRows()); ok {
		t.Error("a route without violations got the section")
	}
}

// More policies and assets than fit are summed up in a "+N more" line.
func TestGateSectionLimits(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	var rows []store.GateAssetViolations
	for p := int64(1); p <= maxGatePolicies+2; p++ {
		for a := int64(1); a <= maxGateAssets+1; a++ {
			rows = append(rows, store.GateAssetViolations{PolicyID: p, PolicyName: "P", Mode: "warn", AssetID: a, AssetName: "a", Count: 1})
		}
	}
	sec, _, _ := d.gateSection(store.Route{}, rows)
	if len(sec.Items) != maxGatePolicies+1 || sec.Items[maxGatePolicies].Text != "+2 more policies" {
		t.Errorf("items = %d, last %+v", len(sec.Items), sec.Items[len(sec.Items)-1])
	}
	if it := sec.Items[0].Items; len(it) != maxGateAssets+1 || it[maxGateAssets].Text != "+1 more asset" {
		t.Errorf("assets = %+v", it)
	}
}

// With a database: a known-exploited policy's violation shows in the
// weekly summary, and not in the daily one.
func TestWeeklySummaryPolicyGates(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	f.addAsset("web-1", "production", true)
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337"}})
	p, err := f.st.CreateGatePolicy(ctx, store.GatePolicy{Name: "No known exploited", Kind: store.GateKnownExploited}, store.Actor{Type: "system", Name: "test"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, weekly := range []bool{true, false} {
		data := &summaryData{d: f.d, ctx: ctx, cache: map[string][]store.IssueCount{}}
		m, _, err := f.d.summaryMessage(r, weekly, data, now.Add(-time.Hour), now, false)
		if err != nil {
			t.Fatal(err)
		}
		var got *Section
		for i := range m.Sections {
			if m.Sections[i].Title == "Policy gates" {
				got = &m.Sections[i]
			}
		}
		if !weekly {
			if got != nil {
				t.Errorf("daily summary has the Policy gates section: %+v", got)
			}
			continue
		}
		if got == nil || len(got.Items) != 1 || !strings.HasPrefix(got.Items[0].Text, "No known exploited [warn]: 1 violation on 1 asset") ||
			!strings.Contains(got.Items[0].Link, "policy_id=") || m.Counts["policy_violations"] != 1 {
			t.Errorf("weekly policy gates = %+v, counts %v (policy %d)", got, m.Counts, p.ID)
		}
	}
}
