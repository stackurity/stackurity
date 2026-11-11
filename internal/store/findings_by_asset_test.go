package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Grouped by asset, the list pages assets, not findings: one asset with
// many findings fills one group with its count, and the next asset is on
// the same page instead of pages later.
func TestListFindingsByAsset(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	add := func(host string, n int, sev func(i int) string) int64 {
		id := ingestHost(t, s, ctx, host, "pkg:deb/ubuntu/linux-image-6.8.0-142-generic@6.8.0-142.142?distro=ubuntu-24.04")
		rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: id})
		if err != nil || len(rows) != 1 {
			t.Fatalf("inventory of %s: %d, %v", host, len(rows), err)
		}
		var in []store.FindingInput
		for i := range n {
			key := fmt.Sprintf("CVE-2026-%05d", i)
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: rows[0].ID, AssetID: id, ComponentID: rows[0].ComponentID,
				Verification: "confirmed", Severity: sev(i), Title: key, Sources: []string{"USN-" + key}})
		}
		if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, []int64{rows[0].ID}, in); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// "big" has 120 findings, of which every tenth is critical.
	big := add("big", 120, func(i int) string {
		if i%10 == 0 {
			return "critical"
		}
		return "medium"
	})
	add("small", 2, func(int) string { return "high" })
	add("zeta", 1, func(int) string { return "low" })

	groups, assets, findings, err := s.ListFindingsByAsset(ctx, store.FindingFilter{Page: store.Page{Limit: 2}}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if assets != 3 || findings != 123 {
		t.Errorf("totals: %d assets, %d findings; want 3 and 123", assets, findings)
	}
	if len(groups) != 2 || groups[0].AssetName != "big" || groups[1].AssetName != "small" {
		t.Fatalf("first page: %+v; want big then small", groups)
	}
	if g := groups[0]; g.AssetID != big || g.Total != 120 || len(g.Findings) != 5 {
		t.Errorf("big: id %d total %d with %d shown; want %d, 120, 5", g.AssetID, g.Total, len(g.Findings), big)
	}
	for _, f := range groups[0].Findings {
		if f.Severity != "critical" || f.AssetID != big {
			t.Errorf("big shows %s %s of asset %d first; want its critical findings", f.Key, f.Severity, f.AssetID)
		}
	}
	if g := groups[1]; g.Total != 2 || len(g.Findings) != 2 {
		t.Errorf("small: total %d with %d shown; want 2 and 2", g.Total, len(g.Findings))
	}

	groups, _, _, err = s.ListFindingsByAsset(ctx, store.FindingFilter{Page: store.Page{Limit: 2, Offset: 2}}, 5)
	if err != nil || len(groups) != 1 || groups[0].AssetName != "zeta" {
		t.Fatalf("second page: %+v, %v; want zeta", groups, err)
	}

	// The filters are the list's: only critical leaves one asset.
	groups, assets, findings, err = s.ListFindingsByAsset(ctx, store.FindingFilter{Severity: []string{"critical"}}, 50)
	if err != nil || assets != 1 || findings != 12 || len(groups) != 1 || len(groups[0].Findings) != 12 {
		t.Errorf("critical only: %d assets, %d findings, %d groups, %v; want 1, 12, 1", assets, findings, len(groups), err)
	}

	// Past the last asset: no groups, totals still right.
	groups, assets, _, err = s.ListFindingsByAsset(ctx, store.FindingFilter{Page: store.Page{Limit: 2, Offset: 10}}, 5)
	if err != nil || len(groups) != 0 || assets != 3 {
		t.Errorf("past the end: %d groups of %d assets, %v", len(groups), assets, err)
	}
}
