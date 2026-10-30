package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// syncBehind makes the evaluation's findings for the asset's only row:
// the behind finding, an end-of-life finding, or neither.
func syncBehind(t *testing.T, s *store.Store, ctx context.Context, asset int64, behind, eol bool) int64 {
	t.Helper()
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil || len(rows) != 1 {
		t.Fatalf("inventory %v %v", rows, err)
	}
	r := rows[0]
	var in []store.FindingInput
	if behind {
		in = append(in, store.FindingInput{Kind: "vulnerability", Key: "behind:wordpress:6.5", InventoryID: r.ID, AssetID: asset,
			ComponentID: r.ComponentID, Verification: "confirmed", Severity: "high", FixedVersion: "6.5.14", Sources: []string{"lifecycle:endoflife"},
			Evidence: map[string]any{"product": "wordpress", "cycle": "6.5", "match": map[string]any{"rule": store.BehindRule}}})
	}
	if eol {
		in = append(in, store.FindingInput{Kind: "end_of_life", Key: "wordpress:6.5", InventoryID: r.ID, AssetID: asset,
			ComponentID: r.ComponentID, Verification: "confirmed", Severity: "high", Sources: []string{"lifecycle:endoflife"},
			Evidence: map[string]any{"product": "wordpress", "cycle": "6.5"}})
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability", "end_of_life"}, []int64{r.ID}, in); err != nil {
		t.Fatal(err)
	}
	return r.ID
}

// A behind finding closes with its own reason: replaced by the end-of-life
// finding, replaced by vulnerability matching, or the lifecycle data no
// longer putting the version behind; never "no longer evaluated" (its row
// never is) or "advisory updated" (it names no advisory).
func TestBehindResolutions(t *testing.T) {
	ctx, s := loopStore(t)
	for _, c := range []struct {
		name       string
		eol, match bool
		resolution string
		replacedBy string
	}{
		{"end of life", true, false, "replaced by the end-of-life finding: wordpress 6.5 reached end of life", "end_of_life"},
		{"matching", false, true, "replaced by vulnerability matching: wordpress 6.5.3 is now matched against advisories", "vulnerability_matching"},
		{"data", false, false, "lifecycle data updated: wordpress 6.5.3 is no longer behind its release line's latest release", ""},
	} {
		asset := ingestImage(t, s, ctx, "registry.example.com/wp/"+strings.ReplaceAll(c.name, " ", "-")+":1", digestA, "pkg:generic/wordpress@6.5.3")
		inv := syncBehind(t, s, ctx, asset, true, false)
		if _, err := s.Pool.Exec(ctx, `UPDATE inventory SET coverage = 'unsupported', coverage_reason = 'content management system core' WHERE id = $1`, inv); err != nil {
			t.Fatal(err)
		}
		if c.match {
			if _, err := s.Pool.Exec(ctx, `UPDATE inventory SET coverage = 'evaluated', coverage_reason = '' WHERE id = $1`, inv); err != nil {
				t.Fatal(err)
			}
		}
		syncBehind(t, s, ctx, asset, false, c.eol)
		fs := findings(t, s, ctx, store.FindingFilter{AssetID: asset, Key: "behind:wordpress:6.5"})
		if len(fs) != 1 {
			t.Fatalf("%s: %+v", c.name, fs)
		}
		f := fs[0]
		if f.Status != "resolved" || f.ResolutionKind != store.ResolutionAdvisoryChanged || f.Resolution != c.resolution ||
			strings.Contains(string(f.ResolutionDetail), "advisories") ||
			(c.replacedBy != "") != strings.Contains(string(f.ResolutionDetail), `"replaced_by": "`+c.replacedBy+`"`) {
			t.Errorf("%s: %s %q %s", c.name, f.ResolutionKind, f.Resolution, f.ResolutionDetail)
		}
	}
}

// An incident of behind findings says so in its detail, so a summary uses
// its title rather than its key; others do not.
func TestBehindIncident(t *testing.T) {
	ctx, s := loopStore(t)
	wp := ingestImage(t, s, ctx, "registry.example.com/wp/site:1", digestA, "pkg:generic/wordpress@6.5.3")
	syncBehind(t, s, ctx, wp, true, false)
	other := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestB, "pkg:npm/lodash@4.17.20")
	syncOpen(t, s, ctx, other, map[string]string{"CVE-2": "lodash"})
	if err := s.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	ins, _, err := s.ListIncidents(ctx, store.IncidentFilter{})
	if err != nil || len(ins) != 2 {
		t.Fatalf("incidents %+v %v", ins, err)
	}
	for _, in := range ins {
		if in.Behind() != (in.Key == "behind:wordpress:6.5") {
			t.Errorf("%s: behind %v, detail %s", in.Key, in.Behind(), in.Detail)
		}
	}
}
