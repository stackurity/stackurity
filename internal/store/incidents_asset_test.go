package store_test

import (
	"sort"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// The asset filter keeps the incidents with a finding on that asset: an
// active one for open incidents, any one for resolved or all.
func TestListIncidentsByAsset(t *testing.T) {
	ctx, s := loopStore(t)
	a := ingestImage(t, s, ctx, "registry.example.com/shop/api:1", digestA, "pkg:npm/lodash@4.17.20")
	b := ingestImage(t, s, ctx, "registry.example.com/shop/web:1", digestB, "pkg:npm/lodash@4.17.20")
	syncOpen(t, s, ctx, a, map[string]string{"CVE-1": "lodash", "CVE-2": "lodash"})
	syncOpen(t, s, ctx, b, map[string]string{"CVE-2": "lodash"})
	if err := s.CorrelateIncidents(ctx); err != nil {
		t.Fatal(err)
	}
	keys := func(f store.IncidentFilter) []string {
		t.Helper()
		ins, total, err := s.ListIncidents(ctx, f)
		if err != nil || total != int64(len(ins)) {
			t.Fatalf("%+v: %v (total %d)", f, err, total)
		}
		var out []string
		for _, in := range ins {
			out = append(out, in.Key)
		}
		sort.Strings(out)
		return out
	}
	check := func(f store.IncidentFilter, want ...string) {
		t.Helper()
		if got := keys(f); len(got) != len(want) || (len(want) > 0 && got[0] != want[0]) || (len(want) > 1 && got[1] != want[1]) {
			t.Errorf("%+v: %v, want %v", f, got, want)
		}
	}
	check(store.IncidentFilter{}, "CVE-1", "CVE-2")
	check(store.IncidentFilter{AssetID: a}, "CVE-1", "CVE-2")
	check(store.IncidentFilter{AssetID: b}, "CVE-2")
	check(store.IncidentFilter{AssetID: b + a + 1000})

	// b's finding is accepted: CVE-2 stays open for a, but not for b.
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET state = 'risk_accepted' WHERE asset_id = $1`, b); err != nil {
		t.Fatal(err)
	}
	check(store.IncidentFilter{AssetID: b})
	check(store.IncidentFilter{AssetID: b, Status: "all"}, "CVE-2")
	check(store.IncidentFilter{AssetID: a}, "CVE-1", "CVE-2")
}
