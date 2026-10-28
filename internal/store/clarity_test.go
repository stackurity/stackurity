package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Prioritize runs every minute over every open finding; rows whose result
// did not change must not be rewritten (that bloated the table).
func TestPrioritizeLeavesUnchangedRowsAlone(t *testing.T) {
	ctx, s, _ := riskFixture(t)
	now := time.Now()
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), now); err != nil {
		t.Fatal(err)
	}
	versions := func() map[int64]string {
		rows, err := s.Pool.Query(ctx, `SELECT id, xmin::text FROM findings`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		out := map[int64]string{}
		for rows.Next() {
			var id int64
			var x string
			if err := rows.Scan(&id, &x); err != nil {
				t.Fatal(err)
			}
			out[id] = x
		}
		return out
	}
	before := versions()
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	after := versions()
	for id, x := range before {
		if after[id] != x {
			t.Errorf("finding %d was rewritten although its priority did not change", id)
		}
	}
	// A policy change still reaches every row it affects.
	p := risk.DefaultPolicy()
	p.Thresholds.P1, p.Thresholds.P2, p.Thresholds.P3 = 0.01, 0.005, 0.001
	if _, err := s.Prioritize(ctx, p, now); err != nil {
		t.Fatal(err)
	}
	fs, _, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		if f.Priority != "P1" {
			t.Errorf("%s: priority %s after lowering every threshold, want P1", f.Key, f.Priority)
		}
	}
}

func TestResolvedWithinAndSummary(t *testing.T) {
	ctx, s, _ := riskFixture(t)
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now() - interval '1 day' WHERE key = 'CVE-NOFIX'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET status = 'resolved', resolved_at = now() - interval '30 days' WHERE key = 'CVE-PRO'`); err != nil {
		t.Fatal(err)
	}
	_, n, err := s.ListFindings(ctx, store.FindingFilter{Status: "resolved", ResolvedWithinDays: 7})
	if err != nil || n != 1 {
		t.Fatalf("resolved in 7 days: %d, %v; want 1", n, err)
	}
	sum, err := s.SummarizeFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Resolved7d != 1 {
		t.Errorf("resolved_7d = %d, want 1", sum.Resolved7d)
	}
	_, open, _ := s.ListFindings(ctx, store.FindingFilter{})
	total := int64(0)
	for _, v := range sum.ByState {
		total += v
	}
	if total != open || open != 2 {
		t.Errorf("summary counts %d open findings, list %d, want 2", total, open)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET first_seen = now() - interval '20 days' WHERE key = 'CVE-KERNEL'`); err != nil {
		t.Fatal(err)
	}
	if _, n, err := s.ListFindings(ctx, store.FindingFilter{NewWithinDays: 7}); err != nil || n != 1 {
		t.Errorf("new this week: %d, %v; want 1", n, err)
	}
	if rows, n, err := s.ListFindings(ctx, store.FindingFilter{ByAsset: true}); err != nil || n != 2 || len(rows) != 2 {
		t.Errorf("sorted by asset: %d rows of %d, %v; want 2", len(rows), n, err)
	}
	if sum.KnownExploited != 2 || sum.AffectedAssets != 1 {
		t.Errorf("known exploited %d, affected assets %d; want 2 and 1", sum.KnownExploited, sum.AffectedAssets)
	}
}

// Every fix group falls in exactly one bucket, and each bucket filter lists
// what the focus summary counts.
func TestFixBuckets(t *testing.T) {
	ctx, s, _ := riskFixture(t)
	now := time.Now()
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Rebuild(ctx, s, now); err != nil {
		t.Fatal(err)
	}
	_, all, err := s.ListFixGroups(ctx, store.FixGroupFilter{})
	if err != nil || all == 0 {
		t.Fatalf("fix groups: %d, %v", all, err)
	}
	prod := risk.DefaultPolicy().ProductionEnvironments
	focus, err := s.SummarizeFixFocus(ctx, 0, prod, false)
	if err != nil {
		t.Fatal(err)
	}
	counted := focus.Groups
	for _, v := range focus.Hidden {
		counted += v["groups"]
	}
	if counted != all {
		t.Errorf("buckets count %d groups, the plan has %d", counted, all)
	}
	listed := int64(0)
	for _, b := range store.FixBuckets {
		_, n, err := s.ListFixGroups(ctx, store.FixGroupFilter{Bucket: b, ProductionEnvs: prod})
		if err != nil {
			t.Fatal(err)
		}
		want := focus.Groups
		if b != store.BucketFocus {
			want = focus.Hidden[b]["groups"]
		}
		if n != want {
			t.Errorf("bucket %s lists %d groups, summary says %d", b, n, want)
		}
		listed += n
	}
	if listed != all {
		t.Errorf("bucket lists add up to %d groups, want %d", listed, all)
	}
	if focus.Hidden[store.BucketNoFix]["groups"] == 0 {
		t.Errorf("the finding with no fixed version should be in the no_fix bucket: %+v", focus.Hidden)
	}
}

// The same upgrade on several assets is one entry when listed by fix, with
// every place, and the findings of all its places can be listed together.
func TestFixGroupsByFix(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	var ids []int64
	var in []store.FindingInput
	for _, h := range []struct{ name, ver string }{{"a", "3.3.1"}, {"b", "3.3.1"}, {"c", "3.2.0"}} {
		host := ingestHost(t, s, ctx, h.name, "pkg:npm/jquery@"+h.ver)
		rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: host})
		if err != nil || len(rows) != 1 {
			t.Fatalf("inventory of %s: %d, %v", h.name, len(rows), err)
		}
		ids = append(ids, rows[0].ID)
		for _, key := range []string{"CVE-2019-11358", "CVE-2020-11022"} {
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: rows[0].ID, AssetID: host, ComponentID: rows[0].ComponentID,
				Verification: "confirmed", Severity: "medium", FixedVersion: "3.5.0", Title: key, Sources: []string{"GHSA-" + key}})
		}
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Rebuild(ctx, s, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, byAsset, err := s.ListFixGroups(ctx, store.FixGroupFilter{})
	if err != nil || byAsset != 3 {
		t.Fatalf("by asset: %d, %v; want 3", byAsset, err)
	}
	raw, byFix, err := s.ListFixGroups(ctx, store.FixGroupFilter{ByFix: true})
	if err != nil || byFix != 2 || len(raw) != 2 {
		t.Fatalf("by fix: %d entries of %d, %v; want 2", len(raw), byFix, err)
	}
	var merged *fixplan.Group
	for _, r := range raw {
		var g fixplan.Group
		if err := json.Unmarshal(r, &g); err != nil {
			t.Fatal(err)
		}
		if g.FromVersion == "3.3.1" {
			merged = &g
		}
	}
	if merged == nil || len(merged.Places) != 2 || merged.FindingCount != 4 || merged.UniqueIssues != 2 {
		t.Fatalf("jquery 3.3.1 = %+v", merged)
	}
	var groups []string
	for _, p := range merged.Places {
		groups = append(groups, p.GroupID)
	}
	if _, n, err := s.ListFindings(ctx, store.FindingFilter{FixGroup: strings.Join(groups, ",")}); err != nil || n != 4 {
		t.Errorf("findings of both places: %d, %v; want 4", n, err)
	}
	// One page of one fix still brings all of its places.
	if raw, _, err := s.ListFixGroups(ctx, store.FixGroupFilter{ByFix: true, Page: store.Page{Limit: 1}}); err != nil || len(raw) != 1 {
		t.Errorf("first page: %d, %v", len(raw), err)
	}

	if v, err := s.FixGrouping(ctx); err != nil || v != store.FixGroupingFix {
		t.Errorf("default grouping = %q, %v", v, err)
	}
	if err := s.SetFixGrouping(ctx, store.FixGroupingAsset); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.FixGrouping(ctx); v != store.FixGroupingAsset {
		t.Errorf("grouping after change = %q", v)
	}
	if err := s.SetFixGrouping(ctx, "server"); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("unknown grouping: %v", err)
	}
}
