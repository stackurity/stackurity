package store_test

import (
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
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
	focus, err := s.SummarizeFixFocus(ctx, 0, prod)
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
