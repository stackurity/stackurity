package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/store"
)

// The alerts task failed with "violates foreign key constraint
// fix_groups_asset_id_fkey" when an asset was deleted while it rebuilt the
// action plan: the plan was built from findings read before the deletion
// and stored after it. The whole plan was rolled back, and the rest of the
// workspace's tick (incidents, alerts, deliveries) skipped.

// fixPlanOf reads two assets' findings and builds their plan, as the
// planner does before it stores it.
func fixPlanOf(t *testing.T, s *store.Store, ctx context.Context) (a, b int64, groups []*fixplan.Group, assign map[int64]string) {
	t.Helper()
	a = ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	b = ingestHost(t, s, ctx, "web-2", "pkg:npm/lodash@4.17.15")
	syncOpen(t, s, ctx, a, map[string]string{"CVE-L": "lodash"})
	syncOpen(t, s, ctx, b, map[string]string{"CVE-L": "lodash"})
	rows, err := s.FixPlanRows(ctx)
	if err != nil {
		t.Fatal(err)
	}
	groups, assign = fixplan.Build(rows, nil)
	for _, id := range []int64{a, b} {
		if !hasGroupFor(groups, id) {
			t.Fatalf("no fix group for asset %d in %d groups", id, len(groups))
		}
	}
	return a, b, groups, assign
}

func hasGroupFor(groups []*fixplan.Group, asset int64) bool {
	for _, g := range groups {
		if g.AssetID == asset {
			return true
		}
	}
	return false
}

// checkPlanWithout checks the stored plan has groups for kept and none for
// gone.
func checkPlanWithout(t *testing.T, s *store.Store, ctx context.Context, kept, gone int64) {
	t.Helper()
	for asset, want := range map[int64]bool{kept: true, gone: false} {
		_, n, err := s.ListFixGroups(ctx, store.FixGroupFilter{AssetID: asset, Page: store.Page{Limit: 10}})
		if err != nil {
			t.Fatal(err)
		}
		if (n > 0) != want {
			t.Errorf("asset %d: %d fix groups stored, want any: %v", asset, n, want)
		}
	}
}

// Deleted after the planner read the findings, before it stored the plan.
func TestFixPlanSkipsAssetDeletedSinceRead(t *testing.T) {
	ctx, s := loopStore(t)
	a, b, groups, assign := fixPlanOf(t, s, ctx)
	if err := s.DeleteAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceFixGroups(ctx, groups, assign); err != nil {
		t.Fatalf("storing the plan: %v", err)
	}
	checkPlanWithout(t, s, ctx, b, a)
}

// Deleted while the plan is being stored: the deletion has removed the
// asset (and its old fix groups) and not committed yet.
func TestFixPlanWaitsForAssetDeletionInFlight(t *testing.T) {
	ctx, s := loopStore(t)
	a, b, groups, assign := fixPlanOf(t, s, ctx)
	if err := s.ReplaceFixGroups(ctx, groups, assign); err != nil {
		t.Fatal(err)
	}
	del, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = del.Rollback(context.Background()) })
	if _, err := del.Exec(ctx, `DELETE FROM assets WHERE id = $1`, a); err != nil {
		t.Fatal(err)
	}
	var xid string
	if err := del.QueryRow(ctx, `SELECT pg_current_xact_id()::xid::text`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.ReplaceFixGroups(ctx, groups, assign) }()
	waitBlockedBy(t, s, xid, done)
	if err := del.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("storing the plan: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("storing the plan did not finish")
	}
	checkPlanWithout(t, s, ctx, b, a)
}

// The second check stores its results for findings read earlier: one on an
// asset being deleted is dropped, and the others are kept.
func TestSecondCheckWaitsForAssetDeletionInFlight(t *testing.T) {
	ctx, s := loopStore(t)
	a := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	b := ingestHost(t, s, ctx, "web-2", "pkg:npm/lodash@4.17.15")
	syncFix(t, s, ctx, a, map[string]string{"CVE-L": "lodash"}, map[string]string{"CVE-L": "1.0.1"})
	syncFix(t, s, ctx, b, map[string]string{"CVE-L": "lodash"}, map[string]string{"CVE-L": "1.0.1"})
	ca, cb := candidate(t, s, ctx, true, one(t, s, ctx, a, "CVE-L").ID), candidate(t, s, ctx, true, one(t, s, ctx, b, "CVE-L").ID)
	if ca == nil || cb == nil {
		t.Fatalf("candidates: %+v %+v", ca, cb)
	}
	del, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = del.Rollback(context.Background()) })
	if _, err := del.Exec(ctx, `DELETE FROM assets WHERE id = $1`, a); err != nil {
		t.Fatal(err)
	}
	var xid string
	if err := del.QueryRow(ctx, `SELECT pg_current_xact_id()::xid::text`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	type result struct {
		changed []int64
		err     error
	}
	got := make(chan result, 1)
	done := make(chan error, 1)
	go func() {
		changed, err := s.RecordSecondChecks(ctx, []store.SecondCheckResult{disagreed(ca), disagreed(cb)})
		got <- result{changed, err}
		done <- err
	}()
	waitBlockedBy(t, s, xid, done)
	if err := del.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-got:
		if r.err != nil || len(r.changed) != 1 || r.changed[0] != b {
			t.Fatalf("record: %v %v", r.changed, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("recording did not finish")
	}
	if sc, err := s.FindingSecondCheck(ctx, cb.FindingID); err != nil || sc == nil || sc.Result != store.SecondCheckDisagreed {
		t.Errorf("check of the kept asset: %+v %v", sc, err)
	}
}
