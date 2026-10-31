package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// Summaries count issues an asset gained or lost, not findings. A release
// upgrade moves most issues to new findings (new versions, renamed packages)
// and can pass through an intermediate state within one summary period; none
// of that is a new or fixed issue.
func TestSummaryCountsIssuesNotFindingChurn(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/oldlib@1.0.0", "pkg:npm/gone@1.0.0", "pkg:npm/legacy@1.0.0")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-S": "oldlib", "CVE-G": "gone", "CVE-M": "legacy"})
	// Announced and scanned an hour ago.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET announced_at = now() - interval '2 hours' WHERE id = $1`, web); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET first_seen = first_seen - interval '1 hour' WHERE asset_id = $1`, web); err != nil {
		t.Fatal(err)
	}
	from := time.Now()

	// First upgrade: oldlib is renamed to midlib and legacy to mid, both
	// still affected.
	ingestHost(t, s, ctx, "web-1", "pkg:npm/midlib@1.5.0", "pkg:npm/gone@1.0.0", "pkg:npm/mid@1.0.0")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-S": "midlib", "CVE-G": "gone", "CVE-M": "mid"})
	// Second upgrade: midlib becomes newlib (still affected), gone and mid
	// are removed, added brings a genuinely new issue.
	ingestHost(t, s, ctx, "web-1", "pkg:npm/newlib@2.0.0", "pkg:npm/added@1.0.0")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-S": "newlib", "CVE-A": "added"})
	to := time.Now().Add(time.Minute)

	keys := func(set store.IssueSet) (n int) {
		t.Helper()
		cs, err := s.CountIssues(ctx, set, from, to)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			n += c.Count
		}
		return n
	}
	// Findings: CVE-S and CVE-M were each closed twice and opened twice
	// (CVE-M's second finding closed again), CVE-G closed, CVE-A opened.
	if n := keys(store.IssuesNew); n != 1 {
		t.Errorf("new = %d, want 1 (CVE-A; CVE-S was already open on the asset)", n)
	}
	if n := keys(store.IssuesFixed); n != 2 {
		t.Errorf("fixed = %d, want 2 (CVE-G and CVE-M once each; CVE-S is still open)", n)
	}

	// Next period: nothing changes, nothing is counted.
	if cs, err := s.CountIssues(ctx, store.IssuesNew, to, to.Add(time.Hour)); err != nil || len(cs) != 0 {
		t.Errorf("next period new: %+v %v", cs, err)
	}
}

// Only an active duplicate makes an issue "already there" or "still there":
// one suppressed, accepted or marked a false positive hides nothing.
func TestSummaryIgnoredDuplicateHidesNothing(t *testing.T) {
	ctx, s := loopStore(t)
	backdate := func(asset int64) {
		t.Helper()
		if _, err := s.Pool.Exec(ctx, `UPDATE assets SET announced_at = now() - interval '2 hours' WHERE id = $1`, asset); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE findings SET first_seen = first_seen - interval '1 hour' WHERE asset_id = $1`, asset); err != nil {
			t.Fatal(err)
		}
	}
	ignore := func(asset int64, key, reason string) {
		t.Helper()
		var f store.Finding
		for _, x := range findings(t, s, ctx, store.FindingFilter{AssetID: asset, Key: key, Status: "open"}) {
			if x.ComponentName == "b" {
				f = x
			}
		}
		spec := store.IgnoreSpec{Reason: reason, Scope: store.ScopeAsset, Expiry: store.ExpiryNever}
		a := store.FindingAction{Action: "ignore", Note: "b only", Ignore: spec}
		if reason != store.ReasonFalsePositive {
			until := time.Now().Add(30 * 24 * time.Hour)
			a.Ignore.Expiry, a.Until = store.ExpiryDate, &until
		}
		if err := s.ApplyFindingAction(ctx, f.ID, a, user); err != nil {
			t.Fatal(err)
		}
	}
	count := func(set store.IssueSet, asset int64, from time.Time) (n int) {
		t.Helper()
		cs, err := s.CountIssues(ctx, set, from, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cs {
			if c.AssetID == asset {
				n += c.Count
			}
		}
		return n
	}

	// CVE-X on a and b, b a false positive: upgrading a fixes it.
	h1 := ingestHost(t, s, ctx, "h1", "pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0")
	syncOpenAll(t, s, ctx, h1, "CVE-X", "a", "b")
	ignore(h1, "CVE-X", store.ReasonFalsePositive)
	backdate(h1)
	from := time.Now()
	ingestHost(t, s, ctx, "h1", "pkg:npm/b@1.0.0")
	syncOpenAll(t, s, ctx, h1, "CVE-X", "b")
	if n := count(store.IssuesFixed, h1, from); n != 1 {
		t.Errorf("fixed = %d, want 1: the duplicate left is a false positive", n)
	}

	// CVE-Y on b, a false positive; c arrives with a real CVE-Y: new.
	h2 := ingestHost(t, s, ctx, "h2", "pkg:npm/b@1.0.0")
	syncOpenAll(t, s, ctx, h2, "CVE-Y", "b")
	ignore(h2, "CVE-Y", store.ReasonFalsePositive)
	backdate(h2)
	from = time.Now()
	ingestHost(t, s, ctx, "h2", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0")
	syncOpenAll(t, s, ctx, h2, "CVE-Y", "b", "c")
	if n := count(store.IssuesNew, h2, from); n != 1 {
		t.Errorf("new = %d, want 1: the duplicate already there is a false positive", n)
	}

	// CVE-Z on b, active when the period starts and accepted during it; c
	// arrives with CVE-Z: the asset already had the issue, not new. The
	// duplicate's state at the start comes from its history.
	h3 := ingestHost(t, s, ctx, "h3", "pkg:npm/b@1.0.0")
	syncOpenAll(t, s, ctx, h3, "CVE-Z", "b")
	backdate(h3)
	from = time.Now()
	time.Sleep(10 * time.Millisecond)
	ignore(h3, "CVE-Z", store.ReasonAcceptedRisk)
	ingestHost(t, s, ctx, "h3", "pkg:npm/b@1.0.0", "pkg:npm/c@1.0.0")
	syncOpenAll(t, s, ctx, h3, "CVE-Z", "b", "c")
	if n := count(store.IssuesNew, h3, from); n != 0 {
		t.Errorf("new = %d, want 0: the issue was active on b when the period began", n)
	}
}

// syncOpenAll opens key on every named package of the asset (syncOpen
// takes one package per key).
func syncOpenAll(t *testing.T, s *store.Store, ctx context.Context, asset int64, key string, names ...string) {
	t.Helper()
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		if r.RemovedAt != nil {
			continue
		}
		ids = append(ids, r.ID)
		for _, n := range names {
			if r.Name == n {
				in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: asset, ComponentID: r.ComponentID,
					Verification: "confirmed", Severity: "high", FixedVersion: "9.9.9", Sources: []string{"GHSA-" + key}, Evidence: map[string]any{}})
			}
		}
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveRemovedFindings(ctx); err != nil {
		t.Fatal(err)
	}
}
