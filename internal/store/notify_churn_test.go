package store_test

import (
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
