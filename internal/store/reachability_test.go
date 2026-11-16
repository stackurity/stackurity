package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// Reachability is stored with the inventory row, and a collector that does
// not assess it sets it back to unknown: an old claim never outlives the
// evidence for it.
func TestIngestReachability(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pool := testdb.New(t)
	s := store.New(pool)
	read := func(assetID int64) (status string, ev []string) {
		t.Helper()
		if err := pool.QueryRow(ctx, `SELECT reachability, COALESCE(reachability_evidence, '[]') FROM inventory
			WHERE asset_id = $1 AND removed_at IS NULL`, assetID).Scan(&status, &ev); err != nil {
			t.Fatal(err)
		}
		return status, ev
	}

	b := batch(mid, true, "pkg:deb/debian/openssl@3.0.1?distro=debian-12")
	b.Observations[0].Reachability = &model.Reachability{Status: model.ReachNotRunning,
		Evidence: []string{"no running process has libssl.so.3 loaded"}}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if st, ev := read(r.AssetID); st != model.ReachNotRunning || len(ev) != 1 {
		t.Fatalf("after first batch: %q %v", st, ev)
	}

	// An agent that does not report reachability (older, or not opted in).
	if _, err := s.Ingest(ctx, batch(mid, true, "pkg:deb/debian/openssl@3.0.1?distro=debian-12"), 0); err != nil {
		t.Fatal(err)
	}
	if st, ev := read(r.AssetID); st != model.ReachUnknown || len(ev) != 0 {
		t.Fatalf("after a batch without reachability: %q %v, want unknown", st, ev)
	}

	// The same package twice in one batch: the safer claim wins.
	b = batch(mid, true, "pkg:deb/debian/openssl@3.0.1?distro=debian-12", "pkg:deb/debian/openssl@3.0.1?distro=debian-12")
	b.Observations[0].Reachability = &model.Reachability{Status: model.ReachNotRunning, Evidence: []string{"not loaded"}}
	b.Observations[1].Reachability = &model.Reachability{Status: model.ReachReachable, Evidence: []string{"loaded by nginx"}}
	if _, err := s.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if st, _ := read(r.AssetID); st != model.ReachReachable {
		t.Fatalf("duplicate rows kept %q, want reachable", st)
	}
}

// A finding shows its inventory row's reachability, and a plan step added
// through PolicySteps sees it when priorities are written.
func TestFindingReachabilityAndPolicySteps(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	b := batch(mid, true, "pkg:deb/debian/openssl@3.0.1?distro=debian-12")
	b.Observations[0].Reachability = &model.Reachability{Status: model.ReachNotRunning, Evidence: []string{"not loaded by any process"}}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	syncFixByName(t, s, ctx, r.AssetID, "CVE-2099-1", map[string]string{"openssl": "3.0.2"})

	var seen []string
	s.PolicySteps = func(context.Context) []risk.Step {
		return []risk.Step{{Name: risk.StepReachability, Apply: func(in risk.Input, res *risk.Result) {
			seen = append(seen, in.Reachability)
			res.Factors = append(res.Factors, risk.Factor{Name: risk.FactorNotReached, Detail: in.ReachabilityEvidence[0]})
		}}}
	}
	p, err := s.RiskPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 1 {
		t.Fatalf("RiskPolicy did not add the plan's steps: %+v", p.Steps)
	}
	if _, err := s.Prioritize(ctx, p, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0] != model.ReachNotRunning {
		t.Fatalf("step saw %v, want [not_running]", seen)
	}
	list, _, err := s.ListFindings(ctx, store.FindingFilter{AssetID: r.AssetID})
	if err != nil || len(list) != 1 {
		t.Fatalf("findings = %v, %v", list, err)
	}
	f := list[0]
	if f.Reachability != model.ReachNotRunning || len(f.ReachabilityEvidence) != 1 || f.PriorityPolicy != p.Version() {
		t.Errorf("finding reachability = %q %v, policy %q (want %q)", f.Reachability, f.ReachabilityEvidence, f.PriorityPolicy, p.Version())
	}
}
