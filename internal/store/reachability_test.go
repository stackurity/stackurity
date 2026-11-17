package store_test

import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
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
			WHERE asset_id = $1 AND purl LIKE 'pkg:deb/debian/openssl@%' AND removed_at IS NULL`, assetID).Scan(&status, &ev); err != nil {
			t.Fatal(err)
		}
		return status, ev
	}

	tok := agentToken(t, s, ctx)
	b := agentBatch(mid, "read 40 processes", "pkg:deb/debian/openssl@3.0.1?distro=debian-12")
	b.Observations[0].Reachability = &model.Reachability{Status: model.ReachNotRunning,
		Evidence: []string{"no running process has libssl.so.3 loaded"}}
	r, err := s.Ingest(ctx, b, tok)
	if err != nil {
		t.Fatal(err)
	}
	if st, ev := read(r.AssetID); st != model.ReachNotRunning || len(ev) != 1 {
		t.Fatalf("after first batch: %q %v", st, ev)
	}

	// An agent that does not report reachability (older, or not opted in).
	if _, err := s.Ingest(ctx, agentBatch(mid, "", "pkg:deb/debian/openssl@3.0.1?distro=debian-12"), tok); err != nil {
		t.Fatal(err)
	}
	if st, ev := read(r.AssetID); st != model.ReachUnknown || len(ev) != 0 {
		t.Fatalf("after a batch without reachability: %q %v, want unknown", st, ev)
	}

	// The same package twice in one batch: the safer claim wins.
	b = agentBatch(mid, "read 40 processes", "pkg:deb/debian/openssl@3.0.1?distro=debian-12", "pkg:deb/debian/openssl@3.0.1?distro=debian-12")
	b.Observations[0].Reachability = &model.Reachability{Status: model.ReachNotRunning, Evidence: []string{"not loaded"}}
	b.Observations[1].Reachability = &model.Reachability{Status: model.ReachReachable, Evidence: []string{"loaded by nginx"}}
	if _, err := s.Ingest(ctx, b, tok); err != nil {
		t.Fatal(err)
	}
	if st, _ := read(r.AssetID); st != model.ReachReachable {
		t.Fatalf("duplicate rows kept %q, want reachable", st)
	}
}

// agentToken is an agent's token: a collector token bound to the host
// (mid), which a first plain report creates.
func agentToken(t *testing.T, s *store.Store, ctx context.Context) int64 {
	t.Helper()
	r, err := s.Ingest(ctx, batch(mid, true, "pkg:deb/debian/zlib1g@1?distro=debian-12"), 0)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := s.CreateAssetToken(ctx, r.AssetID, "agent", 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok.ID
}

var (
	enrolledHost = []model.Identifier{{Scheme: "machine-id", Value: "enrolled-host-0001"}}
	other        = []model.Identifier{{Scheme: "machine-id", Value: "another-host-0002"}}
)

// enrolledToken redeems an enrollment code, as agent.sh does, and has the
// agent report its host (enrolledHost) first; the other host exists too.
func enrolledToken(t *testing.T, s *store.Store, pool *pgxpool.Pool, ctx context.Context) int64 {
	t.Helper()
	if _, err := s.Ingest(ctx, batch(other, true, "pkg:deb/debian/zlib1g@1?distro=debian-12"), 0); err != nil {
		t.Fatal(err)
	}
	_, code, err := s.CreateEnrollment(ctx, store.Enrollment{Label: "fleet", UsesLeft: 5}, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemEnrollment(ctx, code, "web-9"); err != nil {
		t.Fatal(err)
	}
	var tok int64
	if err := pool.QueryRow(ctx, `SELECT token_id FROM enrollment_uses ORDER BY id DESC LIMIT 1`).Scan(&tok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, batch(enrolledHost, true, "pkg:deb/debian/zlib1g@1?distro=debian-12"), tok); err != nil {
		t.Fatal(err)
	}
	return tok
}

// agentBatch is a batch from the Linux agent; reason is its process
// reading's coverage reason ("" for none).
func agentBatch(ids []model.Identifier, reason string, purls ...string) *model.ObservationBatch {
	b := batch(ids, true, purls...)
	b.Collector.ID = model.ReachProcessCollector
	if reason != "" {
		b.Cover(model.ReachProcessScope, "checked", reason)
	}
	return b
}

// A claim that a package is not reached is stored only from the collector
// that can make it, for a type it assesses, after a whole reading; any
// other is stored as unknown, so a token cannot lower priorities by
// claiming what nothing checked.
func TestIngestUntrustedReachability(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pool := testdb.New(t)
	s := store.New(pool)
	claim := func(b *model.ObservationBatch, status string) *model.ObservationBatch {
		for i := range b.Observations {
			b.Observations[i].Reachability = &model.Reachability{Status: status, Evidence: []string{"claimed"}}
		}
		return b
	}
	deb := "pkg:deb/debian/openssl@3.0.1?distro=debian-12"
	agent := agentToken(t, s, ctx)
	plain, _, err := s.CreateToken(ctx, "ci", "collector", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	type tc struct {
		b   *model.ObservationBatch
		tok int64
	}
	// An enrolled agent's token: pinned to the first host it reports, and
	// trusted for that host only.
	enrolled := enrolledToken(t, s, pool, ctx)
	cases := map[string]tc{
		"an enrolled agent, another host": {claim(agentBatch(other, "read 40 processes", deb), model.ReachNotRunning), enrolled},
		"another collector":               {claim(batch(mid, true, deb), model.ReachNotRunning), agent},
		"a partial reading":               {claim(agentBatch(mid, "partial: read 3 processes, 9 could not be read", deb), model.ReachNotRunning), agent},
		"no process reading":              {claim(agentBatch(mid, "", deb), model.ReachNotRunning), agent},
		"not_imported from agent":         {claim(agentBatch(mid, "read 40 processes", deb), model.ReachNotImported), agent},
		"a token not an agent's":          {claim(agentBatch(mid, "read 40 processes", deb), model.ReachNotRunning), plain.ID},
		"no token (a browser)":            {claim(agentBatch(mid, "read 40 processes", deb), model.ReachNotRunning), 0},
	}
	// Its own host is trusted.
	own := claim(agentBatch(enrolledHost, "read 40 processes", deb), model.ReachNotRunning)
	r, err := s.Ingest(ctx, own, enrolled)
	if err != nil {
		t.Fatal(err)
	}
	var st string
	if err := pool.QueryRow(ctx, `SELECT reachability FROM inventory WHERE asset_id = $1 AND purl LIKE 'pkg:deb/debian/openssl@%' AND removed_at IS NULL`, r.AssetID).Scan(&st); err != nil || st != model.ReachNotRunning {
		t.Errorf("an enrolled agent on its own host: %q %v", st, err)
	}
	for name, c := range cases {
		r, err := s.Ingest(ctx, c.b, c.tok)
		if err != nil {
			t.Fatal(name, err)
		}
		var st string
		if err := pool.QueryRow(ctx, `SELECT reachability FROM inventory WHERE asset_id = $1 AND purl LIKE 'pkg:deb/debian/openssl@%' AND removed_at IS NULL`, r.AssetID).Scan(&st); err != nil {
			t.Fatal(name, err)
		}
		if st != model.ReachUnknown {
			t.Errorf("%s: stored %q, want unknown", name, st)
		}
	}
}

// A finding shows its inventory row's reachability, and a plan step added
// through PolicySteps sees it when priorities are written.
func TestFindingReachabilityAndPolicySteps(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	tok := agentToken(t, s, ctx)
	b := agentBatch(mid, "read 40 processes", "pkg:deb/debian/openssl@3.0.1?distro=debian-12")
	b.Observations[0].Reachability = &model.Reachability{Status: model.ReachNotRunning, Evidence: []string{"not loaded by any process"}}
	r, err := s.Ingest(ctx, b, tok)
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
