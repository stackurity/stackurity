package store_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// dbState is everything a preview could conceivably touch: the stored
// scores, the stored policy and the audit log.
func dbState(t *testing.T, ctx context.Context, s *store.Store) (map[string]stored, string, int64) {
	t.Helper()
	p, err := s.RiskPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var audits int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	return snapshot(t, ctx, s), p.Version(), audits
}

// A preview writes nothing, reports exactly what saving the policy and
// rescoring then stores, and only covers the caller's workspace.
func TestPreviewRiskPolicy(t *testing.T) {
	ctx, s, _ := riskFixture(t)
	now := time.Now()
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), now); err != nil {
		t.Fatal(err)
	}
	// Another workspace with the same findings must not show up.
	wsB, _, err := s.CreateWorkspace(context.Background(), "B", "", "b@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	ctxB := tenant.WithWorkspace(context.Background(), wsB.ID)
	riskFixtureIn(t, ctxB, s)
	if _, err := s.Prioritize(ctxB, risk.DefaultPolicy(), now); err != nil {
		t.Fatal(err)
	}

	proposed := risk.DefaultPolicy()
	proposed.KnownExploited = 4 // moves CVE-KEV's score, not its priority
	proposed.Thresholds.P1, proposed.Thresholds.P2, proposed.Thresholds.P3 = 8, 6, 4

	before, beforeVer, beforeAudits := dbState(t, ctx, s)
	beforeB, _, _ := dbState(t, ctxB, s)
	cur, err := s.RiskPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pv, err := s.PreviewRiskPolicy(ctx, cur, proposed, now)
	if err != nil {
		t.Fatal(err)
	}
	after, afterVer, afterAudits := dbState(t, ctx, s)
	if !reflect.DeepEqual(before, after) || beforeVer != afterVer || beforeAudits != afterAudits {
		t.Fatalf("preview wrote to the database:\n%+v %s %d\n%+v %s %d", before, beforeVer, beforeAudits, after, afterVer, afterAudits)
	}
	if afterB, _, _ := dbState(t, ctxB, s); !reflect.DeepEqual(beforeB, afterB) {
		t.Fatalf("preview changed another workspace")
	}

	if pv.Findings != 4 {
		t.Errorf("scored %d findings, want this workspace's 4", pv.Findings)
	}
	if pv.CurrentVersion != risk.DefaultPolicy().Version() || pv.ProposedVersion != proposed.Version() {
		t.Errorf("versions %s -> %s", pv.CurrentVersion, pv.ProposedVersion)
	}
	if pv.PriorityChanged != 2 || pv.Raised != 2 || pv.Lowered != 0 || pv.StoredDiffers != 0 || pv.ScoreChanged != 2 {
		t.Errorf("changes = %+v", pv)
	}
	ids := map[int64]bool{}
	fs, _, err := s.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		ids[f.ID] = true
	}
	for _, f := range pv.Sample {
		if !ids[f.ID] {
			t.Errorf("sample has finding %d from another workspace", f.ID)
		}
		if len(f.Factors) == 0 && f.ScoreBefore != f.ScoreAfter {
			t.Errorf("%s: score moved with no factor delta", f.Key)
		}
	}

	// Save it for real and rescore: the stored result is what the preview said.
	if _, err := s.ReplaceRiskPolicy(ctx, proposed, store.Actor{Type: "user", Name: "admin@x.io"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prioritize(ctx, proposed, now); err != nil {
		t.Fatal(err)
	}
	saved := snapshot(t, ctx, s)
	counts, sos := map[string]int{"P1": 0, "P2": 0, "P3": 0, "P4": 0}, 0
	for _, f := range saved {
		counts[f.Priority]++
		if f.SOS {
			sos++
		}
	}
	if !reflect.DeepEqual(counts, pv.After) || sos != pv.SOSAfter {
		t.Errorf("saved counts %v SOS %d, preview said %v SOS %d", counts, sos, pv.After, pv.SOSAfter)
	}
	inSample := map[string]bool{}
	for _, f := range pv.Sample {
		inSample[f.Key] = true
		if got := saved[f.Key]; got.Priority != f.After || float64(got.Score) != f.ScoreAfter || got.SOS != f.SOSAfter {
			t.Errorf("%s saved as %+v, preview said %s %.1f SOS %v", f.Key, got, f.After, f.ScoreAfter, f.SOSAfter)
		}
		if before[f.Key].Priority != f.Before {
			t.Errorf("%s was %s, preview said %s", f.Key, before[f.Key].Priority, f.Before)
		}
	}
	for k, f := range saved {
		if !inSample[k] && f.Priority != before[k].Priority {
			t.Errorf("%s changed priority (%s -> %s) but is not in the preview", k, before[k].Priority, f.Priority)
		}
	}
	// The policy change is attributed in the audit log.
	last, err := s.LastRiskPolicyChange(ctx)
	if err != nil || last == nil || last.ActorName != "admin@x.io" || last.AfterVersion != proposed.Version() {
		t.Errorf("last change = %+v, %v", last, err)
	}
	if last, err := s.LastRiskPolicyChange(ctxB); err != nil || last != nil {
		t.Errorf("workspace B sees a policy change: %+v %v", last, err)
	}

	// Previewing the policy in force changes nothing.
	same, err := s.PreviewRiskPolicy(ctx, proposed, proposed, now)
	if err != nil {
		t.Fatal(err)
	}
	if same.PriorityChanged != 0 || len(same.Sample) != 0 || len(same.ChangedFields) != 0 || !reflect.DeepEqual(same.Before, same.After) {
		t.Errorf("identical policy preview = %+v", same)
	}
}
