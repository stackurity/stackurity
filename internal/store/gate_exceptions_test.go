package store_test

import (
	"errors"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

func TestGateExceptionWorkflow(t *testing.T) {
	f := newGateFixture(t)
	s, ctx := f.s, f.ctx
	kev := f.create(t, store.GatePolicy{Name: "kev", Kind: store.GateKnownExploited})
	eol := f.create(t, store.GatePolicy{Name: "eol", Kind: store.GateEndOfLife})
	eng := store.Actor{Type: "user", Name: "eng"}
	sec := store.Actor{Type: "user", Name: "sec"}
	in := func(days int) *time.Time { t := time.Now().AddDate(0, 0, days); return &t }
	fid := f.kevFinding

	// Validation: reason, note, dates, targets, and the policy must apply
	// to the asset.
	for name, bad := range map[string]store.GateExceptionRequest{
		"reason":        {PolicyID: kev.ID, AssetID: f.web, TargetKind: "asset", Reason: "because", Note: "x"},
		"no note":       {PolicyID: kev.ID, AssetID: f.web, TargetKind: "asset", Reason: "mitigated", Note: "  "},
		"past":          {PolicyID: kev.ID, AssetID: f.web, TargetKind: "asset", Reason: "mitigated", Note: "x", ExpiresAt: in(-1)},
		"too long":      {PolicyID: kev.ID, AssetID: f.web, TargetKind: "asset", Reason: "mitigated", Note: "x", ExpiresAt: in(400)},
		"kind":          {PolicyID: kev.ID, AssetID: f.web, TargetKind: "host", Reason: "mitigated", Note: "x"},
		"asset+finding": {PolicyID: kev.ID, AssetID: f.web, TargetKind: "asset", FindingID: &fid, Reason: "mitigated", Note: "x"},
		"finding none":  {PolicyID: kev.ID, AssetID: f.web, TargetKind: "finding", Reason: "mitigated", Note: "x"},
		"other asset":   {PolicyID: kev.ID, AssetID: f.db, TargetKind: "finding", FindingID: &fid, Reason: "mitigated", Note: "x"},
		"no component":  {PolicyID: kev.ID, AssetID: f.web, TargetKind: "component", ComponentKey: "pkg:generic/nope", Reason: "mitigated", Note: "x"},
	} {
		if _, err := s.RequestGateException(ctx, bad, 90, eng); !errors.Is(err, store.ErrInvalidAction) {
			t.Errorf("%s: %v, want invalid", name, err)
		}
	}
	if _, err := s.RequestGateException(ctx, store.GateExceptionRequest{PolicyID: 999999, AssetID: f.web, TargetKind: "asset",
		Reason: "mitigated", Note: "x"}, 90, eng); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown policy: %v", err)
	}

	// A request for the known exploited finding on web: pending, the
	// violation still counts.
	x, err := s.RequestGateException(ctx, store.GateExceptionRequest{PolicyID: kev.ID, AssetID: f.web, TargetKind: "finding",
		FindingID: &fid, Reason: "mitigated", Note: " WAF rule blocks the exploit ", ExpiresAt: in(30)}, 90, eng)
	if err != nil {
		t.Fatal(err)
	}
	if x.Status != "pending" || x.Note != "WAF rule blocks the exploit" || x.TargetLabel != "CVE-2026-1234 in openssl 3.0.2" ||
		x.PolicyName != "kev" || x.AssetName != "web" || x.RequestedByName != "eng" || x.RequestedExpiresAt == nil || x.ExpiresAt != nil ||
		x.RuleVersion != kev.RuleVersion {
		t.Fatalf("request: %+v", x)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}), "kev@web")
	if _, err := s.RequestGateException(ctx, store.GateExceptionRequest{PolicyID: kev.ID, AssetID: f.web, TargetKind: "finding",
		FindingID: &fid, Reason: "no_fix", Note: "again"}, 90, eng); !errors.Is(err, store.ErrConflict) {
		t.Errorf("second request for the same finding: %v", err)
	}

	// Approve: the requested date stands (within the limit); the violation
	// goes. A second decision conflicts.
	x, err = s.DecideGateException(ctx, x.ID, true, "", nil, 90, sec)
	if err != nil {
		t.Fatal(err)
	}
	if x.Status != "approved" || x.DecidedByName != "sec" || x.ExpiresAt == nil || x.ExpiresAt.Sub(*x.RequestedExpiresAt).Abs() > time.Second ||
		!x.Active(time.Now()) {
		t.Fatalf("approved: %+v", x)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}))
	if _, err := s.DecideGateException(ctx, x.ID, false, "no", nil, 90, sec); !errors.Is(err, store.ErrConflict) {
		t.Errorf("decided twice: %v", err)
	}

	// The approver's date is capped at the limit.
	eolX, err := s.RequestGateException(ctx, store.GateExceptionRequest{PolicyID: eol.ID, AssetID: f.db, TargetKind: "asset",
		Reason: "accepted_risk", Note: "migrating in Q1"}, 90, eng)
	if err != nil {
		t.Fatal(err)
	}
	eolX, err = s.DecideGateException(ctx, eolX.ID, true, "ok", in(365), 30, sec)
	if err != nil {
		t.Fatal(err)
	}
	if d := eolX.ExpiresAt.Sub(time.Now().AddDate(0, 0, 30)); d.Abs() > time.Minute {
		t.Errorf("capped expiry: %v (off by %v)", eolX.ExpiresAt, d)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.db}))

	// End early: the violation returns; ending twice conflicts.
	eolX, err = s.EndGateException(ctx, eolX.ID, "the migration slipped", sec)
	if err != nil {
		t.Fatal(err)
	}
	if eolX.Status != "ended" || eolX.EndReason != "revoked" || eolX.EndNote != "the migration slipped" || eolX.EndedByName != "sec" {
		t.Errorf("ended: %+v", eolX)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.db}), "eol@db")
	if _, err := s.EndGateException(ctx, eolX.ID, "", sec); !errors.Is(err, store.ErrConflict) {
		t.Errorf("ended twice: %v", err)
	}

	// Decline needs a reason.
	comp, err := s.RequestGateException(ctx, store.GateExceptionRequest{PolicyID: kev.ID, AssetID: f.web, TargetKind: "component",
		ComponentKey: componentKey(t, f, fid), Reason: "no_fix", Note: "vendor build"}, 90, eng)
	if err != nil {
		t.Fatal(err)
	}
	if comp.TargetLabel != "openssl" {
		t.Errorf("component label: %q", comp.TargetLabel)
	}
	if _, err := s.DecideGateException(ctx, comp.ID, false, " ", nil, 90, sec); !errors.Is(err, store.ErrInvalidAction) {
		t.Errorf("decline without a note: %v", err)
	}
	if _, err := s.EndGateException(ctx, comp.ID, "", sec); !errors.Is(err, store.ErrConflict) {
		t.Errorf("end a pending request: %v", err)
	}
	comp, err = s.DecideGateException(ctx, comp.ID, false, "fix it instead", nil, 90, sec)
	if err != nil || comp.Status != "declined" || comp.DecisionNote != "fix it instead" || comp.ExpiresAt != nil {
		t.Fatalf("declined: %+v %v", comp, err)
	}

	// Expiry: the approved finding exception passes its end. Readers report
	// it as ended (expired) at once and the violation returns; the upkeep
	// tick then records it.
	if _, err := s.Pool.Exec(ctx, `UPDATE gate_policy_exceptions SET expires_at = now() - interval '1 minute' WHERE id = $1`, x.ID); err != nil {
		t.Fatal(err)
	}
	wantViolations(t, f.violations(t, store.GateViolationFilter{AssetID: f.web}), "kev@web")
	got, err := s.GetGateException(ctx, x.ID)
	if err != nil || got.Status != "ended" || got.EndReason != "expired" || got.EndedAt == nil || got.Active(time.Now()) {
		t.Fatalf("expired, before the tick: %+v %v", got, err)
	}
	if _, err := s.ExpireSuppressions(ctx); err != nil {
		t.Fatal(err)
	}
	var status, reason string
	if err := s.Pool.QueryRow(ctx, `SELECT status, end_reason FROM gate_policy_exceptions WHERE id = $1`, x.ID).Scan(&status, &reason); err != nil ||
		status != "ended" || reason != "expired" {
		t.Errorf("after the tick: %s %s %v", status, reason, err)
	}
	// A new request for the same finding is allowed once it has ended.
	if _, err := s.RequestGateException(ctx, store.GateExceptionRequest{PolicyID: kev.ID, AssetID: f.web, TargetKind: "finding",
		FindingID: &fid, Reason: "mitigated", Note: "renew"}, 90, eng); err != nil {
		t.Errorf("renewal: %v", err)
	}

	// Listing: by status (expired counts as ended), policy and asset.
	count := func(flt store.GateExceptionFilter) int64 {
		t.Helper()
		items, total, err := s.ListGateExceptions(ctx, flt)
		if err != nil {
			t.Fatal(err)
		}
		if int64(len(items)) != total {
			t.Errorf("%+v: %d items, total %d", flt, len(items), total)
		}
		return total
	}
	for _, c := range []struct {
		f    store.GateExceptionFilter
		want int64
	}{
		{store.GateExceptionFilter{}, 4},
		{store.GateExceptionFilter{Status: "pending"}, 1},
		{store.GateExceptionFilter{Status: "approved"}, 0},
		{store.GateExceptionFilter{Status: "ended"}, 2},
		{store.GateExceptionFilter{Status: "declined"}, 1},
		{store.GateExceptionFilter{PolicyID: eol.ID}, 1},
		{store.GateExceptionFilter{AssetID: f.web}, 3},
	} {
		if got := count(c.f); got != c.want {
			t.Errorf("%+v: %d, want %d", c.f, got, c.want)
		}
	}

	// The evidence pack still reads them all.
	ev, err := s.GatePolicyExceptions(ctx, time.Now().AddDate(0, 0, -1), time.Now().Add(time.Hour))
	if err != nil || len(ev) != 4 {
		t.Errorf("evidence: %d %v", len(ev), err)
	}
}

func componentKey(t *testing.T, f *gateFixture, finding int64) string {
	t.Helper()
	var k string
	if err := f.s.Pool.QueryRow(f.ctx, `SELECT c.purl_key FROM components c JOIN findings fi ON fi.component_id = c.id WHERE fi.id = $1`,
		finding).Scan(&k); err != nil {
		t.Fatal(err)
	}
	return k
}
