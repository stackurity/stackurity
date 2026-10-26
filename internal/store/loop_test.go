package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func loopStore(t *testing.T) (context.Context, *store.Store) {
	t.Helper()
	return tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), store.New(testdb.New(t))
}

var user = store.Actor{Type: "user", Name: "sec@x.io"}

// syncFix is syncOpen with a fixed version per key ("" for none).
func syncFix(t *testing.T, s *store.Store, ctx context.Context, asset int64, want map[string]string, fixed map[string]string) {
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
		for key, name := range want {
			if r.Name == name {
				in = append(in, store.FindingInput{Kind: "vulnerability", Key: key, InventoryID: r.ID, AssetID: asset, ComponentID: r.ComponentID,
					Verification: "confirmed", Severity: "high", FixedVersion: fixed[key], Sources: []string{"GHSA-" + key}, Evidence: map[string]any{}})
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

func findings(t *testing.T, s *store.Store, ctx context.Context, f store.FindingFilter) []store.Finding {
	t.Helper()
	if f.Status == "" {
		f.Status = "all"
	}
	out, _, err := s.ListFindings(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func one(t *testing.T, s *store.Store, ctx context.Context, asset int64, key string) store.Finding {
	t.Helper()
	fs := findings(t, s, ctx, store.FindingFilter{AssetID: asset, Key: key, Status: "open"})
	if len(fs) != 1 {
		t.Fatalf("%s on asset %d: %d open findings, want 1", key, asset, len(fs))
	}
	return fs[0]
}

func actions(t *testing.T, s *store.Store, ctx context.Context, id int64) []string {
	t.Helper()
	evs, err := s.FindingEvents(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range evs {
		out = append(out, e.Action)
	}
	return out
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// An issue that was fixed by an upgrade or removal and comes back on the
// same asset is regressed; one closed only because the intelligence changed,
// or an upgrade that left the component vulnerable, is not.
func TestRegressed(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L": "lodash", "CVE-E": "express"})
	lodash := one(t, s, ctx, web, "CVE-L")
	if err := s.ApplyFindingAction(ctx, lodash.ID, store.FindingAction{Action: "start"}, user); err != nil {
		t.Fatal(err)
	}

	// The intelligence stops matching CVE-E and matches it again: reopened,
	// not regressed.
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L": "lodash"})
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L": "lodash", "CVE-E": "express"})
	if f := one(t, s, ctx, web, "CVE-E"); f.RegressedAt != nil || f.DisplayState != "new" {
		t.Errorf("re-evaluated issue: regressed_at %v, display %s; want not regressed", f.RegressedAt, f.DisplayState)
	}

	// lodash is removed (fixed), then the same version is back: regressed.
	ingestHost(t, s, ctx, "web-1", "pkg:npm/express@4.0.0")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-E": "express"})
	if n := len(findings(t, s, ctx, store.FindingFilter{AssetID: web, Key: "CVE-L", Status: "open"})); n != 0 {
		t.Fatalf("CVE-L open after removal: %d", n)
	}
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L": "lodash", "CVE-E": "express"})
	f := one(t, s, ctx, web, "CVE-L")
	if f.ID != lodash.ID || f.RegressedAt == nil || f.DisplayState != "regressed" || f.State != "new" {
		t.Fatalf("came back: id %d (was %d), regressed_at %v, display %s, state %s; want the same finding regressed and back to new",
			f.ID, lodash.ID, f.RegressedAt, f.DisplayState, f.State)
	}
	if a := actions(t, s, ctx, f.ID); !has(a, "regressed") || !has(a, "reopened") || !has(a, "resolved") {
		t.Errorf("history %v keeps resolved, reopened and regressed", a)
	}
	sum, err := s.SummarizeFindings(ctx)
	if err != nil || sum.Regressed != 1 {
		t.Errorf("summary regressed = %d, %v; want 1", sum.Regressed, err)
	}
	if got := findings(t, s, ctx, store.FindingFilter{State: "regressed"}); len(got) != 1 || got[0].Key != "CVE-L" {
		t.Errorf("state=regressed lists %d findings", len(got))
	}
	// Starting work on it shows it in progress.
	if err := s.ApplyFindingAction(ctx, f.ID, store.FindingAction{Action: "start"}, user); err != nil {
		t.Fatal(err)
	}
	if f := one(t, s, ctx, web, "CVE-L"); f.DisplayState != "in_progress" {
		t.Errorf("started: display %s, want in_progress", f.DisplayState)
	}
}

func TestRegressedOnANewVersion(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L": "lodash"})

	// An upgrade that is still vulnerable: a new finding on the new
	// version, not a regression, whichever order the matcher closes the old
	// one in.
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.16")
	if _, err := s.ResolveRemovedFindings(ctx); err != nil { // another asset's evaluation ran first
		t.Fatal(err)
	}
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L": "lodash"})
	if f := one(t, s, ctx, web, "CVE-L"); f.RegressedAt != nil || f.Version != "4.17.16" {
		t.Fatalf("upgrade still vulnerable: version %s regressed_at %v; want not regressed", f.Version, f.RegressedAt)
	}

	// Fixed by an upgrade, then a downgrade brings it back on a new version.
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.21")
	syncOpen(t, s, ctx, web, nil)
	time.Sleep(10 * time.Millisecond)
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.10")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L": "lodash"})
	f := one(t, s, ctx, web, "CVE-L")
	if f.RegressedAt == nil || f.DisplayState != "regressed" || f.Version != "4.17.10" {
		t.Fatalf("downgrade: version %s regressed_at %v display %s; want regressed", f.Version, f.RegressedAt, f.DisplayState)
	}
	if a := actions(t, s, ctx, f.ID); !has(a, "regressed") {
		t.Errorf("history %v has no regressed event", a)
	}
	// Notifications: announced once.
	counts, upto, err := s.RegressedToAnnounce(ctx)
	if err != nil || len(counts) != 1 || counts[0].Count != 1 || counts[0].AssetID != web {
		t.Fatalf("to announce: %+v %v", counts, err)
	}
	if err := s.MarkRegressedNotified(ctx, upto); err != nil {
		t.Fatal(err)
	}
	if counts, _, err := s.RegressedToAnnounce(ctx); err != nil || len(counts) != 0 {
		t.Errorf("announced twice: %+v %v", counts, err)
	}
	rc, err := s.CountIssues(ctx, store.IssuesRegressed, time.Now().Add(-time.Hour), time.Now().Add(time.Minute))
	if err != nil || len(rc) != 1 {
		t.Errorf("summary count of regressed: %+v %v", rc, err)
	}
}

// Snoozed until a fix ships: the issue returns on its own when a free fixed
// version appears, and Home's hidden counts keep counting it meanwhile.
func TestSnoozeUntilFix(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash", "CVE-E": "express"}, map[string]string{"CVE-E": "4.0.1"})
	l, e := one(t, s, ctx, web, "CVE-L"), one(t, s, ctx, web, "CVE-E")

	if err := s.ApplyFindingAction(ctx, e.ID, store.FindingAction{Action: "suppress", Note: "later", UntilFix: true}, user); !errors.Is(err, store.ErrInvalidAction) {
		t.Errorf("snooze until a fix when one exists: %v, want invalid", err)
	}
	if err := s.ApplyFindingAction(ctx, l.ID, store.FindingAction{Action: "suppress", Note: "no fix yet", UntilFix: true}, user); err != nil {
		t.Fatal(err)
	}
	f := one(t, s, ctx, web, "CVE-L")
	if f.State != "suppressed" || !f.UntilFix || f.SuppressedUntil == nil || f.DisplayState != "snoozed" {
		t.Fatalf("snoozed: %+v", f)
	}
	if n, err := s.ExpireSuppressions(ctx); err != nil || n != 0 {
		t.Fatalf("nothing should return yet: %d %v", n, err)
	}
	sum, err := s.SummarizeFindings(ctx)
	if err != nil || sum.ByState["suppressed"] != 1 || sum.UntilFix != 1 {
		t.Fatalf("summary while waiting: suppressed %d until_fix %d %v", sum.ByState["suppressed"], sum.UntilFix, err)
	}
	// A fix only in a paid subscription does not count.
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET fixed_version = '4.17.21', evidence = '{"requires_ubuntu_pro": true}' WHERE id = $1`, l.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.ExpireSuppressions(ctx); n != 0 {
		t.Fatalf("a paid-only fix returned the issue")
	}
	// The intelligence now has a free fixed version.
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash", "CVE-E": "express"}, map[string]string{"CVE-L": "4.17.21", "CVE-E": "4.0.1"})
	if n, err := s.ExpireSuppressions(ctx); err != nil || n != 1 {
		t.Fatalf("fix shipped: returned %d, %v; want 1", n, err)
	}
	f = one(t, s, ctx, web, "CVE-L")
	if f.State != "new" || f.UntilFix || f.SuppressedUntil != nil {
		t.Errorf("returned: state %s until_fix %v until %v", f.State, f.UntilFix, f.SuppressedUntil)
	}
	if a := actions(t, s, ctx, f.ID); !has(a, "fix_available") {
		t.Errorf("history %v has no fix_available event", a)
	}
}

// Ignore with scope everywhere covers every asset with the issue, including
// assets and findings that appear later; asset scope covers only its asset.
func TestIgnoreEverywhere(t *testing.T) {
	ctx, s := loopStore(t)
	a := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	b := ingestHost(t, s, ctx, "web-2", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	for _, asset := range []int64{a, b} {
		syncOpen(t, s, ctx, asset, map[string]string{"CVE-L": "lodash", "CVE-E": "express"})
	}
	fp := store.FindingAction{Action: "ignore", Note: "not reachable: we never call merge", Ignore: store.IgnoreSpec{
		Reason: store.ReasonFalsePositive, Scope: store.ScopeEverywhere, Expiry: store.ExpiryNever}}
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, a, "CVE-L").ID, fp, user); err != nil {
		t.Fatal(err)
	}
	for _, asset := range []int64{a, b} {
		f := one(t, s, ctx, asset, "CVE-L")
		if f.State != "risk_accepted" || f.IgnoreReason != store.ReasonFalsePositive || f.Verification != "rejected" ||
			f.SuppressedUntil != nil || f.ExceptionID == nil || f.DisplayState != "accepted" {
			t.Errorf("asset %d after ignore everywhere: %+v", asset, f)
		}
	}
	// Asset scope: only that asset.
	mit := store.FindingAction{Action: "ignore", Note: "WAF rule 942100", Mitigation: "WAF", Until: ptr(time.Now().AddDate(0, 1, 0)),
		Ignore: store.IgnoreSpec{Reason: store.ReasonMitigated, Scope: store.ScopeAsset, Expiry: store.ExpiryDate}}
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, a, "CVE-E").ID, mit, user); err != nil {
		t.Fatal(err)
	}
	if f := one(t, s, ctx, b, "CVE-E"); f.State != "new" {
		t.Errorf("asset scope reached another asset: %s", f.State)
	}
	// A second ignore with the same scope replaces the rule; what the old
	// rule ignored follows the new one.
	until := time.Now().AddDate(0, 0, 3)
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, b, "CVE-E").ID, store.FindingAction{Action: "ignore", Note: "short", Until: &until,
		Ignore: store.IgnoreSpec{Reason: store.ReasonAcceptedRisk, Scope: store.ScopeEverywhere, Expiry: store.ExpiryDate}}, user); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, b, "CVE-E").ID, store.FindingAction{Action: "reopen"}, user); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, a, "CVE-E").ID, store.FindingAction{Action: "reopen"}, user); err != nil {
		t.Fatal(err)
	}
	ev := store.FindingAction{Action: "ignore", Note: "first", Until: &until,
		Ignore: store.IgnoreSpec{Reason: store.ReasonAcceptedRisk, Scope: store.ScopeAsset, Expiry: store.ExpiryDate}}
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, a, "CVE-E").ID, ev, user); err != nil {
		t.Fatal(err)
	}
	first := one(t, s, ctx, a, "CVE-E").ExceptionID
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, a, "CVE-E").ID, store.FindingAction{Action: "reopen"}, user); err != nil {
		t.Fatal(err)
	}
	ev.Note, ev.Ignore.Reason = "second", store.ReasonMitigated
	if err := s.ApplyFindingAction(ctx, one(t, s, ctx, a, "CVE-E").ID, ev, user); err != nil {
		t.Fatal(err)
	}
	if f := one(t, s, ctx, a, "CVE-E"); f.ExceptionID == nil || *f.ExceptionID == *first || f.IgnoreReason != store.ReasonMitigated || f.StateReason != "second" {
		t.Errorf("replaced rule: %+v", f)
	}

	// A host added later, and a new version on an existing host.
	c := ingestHost(t, s, ctx, "web-3", "pkg:npm/lodash@4.17.15")
	syncOpen(t, s, ctx, c, map[string]string{"CVE-L": "lodash"})
	ingestHost(t, s, ctx, "web-2", "pkg:npm/lodash@4.17.16", "pkg:npm/express@4.0.0")
	syncOpen(t, s, ctx, b, map[string]string{"CVE-L": "lodash", "CVE-E": "express"})
	for _, asset := range []int64{b, c} {
		if f := one(t, s, ctx, asset, "CVE-L"); f.State != "risk_accepted" || f.Verification != "rejected" {
			t.Errorf("found later on asset %d: state %s verification %s; want ignored", asset, f.State, f.Verification)
		}
	}
	// The matcher keeps a false positive rejected.
	syncOpen(t, s, ctx, c, map[string]string{"CVE-L": "lodash"})
	if f := one(t, s, ctx, c, "CVE-L"); f.Verification != "rejected" {
		t.Errorf("re-evaluation reset verification to %s", f.Verification)
	}

	// Reopening one finding detaches it: the rule does not ignore it again.
	cf := one(t, s, ctx, c, "CVE-L")
	if err := s.ApplyFindingAction(ctx, cf.ID, store.FindingAction{Action: "reopen"}, user); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyExceptions(ctx); err != nil {
		t.Fatal(err)
	}
	if f := one(t, s, ctx, c, "CVE-L"); f.State != "new" || f.Verification != "confirmed" || f.IgnoreReason != "" {
		t.Errorf("reopened: state %s verification %s reason %q", f.State, f.Verification, f.IgnoreReason)
	}

	rules, _, err := s.ListIgnoreRules(ctx, false, store.Page{})
	if err != nil || len(rules) != 3 {
		t.Fatalf("rules: %+v %v", rules, err)
	}
	var everywhere store.IgnoreRule
	for _, r := range rules {
		if r.Scope == "everywhere" {
			everywhere = r
		}
	}
	if everywhere.Findings != 2 || everywhere.Reason != store.ReasonFalsePositive {
		t.Errorf("everywhere rule: %+v; want 2 findings", everywhere)
	}
	// Ending the rule returns what it ignores.
	n, err := s.EndIgnoreRule(ctx, everywhere.ID, user)
	if err != nil || n != 2 {
		t.Fatalf("end rule: %d %v", n, err)
	}
	for _, asset := range []int64{a, b} {
		if f := one(t, s, ctx, asset, "CVE-L"); f.State != "new" || f.Verification != "confirmed" {
			t.Errorf("after the rule ended, asset %d: %s %s", asset, f.State, f.Verification)
		}
	}
	if _, err := s.EndIgnoreRule(ctx, everywhere.ID, user); !errors.Is(err, store.ErrConflict) {
		t.Errorf("ending twice: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestIgnoreExpiryAndLimits(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash", "CVE-E": "express"}, map[string]string{"CVE-L": "4.17.21"})
	f := one(t, s, ctx, web, "CVE-L")

	bad := []store.IgnoreSpec{
		{Reason: "because", Scope: "asset", Expiry: "never"},
		{Reason: store.ReasonAcceptedRisk, Scope: "asset", Expiry: "never"}, // only false positives never expire
		{Reason: store.ReasonAcceptedRisk, Scope: "galaxy", Expiry: "date"},
		{Reason: store.ReasonAcceptedRisk, Scope: "asset", Expiry: "date"}, // no date
	}
	for _, sp := range bad {
		if err := s.ApplyFindingAction(ctx, f.ID, store.FindingAction{Action: "ignore", Note: "x", Ignore: sp}, user); !errors.Is(err, store.ErrInvalidAction) {
			t.Errorf("%+v: %v, want invalid", sp, err)
		}
	}
	tooLate := time.Now().AddDate(0, 0, 40)
	if err := s.ApplyFindingAction(ctx, f.ID, store.FindingAction{Action: "ignore", Note: "x", Until: &tooLate, MaxDays: 30,
		Ignore: store.IgnoreSpec{Reason: store.ReasonAcceptedRisk, Expiry: store.ExpiryDate}}, user); !errors.Is(err, store.ErrInvalidAction) {
		t.Errorf("past the exception limit: %v", err)
	}
	until := time.Now().AddDate(0, 0, 10)
	if err := s.ApplyFindingAction(ctx, f.ID, store.FindingAction{Action: "ignore", Note: "accepted for the sprint", Until: &until,
		Ignore: store.IgnoreSpec{Reason: store.ReasonAcceptedRisk, Scope: store.ScopeEverywhere, Expiry: store.ExpiryDate}}, user); err != nil {
		t.Fatal(err)
	}
	// Until a fix ships keeps the exception limit as a backstop.
	e := one(t, s, ctx, web, "CVE-E")
	if err := s.ApplyFindingAction(ctx, e.ID, store.FindingAction{Action: "ignore", Note: "no fix", MaxDays: 30,
		Ignore: store.IgnoreSpec{Reason: store.ReasonNoFix, Expiry: store.ExpiryUntilFix}}, user); err != nil {
		t.Fatal(err)
	}
	if e = one(t, s, ctx, web, "CVE-E"); !e.UntilFix || e.SuppressedUntil == nil || e.SuppressedUntil.After(time.Now().AddDate(0, 0, 31)) {
		t.Errorf("until a fix: until_fix %v backstop %v", e.UntilFix, e.SuppressedUntil)
	}

	// The date passes: the issue returns to new with an event, the rule ends.
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET suppressed_until = now() - interval '1 minute' WHERE id = $1`, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE finding_exceptions SET expires_at = now() - interval '1 minute' WHERE reason = 'accepted_risk'`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.ExpireSuppressions(ctx); err != nil || n != 1 {
		t.Fatalf("expired %d, %v; want 1", n, err)
	}
	got := one(t, s, ctx, web, "CVE-L")
	if got.State != "new" || got.IgnoreReason != "" || got.SuppressedUntil != nil {
		t.Errorf("expired: %+v", got)
	}
	evs, _ := s.FindingEvents(ctx, f.ID)
	last := evs[len(evs)-1]
	if last.Action != "expired" || last.FromState != "risk_accepted" || last.ToState != "new" {
		t.Errorf("expiry event: %+v", last)
	}
	rules, _, _ := s.ListIgnoreRules(ctx, true, store.Page{})
	for _, r := range rules {
		if r.Reason == store.ReasonAcceptedRisk && (r.EndedAt == nil || r.EndedReason != "expired") {
			t.Errorf("expired rule still active: %+v", r)
		}
	}
	// An ended rule ignores nothing found later.
	other := ingestHost(t, s, ctx, "web-2", "pkg:npm/lodash@4.17.15")
	syncFix(t, s, ctx, other, map[string]string{"CVE-L": "lodash"}, map[string]string{"CVE-L": "4.17.21"})
	if f := one(t, s, ctx, other, "CVE-L"); f.State != "new" {
		t.Errorf("expired rule applied to a new asset: %s", f.State)
	}
}

// The approval inbox: a request records who, why, scope and expiry, and
// only a pending request can be decided, once.
func TestIgnoreRequests(t *testing.T) {
	ctx, s := loopStore(t)
	a := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	b := ingestHost(t, s, ctx, "web-2", "pkg:npm/lodash@4.17.15")
	syncFix(t, s, ctx, a, map[string]string{"CVE-L": "lodash", "CVE-E": "express"}, map[string]string{"CVE-E": "4.0.1"})
	syncFix(t, s, ctx, b, map[string]string{"CVE-L": "lodash"}, nil)
	eng := store.Actor{Type: "user", Name: "eng@x.io"}
	l := one(t, s, ctx, a, "CVE-L")
	if _, err := s.CreateIgnoreRequest(ctx, store.NewIgnoreRequest{FindingIDs: []int64{one(t, s, ctx, a, "CVE-E").ID}, IgnoreSpec: store.IgnoreSpec{
		Reason: store.ReasonNoFix, Expiry: store.ExpiryUntilFix, Note: "x"}}, 0, eng); !errors.Is(err, store.ErrInvalidAction) {
		t.Errorf("until a fix for an issue with a fix: %v", err)
	}

	if _, err := s.CreateIgnoreRequest(ctx, store.NewIgnoreRequest{FindingIDs: []int64{l.ID, 999999}, IgnoreSpec: store.IgnoreSpec{
		Reason: store.ReasonMitigated, Expiry: store.ExpiryUntilFix, Note: "x"}}, 0, eng); !errors.Is(err, store.ErrInvalidAction) {
		t.Errorf("unknown finding: %v", err)
	}
	if _, err := s.CreateIgnoreRequest(ctx, store.NewIgnoreRequest{FindingIDs: []int64{l.ID}, IgnoreSpec: store.IgnoreSpec{
		Reason: store.ReasonMitigated, Expiry: store.ExpiryUntilFix}}, 0, eng); !errors.Is(err, store.ErrInvalidAction) {
		t.Errorf("no reason given: %v", err)
	}
	req, err := s.CreateIgnoreRequest(ctx, store.NewIgnoreRequest{FindingIDs: []int64{l.ID}, IgnoreSpec: store.IgnoreSpec{
		Reason: store.ReasonMitigated, Scope: store.ScopeEverywhere, Expiry: store.ExpiryUntilFix, Note: "behind the WAF", Mitigation: "WAF"}}, 0, eng)
	if err != nil {
		t.Fatal(err)
	}
	if req.Status != "pending" || req.RequestedByName != "eng@x.io" || req.Title != "CVE-L in lodash on web-1" || req.Scope != "everywhere" {
		t.Errorf("request: %+v", req)
	}
	if f := one(t, s, ctx, a, "CVE-L"); f.State != "new" {
		t.Errorf("a request changed the issue: %s", f.State)
	}
	list, n, err := s.ListIgnoreRequests(ctx, store.IgnoreRequestFilter{Status: "pending"})
	if err != nil || n != 1 || len(list) != 1 {
		t.Fatalf("pending: %d %v", n, err)
	}

	got, err := s.DecideIgnoreRequest(ctx, req.ID, true, "ok, WAF covers it", 0, user)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "approved" || got.DecidedByName != "sec@x.io" || got.Applied != 1 || got.DecidedAt == nil {
		t.Errorf("approved: %+v", got)
	}
	for _, asset := range []int64{a, b} {
		if f := one(t, s, ctx, asset, "CVE-L"); f.State != "risk_accepted" || f.IgnoreReason != store.ReasonMitigated || !f.UntilFix {
			t.Errorf("asset %d after approval: %s %s %v", asset, f.State, f.IgnoreReason, f.UntilFix)
		}
	}
	if _, err := s.DecideIgnoreRequest(ctx, req.ID, false, "", 0, user); !errors.Is(err, store.ErrConflict) {
		t.Errorf("deciding twice: %v", err)
	}
	// Declined: nothing changes.
	e := one(t, s, ctx, a, "CVE-E")
	req2, err := s.CreateIgnoreRequest(ctx, store.NewIgnoreRequest{FindingIDs: []int64{e.ID}, IgnoreSpec: store.IgnoreSpec{
		Reason: store.ReasonAcceptedRisk, Expiry: store.ExpiryDate, Until: ptr(time.Now().AddDate(0, 0, 7)), Note: "later"}}, 0, eng)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.DecideIgnoreRequest(ctx, req2.ID, false, "fix it instead", 0, user); err != nil || got.Status != "declined" || got.Applied != 0 {
		t.Fatalf("declined: %+v %v", got, err)
	}
	if f := one(t, s, ctx, a, "CVE-E"); f.State != "new" {
		t.Errorf("declined request changed the issue: %s", f.State)
	}
}

// checkFixture is a host with two issues fixed by one package upgrade (a fix
// group) and one on another package.
func checkFixture(t *testing.T) (context.Context, *store.Store, int64, string) {
	t.Helper()
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	syncOpen(t, s, ctx, web, map[string]string{"CVE-L1": "lodash", "CVE-L2": "lodash", "CVE-E": "express"})
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Rebuild(ctx, s, time.Now()); err != nil {
		t.Fatal(err)
	}
	l := one(t, s, ctx, web, "CVE-L1")
	if l.FixGroup == "" || one(t, s, ctx, web, "CVE-L2").FixGroup != l.FixGroup {
		t.Fatalf("lodash issues share no fix group: %q", l.FixGroup)
	}
	return ctx, s, web, l.FixGroup
}

// report sends a new complete collection and evaluates it, as the agent and
// the evaluate job would.
func report(t *testing.T, s *store.Store, ctx context.Context, asset int64, want map[string]string, purls ...string) {
	t.Helper()
	time.Sleep(5 * time.Millisecond)
	start, err := s.DBNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ingestHost(t, s, ctx, "web-1", purls...)
	syncOpen(t, s, ctx, asset, want)
	if err := s.MarkEvaluated(ctx, asset, start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	// The evaluate job the ingest queued has run.
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE done_at IS NULL`); err != nil {
		t.Fatal(err)
	}
}

func TestCheckAgainLifecycle(t *testing.T) {
	ctx, s, web, group := checkFixture(t)
	c, created, err := s.RequestCheck(ctx, store.CheckRequest{FixGroup: group}, user)
	if err != nil || !created {
		t.Fatalf("request: %v %v", created, err)
	}
	if c.AssetID != web || c.Method != store.CheckAgent || c.Status != "waiting" || c.OpenBefore != 2 || c.FixTitle == "" {
		t.Fatalf("check: %+v", c)
	}
	// Asking again while it waits returns the same check.
	if again, created, err := s.RequestCheck(ctx, store.CheckRequest{FixGroup: group}, user); err != nil || created || again.ID != c.ID {
		t.Errorf("second request: %v %v %v", again, created, err)
	}
	// Another asset's agent is not asked; this one is.
	if due, err := s.AgentCheckDue(ctx, []int64{web + 1000}); err != nil || due {
		t.Errorf("other asset: %v %v", due, err)
	}
	if due, err := s.AgentCheckDue(ctx, []int64{web}); err != nil || !due {
		t.Fatalf("agent poll: %v %v", due, err)
	}
	if c, _ = s.GetCheck(ctx, c.ID); c.PickedUpAt == nil || c.AgentPolledAt == nil {
		t.Errorf("picked up: %+v", c)
	}
	// The report arrives; until it is evaluated the check is evaluating and
	// the agent is not asked again.
	time.Sleep(5 * time.Millisecond)
	ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.21", "pkg:npm/express@4.0.0")
	if c, _ = s.GetCheck(ctx, c.ID); c.Status != "evaluating" {
		t.Errorf("after the report: %s", c.Status)
	}
	if due, _ := s.AgentCheckDue(ctx, []int64{web}); due {
		t.Error("agent asked to report again after it reported")
	}
	if n, err := s.CompleteChecks(ctx); err != nil || n != 0 {
		t.Fatalf("completed before evaluation: %d %v", n, err)
	}
	start, _ := s.DBNow(ctx)
	syncOpen(t, s, ctx, web, map[string]string{"CVE-E": "express"})
	if err := s.MarkEvaluated(ctx, web, start); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE done_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CompleteChecks(ctx); err != nil || n != 1 {
		t.Fatalf("complete: %d %v", n, err)
	}
	c, _ = s.GetCheck(ctx, c.ID)
	if c.Outcome != "passed" || c.Fixed != 2 || c.Remaining != 0 || c.CompletedAt == nil || c.Status != "done" || c.CollectionID == nil {
		t.Errorf("passed: %+v", c)
	}
	list, n, err := s.ListChecks(ctx, store.CheckFilter{FixGroup: group})
	if err != nil || n != 1 || list[0].ID != c.ID {
		t.Errorf("list by fix: %d %v", n, err)
	}
}

func TestCheckOutcomes(t *testing.T) {
	ctx, s, web, group := checkFixture(t)
	// Partly fixed: an upgrade that closes one of the fix's two issues (the
	// other stays, on the new version's finding).
	partly, _, err := s.RequestCheck(ctx, store.CheckRequest{FixGroup: group}, user)
	if err != nil {
		t.Fatal(err)
	}
	whole, _, err := s.RequestCheck(ctx, store.CheckRequest{AssetID: web}, user)
	if err != nil || whole.ID == partly.ID || whole.OpenBefore != 3 {
		t.Fatalf("asset check: %+v %v", whole, err)
	}
	report(t, s, ctx, web, map[string]string{"CVE-L2": "lodash", "CVE-E": "express", "CVE-NEW": "express"},
		"pkg:npm/lodash@4.17.16", "pkg:npm/express@4.0.0")
	if n, err := s.CompleteChecks(ctx); err != nil || n != 2 {
		t.Fatalf("completed %d %v", n, err)
	}
	if c, _ := s.GetCheck(ctx, partly.ID); c.Outcome != "partly_fixed" || c.Fixed != 1 || c.Remaining != 1 {
		t.Errorf("partly fixed: %+v", c)
	}
	if c, _ := s.GetCheck(ctx, whole.ID); c.Outcome != "partly_fixed" || c.Fixed != 1 || c.Remaining != 2 || c.NewIssues != 1 {
		t.Errorf("asset check: %+v", c)
	}

	// Still open: nothing changed. The action plan has regrouped the
	// remaining issue (on the new version) by now.
	if _, err := planner.Rebuild(ctx, s, time.Now()); err != nil {
		t.Fatal(err)
	}
	group = one(t, s, ctx, web, "CVE-L2").FixGroup
	still, _, err := s.RequestCheck(ctx, store.CheckRequest{FixGroup: group}, user)
	if err != nil {
		t.Fatal(err)
	}
	report(t, s, ctx, web, map[string]string{"CVE-L2": "lodash", "CVE-E": "express", "CVE-NEW": "express"},
		"pkg:npm/lodash@4.17.16", "pkg:npm/express@4.0.0")
	if _, err := s.CompleteChecks(ctx); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetCheck(ctx, still.ID); c.Outcome != "still_open" || c.Fixed != 0 || c.Remaining != 1 {
		t.Errorf("still open: %+v", c)
	}

	// No report within 7 days: expired.
	old, _, err := s.RequestCheck(ctx, store.CheckRequest{AssetID: web}, user)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE checks SET requested_at = now() - interval '8 days' WHERE id = $1`, old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE collections SET received_at = now() - interval '9 days'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteChecks(ctx); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.GetCheck(ctx, old.ID); c.Outcome != "expired" {
		t.Errorf("expired: %+v", c)
	}
	if store.CheckOutcome(0, 0) != "passed" || store.CheckOutcome(2, 1) != "partly_fixed" || store.CheckOutcome(0, 3) != "still_open" {
		t.Error("CheckOutcome")
	}
}

// "I applied this" sets the fix's issues in progress and never resolves
// anything: only the fresh report does.
func TestFixAppliedResolvesNothing(t *testing.T) {
	ctx, s, web, group := checkFixture(t)
	n, err := s.MarkFixApplied(ctx, group, user)
	if err != nil || n != 2 {
		t.Fatalf("applied: %d %v", n, err)
	}
	for _, key := range []string{"CVE-L1", "CVE-L2"} {
		f := one(t, s, ctx, web, key)
		if f.Status != "open" || f.State != "in_progress" || f.StateReason != "applied, waiting for a check" {
			t.Errorf("%s: %s %s %q", key, f.Status, f.State, f.StateReason)
		}
		if a := actions(t, s, ctx, f.ID); !has(a, "applied") {
			t.Errorf("%s history %v", key, a)
		}
	}
	if f := one(t, s, ctx, web, "CVE-E"); f.State != "new" {
		t.Errorf("another fix's issue changed: %s", f.State)
	}
	if _, err := s.MarkFixApplied(ctx, "no-such-fix", user); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown fix: %v", err)
	}
	// Without a new report nothing completes and nothing is resolved.
	c, _, err := s.RequestCheck(ctx, store.CheckRequest{FixGroup: group, Reason: "applied"}, user)
	if err != nil || c.Reason != "applied" {
		t.Fatalf("check: %+v %v", c, err)
	}
	if n, _ := s.CompleteChecks(ctx); n != 0 {
		t.Errorf("a check completed without a report")
	}
	if open := findings(t, s, ctx, store.FindingFilter{AssetID: web, Status: "open"}); len(open) != 3 {
		t.Errorf("open issues: %d, want 3", len(open))
	}
}

// Checks of a repository with a server-side scan, or with uploads only.
func TestCheckMethods(t *testing.T) {
	ctx, s := loopStore(t)
	b := model.NewBatch(model.Collector{ID: "scan", Version: "1", Method: "lockfile"},
		model.AssetRef{Kind: model.AssetRepository, Name: "github.com/x/app", Identifiers: []model.Identifier{{Scheme: "repo-url", Value: "https://github.com/x/app"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := s.RequestCheck(ctx, store.CheckRequest{AssetID: r.AssetID}, user)
	if err != nil || c.Method != store.CheckReport || c.IntegrationID != nil {
		t.Fatalf("uploaded repository: %+v %v", c, err)
	}
	if _, _, err := s.RequestCheck(ctx, store.CheckRequest{AssetID: 999999}, user); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown asset: %v", err)
	}
	if _, _, err := s.RequestCheck(ctx, store.CheckRequest{FixGroup: "nope"}, user); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown fix: %v", err)
	}
}
