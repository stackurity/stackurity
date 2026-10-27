package store_test

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

func candidate(t *testing.T, s *store.Store, ctx context.Context, all bool, id int64) *store.SecondCheckCandidate {
	t.Helper()
	cs, err := s.SecondCheckCandidates(ctx, 1000, all)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.FindingID == id {
			return &c
		}
	}
	return nil
}

func disagreed(c *store.SecondCheckCandidate) store.SecondCheckResult {
	return store.SecondCheckResult{FindingID: c.FindingID, AssetID: c.AssetID, Basis: c.Basis, Result: store.SecondCheckDisagreed,
		Reason:      "fixed version: the matcher says 1.0.1, the second check finds 1.0.2",
		Differences: []store.SecondCheckDifference{{Field: "fixed_version", Matcher: "1.0.1", Independent: "1.0.2"}},
		Kind:        c.Kind, Key: c.Key, Purl: c.Purl, Version: c.Version, Inputs: map[string]any{"records": []string{}}}
}

// A disagreement is shown and kept while the match stands, through
// re-evaluation, without touching verification (so never priority or SOS);
// a new match is checked again.
func TestSecondCheckDisagreementHoldsUntilTheMatchChanges(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash"}, map[string]string{"CVE-L": "1.0.1"})
	f := one(t, s, ctx, web, "CVE-L")
	c := candidate(t, s, ctx, true, f.ID)
	if c == nil || c.Purl != "pkg:npm/lodash@4.17.15" || c.Version != "4.17.15" {
		t.Fatalf("candidate: %+v", c)
	}
	changed, err := s.RecordSecondChecks(ctx, []store.SecondCheckResult{disagreed(c)})
	if err != nil || len(changed) != 1 || changed[0] != web {
		t.Fatalf("record: %v %v", changed, err)
	}
	f = one(t, s, ctx, web, "CVE-L")
	if f.Verification != "confirmed" || f.SecondCheck != store.SecondCheckDisagreed || !has(actions(t, s, ctx, f.ID), "second_check_disagreed") {
		t.Fatalf("after a disagreement: %s %v", f.Verification, actions(t, s, ctx, f.ID))
	}
	sc, err := s.FindingSecondCheck(ctx, f.ID)
	if err != nil || sc == nil || sc.Result != store.SecondCheckDisagreed || len(sc.Differences) != 1 {
		t.Fatalf("check: %+v %v", sc, err)
	}
	if got := findings(t, s, ctx, store.FindingFilter{SecondCheck: store.SecondCheckDisagreed}); len(got) != 1 {
		t.Errorf("second_check filter: %d", len(got))
	}
	// Re-evaluation with the same match keeps it needs validation.
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash"}, map[string]string{"CVE-L": "1.0.1"})
	if f = one(t, s, ctx, web, "CVE-L"); f.Verification != "confirmed" || f.SecondCheck != store.SecondCheckDisagreed {
		t.Fatalf("re-evaluated with the same match: %s %q", f.Verification, f.SecondCheck)
	}
	sum, err := s.SummarizeSecondChecks(ctx)
	if err != nil || sum.Disagreed != 1 || sum.Logged30d != 1 || len(sum.Recent) != 1 || sum.Recent[0].Purl != "pkg:npm/lodash@4.17.15" {
		t.Fatalf("summary: %+v %v", sum, err)
	}
	// A result for an older match is dropped.
	stale := disagreed(c)
	stale.Result = store.SecondCheckAgreed
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash"}, map[string]string{"CVE-L": "1.0.2"})
	if f = one(t, s, ctx, web, "CVE-L"); f.Verification != "confirmed" || f.SecondCheck != "" {
		t.Fatalf("after the match changed: %s %q", f.Verification, f.SecondCheck)
	}
	if sc, _ := s.FindingSecondCheck(ctx, f.ID); sc != nil {
		t.Fatalf("the check of the old match stands: %+v", sc)
	}
	if _, err := s.RecordSecondChecks(ctx, []store.SecondCheckResult{stale}); err != nil {
		t.Fatal(err)
	}
	if sc, _ := s.FindingSecondCheck(ctx, f.ID); sc != nil {
		t.Fatalf("a result for an older match was recorded: %+v", sc)
	}
	if c2 := candidate(t, s, ctx, true, f.ID); c2 == nil || c2.Basis == c.Basis {
		t.Fatalf("the new match is not waiting for a check: %+v", c2)
	}
	if sum, _ := s.SummarizeSecondChecks(ctx); sum.Disagreed != 0 || sum.Logged30d != 1 {
		t.Errorf("the log keeps old disagreements: %+v", sum)
	}
}

// A person's false positive stays rejected, and reopening it gives back the
// matcher's own verdict; the disagreement is still shown.
func TestSecondCheckKeepsRejected(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash"}, nil)
	f := one(t, s, ctx, web, "CVE-L")
	fp := store.FindingAction{Action: "ignore", Note: "never reached", Ignore: store.IgnoreSpec{
		Reason: store.ReasonFalsePositive, Scope: store.ScopeAsset, Expiry: store.ExpiryNever}}
	if err := s.ApplyFindingAction(ctx, f.ID, fp, user); err != nil {
		t.Fatal(err)
	}
	c := candidate(t, s, ctx, true, f.ID)
	if _, err := s.RecordSecondChecks(ctx, []store.SecondCheckResult{disagreed(c)}); err != nil {
		t.Fatal(err)
	}
	if f = one(t, s, ctx, web, "CVE-L"); f.Verification != "rejected" {
		t.Fatalf("rejected became %s", f.Verification)
	}
	if err := s.ApplyFindingAction(ctx, f.ID, store.FindingAction{Action: "reopen"}, user); err != nil {
		t.Fatal(err)
	}
	if f = one(t, s, ctx, web, "CVE-L"); f.Verification != "confirmed" || f.SecondCheck != store.SecondCheckDisagreed {
		t.Fatalf("reopened after a disagreement: %s %q", f.Verification, f.SecondCheck)
	}
}

// Only high-impact or ambiguous findings are candidates by default.
func TestSecondCheckCandidates(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: web})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		ev := map[string]any{"match": map[string]any{"rule": "range"}}
		if r.Name == "express" {
			ev["known_exploited"] = true
		}
		in = append(in, store.FindingInput{Kind: "vulnerability", Key: "CVE-" + r.Name, InventoryID: r.ID, AssetID: web,
			ComponentID: r.ComponentID, Verification: "confirmed", Severity: "low", Sources: []string{"GHSA-" + r.Name}, Evidence: ev})
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	lodash, express := one(t, s, ctx, web, "CVE-lodash"), one(t, s, ctx, web, "CVE-express")
	if candidate(t, s, ctx, false, lodash.ID) != nil {
		t.Error("a low, unexploited, confirmed and unambiguous finding was a candidate")
	}
	if candidate(t, s, ctx, false, express.ID) == nil {
		t.Error("a known exploited finding was not a candidate")
	}
	if sum, _ := s.SummarizeSecondChecks(ctx); sum.Pending != 1 {
		t.Errorf("pending: %+v", sum)
	}
	if waiting, err := s.SecondCheckWaiting(ctx); err != nil || !waiting {
		t.Fatalf("waiting: %v %v", waiting, err)
	}
	c := candidate(t, s, ctx, false, express.ID)
	if _, err := s.RecordSecondChecks(ctx, []store.SecondCheckResult{{FindingID: c.FindingID, AssetID: c.AssetID, Basis: c.Basis,
		Result: store.SecondCheckAgreed}}); err != nil {
		t.Fatal(err)
	}
	if waiting, err := s.SecondCheckWaiting(ctx); err != nil || waiting {
		t.Errorf("waiting after the check: %v %v", waiting, err)
	}
}

// A check made under older second-check rules is redone: a false
// disagreement from a rule that has since been fixed clears itself on the
// next run, though the match did not change.
func TestSecondCheckRedoneWhenRulesChange(t *testing.T) {
	ctx, s := loopStore(t)
	web := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	syncFix(t, s, ctx, web, map[string]string{"CVE-L": "lodash"}, map[string]string{"CVE-L": "1.0.1"})
	f := one(t, s, ctx, web, "CVE-L")
	c := candidate(t, s, ctx, true, f.ID)
	if _, err := s.RecordSecondChecks(ctx, []store.SecondCheckResult{disagreed(c)}); err != nil {
		t.Fatal(err)
	}
	if candidate(t, s, ctx, true, f.ID) != nil {
		t.Fatal("a current check was offered again")
	}
	sc, _ := s.FindingSecondCheck(ctx, f.ID)
	if fmt.Sprint(sc.Independent["checker"]) != strconv.Itoa(store.SecondCheckRules) {
		t.Fatalf("checker version not stored: %v", sc.Independent)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE second_checks SET independent = jsonb_set(independent, '{checker}', '1')`); err != nil {
		t.Fatal(err)
	}
	if candidate(t, s, ctx, true, f.ID) == nil {
		t.Fatal("a check made under older rules is not redone")
	}
	agreed := disagreed(c)
	agreed.Result, agreed.Reason, agreed.Differences = store.SecondCheckAgreed, "", nil
	if _, err := s.RecordSecondChecks(ctx, []store.SecondCheckResult{agreed}); err != nil {
		t.Fatal(err)
	}
	if f = one(t, s, ctx, web, "CVE-L"); f.SecondCheck != store.SecondCheckAgreed {
		t.Fatalf("the false disagreement did not clear: %q", f.SecondCheck)
	}
}
