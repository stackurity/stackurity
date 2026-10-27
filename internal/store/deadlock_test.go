package store_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// The deadlock of 27 Oct 2026: an evaluation's upsert locked findings in the
// matcher's order (here the higher id first) while the priority pass, which
// updates findings one by one, held a lower one and wanted the higher one.
// Postgres aborted the evaluation. An evaluation now locks every finding it
// may change in id order before changing any, the order the priority pass
// uses, so the two wait for each other instead.
func TestEvaluationAndPriorityUpdateDoNotDeadlock(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	asset := ingestHost(t, s, ctx, "web-1", "pkg:npm/aaa@1.0.0", "pkg:npm/bbb@1.0.0")
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil || len(rows) != 2 {
		t.Fatalf("inventory: %v %v", rows, err)
	}
	want := func(severity string) ([]int64, []store.FindingInput) {
		var ids []int64
		var in []store.FindingInput
		for _, r := range rows {
			ids = append(ids, r.ID)
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: "CVE-2026-" + r.Name, InventoryID: r.ID, AssetID: asset,
				ComponentID: r.ComponentID, Verification: "confirmed", Severity: severity, FixedVersion: "9.9.9",
				Sources: []string{"GHSA-" + r.Name}, Evidence: map[string]any{}})
		}
		return ids, in
	}
	ids, in := want("high")
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	fs, _, err := s.ListFindings(ctx, store.FindingFilter{AssetID: asset})
	if err != nil || len(fs) != 2 {
		t.Fatalf("findings: %v %v", fs, err)
	}
	low, high := min(fs[0].ID, fs[1].ID), max(fs[0].ID, fs[1].ID)

	// The priority pass, as a separate connection: it has updated the
	// lower finding and has not reached the higher one yet.
	p, pxid := lockFinding(t, s, ctx, low)

	// The evaluation changes both, with the higher one first in its input.
	ids, in = want("critical")
	highInv := fs[0].InventoryID
	if fs[1].ID == high {
		highInv = fs[1].InventoryID
	}
	if in[0].InventoryID != highInv {
		in[0], in[1] = in[1], in[0]
	}
	evalDone := make(chan error, 1)
	go func() { _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in); evalDone <- err }()
	waitBlockedBy(t, s, pxid, evalDone)

	// The priority pass goes on to the higher finding. Before the fix the
	// evaluation held it: a deadlock, and Postgres aborted one side.
	finishAfter(t, ctx, p, high, evalDone, "evaluation")
	fs, _, _ = s.ListFindings(ctx, store.FindingFilter{AssetID: asset})
	for _, f := range fs {
		if f.Severity != "critical" {
			t.Errorf("finding %d: severity %s after the evaluation", f.ID, f.Severity)
		}
	}
}

// Ignoring an issue everywhere changes the finding ignored, then the other
// findings of the issue. Locked in that order, it held the higher finding
// and waited for a lower one an evaluation held, while the evaluation waited
// for the higher one. Now the issue's findings are locked in id order first.
func TestIgnoreAndEvaluationDoNotDeadlock(t *testing.T) {
	ctx, s := loopStore(t)
	a := ingestHost(t, s, ctx, "web-1", "pkg:npm/lodash@4.17.15")
	b := ingestHost(t, s, ctx, "web-2", "pkg:npm/lodash@4.17.15")
	syncFix(t, s, ctx, a, map[string]string{"CVE-L": "lodash"}, nil)
	syncFix(t, s, ctx, b, map[string]string{"CVE-L": "lodash"}, nil)
	fa, fb := one(t, s, ctx, a, "CVE-L"), one(t, s, ctx, b, "CVE-L")
	low, high := min(fa.ID, fb.ID), max(fa.ID, fb.ID)

	// An evaluation (or the priority pass) has locked the lower finding,
	// and will want the higher one.
	p, pxid := lockFinding(t, s, ctx, low)

	done := make(chan error, 1)
	go func() {
		done <- s.ApplyFindingAction(ctx, high, store.FindingAction{Action: "ignore", Note: "not reachable",
			Ignore: store.IgnoreSpec{Reason: store.ReasonFalsePositive, Scope: store.ScopeEverywhere, Expiry: store.ExpiryNever}}, user)
	}()
	waitBlockedBy(t, s, pxid, done)
	finishAfter(t, ctx, p, high, done, "ignore")
	for _, f := range []int64{low, high} {
		got, err := s.GetFinding(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != "risk_accepted" {
			t.Errorf("finding %d: state %s after the ignore, want risk_accepted", f, got.State)
		}
	}
}

// The evaluation and the priority pass themselves, side by side over a
// small set of findings: the evaluation's input runs in descending id order
// (the matcher's order is arbitrary) and flips every finding's severity, so
// the priority pass keeps rewriting what the evaluation changed. Before the
// fix, Postgres reported a deadlock within a few rounds.
func TestEvaluationAndPriorityPassStress(t *testing.T) {
	if testing.Short() {
		t.Skip("stress")
	}
	const (
		packages = 100
		rounds   = 40
	)
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	purls := make([]string, packages)
	for i := range purls {
		purls[i] = fmt.Sprintf("pkg:npm/p%02d@1.0.0", i)
	}
	asset := ingestHost(t, s, ctx, "web-1", purls...)
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil || len(rows) != packages {
		t.Fatalf("inventory: %d rows, %v", len(rows), err)
	}
	// The findings are created in inventory order, so their ids follow it;
	// the evaluations after that list them the other way round.
	slices.SortFunc(rows, func(x, y store.InventoryRow) int { return int(x.ID - y.ID) })
	ids := make([]int64, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	evaluate := func(severity string) error {
		in := make([]store.FindingInput, 0, len(rows))
		for _, r := range rows {
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: "CVE-2026-" + r.Name, InventoryID: r.ID, AssetID: asset,
				ComponentID: r.ComponentID, Verification: "confirmed", Severity: severity, FixedVersion: "9.9.9",
				Sources: []string{"GHSA-" + r.Name}, Evidence: map[string]any{}})
		}
		_, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, ids, in)
		return err
	}
	policy, err := s.RiskPolicy(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := evaluate("low"); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(rows)
	// Both run side by side, rounds times each: the evaluation flips every
	// severity, and the priority pass rewrites the priorities that changed.
	severities := []string{"critical", "low"}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	stop := make(chan struct{})
	var once sync.Once
	run := func(i int, f func(round int) error) {
		defer wg.Done()
		for round := range rounds {
			select {
			case <-stop:
				return
			default:
			}
			if err := f(round); err != nil {
				errs[i] = fmt.Errorf("round %d: %w", round, err)
				once.Do(func() { close(stop) })
				return
			}
		}
	}
	wg.Add(2)
	go run(0, func(round int) error { return evaluate(severities[round%2]) })
	go run(1, func(int) error { _, err := s.PrioritizeAsset(ctx, policy, time.Now(), asset); return err })
	wg.Wait()
	for i, err := range errs {
		if err == nil {
			continue
		}
		what := []string{"evaluation", "priority pass"}[i]
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "40P01" {
			t.Errorf("%s: deadlock: %v", what, err)
		} else {
			t.Errorf("%s: %v", what, err)
		}
	}
}

// lockFinding updates finding id in a new transaction, as a writer that
// locks findings in id order has reached it, and returns the transaction
// and its id.
func lockFinding(t *testing.T, s *store.Store, ctx context.Context, id int64) (pgx.Tx, string) {
	t.Helper()
	p, err := s.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Rollback(context.Background()) })
	if _, err := p.Exec(ctx, `UPDATE findings SET priority = 'P1' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	var xid string
	if err := p.QueryRow(ctx, `SELECT pg_current_xact_id()::xid::text`).Scan(&xid); err != nil {
		t.Fatal(err)
	}
	return p, xid
}

// waitBlockedBy waits until another transaction waits for transaction xid.
func waitBlockedBy(t *testing.T, s *store.Store, xid string, done chan error) {
	t.Helper()
	sys := tenant.System(context.Background())
	deadline := time.Now().Add(10 * time.Second)
	for {
		var waiting int
		if err := s.Pool.QueryRow(sys, `SELECT count(*) FROM pg_locks
			WHERE NOT granted AND locktype = 'transactionid' AND transactionid::text = $1`, xid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			return
		}
		if len(done) > 0 {
			t.Fatalf("finished without waiting: %v", <-done)
		}
		if time.Now().After(deadline) {
			t.Fatal("never waited for the other transaction")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// finishAfter has p update finding id too (the one the other side would
// hold if it locked out of order), commits p, and checks the other side
// then finishes without error.
func finishAfter(t *testing.T, ctx context.Context, p pgx.Tx, id int64, done chan error, what string) {
	t.Helper()
	if _, err := p.Exec(ctx, `UPDATE findings SET priority = 'P1' WHERE id = $1`, id); err != nil {
		t.Fatalf("update of finding %d: %v", id, err)
	}
	if err := p.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the %s did not finish", what)
	}
}
