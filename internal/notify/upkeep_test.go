package notify

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// While an evaluation of the workspace runs, a tick does not touch findings
// (no priority pass, no ignore rules, no correlation): those statements
// lock many findings in their own order and could deadlock with the
// evaluation's. It waits a few seconds, then delivers what is queued and
// leaves the upkeep to the next tick, which catches up.
func TestTickWaitsForEvaluation(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("web-1", "production", true)
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337"}})
	f.tick()
	priority := func() string {
		var p string
		if err := f.st.Pool.QueryRow(ctx, `SELECT priority FROM findings`).Scan(&p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	want := priority()
	if _, err := f.st.Pool.Exec(ctx, `UPDATE findings SET priority = 'P4', priority_score = 0`); err != nil {
		t.Fatal(err)
	}
	if want == "P4" {
		t.Fatal("the fixture's finding should not be P4")
	}

	release, err := f.st.LockEvaluations(ctx) // an evaluation is running
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	f.tick()
	if waited := time.Since(start); waited < tickLockWait {
		t.Errorf("the tick waited %s for the evaluation, want %s", waited, tickLockWait)
	}
	if p := priority(); p != "P4" {
		t.Errorf("the priority pass ran during an evaluation: %s", p)
	}
	if n := f.d.skipped(tenant.DefaultWorkspace, false); n != 1 {
		t.Errorf("%d ticks skipped, want 1", n)
	}
	release()
	f.tick()
	if p := priority(); p != want {
		t.Errorf("after the evaluation: priority %s, want %s", p, want)
	}
	if n := f.d.skipped(tenant.DefaultWorkspace, false); n != 0 {
		t.Errorf("skips not reset: %d", n)
	}
}
