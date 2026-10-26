package intel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Two evaluations overlap: A reads the feeds while a sync has not committed
// (the package cannot be evaluated), the sync commits, B evaluates and opens
// the finding, then A writes. A must not resolve what B opened (it used to:
// resolved, then reopened by the next evaluation, with a duplicate incident
// and a "fixed" that never happened). Evaluations are serialised, so B waits
// for A and reads what A wrote.
func TestOverlappingEvaluationsDoNotResolveNewerFindings(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, _, up := setup(t)
	app := ingest(t, st, model.AssetRepository, "shop", true, confirmed("pkg:npm/lodash@4.17.15", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-p6mc.json": ghsaLodash}))
	if _, err := sy.Sync(ctx, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	sys := tenant.System(context.Background())
	setSynced := func(on bool) {
		t.Helper()
		q := `UPDATE feeds SET last_success = NULL WHERE name = 'osv:npm'`
		if on {
			q = `UPDATE feeds SET last_success = now() WHERE name = 'osv:npm'`
		}
		if _, err := st.Pool.Exec(sys, q); err != nil {
			t.Fatal(err)
		}
	}
	setSynced(false) // the sync has not committed yet

	read, resume := make(chan struct{}), make(chan struct{})
	a := &Evaluator{Store: st, afterRead: func() { close(read); <-resume }}
	aDone := make(chan error, 1)
	go func() { _, err := a.Evaluate(ctx, nil, app); aDone <- err }()
	<-read // A has read the feed as not synced

	setSynced(true) // the sync commits
	// B starts while A has not written: it does nothing and says the
	// workspace is busy (its job is deferred and runs again shortly).
	b := &Evaluator{Store: st}
	if _, err := b.Evaluate(ctx, nil, app); !errors.Is(err, store.ErrEvaluationBusy) {
		t.Fatalf("an evaluation while another runs: %v, want ErrEvaluationBusy", err)
	}
	close(resume)
	if err := <-aDone; err != nil {
		t.Fatal(err)
	}
	// B again, as its deferred job would: it reads what A wrote.
	if _, err := b.Evaluate(ctx, nil, app); err != nil {
		t.Fatal(err)
	}

	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: app, Status: "all"})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Status != "open" {
		t.Fatalf("after overlapping evaluations: %+v", fs)
	}
	var resolvedEvents int
	if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM finding_events WHERE finding_id = $1 AND action IN ('resolved', 'reopened')`, fs[0].ID).Scan(&resolvedEvents); err != nil {
		t.Fatal(err)
	}
	var resolvedAt *time.Time
	if err := st.Pool.QueryRow(ctx, `SELECT resolved_at FROM findings WHERE id = $1`, fs[0].ID).Scan(&resolvedAt); err != nil {
		t.Fatal(err)
	}
	if resolvedEvents != 0 || resolvedAt != nil {
		t.Errorf("the finding was resolved by the older evaluation: %d events, resolved_at %v", resolvedEvents, resolvedAt)
	}
}
