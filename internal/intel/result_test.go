package intel

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A collection is reported as evaluated only once its findings have been
// prioritised: between matching and scoring they carry the default P4 and
// a CI gate reading them would pass wrongly.
func TestCollectionResultWaitsForPriorities(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	b := model.NewBatch(model.Collector{ID: "t-repo", Method: "test"},
		model.AssetRef{Kind: model.AssetRepository, Name: "shop", Environment: "production", Identifiers: []model.Identifier{{Scheme: "test", Value: "shop"}}})
	b.Observations, b.Complete = []model.Observation{confirmed("pkg:npm/lodash@4.17.15", nil)}, true
	r, err := st.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	_ = EnsureFeeds(ctx, st)
	up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"a.json": ghsaLodash}))
	up.set("/kev.json", kev)
	for _, f := range []string{"osv:npm", FeedKEV} {
		if _, err := sy.Sync(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	// Stand in for the worker: the ingest queued an evaluate job.
	if _, err := st.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE dedupe_key LIKE 'evaluate:asset:%'`); err != nil {
		t.Fatal(err)
	}
	start, _ := st.DBNow(ctx)
	if _, err := ev.Evaluate(ctx, nil, r.AssetID); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkEvaluated(ctx, r.AssetID, start); err != nil {
		t.Fatal(err)
	}
	res, err := st.GetCollectionResult(ctx, r.CollectionID)
	if err != nil || res.Status != "scoring" || len(res.Findings) != 0 {
		t.Fatalf("matched, not prioritised: %+v %v", res, err)
	}
	// What the evaluate job now does before marking the asset evaluated.
	if _, err := st.PrioritizeAsset(ctx, risk.DefaultPolicy(), time.Now(), r.AssetID); err != nil {
		t.Fatal(err)
	}
	res, err = st.GetCollectionResult(ctx, r.CollectionID)
	if err != nil || res.Status != "evaluated" || len(res.Findings) != 1 {
		t.Fatalf("prioritised: %+v %v", res, err)
	}
	if f := res.Findings[0]; f.Priority == "P4" || f.PriorityPolicy == "" {
		t.Errorf("finding = priority %s, policy %q", f.Priority, f.PriorityPolicy)
	}
}
