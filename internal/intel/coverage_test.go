package intel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// rowCoverage returns the coverage of each current inventory row of an
// asset, keyed by purl.
func rowCoverage(t *testing.T, ctx context.Context, st *store.Store, asset int64) map[string]store.InventoryRow {
	t.Helper()
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: asset, Page: store.Page{Limit: 500}})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.InventoryRow{}
	for _, r := range rows {
		out[r.Purl] = r
	}
	return out
}

// Coverage belongs to the inventory row: evaluating another asset, or another
// workspace, with the same package must not clear a row's gap.
func TestCoverageIsPerRow(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	bad := ingest(t, st, model.AssetRepository, "bad", true, confirmed("pkg:npm/lodash@latest", nil))
	good := ingest(t, st, model.AssetRepository, "good", true, confirmed("pkg:npm/lodash@4.17.21", nil))

	ws2, _, err := st.CreateWorkspace(tenant.System(context.Background()), "Other", "other", "other@example.com", "Other", "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	ctx2 := tenant.WithWorkspace(context.Background(), ws2.ID)
	b := model.NewBatch(model.Collector{ID: "t", Method: "test"},
		model.AssetRef{Kind: model.AssetRepository, Name: "elsewhere", Identifiers: []model.Identifier{{Scheme: "test", Value: "elsewhere"}}})
	b.Observations, b.Complete = []model.Observation{confirmed("pkg:npm/lodash@4.17.20", nil)}, true
	r2, err := st.Ingest(ctx2, b, 0)
	if err != nil {
		t.Fatal(err)
	}

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-p6mc.json": ghsaLodash}))
	if _, err := sy.Sync(ctx, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		if c := rowCoverage(t, ctx, st, bad)["pkg:npm/lodash@latest"]; c.Coverage != store.CoverageNotEvaluated || c.CoverageReason == "" {
			t.Errorf("%s: unparseable version must stay not evaluated: %+v", when, c)
		}
		if c := rowCoverage(t, ctx, st, good)["pkg:npm/lodash@4.17.21"]; c.Coverage != store.CoverageEvaluated || c.CoverageFeed != "osv:npm" {
			t.Errorf("%s: a parseable version of the same package is evaluated: %+v", when, c)
		}
	}
	check("full run")

	// Evaluating only the good asset (as after its next collection) and the
	// other workspace's asset must leave the bad row's gap in place.
	if _, err := ev.Evaluate(ctx, nil, good); err != nil {
		t.Fatal(err)
	}
	check("after evaluating another asset")
	if _, err := ev.Evaluate(ctx2, nil, 0); err != nil {
		t.Fatal(err)
	}
	check("after evaluating another workspace")
	if c := rowCoverage(t, ctx2, st, r2.AssetID)["pkg:npm/lodash@4.17.20"]; c.Coverage != store.CoverageEvaluated {
		t.Errorf("other workspace row = %+v", c)
	}

	// The workspace's gap list and counts only see its own rows.
	gaps, n, err := st.ListEvaluationGaps(ctx, store.Page{})
	if err != nil || n != 1 || len(gaps) != 1 || gaps[0].PurlKey != "pkg:npm/lodash" || gaps[0].AssetCount != 1 {
		t.Errorf("gaps = %+v %d %v", gaps, n, err)
	}
	if gaps, _, _ := st.ListEvaluationGaps(ctx2, store.Page{}); len(gaps) != 0 {
		t.Errorf("the other workspace has no gaps: %+v", gaps)
	}
	if sum, _ := st.SummarizeFindings(ctx); sum.EvaluationGaps != 1 {
		t.Errorf("summary gaps = %d", sum.EvaluationGaps)
	}
}

// A distro release the feed has no advisories for (too new, out of the
// source's support, or never published) is not evaluated rather than clean.
func TestReleaseWithoutAdvisoriesIsNotEvaluated(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	known := ingest(t, st, model.AssetHost, "bookworm", true,
		confirmed("pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl", nil))
	unknown := ingest(t, st, model.AssetHost, "future", true,
		confirmed("pkg:deb/debian/libssl3@3.5.0-1?distro=debian-15&upstream=openssl", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/Debian/all.zip", zipOf(t, map[string]string{"DSA-5532-1.json": debOpenssl}))
	if _, err := sy.Sync(ctx, "osv:Debian"); err != nil {
		t.Fatal(err)
	}
	if f, _ := st.GetFeed(ctx, "osv:Debian"); len(f.Ecosystems) != 2 || f.Ecosystems[0] != "Debian:11" || f.Ecosystems[1] != "Debian:12" {
		t.Errorf("feed ecosystems = %v", f.Ecosystems)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if c := rowCoverage(t, ctx, st, known)["pkg:deb/debian/libssl3@3.0.11-1~deb12u2?distro=debian-12&upstream=openssl"]; c.Coverage != store.CoverageEvaluated {
		t.Errorf("Debian 12 row = %+v", c)
	}
	c := rowCoverage(t, ctx, st, unknown)["pkg:deb/debian/libssl3@3.5.0-1?distro=debian-15&upstream=openssl"]
	if c.Coverage != store.CoverageNotEvaluated || !strings.Contains(c.CoverageReason, "no advisories for Debian:15") {
		t.Errorf("Debian 15 row = %+v", c)
	}

	// An incremental sync adds the releases of the records it reads.
	up.set("/osv/Debian/modified_id.csv", time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)+",DSA-9999-1\n")
	up.set("/osv/Debian/DSA-9999-1.json", `{"id":"DSA-9999-1","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2026-9999"],
	 "affected":[{"package":{"ecosystem":"Debian:15","name":"openssl"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.5.0-2"}]}]}]}`)
	if res, err := sy.Sync(ctx, "osv:Debian"); err != nil || res.Full {
		t.Fatalf("incremental sync: %+v %v", res, err)
	}
	if f, _ := st.GetFeed(ctx, "osv:Debian"); len(f.Ecosystems) != 3 {
		t.Errorf("feed ecosystems after an incremental sync = %v", f.Ecosystems)
	}
	if _, err := ev.Evaluate(ctx, nil, unknown); err != nil {
		t.Fatal(err)
	}
	if c := rowCoverage(t, ctx, st, unknown)["pkg:deb/debian/libssl3@3.5.0-1?distro=debian-15&upstream=openssl"]; c.Coverage != store.CoverageEvaluated {
		t.Errorf("Debian 15 row once the source publishes for it = %+v", c)
	}
}
