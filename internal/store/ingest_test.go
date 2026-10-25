package store_test

import (
	"context"
	"github.com/stackurity/stackurity/internal/tenant"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

func batch(ids []model.Identifier, complete bool, purls ...string) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: "web-1", Identifiers: ids, Attributes: map[string]string{"os": "debian"}})
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Location: "/var/lib/dpkg/status"})
	}
	b.Cover("dpkg", "checked", "")
	b.Complete = complete
	if err := b.Validate(); err != nil {
		panic(err)
	}
	return b
}

var mid = []model.Identifier{{Scheme: "machine-id", Value: "m1"}}

func TestIngestCreatesAndUpdates(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))

	r1, err := s.Ingest(ctx, batch(mid, true, "pkg:deb/debian/openssl@3.0.1?distro=debian-12", "pkg:deb/debian/bash@5.2"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !r1.NewAsset || r1.Observations != 2 {
		t.Errorf("first ingest = %+v", r1)
	}
	// openssl upgraded, bash removed, curl added.
	r2, err := s.Ingest(ctx, batch(mid, true, "pkg:deb/debian/openssl@3.0.2?distro=debian-12", "pkg:deb/debian/curl@8.0"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r2.NewAsset || r2.AssetID != r1.AssetID || r2.Removed != 2 {
		t.Errorf("second ingest = %+v", r2)
	}
	rows, total, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: r1.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || rows[0].Name != "curl" || rows[1].Version != "3.0.2" {
		t.Errorf("inventory = %+v", rows)
	}
	all, _, _ := s.ListInventory(ctx, store.InventoryFilter{AssetID: r1.AssetID, IncludeRemoved: true})
	if len(all) != 4 {
		t.Errorf("history should keep removed rows, got %d", len(all))
	}
	// Both openssl versions share one component.
	comps, _, _ := s.ListComponents(ctx, store.ComponentFilter{Search: "openssl"})
	if len(comps) != 1 || comps[0].Versions[0] != "3.0.2" || comps[0].AssetCount != 1 {
		t.Errorf("components = %+v", comps)
	}
}

func TestPartialBatchDoesNotRemove(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	r, _ := s.Ingest(ctx, batch(mid, true, "pkg:deb/debian/a@1", "pkg:deb/debian/b@1"), 0)
	partial := batch(mid, false, "pkg:deb/debian/a@1")
	partial.Coverage = []model.CoverageItem{{Scope: "dpkg", Status: "failed", Reason: "permission denied"}}
	r2, err := s.Ingest(ctx, partial, 0)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Removed != 0 {
		t.Errorf("partial batch removed %d rows", r2.Removed)
	}
	a, _ := s.GetAsset(ctx, r.AssetID)
	if a.CollectionStatus != "partial" || a.ComponentCount != 2 {
		t.Errorf("asset = %+v", a)
	}
	cov, _, _ := s.ListCoverage(ctx, r.AssetID, false, store.Page{})
	if len(cov) != 1 || cov[0].Status != "failed" || cov[0].LastSuccess == nil {
		t.Errorf("coverage must keep last success after a failure: %+v", cov)
	}
}

func TestDuplicateRowsInOneBatch(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	b := batch(mid, true)
	yes, no := true, false
	b.Observations = []model.Observation{
		{Purl: "pkg:npm/debug@4.3.4", Version: "4.3.4", Location: "package-lock.json", Direct: &no, Confidence: model.ConfidenceConfirmed},
		{Purl: "pkg:npm/debug@4.3.4", Version: "4.3.4", Location: "package-lock.json", Direct: &yes, Confidence: model.ConfidenceConfirmed},
	}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, _ := s.ListInventory(ctx, store.InventoryFilter{AssetID: r.AssetID})
	if len(rows) != 1 || rows[0].Direct == nil || !*rows[0].Direct {
		t.Errorf("rows = %+v", rows)
	}
}

func TestIdentityConflictAndMerge(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	a, _ := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "machine-id", Value: "m1"}}, true, "pkg:deb/debian/a@1"), 0)
	b, _ := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "hostname", Value: "web-1"}}, true, "pkg:deb/debian/b@1"), 0)
	if a.AssetID == b.AssetID {
		t.Fatal("expected two assets")
	}
	r, err := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "machine-id", Value: "m1"}, {Scheme: "hostname", Value: "web-1"}}, true, "pkg:deb/debian/a@1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Conflict) != 2 || r.AssetID != a.AssetID {
		t.Errorf("result = %+v", r)
	}
	conflicts, _ := s.ListConflicts(ctx)
	if len(conflicts) != 1 {
		t.Fatalf("conflicts = %+v", conflicts)
	}
	// Re-ingesting does not duplicate the open conflict.
	_, _ = s.Ingest(ctx, batch([]model.Identifier{{Scheme: "machine-id", Value: "m1"}, {Scheme: "hostname", Value: "web-1"}}, true, "pkg:deb/debian/a@1"), 0)
	if c, _ := s.ListConflicts(ctx); len(c) != 1 {
		t.Errorf("conflict duplicated: %d", len(c))
	}
	if err := s.ResolveConflict(ctx, conflicts[0].ID, a.AssetID, 0); err != nil {
		t.Fatal(err)
	}
	assets, total, _ := s.ListAssets(ctx, store.AssetFilter{})
	if total != 1 || assets[0].ID != a.AssetID {
		t.Errorf("assets after merge = %+v", assets)
	}
	ids, _ := s.AssetIdentifiers(ctx, a.AssetID)
	if len(ids) != 2 {
		t.Errorf("identifiers = %+v", ids)
	}
	// Later batches for the merged identity land on the surviving asset.
	r3, _ := s.Ingest(ctx, batch([]model.Identifier{{Scheme: "hostname", Value: "web-1"}}, false, "pkg:deb/debian/c@1"), 0)
	if r3.AssetID != a.AssetID || len(r3.Conflict) != 0 {
		t.Errorf("post-merge ingest = %+v", r3)
	}
}

func TestStaleAssets(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	b := batch(mid, true, "pkg:deb/debian/a@1")
	b.ObservedAt = time.Now().Add(-72 * time.Hour)
	r, _ := s.Ingest(ctx, b, 0)
	n, err := s.MarkStaleAssets(ctx, 48*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("marked %d, err %v", n, err)
	}
	a, _ := s.GetAsset(ctx, r.AssetID)
	if a.CollectionStatus != "stale" {
		t.Errorf("status = %s", a.CollectionStatus)
	}
	o, err := s.Overview(ctx)
	if err != nil || o.AssetStatus["stale"] != 1 || o.Ecosystems["deb"] != 1 {
		t.Errorf("overview = %+v err %v", o, err)
	}
}

// A batch that arrives while its asset is being evaluated must not be lost
// to the deduplicated job that is already running.
func TestIngestRequeuesRunningEvaluation(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	if _, err := s.Ingest(ctx, batch(mid, true, "pkg:deb/debian/bash@5.2"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET run_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	j, err := s.Claim(ctx, "w1")
	if err != nil || j == nil || j.Kind != "evaluate" {
		t.Fatalf("claim = %+v, %v", j, err)
	}
	if _, err := s.Ingest(ctx, batch(mid, true, "pkg:deb/debian/bash@5.3"), 0); err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteJob(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	again, err := s.Claim(ctx, "w1")
	if err != nil || again == nil || again.ID != j.ID {
		t.Fatalf("requeued job not runnable: %+v, %v", again, err)
	}
	if err := s.CompleteJob(ctx, again.ID); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE done_at IS NULL`).Scan(&pending); err != nil || pending != 0 {
		t.Errorf("pending jobs = %d, %v", pending, err)
	}
}

func TestRebootRequiredFilter(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	b := batch(mid, true, "pkg:deb/debian/bash@5.2")
	b.Asset.Attributes["reboot_required"] = "true"
	if _, err := s.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	other := batch([]model.Identifier{{Scheme: "machine-id", Value: "m2"}}, true, "pkg:deb/debian/bash@5.2")
	other.Asset.Attributes["reboot_required"] = "false"
	if _, err := s.Ingest(ctx, other, 0); err != nil {
		t.Fatal(err)
	}
	items, total, err := s.ListAssets(ctx, store.AssetFilter{RebootRequired: true})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("filtered = %d %+v %v", total, items, err)
	}
	o, err := s.Overview(ctx)
	if err != nil || o.RebootRequired != 1 {
		t.Errorf("overview reboot_required = %+v %v", o, err)
	}
	// A later report clears it: attributes merge, so "false" overwrites "true".
	b = batch(mid, true, "pkg:deb/debian/bash@5.2")
	b.Asset.Attributes["reboot_required"] = "false"
	if _, err := s.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if _, total, _ := s.ListAssets(ctx, store.AssetFilter{RebootRequired: true}); total != 0 {
		t.Errorf("still flagged after reboot: %d", total)
	}
}
