package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func quotaBatch(kind model.AssetKind, name, scheme string, rels ...model.RelationRef) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: "plugin:kubernetes", Method: "plugin"},
		model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: scheme, Value: name}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/left-pad@1.0.0", Confidence: model.ConfidenceConfirmed}}
	b.Relations, b.Complete = rels, true
	return b
}

func limit(n int64) *int64 { return &n }

// TestAssetLimitStore: at the limit new assets of every counted kind are
// refused, assets already monitored keep being updated, workloads ride with
// their cluster, refusals are remembered, and deleting an asset frees room.
func TestAssetLimitStore(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	ingest := func(b *model.ObservationBatch) (*store.IngestResult, error) {
		t.Helper()
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		return s.Ingest(ctx, b, 0)
	}

	// No limit: anything goes.
	host, err := ingest(quotaBatch(model.AssetHost, "web-1", "machine-id"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetAssetLimit(ctx, tenant.DefaultWorkspace, limit(2)); err != nil {
		t.Fatal(err)
	}
	cluster, err := ingest(quotaBatch(model.AssetCluster, "lab", "k8s-cluster"))
	if err != nil {
		t.Fatal(err)
	}
	// Two of two: every kind that counts is refused.
	for _, b := range []*model.ObservationBatch{
		quotaBatch(model.AssetHost, "web-2", "machine-id"),
		quotaBatch(model.AssetRepository, "github.com/x/repo", "git-url"), // a Git integration or a CI upload
		quotaBatch(model.AssetImage, "docker.io/library/nginx:1", "image-ref"),
		quotaBatch(model.AssetApplication, "shop", "name:application"),
		quotaBatch(model.AssetSBOM, "vendor-bom", "name:sbom"),
		quotaBatch(model.AssetManagedService, "rds-1", "aws-arn"),
		quotaBatch(model.AssetCluster, "lab-2", "k8s-cluster"),
	} {
		_, err := ingest(b)
		var le *store.AssetLimitError
		if !errors.As(err, &le) || !errors.Is(err, store.ErrAssetLimit) || le.Limit != 2 || le.Monitored != 2 {
			t.Errorf("%s %s at the limit: %v", b.Asset.Kind, b.Asset.Name, err)
		}
	}
	// The assets already monitored keep being updated, with new packages.
	again := quotaBatch(model.AssetHost, "web-1", "machine-id")
	again.Observations = append(again.Observations, model.Observation{Purl: "pkg:npm/lodash@4.17.20", Confidence: model.ConfidenceConfirmed})
	r, err := ingest(again)
	if err != nil || r.AssetID != host.AssetID || r.NewAsset {
		t.Fatalf("existing host at the limit: %+v %v", r, err)
	}
	inv, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: host.AssetID})
	if err != nil || len(inv) != 2 {
		t.Errorf("existing host's inventory at the limit: %d %v", len(inv), err)
	}
	// A workload on the monitored cluster is added (workloads do not count);
	// one whose cluster is not monitored is not.
	onLab := model.RelationRef{Kind: "runs_on", To: []model.Identifier{{Scheme: "k8s-cluster", Value: "lab"}}}
	if _, err := ingest(quotaBatch(model.AssetWorkload, "lab/shop/deployment/web", "k8s-workload", onLab)); err != nil {
		t.Errorf("workload on a monitored cluster: %v", err)
	}
	onLab2 := model.RelationRef{Kind: "runs_on", To: []model.Identifier{{Scheme: "k8s-cluster", Value: "lab-2"}}}
	_, err = ingest(quotaBatch(model.AssetWorkload, "lab-2/shop/deployment/web", "k8s-workload", onLab2))
	var le *store.AssetLimitError
	if !errors.As(err, &le) || !le.NoCluster {
		t.Errorf("workload on a cluster that is not monitored: %v", err)
	}

	u, err := s.AssetUsage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if u.Monitored != 2 || u.Limit == nil || *u.Limit != 2 || !u.AtLimit || u.Workloads != 1 || u.ByKind["host"] != 1 || u.ByKind["cluster"] != 1 {
		t.Errorf("usage: %+v", u)
	}
	if len(u.Refused) != 8 || u.RefusedRecently != 8 {
		t.Errorf("refused: %d %d %+v", len(u.Refused), u.RefusedRecently, u.Refused)
	}
	// A second refusal of the same asset counts an attempt, not a row.
	_, _ = ingest(quotaBatch(model.AssetHost, "web-2", "machine-id"))
	u, _ = s.AssetUsage(ctx)
	if len(u.Refused) != 8 || u.Refused[0].Name != "web-2" || u.Refused[0].Attempts != 2 {
		t.Errorf("refused again: %+v", u.Refused[0])
	}

	// Deleting an asset frees a place.
	if err := s.DeleteAsset(ctx, cluster.AssetID); err != nil {
		t.Fatal(err)
	}
	if _, err := ingest(quotaBatch(model.AssetHost, "web-2", "machine-id")); err != nil {
		t.Errorf("after a deletion: %v", err)
	}
	// Removing the limit lets everything in.
	if err := s.SetAssetLimit(ctx, tenant.DefaultWorkspace, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ingest(quotaBatch(model.AssetHost, "web-3", "machine-id")); err != nil {
		t.Errorf("without a limit: %v", err)
	}
	if err := s.SetAssetLimit(ctx, tenant.DefaultWorkspace, limit(-1)); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("negative limit: %v", err)
	}
}

// TestAssetLimitPluginBatches: a plugin run at the limit (Kubernetes: the
// cluster, its images, its workloads) stores what it may and names what it
// could not, rather than stopping at the first refusal.
func TestAssetLimitPluginBatches(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	onLab := model.RelationRef{Kind: "runs_on", To: []model.Identifier{{Scheme: "k8s-cluster", Value: "lab"}}}
	batches := []*model.ObservationBatch{
		quotaBatch(model.AssetCluster, "lab", "k8s-cluster"),
		quotaBatch(model.AssetImage, "nginx:1", "image-ref"),
		quotaBatch(model.AssetImage, "redis:7", "image-ref"),
		quotaBatch(model.AssetWorkload, "lab/a/deployment/web", "k8s-workload", onLab),
	}
	if err := s.SetAssetLimit(ctx, tenant.DefaultWorkspace, limit(2)); err != nil {
		t.Fatal(err)
	}
	res, refused, err := s.IngestAll(ctx, batches, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res[0] == nil || res[1] == nil || res[2] != nil || res[3] == nil || len(refused) != 1 || refused[0] != "redis:7" {
		t.Fatalf("first run: %v %v", res, refused)
	}
	// The next run updates everything already monitored.
	res, refused, err = s.IngestAll(ctx, batches, 0)
	if err != nil || res[0] == nil || res[0].NewAsset || res[1] == nil || res[3] == nil || len(refused) != 1 {
		t.Fatalf("second run: %v %v %v", res, refused, err)
	}
}

// TestAssetLimitConcurrent: collectors racing for the last places cannot
// go over the limit.
func TestAssetLimitConcurrent(t *testing.T) {
	s := store.New(testdb.New(t))
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := s.SetAssetLimit(ctx, tenant.DefaultWorkspace, limit(3)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, refused := 0, 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.Ingest(ctx, quotaBatch(model.AssetHost, fmt.Sprintf("host-%d", i), "machine-id"), 0)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, store.ErrAssetLimit):
				refused++
			default:
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if ok != 3 || refused != 9 {
		t.Errorf("created %d, refused %d; want 3 and 9", ok, refused)
	}
}

// TestAssetLimitPerWorkspace: one organisation's limit and usage are its
// own, and a caller narrowed to a project still counts every asset.
func TestAssetLimitPerWorkspace(t *testing.T) {
	s := store.New(testdb.New(t))
	bg := context.Background()
	a := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	wsB, _, err := s.CreateWorkspace(bg, "Beta", "", "admin-b@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	b := tenant.WithWorkspace(bg, wsB.ID)
	if err := s.SetAssetLimit(bg, tenant.DefaultWorkspace, limit(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(a, quotaBatch(model.AssetHost, "a-1", "machine-id"), 0); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := s.Ingest(b, quotaBatch(model.AssetHost, fmt.Sprintf("b-%d", i), "machine-id"), 0); err != nil {
			t.Fatalf("B has no limit: %v", err)
		}
	}
	if _, err := s.Ingest(a, quotaBatch(model.AssetHost, "a-2", "machine-id"), 0); !errors.Is(err, store.ErrAssetLimit) {
		t.Errorf("A over its limit: %v", err)
	}
	ua, _ := s.AssetUsage(a)
	ub, _ := s.AssetUsage(b)
	if ua.Monitored != 1 || !ua.AtLimit || len(ua.Refused) != 1 || ub.Monitored != 3 || ub.Limit != nil || len(ub.Refused) != 0 {
		t.Errorf("usage A %+v, B %+v", ua, ub)
	}
	// An admin narrowed to an empty project still sees the organisation's
	// total and the limit applies to the whole organisation.
	p, err := s.CreateProject(a, "empty", "")
	if err != nil {
		t.Fatal(err)
	}
	narrowed := tenant.WithProject(a, p.ID)
	if u, err := s.AssetUsage(narrowed); err != nil || u.Monitored != 1 {
		t.Errorf("narrowed usage: %+v %v", u, err)
	}
	if _, err := s.Ingest(narrowed, quotaBatch(model.AssetHost, "a-3", "machine-id"), 0); !errors.Is(err, store.ErrAssetLimit) {
		t.Errorf("narrowed ingest over the limit: %v", err)
	}
	// Without a scope nothing is counted or refused for anyone.
	if u, err := s.AssetUsage(bg); err == nil {
		t.Errorf("usage without a scope: %+v", u)
	}
}
