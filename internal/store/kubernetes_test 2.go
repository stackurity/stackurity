package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// k8sFixture ingests what the Kubernetes plugin reports for a small
// cluster: an exposed workload running nginx, an internal one running redis
// and a third image no workload references.
func k8sFixture(t *testing.T) (context.Context, *store.Store, map[string]int64) {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	ids := map[string]int64{}
	ingest := func(kind model.AssetKind, name, scheme string, attrs map[string]string, rels []model.RelationRef, purls ...string) {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "plugin:kubernetes", Version: "0.1.0", Method: "plugin"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: scheme, Value: name}}, Attributes: attrs})
		for _, p := range purls {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
		}
		b.Relations, b.Complete = rels, true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		ids[name] = r.AssetID
	}
	onCluster := model.RelationRef{Kind: "runs_on", To: []model.Identifier{{Scheme: "k8s-cluster", Value: "lab"}}}
	runs := func(img string) model.RelationRef {
		return model.RelationRef{Kind: "deployed_as", To: []model.Identifier{{Scheme: "image-ref", Value: img}}}
	}
	ingest(model.AssetCluster, "lab", "k8s-cluster", nil, nil, "pkg:generic/kubernetes@1.32.2")
	ingest(model.AssetImage, "docker.io/library/nginx@sha256:aa", "image-ref", nil, nil)
	ingest(model.AssetImage, "docker.io/library/redis@sha256:bb", "image-ref", nil, nil)
	ingest(model.AssetImage, "docker.io/library/busybox:1", "image-ref", nil, nil)
	ingest(model.AssetWorkload, "lab/shop/deployment/web", "k8s-workload", map[string]string{"exposure": "external"},
		[]model.RelationRef{onCluster, runs("docker.io/library/nginx@sha256:aa")})
	ingest(model.AssetWorkload, "lab/shop/deployment/api", "k8s-workload", map[string]string{"exposure": "internal"},
		[]model.RelationRef{onCluster, runs("docker.io/library/redis@sha256:bb"), runs("docker.io/library/nginx@sha256:aa")})
	return ctx, s, ids
}

func TestKubernetesExposure(t *testing.T) {
	ctx, s, ids := k8sFixture(t)
	exposed := func(name string) *bool {
		t.Helper()
		a, err := s.GetAsset(ctx, ids[name])
		if err != nil {
			t.Fatal(err)
		}
		return a.Exposed
	}
	is := func(v *bool, want string) bool {
		switch want {
		case "unknown":
			return v == nil
		case "yes":
			return v != nil && *v
		}
		return v != nil && !*v
	}
	for name, want := range map[string]string{
		"lab/shop/deployment/web": "yes", "lab/shop/deployment/api": "no",
		// An image is exposed when any workload deployed as it is.
		"docker.io/library/nginx@sha256:aa": "yes", "docker.io/library/redis@sha256:bb": "no",
		"docker.io/library/busybox:1": "unknown", "lab": "unknown",
	} {
		if v := exposed(name); !is(v, want) {
			t.Errorf("%s exposed = %v, want %s", name, v, want)
		}
	}
	yes := true
	list, _, err := s.ListAssets(ctx, store.AssetFilter{Exposed: &yes})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, a := range list {
		names = append(names, a.Name)
	}
	if strings.Join(names, ",") != "docker.io/library/nginx@sha256:aa,lab/shop/deployment/web" {
		t.Errorf("exposed assets = %v", names)
	}

	// An operator's setting wins over what the cluster reports.
	no := false
	if err := s.UpdateAsset(ctx, ids["docker.io/library/nginx@sha256:aa"], store.AssetUpdate{InternetExposed: store.Nullable[bool]{Set: true, Value: &no}}); err != nil {
		t.Fatal(err)
	}
	if v := exposed("docker.io/library/nginx@sha256:aa"); !is(v, "no") {
		t.Errorf("override ignored: %v", v)
	}
	// A workload that is gone (stale) no longer exposes its image.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'stale' WHERE id = $1`, ids["lab/shop/deployment/api"]); err != nil {
		t.Fatal(err)
	}
	if v := exposed("docker.io/library/redis@sha256:bb"); !is(v, "unknown") {
		t.Errorf("stale workload still counted: %v", v)
	}
}

func TestKubernetesExposureFeedsRisk(t *testing.T) {
	ctx, s, ids := k8sFixture(t)
	img := ids["docker.io/library/nginx@sha256:aa"]
	b := model.NewBatch(model.Collector{ID: store.ImageScanCollector, Method: "scanner"}, model.AssetRef{Kind: model.AssetImage,
		Name: "docker.io/library/nginx@sha256:aa", Identifiers: []model.Identifier{{Scheme: "image-ref", Value: "docker.io/library/nginx@sha256:aa"}}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/openssl@3.0.1?distro=debian-12", Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: img})
	if err != nil || len(rows) != 1 {
		t.Fatal(err, rows)
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, []int64{rows[0].ID}, []store.FindingInput{{
		Kind: "vulnerability", Key: "CVE-2024-0001", InventoryID: rows[0].ID, AssetID: img, ComponentID: rows[0].ComponentID,
		Verification: "confirmed", Severity: "high", Title: "openssl", Sources: []string{"DSA-1"}, Evidence: map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Prioritize(ctx, risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	fs, _, err := s.ListFindings(ctx, store.FindingFilter{AssetIDs: []int64{img}})
	if err != nil || len(fs) != 1 {
		t.Fatal(err, fs)
	}
	if !strings.Contains(string(fs[0].PriorityFactors), "Internet exposed") {
		t.Errorf("factors = %s", fs[0].PriorityFactors)
	}
}

func TestKubernetesStack(t *testing.T) {
	ctx, s, ids := k8sFixture(t)
	roles := func(id int64) map[string]string {
		t.Helper()
		st, err := s.GetStack(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		for _, mb := range st.Members {
			m[mb.Name] = mb.Role
		}
		return m
	}
	// Which workloads run this image?
	r := roles(ids["docker.io/library/nginx@sha256:aa"])
	if r["lab/shop/deployment/web"] != "workload" || r["lab/shop/deployment/api"] != "workload" {
		t.Errorf("image stack = %v", r)
	}
	// A cluster's workloads and their images.
	r = roles(ids["lab"])
	if r["lab/shop/deployment/web"] != "workload" || r["docker.io/library/redis@sha256:bb"] != "image" || len(r) != 5 {
		t.Errorf("cluster stack = %v", r)
	}
	// A workload's cluster is shown as the cluster, not a host.
	r = roles(ids["lab/shop/deployment/web"])
	if r["lab"] != "cluster" || r["docker.io/library/nginx@sha256:aa"] != "image" {
		t.Errorf("workload stack = %v", r)
	}
}

func TestQueueImageScans(t *testing.T) {
	ctx, s, ids := k8sFixture(t)
	reqs := []store.ImageScan{
		{AssetID: ids["docker.io/library/nginx@sha256:aa"], Image: "docker.io/library/nginx@sha256:aa", Platform: "linux/arm64"},
		{AssetID: ids["docker.io/library/redis@sha256:bb"], Image: "docker.io/library/redis@sha256:bb"},
	}
	st, err := s.QueueImageScans(ctx, reqs, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Queued != 1 || st.Limited != 1 {
		t.Errorf("first run = %+v", st)
	}
	cov := func(id int64) store.CoverageRow {
		t.Helper()
		rows, _, err := s.ListCoverage(ctx, id, false, store.Page{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.CollectorID == store.ImageScanCollector {
				return r
			}
		}
		t.Fatalf("no image-scanner coverage on %d: %+v", id, rows)
		return store.CoverageRow{}
	}
	// Not yet scanned: visible as such, never clean.
	if c := cov(reqs[0].AssetID); c.Status != "skipped" || c.Reason != "queued for scanning" {
		t.Errorf("nginx coverage = %+v", c)
	}
	if c := cov(reqs[1].AssetID); c.Status != "skipped" || !strings.Contains(c.Reason, "at most 1") {
		t.Errorf("redis coverage = %+v", c)
	}
	for _, r := range reqs {
		if a, _ := s.GetAsset(ctx, r.AssetID); a.CollectionStatus != "partial" {
			t.Errorf("%s status = %s", a.Name, a.CollectionStatus)
		}
	}
	// The same digest is not queued twice while pending.
	st, err = s.QueueImageScans(ctx, reqs, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Pending != 1 || st.Queued != 1 {
		t.Errorf("second run = %+v", st)
	}
	var jobs int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM jobs WHERE kind = 'image.scan' AND done_at IS NULL`).Scan(&jobs); err != nil || jobs != 2 {
		t.Errorf("jobs = %d %v", jobs, err)
	}

	// A failed scan keeps its reason when the image is queued again.
	fail := model.NewBatch(model.Collector{ID: store.ImageScanCollector, Method: "scanner"}, model.AssetRef{Kind: model.AssetImage,
		Name: reqs[1].Image, Identifiers: []model.Identifier{{Scheme: "image-ref", Value: reqs[1].Image}}})
	fail.Cover("image:"+reqs[1].Image, "failed", "UNAUTHORIZED: authentication required")
	if _, err := s.Ingest(ctx, fail, 0); err != nil {
		t.Fatal(err)
	}
	// Once scanned, an image is not scanned again within the window.
	ok := model.NewBatch(model.Collector{ID: store.ImageScanCollector, Method: "scanner"}, model.AssetRef{Kind: model.AssetImage,
		Name: reqs[0].Image, Identifiers: []model.Identifier{{Scheme: "image-ref", Value: reqs[0].Image}}})
	ok.Cover("image:"+reqs[0].Image, "checked", "")
	ok.Complete = true
	if _, err := s.Ingest(ctx, ok, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE kind = 'image.scan'`); err != nil {
		t.Fatal(err)
	}
	st, err = s.QueueImageScans(ctx, reqs, 5, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if st.Fresh != 1 || st.Queued != 1 {
		t.Errorf("third run = %+v", st)
	}
	if c := cov(reqs[1].AssetID); c.Status != "failed" || !strings.Contains(c.Reason, "UNAUTHORIZED") {
		t.Errorf("failed scan overwritten: %+v", c)
	}
	if a, _ := s.GetAsset(ctx, reqs[0].AssetID); a.CollectionStatus != "ok" {
		t.Errorf("scanned image status = %s", a.CollectionStatus)
	}
}
