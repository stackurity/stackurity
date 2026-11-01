package registrysync_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/collect/image"
	"github.com/stackurity/stackurity/internal/collect/registry"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/registrysync"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

var t0 = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

type img struct {
	manifest, config []byte
	digest, cfgDig   string
}

func newImg(created time.Time, salt string) img {
	cfg, _ := json.Marshal(map[string]any{"created": created.Format(time.RFC3339), "salt": salt})
	cs := sha256.Sum256(cfg)
	man, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{"digest": "sha256:" + hex.EncodeToString(cs[:])}})
	ms := sha256.Sum256(man)
	return img{man, cfg, "sha256:" + hex.EncodeToString(ms[:]), "sha256:" + hex.EncodeToString(cs[:])}
}

// fakeRegistry is a small OCI registry without authentication.
type fakeRegistry struct {
	mu     sync.Mutex
	repos  map[string]map[string]img
	broken map[string]bool // repositories whose tag list fails
	srv    *httptest.Server
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{repos: map[string]map[string]img{}, broken: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	t.Cleanup(registry.SetTestTLS(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // tests only
	return f
}

func (f *fakeRegistry) set(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

func (f *fakeRegistry) push(repo, tag string, im img) {
	f.set(func() {
		if f.repos[repo] == nil {
			f.repos[repo] = map[string]img{}
		}
		f.repos[repo][tag] = im
	})
}

func (f *fakeRegistry) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v2/")
	if p == "_catalog" {
		var names []string
		for k := range f.repos {
			names = append(names, k)
		}
		sort.Strings(names)
		_ = json.NewEncoder(w).Encode(map[string]any{"repositories": names})
		return
	}
	for repo, tags := range f.repos {
		rest, ok := strings.CutPrefix(p, repo+"/")
		if !ok {
			continue
		}
		if f.broken[repo] {
			w.WriteHeader(500)
			return
		}
		switch {
		case rest == "tags/list":
			names := []string{}
			for t := range tags {
				names = append(names, t)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tags": names})
			return
		case strings.HasPrefix(rest, "manifests/"):
			ref := strings.TrimPrefix(rest, "manifests/")
			for tag, im := range tags {
				if tag == ref || im.digest == ref {
					w.Header().Set("Docker-Content-Digest", im.digest)
					_, _ = w.Write(im.manifest)
					return
				}
			}
		case strings.HasPrefix(rest, "blobs/"):
			for _, im := range tags {
				if im.cfgDig == strings.TrimPrefix(rest, "blobs/") {
					_, _ = w.Write(im.config)
					return
				}
			}
		}
	}
	w.WriteHeader(404)
}

type fixture struct {
	ctx context.Context
	s   *store.Store
	in  *store.Integration
	cfg registry.Config
	reg *fakeRegistry
}

func newFixture(t *testing.T, mutate func(*registry.Config)) *fixture {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	reg := newFakeRegistry(t)
	cfg := registry.Config{Provider: registry.OCI, URL: reg.srv.URL}
	if mutate != nil {
		mutate(&cfg)
	}
	in, err := s.CreateIntegration(ctx, registrysync.Kind, "fake", cfg, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{ctx, s, in, cfg, reg}
}

func (f *fixture) run(t *testing.T) registrysync.Summary {
	t.Helper()
	sum, err := registrysync.Run(f.ctx, f.s, f.in, f.cfg, registry.Credentials{}, registrysync.Options{Version: "test", Fresh: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func (f *fixture) images(t *testing.T) map[string]store.RegistryImage {
	t.Helper()
	rows, err := f.s.RegistryImages(f.ctx, f.in.ID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.RegistryImage{}
	for _, r := range rows {
		out[r.Repository+":"+strings.Join(r.Tags, ",")] = r
	}
	return out
}

func (f *fixture) host() string { return strings.TrimPrefix(f.reg.srv.URL, "https://") }

func (f *fixture) scanJobs(t *testing.T) map[string]bool {
	t.Helper()
	js, err := f.s.ListJobs(f.ctx, "pending", 200)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, j := range js {
		if j.Kind == "image.scan" {
			var p store.ImageScan
			_ = json.Unmarshal(j.Payload, &p)
			out[p.Image] = true
			if p.IntegrationID != f.in.ID {
				t.Errorf("scan of %s queued for integration %d, want %d", p.Image, p.IntegrationID, f.in.ID)
			}
		}
	}
	return out
}

// scanned stands in for the image scanner's report on an asset.
func (f *fixture) scanned(t *testing.T, ref string, purls ...string) {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: store.ImageScanCollector, Version: "test", Method: "scanner"},
		model.AssetRef{Kind: model.AssetImage, Name: ref, Identifiers: []model.Identifier{{Scheme: "image-ref", Value: ref}}})
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
	}
	b.Cover("image:"+ref, "checked", "")
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.Ingest(f.ctx, b, 0); err != nil {
		t.Fatal(err)
	}
}

func TestRunTracksScansUntracksAndRemoves(t *testing.T) {
	f := newFixture(t, func(c *registry.Config) { c.RecentTags = 1; c.TagPatterns = []string{"stable"} })
	v1, v2 := newImg(t0, "1"), newImg(t0.Add(time.Hour), "2")
	f.reg.push("shop", "1.0", v1)
	f.reg.push("shop", "1.1", v2)
	f.reg.push("shop", "latest", v2)
	f.reg.push("old", "1", newImg(t0, "old"))

	sum := f.run(t)
	if sum.Repositories != 2 || sum.Tracked != 2 || sum.NewImages != 2 || sum.Scans.Queued != 2 || sum.Note() != nil {
		t.Fatalf("first run = %+v (note %v)", sum, sum.Note())
	}
	ims := f.images(t)
	shop := ims["shop:1.1,latest"]
	if shop.AssetID == nil || !shop.Tracked || shop.ImageRef != f.host()+"/shop@"+v2.digest {
		t.Fatalf("shop = %+v; images = %v", shop, ims)
	}
	a, err := f.s.GetAsset(f.ctx, *shop.AssetID)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name != f.host()+"/shop:1.1" || a.Kind != "image" || a.Attributes["digest"] != v2.digest || a.Attributes["tags"] != "1.1, latest" ||
		a.CollectionStatus != "partial" {
		t.Errorf("asset = %+v: named by tag, found by digest, not clean before its scan", a)
	}
	jobs := f.scanJobs(t)
	if !jobs[shop.ImageRef] || len(jobs) != 2 {
		t.Errorf("scan jobs = %v", jobs)
	}

	// The scanner reports; a second run adds nothing and rescans nothing:
	// the digest was scanned within the freshness window.
	f.scanned(t, shop.ImageRef, "pkg:deb/debian/openssl@3.0.11", "pkg:npm/lodash@4.17.20")
	oldRef := ims["old:1"].ImageRef
	f.scanned(t, oldRef, "pkg:deb/debian/zlib@1.2.13")
	// A re-tag of the same digest is one image: tags follow, no new asset.
	f.reg.push("shop", "stable", v2)
	sum = f.run(t)
	if sum.NewImages != 0 || sum.Scans.Queued != 0 || sum.Scans.Fresh != 2 || sum.Removed != 0 {
		t.Errorf("second run = %+v", sum)
	}
	ims = f.images(t)
	if r, ok := ims["shop:1.1,stable,latest"]; !ok || *r.AssetID != *shop.AssetID {
		t.Errorf("re-tagged image = %+v (images %v)", r, ims)
	}
	if a, _ := f.s.GetAsset(f.ctx, *shop.AssetID); a.Attributes["tags"] != "1.1, stable, latest" {
		t.Errorf("asset tags = %q", a.Attributes["tags"])
	}

	// A newer push takes the place of 1.1 (which "stable" still names, so
	// it stays tracked by the pattern); pushing over "stable" leaves 1.1
	// untracked, not removed: it is still in the registry.
	v3 := newImg(t0.Add(2*time.Hour), "3")
	f.reg.push("shop", "1.2", v3)
	f.reg.push("shop", "stable", v3)
	sum = f.run(t)
	if sum.NewImages != 1 || sum.Untracked != 1 || sum.Removed != 0 {
		t.Errorf("third run = %+v", sum)
	}
	ims = f.images(t)
	old11 := ims["shop:1.1,stable,latest"]
	if old11.Tracked || old11.RemovedAt != nil {
		t.Errorf("1.1 = %+v, want untracked and not removed", old11)
	}
	if a, _ := f.s.GetAsset(f.ctx, *shop.AssetID); a.CollectionStatus != "ok" {
		t.Errorf("untracked image's asset status = %s, want ok (unchanged)", a.CollectionStatus)
	}

	// 1.1 and latest are deleted from the registry: the image is removed,
	// its inventory closes (history kept), and its asset says why.
	f.reg.set(func() { delete(f.reg.repos["shop"], "1.1"); delete(f.reg.repos["shop"], "latest") })
	// The whole "old" repository is deleted too.
	f.reg.set(func() { delete(f.reg.repos, "old") })
	sum = f.run(t)
	if sum.Removed != 2 {
		t.Errorf("fourth run = %+v, want 2 removed", sum)
	}
	ims = f.images(t)
	if r := ims["shop:1.1,stable,latest"]; r.RemovedAt == nil {
		t.Errorf("1.1 not removed: %+v", r)
	}
	if r := ims["old:1"]; r.RemovedAt == nil {
		t.Errorf("old not removed: %+v", r)
	}
	a, _ = f.s.GetAsset(f.ctx, *shop.AssetID)
	if a.CollectionStatus != store.AssetRemoved {
		t.Errorf("removed image's asset status = %s", a.CollectionStatus)
	}
	open, _, err := f.s.ListInventory(f.ctx, store.InventoryFilter{AssetID: *shop.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	all, _, err := f.s.ListInventory(f.ctx, store.InventoryFilter{AssetID: *shop.AssetID, IncludeRemoved: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(open) != 0 || len(all) != 2 {
		t.Errorf("inventory: %d current, %d with history; want 0 and 2", len(open), len(all))
	}
	rows, _, err := f.s.ListCoverage(f.ctx, *shop.AssetID, false, store.Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range rows {
		if c.CollectorID == store.ImageScanCollector && strings.Contains(c.Reason, "deleted from the registry") && c.Status == "skipped" {
			found = true
		}
	}
	if !found {
		t.Errorf("no coverage saying the image was deleted: %+v", rows)
	}
	var evaluate int
	if err := f.s.Pool.QueryRow(f.ctx, `SELECT count(*) FROM jobs WHERE kind = 'evaluate' AND payload->>'asset_id' = $1::text`,
		fmt.Sprint(*shop.AssetID)).Scan(&evaluate); err != nil || evaluate == 0 {
		t.Errorf("no evaluation queued for the removed image (%v)", err)
	}

	// Pushed again: tracked again, and scanned again (the last scan is
	// forgotten when it was removed).
	f.reg.push("shop", "1.1", v2)
	f.reg.push("shop", "9.9", v2)
	f.cfg.TagPatterns = []string{"stable", "9.9"}
	sum = f.run(t)
	ims = f.images(t)
	back := ims["shop:9.9,1.1"]
	if back.RemovedAt != nil || !back.Tracked || back.AssetID == nil || *back.AssetID != *shop.AssetID {
		t.Errorf("pushed again = %+v (images %v)", back, ims)
	}
	if !f.scanJobs(t)[back.ImageRef] {
		t.Errorf("the image pushed again was not queued for a scan: %+v", sum)
	}
	if a, _ := f.s.GetAsset(f.ctx, *shop.AssetID); a.CollectionStatus == store.AssetRemoved {
		t.Error("the image pushed again still shows as removed")
	}
}

// A repository that could not be read proves nothing: its images are
// neither removed nor untracked, and the integration says so.
func TestUnreadableRepositoryRemovesNothing(t *testing.T) {
	f := newFixture(t, nil)
	f.reg.push("shop", "1.0", newImg(t0, "1"))
	f.run(t)
	f.reg.set(func() { f.reg.broken["shop"] = true })
	sum := f.run(t)
	if sum.Removed != 0 || sum.Untracked != 0 || sum.Note() == nil || !strings.Contains(sum.Note().Error(), "shop") {
		t.Errorf("run = %+v, note %v", sum, sum.Note())
	}
	for _, r := range f.images(t) {
		if !r.Tracked || r.RemovedAt != nil {
			t.Errorf("%+v changed although its repository was not read", r)
		}
	}
	// Control: once readable and the tag is gone, it is removed.
	f.reg.set(func() {
		f.reg.broken["shop"] = false
		f.reg.repos["shop"] = map[string]img{"2.0": newImg(t0.Add(time.Hour), "2")}
	})
	if sum := f.run(t); sum.Removed != 1 {
		t.Errorf("control run = %+v", sum)
	}
}

// Leaving a repository out of the selection stops tracking it; it does
// not mark its images removed.
func TestExcludedRepositoryIsUntrackedNotRemoved(t *testing.T) {
	f := newFixture(t, nil)
	f.reg.push("shop", "1.0", newImg(t0, "1"))
	f.reg.push("web", "1.0", newImg(t0, "2"))
	f.run(t)
	f.cfg.Exclude = []string{"web"}
	sum := f.run(t)
	if sum.Untracked != 1 || sum.Removed != 0 {
		t.Errorf("run = %+v", sum)
	}
}

func TestAssetLimitLeavesNewImagesOutUntilThereIsRoom(t *testing.T) {
	f := newFixture(t, nil)
	f.reg.push("a", "1", newImg(t0, "a"))
	f.reg.push("b", "1", newImg(t0, "b"))
	one := int64(1)
	if err := f.s.SetAssetLimit(f.ctx, tenant.DefaultWorkspace, &one); err != nil {
		t.Fatal(err)
	}
	sum := f.run(t)
	if sum.NewImages != 1 || sum.Refused != 1 || !errors.Is(sum.Note(), store.ErrAssetLimit) || sum.Scans.Queued != 1 {
		t.Errorf("run at the limit = %+v (note %v)", sum, sum.Note())
	}
	if err := f.s.SetAssetLimit(f.ctx, tenant.DefaultWorkspace, nil); err != nil {
		t.Fatal(err)
	}
	if sum := f.run(t); sum.NewImages != 1 || sum.Refused != 0 || sum.Note() != nil {
		t.Errorf("run with room = %+v", sum)
	}
}

// The image scan of a registry's image gets the registry's credentials
// only for an image on that registry's host.
func TestScanSecretOnlyForTheRegistryHost(t *testing.T) {
	f := newFixture(t, func(c *registry.Config) { c.Username = "robot" })
	if err := f.s.UpdateIntegration(f.ctx, f.in.ID, store.IntegrationUpdate{SecretRef: ptr("secret:reg")}); err != nil {
		t.Fatal(err)
	}
	res := secrets.Resolver{Stored: func(_ context.Context, name string) (string, error) {
		if name == "reg" {
			return "registry-password", nil
		}
		return "", errors.New("no such secret")
	}}
	cfg := image.Config{Image: f.host() + "/shop@sha256:" + strings.Repeat("a", 64)}
	got, err := registrysync.ScanSecret(f.ctx, f.s, res, store.ImageScan{IntegrationID: f.in.ID, Image: cfg.Image}, &cfg)
	if err != nil || got != "registry-password" || cfg.Username != "robot" {
		t.Errorf("same host: %q %q %v", got, cfg.Username, err)
	}
	other := image.Config{Image: "evil.example.com/shop@sha256:" + strings.Repeat("a", 64)}
	got, err = registrysync.ScanSecret(f.ctx, f.s, res, store.ImageScan{IntegrationID: f.in.ID, Image: other.Image}, &other)
	if err == nil || got != "" || other.Username != "" {
		t.Errorf("another host: %q %v", got, err)
	}
	// Images found running by a plugin, or queued before integrations
	// were recorded, are read without credentials.
	none := image.Config{Image: cfg.Image}
	if got, err := registrysync.ScanSecret(f.ctx, f.s, res, store.ImageScan{Image: cfg.Image}, &none); got != "" || err != nil {
		t.Errorf("no integration: %q %v", got, err)
	}
	plug, err := f.s.CreateIntegration(f.ctx, "plugin", "k8s", map[string]any{"plugin": "kubernetes"}, "secret:reg", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := registrysync.ScanSecret(f.ctx, f.s, res, store.ImageScan{IntegrationID: plug.ID, Image: cfg.Image}, &none); got != "" || err != nil {
		t.Errorf("plugin integration: %q %v", got, err)
	}
}

func TestAWSIntegrationCredentials(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	aws, err := s.CreateIntegration(ctx, "plugin", "aws", map[string]any{"plugin": "aws-managed",
		"config": map[string]any{"regions": []string{"eu-west-1"}, "role_arn": "arn:aws:iam::123456789012:role/ro", "external_id": "ext-1"}},
		"secret:aws", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	k8s, err := s.CreateIntegration(ctx, "plugin", "k8s", map[string]any{"plugin": "kubernetes"}, "secret:aws", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	res := secrets.Resolver{Stored: func(_ context.Context, name string) (string, error) {
		return `{"aws_access_key_id":"AKID","aws_secret_access_key":"SECRET"}`, nil
	}}
	cfg, cr, err := registrysync.Credentials(ctx, s, res, registry.Config{Provider: registry.ECR, Region: "eu-west-1", AWSIntegrationID: aws.ID}, "")
	if err != nil || cr.AWS == nil || cr.AWS.AccessKeyID != "AKID" || cfg.RoleARN != "arn:aws:iam::123456789012:role/ro" || cfg.ExternalID != "ext-1" {
		t.Errorf("borrowed = %+v %+v %v", cfg, cr, err)
	}
	if _, _, err := registrysync.Credentials(ctx, s, res, registry.Config{Provider: registry.ECR, Region: "eu-west-1", AWSIntegrationID: k8s.ID}, ""); !errors.Is(err, registrysync.ErrAWSIntegration) {
		t.Errorf("a kubernetes integration was accepted: %v", err)
	}
	// Another workspace's integration is not found (row-level security).
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	if _, _, err := registrysync.Credentials(ws2, s, res, registry.Config{Provider: registry.ECR, Region: "eu-west-1", AWSIntegrationID: aws.ID}, ""); !errors.Is(err, registrysync.ErrAWSIntegration) {
		t.Errorf("another workspace's integration was used: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }
