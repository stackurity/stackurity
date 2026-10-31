package store_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// updatesFixture: two images in the default workspace and one in another,
// with release data for their packages.
//
//	shop/api:1   lodash 4.17.15 (patch), react 17.0.2 (major), foo (generic),
//	             left-pad (current), next (latest is a pre-release), vite
//	             (installed pre-release ahead of the latest), the WordPress
//	             plugin akismet 5.2 from wordpress.org (minor), and acme-pro,
//	             a plugin the collector marked not from wordpress.org
//	shop/web:1   lodash 4.17.20 (patch), express 4.17.0 (minor)
//	Beta's image lodash 4.17.10, express 4.17.0
func updatesFixture(t *testing.T) (a, b context.Context, s *store.Store, api, web int64) {
	t.Helper()
	s = store.New(testdb.New(t))
	bg := context.Background()
	a = tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	ws, _, err := s.CreateWorkspace(bg, "Beta", "", "beta@x.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	b = tenant.WithWorkspace(bg, ws.ID)
	// acme-pro is marked as the WordPress collector marks a plugin whose
	// Update URI names another host.
	batch := model.NewBatch(model.Collector{ID: "image-scanner", Version: "1", Method: "scanner"},
		model.AssetRef{Kind: model.AssetImage, Name: "registry.example.com/shop/api:1",
			Identifiers: []model.Identifier{{Scheme: "image-ref", Value: "registry.example.com/shop/api:1"}},
			Attributes:  map[string]string{"image": "registry.example.com/shop/api:1", "digest": digestA}})
	for _, p := range []string{"pkg:npm/lodash@4.17.15", "pkg:npm/react@17.0.2", "pkg:generic/foo@1.0", "pkg:npm/left-pad@1.3.0", "pkg:npm/next@14.1.0",
		"pkg:npm/vite@6.0.0-beta.1", "pkg:generic/wordpress-plugin/akismet@5.2"} {
		batch.Observations = append(batch.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
	}
	batch.Observations = append(batch.Observations, model.Observation{Purl: "pkg:generic/wordpress-plugin/acme-pro@3.2.1", Confidence: model.ConfidenceConfirmed,
		Evidence: map[string]string{"wordpress_org": "no", "wordpress_org_reason": "its Update URI names updates.acme.example"}})
	batch.Complete = true
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := s.Ingest(a, batch, 0)
	if err != nil {
		t.Fatal(err)
	}
	api = res.AssetID
	web = ingestImage(t, s, a, "registry.example.com/shop/web:1", digestB, "pkg:npm/lodash@4.17.20", "pkg:npm/express@4.17.0")
	ingestImage(t, s, b, "registry.example.com/beta/app:1", digestA, "pkg:npm/lodash@4.17.10", "pkg:npm/express@4.17.0")

	latest := map[string]string{"lodash": "4.17.21", "react": "18.3.1", "foo": "2.0", "left-pad": "1.3.0", "next": "15.0.0-rc.1",
		"vite": "5.4.0", "akismet": "5.3", "acme-pro": "3.3.0", "express": "4.21.0"}
	for _, asset := range []int64{api, web} {
		rows, _, err := s.ListInventory(a, store.InventoryFilter{AssetID: asset})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if err := s.UpsertRelease(a, store.Release{ComponentID: r.ComponentID, Latest: latest[r.Name], LatestStable: latest[r.Name],
				Source: "releases:" + r.Type, CheckedAt: time.Now()}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return a, b, s, api, web
}

// The summary counts installs behind by update type and lists the packages
// with the most installs behind. Generic packages other than WordPress
// plugins and themes, current versions, pre-releases (as latest, or
// installed ahead of it) and plugins not from wordpress.org are left out,
// and another workspace's installs are never counted.
func TestUpdatesSummary(t *testing.T) {
	a, b, s, api, web := updatesFixture(t)

	sum, err := s.SummarizeWorkspaceUpdates(a, store.UpdatesFilter{})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"patch": 2, "minor": 2, "major": 1, "total": 5}
	if !mapsEqual(sum.Counts, want) || sum.Components != 4 || len(sum.Top) != 4 {
		t.Fatalf("summary = %+v", sum)
	}
	lodash := sum.Top[0]
	if lodash.Name != "lodash" || lodash.Installs != 2 || lodash.Assets != 2 || lodash.LatestStable != "4.17.21" ||
		lodash.UpdateType != "patch" || !slices.Equal(lodash.InstalledVersions, []string{"4.17.15", "4.17.20"}) {
		t.Errorf("lodash = %+v", lodash)
	}
	// Equal installs: the larger change first, then by name.
	if sum.Top[1].Name != "react" || sum.Top[1].UpdateType != "major" || sum.Top[2].Name != "akismet" || sum.Top[2].Namespace != "wordpress-plugin" ||
		sum.Top[2].UpdateType != "minor" || sum.Top[3].Name != "express" {
		t.Errorf("top = %+v", sum.Top)
	}

	minor, err := s.SummarizeWorkspaceUpdates(a, store.UpdatesFilter{UpdateType: "minor"})
	if err != nil || !mapsEqual(minor.Counts, want) || minor.Components != 2 || minor.Top[0].Name != "akismet" || minor.Top[1].Name != "express" {
		t.Errorf("minor = %+v %v", minor, err)
	}
	one, err := s.SummarizeWorkspaceUpdates(a, store.UpdatesFilter{AssetID: web, Limit: 1})
	if err != nil || one.Counts["total"] != 2 || one.Components != 2 || len(one.Top) != 1 || one.Top[0].Assets != 1 {
		t.Errorf("one asset, limit 1 = %+v %v", one, err)
	}
	if _, err := s.SummarizeWorkspaceUpdates(a, store.UpdatesFilter{UpdateType: "huge"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad update type: %v", err)
	}

	// Beta sees its own two installs, nothing of the default workspace.
	beta, err := s.SummarizeWorkspaceUpdates(b, store.UpdatesFilter{})
	if err != nil || beta.Counts["total"] != 2 || beta.Components != 2 {
		t.Fatalf("beta = %+v %v", beta, err)
	}
	for _, c := range beta.Top {
		if slices.Contains(c.InstalledVersions, "4.17.15") || slices.Contains(c.InstalledVersions, "4.17.20") {
			t.Errorf("beta sees the default workspace's versions: %+v", c)
		}
	}
	if other, err := s.SummarizeWorkspaceUpdates(b, store.UpdatesFilter{AssetID: api}); err != nil || other.Counts["total"] != 0 {
		t.Errorf("beta asking for the default workspace's asset = %+v %v", other, err)
	}
}

// The inventory's update_type filter keeps the rows with a newer stable
// release of that type, paged after classification.
func TestInventoryUpdateTypeFilter(t *testing.T) {
	a, b, s, api, web := updatesFixture(t)
	names := func(f store.InventoryFilter) ([]string, int64) {
		t.Helper()
		rows, total, err := s.ListInventory(a, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.Name+"@"+r.Version+":"+r.UpdateType)
		}
		return out, total
	}
	if got, total := names(store.InventoryFilter{UpdateType: "any"}); total != 5 ||
		!slices.Equal(got, []string{"akismet@5.2:minor", "express@4.17.0:minor", "lodash@4.17.15:patch", "lodash@4.17.20:patch", "react@17.0.2:major"}) {
		t.Errorf("any = %v (%d)", got, total)
	}
	if got, total := names(store.InventoryFilter{UpdateType: "patch", Page: store.Page{Limit: 1, Offset: 1}}); total != 2 ||
		!slices.Equal(got, []string{"lodash@4.17.20:patch"}) {
		t.Errorf("patch, second page = %v (%d)", got, total)
	}
	if got, total := names(store.InventoryFilter{UpdateType: "patch", Page: store.Page{Limit: 5, Offset: 10}}); total != 2 || len(got) != 0 {
		t.Errorf("patch, past the end = %v (%d)", got, total)
	}
	if got, total := names(store.InventoryFilter{UpdateType: "major", AssetID: web}); total != 0 || len(got) != 0 {
		t.Errorf("major on web = %v (%d)", got, total)
	}
	if got, total := names(store.InventoryFilter{UpdateType: "any", AssetID: api, Search: "react"}); total != 1 || len(got) != 1 {
		t.Errorf("search react on api = %v (%d)", got, total)
	}
	// Without the filter every row is listed, the excluded ones with no
	// update type (vite: ahead, which is not an update).
	all, _, err := s.ListInventory(a, store.InventoryFilter{AssetID: api})
	if err != nil || len(all) != 8 {
		t.Fatalf("api rows = %v %v", all, err)
	}
	wantType := map[string]string{"lodash": "patch", "react": "major", "akismet": "minor", "vite": "ahead"}
	for _, r := range all {
		if r.UpdateType != wantType[r.Name] {
			t.Errorf("%s@%s has update type %q, want %q", r.Name, r.Version, r.UpdateType, wantType[r.Name])
		}
		if r.Name == "acme-pro" && (r.LatestStable != "" || r.Evidence["wordpress_org"] != "no") {
			t.Errorf("acme-pro, not from wordpress.org: %+v", r)
		}
	}
	if _, _, err := s.ListInventory(a, store.InventoryFilter{UpdateType: "huge"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bad update type: %v", err)
	}
	if rows, total, err := s.ListInventory(b, store.InventoryFilter{UpdateType: "any"}); err != nil || total != 2 || len(rows) != 2 {
		t.Errorf("beta = %v (%d) %v", rows, total, err)
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
