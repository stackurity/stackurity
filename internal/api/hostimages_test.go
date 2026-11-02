package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The images of a host's Docker containers (stackurity agent --docker):
// each is an image asset identified by its tag scoped to the host, so the
// same tag on two hosts is two assets, a rebuilt image under the same tag
// updates its asset, and an image no running container uses any more is
// marked removed with its history kept.
func TestHostImageBatches(t *testing.T) {
	e := newEnv(t)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	_, collector, _ := e.st.CreateToken(ctx, "c", auth.RoleCollector, nil, 0, 0)
	send := func(token string, b *model.ObservationBatch) (int, store.IngestResult) {
		t.Helper()
		raw, _ := json.Marshal(b)
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var res store.IngestResult
		_ = json.NewDecoder(resp.Body).Decode(&res)
		return resp.StatusCode, res
	}
	hostIDs := func(m string) []model.Identifier { return []model.Identifier{{Scheme: "machine-id", Value: m}} }
	host := func(m string) *model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: m, Identifiers: hostIDs(m)})
		b.Observations = []model.Observation{{Purl: "pkg:deb/debian/docker-ce@27.3.1", Confidence: model.ConfidenceConfirmed}}
		b.Complete = true
		return b
	}
	// dockerHost is the agent's linux-docker batch for the host, listing
	// the images its running containers use.
	dockerHost := func(m string, refs ...string) *model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux-docker", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: m, Identifiers: hostIDs(m)})
		b.Cover("docker", "checked", "")
		b.Images = &model.ImageList{Refs: append([]string{}, refs...)}
		b.Complete = true
		return b
	}
	image := func(m, ref, id string, purls ...string) *model.ObservationBatch {
		b := model.NewBatch(model.Collector{ID: "linux-docker", Method: "agent"}, model.AssetRef{Kind: model.AssetImage, Name: ref + " on " + m,
			Identifiers: []model.Identifier{{Scheme: model.HostImageScheme, Value: ref}},
			Attributes:  map[string]string{"image": ref, "image_id": id, "host": m}})
		for _, p := range purls {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Location: "/var/lib/dpkg/status", Confidence: model.ConfidenceConfirmed})
		}
		b.Relations = []model.RelationRef{{Kind: "runs_on", To: hostIDs(m)}}
		b.Cover("image:"+ref, "checked", "")
		b.Complete = true
		return b
	}
	asset := func(id int64) store.Asset {
		t.Helper()
		a, err := e.st.GetAsset(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return *a
	}
	live := func(id int64) []string {
		t.Helper()
		rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: id, IncludeRemoved: true})
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			if r.RemovedAt == nil {
				out = append(out, r.Name+"@"+r.Version)
			}
		}
		slices.Sort(out)
		return out
	}
	const id1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	const id2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	const untagged = "sha256:3333333333333333333333333333333333333333333333333333333333333333"

	var meta struct{ Features []string }
	if code := admin.do("GET", "/api/v1/meta", nil, &meta); code != 200 || !slices.Contains(meta.Features, api.FeatureHostImages) {
		t.Errorf("meta features: %d %v", code, meta.Features)
	}
	if code, _ := send(collector, image("m1", "postgres:16", id1, "pkg:deb/debian/libpq5@16.4")); code != 409 {
		t.Errorf("image before its host: %d", code)
	}
	bad := image("m1", "postgres:16", id1)
	bad.Relations = nil
	if code, _ := send(collector, bad); code != 400 {
		t.Errorf("image without runs_on: %d", code)
	}
	bad = image("m1", "postgres:16", id1)
	bad.Asset.Identifiers = append(bad.Asset.Identifiers, model.Identifier{Scheme: "image-ref", Value: "postgres:16"})
	if code, _ := send(collector, bad); code != 400 {
		t.Errorf("host-image with another identifier: %d", code)
	}
	for _, m := range []string{"m1", "m2"} {
		if code, _ := send(collector, host(m)); code != 201 {
			t.Fatal(code)
		}
	}

	code, p1 := send(collector, image("m1", "postgres:16", id1, "pkg:deb/debian/libpq5@16.4", "pkg:deb/debian/libssl3@3.0.11"))
	if code != 201 || !p1.NewAsset {
		t.Fatalf("image on m1: %d %+v", code, p1)
	}
	_, p2 := send(collector, image("m2", "postgres:16", id1, "pkg:deb/debian/libpq5@16.4"))
	if p2.AssetID == p1.AssetID {
		t.Error("the same tag on two hosts must be two assets")
	}
	if a := asset(p1.AssetID); a.Kind != string(model.AssetImage) || a.Name != "postgres:16 on m1" || a.Attributes["image_id"] != id1 {
		t.Errorf("asset = %+v", a)
	}
	rels, _ := e.st.AssetRelations(ctx, p1.AssetID)
	if len(rels) != 1 || rels[0].Kind != "runs_on" || rels[0].ToName != "m1" {
		t.Errorf("relations = %+v", rels)
	}

	// Rebuilt under the same tag: a new image ID, the same asset, its
	// inventory replaced.
	code, re := send(collector, image("m1", "postgres:16", id2, "pkg:deb/debian/libpq5@16.6", "pkg:deb/debian/libssl3@3.0.15"))
	if code != 201 || re.AssetID != p1.AssetID || re.NewAsset {
		t.Fatalf("rebuilt image: %d %+v", code, re)
	}
	if a := asset(p1.AssetID); a.Attributes["image_id"] != id2 {
		t.Errorf("image_id after rebuild = %q", a.Attributes["image_id"])
	}
	if got := live(p1.AssetID); !slices.Equal(got, []string{"libpq5@16.6", "libssl3@3.0.15"}) {
		t.Errorf("inventory after rebuild = %v", got)
	}

	// An untagged image is identified by its image ID.
	_, u := send(collector, image("m1", untagged, untagged, "pkg:deb/debian/curl@7.88.1"))
	if u.AssetID == 0 || u.AssetID == p1.AssetID {
		t.Fatalf("untagged image: %+v", u)
	}

	// Both still run: nothing removed.
	if code, r := send(collector, dockerHost("m1", "postgres:16", untagged)); code != 201 || len(r.ImagesRemoved) != 0 {
		t.Errorf("both listed: %d %+v", code, r)
	}
	// postgres:16 no longer runs on m1.
	code, r := send(collector, dockerHost("m1", untagged))
	if code != 201 || !slices.Equal(r.ImagesRemoved, []int64{p1.AssetID}) {
		t.Fatalf("vanished image: %d %+v", code, r)
	}
	if a := asset(p1.AssetID); a.CollectionStatus != store.AssetRemoved {
		t.Errorf("vanished image status = %q", a.CollectionStatus)
	}
	if got := live(p1.AssetID); len(got) != 0 {
		t.Errorf("vanished image still has live rows %v", got)
	}
	rows, _, _ := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: p1.AssetID, IncludeRemoved: true})
	if len(rows) == 0 {
		t.Error("history of the vanished image was deleted")
	}
	if a := asset(p2.AssetID); a.CollectionStatus == store.AssetRemoved {
		t.Error("the same tag on another host was removed")
	}
	if a := asset(u.AssetID); a.CollectionStatus == store.AssetRemoved {
		t.Error("the image still running was removed")
	}
	// Listing again does not remove it twice.
	if _, r := send(collector, dockerHost("m1", untagged)); len(r.ImagesRemoved) != 0 {
		t.Errorf("removed again: %+v", r)
	}
	// It runs again: present again.
	send(collector, image("m1", "postgres:16", id2, "pkg:deb/debian/libpq5@16.6"))
	if a := asset(p1.AssetID); a.CollectionStatus == store.AssetRemoved {
		t.Errorf("image running again is still %q", a.CollectionStatus)
	}

	// Without a list (the agent could not read Docker) nothing is removed,
	// and an application list does not touch images.
	unread := dockerHost("m1")
	unread.Images = nil
	unread.Coverage = []model.CoverageItem{{Scope: "docker", Status: "failed", Reason: "permission denied"}}
	unread.Complete = false
	if _, r := send(collector, unread); len(r.ImagesRemoved) != 0 {
		t.Errorf("removed without a list: %+v", r)
	}
	apps := host("m1")
	apps.Apps = &model.AppList{Dirs: []string{}}
	if _, r := send(collector, apps); len(r.ImagesRemoved) != 0 || len(r.AppsRemoved) != 0 {
		t.Errorf("app list touched images: %+v", r)
	}
	if a := asset(p1.AssetID); a.CollectionStatus == store.AssetRemoved {
		t.Error("image removed by an app list")
	}

	// A host-bound token reports its own host's images only, and an image
	// list on its host's batch removes only that host's images.
	m1, _ := e.st.AssetByIdentifier(ctx, "machine-id", "m1")
	_, bound, err := e.st.CreateAssetToken(ctx, m1, "host", 0)
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := send(bound, image("m2", "postgres:16", id1)); code != 403 {
		t.Errorf("bound token reported another host's image: %d", code)
	}
	if code, r := send(bound, image("m1", "postgres:16", id2, "pkg:deb/debian/libpq5@16.6")); code != 201 || r.AssetID != p1.AssetID {
		t.Errorf("bound token, own image: %d %+v", code, r)
	}
	ids, err := e.st.AssetsReportingThrough(ctx, m1, []int64{p1.AssetID, p2.AssetID, u.AssetID})
	slices.Sort(ids)
	if want := []int64{p1.AssetID, u.AssetID}; err != nil || !slices.Equal(ids, want) {
		t.Errorf("assets reporting through m1 = %v %v, want %v", ids, err, want)
	}
	if code, r := send(bound, dockerHost("m1")); code != 201 || len(r.ImagesRemoved) != 2 {
		t.Errorf("empty list on m1: %d %+v", code, r)
	}
	if a := asset(p2.AssetID); a.CollectionStatus == store.AssetRemoved {
		t.Error("m1's list removed m2's image")
	}
}
