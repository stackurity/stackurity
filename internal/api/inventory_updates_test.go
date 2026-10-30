package api_test

import (
	"context"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Updates available: the inventory's update_type filter, the summary
// endpoint, and the route setting that adds them to summaries (off by
// default, kept when a request leaves it out).
func TestInventoryUpdatesEndpoints(t *testing.T) {
	e := newEnv(t)
	e.user("view@x.io", auth.RoleViewer)
	e.user("admin@x.io", auth.RoleAdmin)
	view, admin := e.login("view@x.io"), e.login("admin@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	b := model.NewBatch(model.Collector{ID: "agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "web-1"}}})
	b.Observations = []model.Observation{
		{Purl: "pkg:npm/bootstrap@5.3.3", Confidence: model.ConfidenceConfirmed},
		{Purl: "pkg:npm/react@17.0.2", Confidence: model.ConfidenceConfirmed},
		{Purl: "pkg:deb/debian/openssl@3.0.2-1?distro=debian-12", Confidence: model.ConfidenceConfirmed},
	}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := e.st.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, err := e.st.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	latest := map[string]string{"bootstrap": "5.3.8", "react": "18.3.1", "openssl": "3.4.0"}
	var bootstrap int64
	for _, r := range rows {
		if r.Name == "bootstrap" {
			bootstrap = r.ComponentID
		}
		if err := e.st.UpsertRelease(ctx, store.Release{ComponentID: r.ComponentID, Latest: latest[r.Name], LatestStable: latest[r.Name],
			Source: "releases:" + r.Type, CheckedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}

	var sum store.UpdatesSummary
	if code := view.do("GET", "/api/v1/inventory/updates", nil, &sum); code != 200 || sum.Counts["total"] != 2 ||
		sum.Counts["patch"] != 1 || sum.Counts["major"] != 1 || sum.Components != 2 || len(sum.Top) != 2 {
		t.Fatalf("summary: %d %+v", code, sum)
	}
	if code := view.do("GET", "/api/v1/inventory/updates?update_type=patch&asset_id="+itoa(res.AssetID), nil, &sum); code != 200 ||
		len(sum.Top) != 1 || sum.Top[0].ComponentID != bootstrap || sum.Top[0].LatestStable != "5.3.8" || sum.Top[0].Assets != 1 {
		t.Errorf("patch summary: %d %+v", code, sum)
	}
	if code := view.do("GET", "/api/v1/inventory/updates?update_type=newest", nil, nil); code != 400 {
		t.Errorf("bad update_type: %d", code)
	}

	var list struct {
		Items []store.InventoryRow `json:"items"`
		Total int64                `json:"total"`
	}
	if code := view.do("GET", "/api/v1/inventory?update_type=any", nil, &list); code != 200 || list.Total != 2 {
		t.Errorf("inventory any: %d %+v", code, list)
	}
	if code := view.do("GET", "/api/v1/assets/"+itoa(res.AssetID)+"/inventory?update_type=major", nil, &list); code != 200 ||
		list.Total != 1 || list.Items[0].Name != "react" || list.Items[0].UpdateType != "major" {
		t.Errorf("asset inventory major: %d %+v", code, list)
	}
	if code := view.do("GET", "/api/v1/inventory?update_type=all", nil, nil); code != 400 {
		t.Errorf("bad inventory update_type: %d", code)
	}

	// The route setting: off by default, set by name, kept when omitted.
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "webhook", "name": "h", "config": map[string]string{"url": "https://h.example/x"}}, &ch); code != 201 {
		t.Fatalf("create webhook: %d", code)
	}
	var rt store.Route
	if code := admin.do("POST", "/api/v1/routes", map[string]any{"name": "weekly", "channel_id": ch.ID, "enabled": true,
		"events": []string{"weekly_summary"}}, &rt); code != 201 || rt.SummaryUpdates {
		t.Fatalf("create route: %d %+v", code, rt)
	}
	path := "/api/v1/routes/" + itoa(rt.ID)
	if code := admin.do("PUT", path, map[string]any{"name": "weekly", "channel_id": ch.ID, "enabled": true, "summary_updates": true}, &rt); code != 200 || !rt.SummaryUpdates {
		t.Fatalf("turn on: %d %+v", code, rt)
	}
	if code := admin.do("PUT", path, map[string]any{"name": "weekly", "channel_id": ch.ID, "enabled": true}, &rt); code != 200 || !rt.SummaryUpdates {
		t.Errorf("an older client's PUT turned it off: %d %+v", code, rt)
	}
	if code := admin.do("PUT", path, map[string]any{"name": "weekly", "channel_id": ch.ID, "enabled": true, "summary_updates": false}, &rt); code != 200 || rt.SummaryUpdates {
		t.Errorf("turn off: %d %+v", code, rt)
	}

	// Nothing here is a finding.
	if fs, total, err := e.st.ListFindings(ctx, store.FindingFilter{}); err != nil || total != 0 {
		t.Errorf("updates raised findings: %v %v", fs, err)
	}
}
