package notify

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// addSchemeAsset ingests one production host with lodash, identified by
// scheme, and records it like addNewAsset (first scan not announced).
func (f *fixture) addSchemeAsset(name, scheme string) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	b := model.NewBatch(model.Collector{ID: "t", Method: "selftest"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Environment: "production", Identifiers: []model.Identifier{{Scheme: scheme, Value: name}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed, Scope: "runtime"}}
	b.Complete = true
	r, err := f.st.Ingest(store.AllowSelftest(ctx), b, 0) // as an admin's selftest
	if err != nil {
		f.t.Fatal(err)
	}
	exposed := true
	if err := f.st.UpdateAsset(ctx, r.AssetID, store.AssetUpdate{InternetExposed: store.Nullable[bool]{Set: true, Value: &exposed}}); err != nil {
		f.t.Fatal(err)
	}
	rows, _, _ := f.st.ListInventory(ctx, store.InventoryFilter{AssetID: r.AssetID})
	f.inv[name], f.asset[name] = rows[0].ID, r.AssetID
}

// everyEvent makes the fixture's route send everything, from P4 up.
func (f *fixture) everyEvent() {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	routes, _ := f.st.ListRoutes(ctx)
	r := routes[0]
	r.Mode, r.MinPriority, r.NewMinPriority = "", "P4", "P4"
	r.Events = []string{store.EventUrgent, store.EventNewIssues, store.EventRegressed, store.EventOverdue, store.EventConnected,
		store.EventProblems, store.EventDailySummary, store.EventWeeklySummary}
	if _, err := f.st.SaveRoute(ctx, r); err != nil {
		f.t.Fatal(err)
	}
}

// ticks runs the dispatcher as a server would while a selftest runs and
// after: ticks, then the asset's first scan counted as evaluated (six
// hours old), more ticks and the hourly digest.
func (f *fixture) ticks(name string) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f.tick()
	if _, err := f.st.Pool.Exec(ctx, `UPDATE assets SET created_at = now() - interval '7 hours' WHERE id = $1`, f.asset[name]); err != nil {
		f.t.Fatal(err)
	}
	f.tick()
	f.tick()
	if err := f.d.Digest(ctx); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) queued() int {
	var n int
	if err := f.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM deliveries`).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// The throwaway asset `stackurity selftest` creates sends nothing on any
// channel: no "connected" message for its first scan, no urgent alert for
// a known exploited issue on an exposed production host, no tracker issue,
// and it joins no incident another asset raised. The same asset with an
// ordinary identifier does send (the control), so the test can see a
// delivery when there is one.
func TestSelftestAssetSendsNothing(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	control := setup(t)
	control.everyEvent()
	control.addSchemeAsset("plain-1", "test")
	control.setFindings("plain-1")
	control.ticks("plain-1")
	if control.queued() == 0 || len(control.hook.events()) == 0 {
		t.Fatal("control: an ordinary asset sent nothing, so the test cannot tell")
	}

	f := setup(t)
	f.everyEvent()
	f.addSchemeAsset("stackurity-selftest-1", store.SelftestScheme)
	f.setFindings("stackurity-selftest-1")
	f.ticks("stackurity-selftest-1")
	if n := f.queued(); n != 0 {
		t.Errorf("%d deliveries queued for a selftest asset", n)
	}
	if ev := f.hook.events(); len(ev) != 0 {
		t.Errorf("channel received %v for a selftest asset", ev)
	}
	incs, _, err := f.st.ListIncidents(ctx, store.IncidentFilter{Status: "all"})
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range incs {
		if in.Kind == "vulnerability" {
			t.Errorf("incident for a selftest finding: %+v", in)
		}
	}

	// A real asset with the same issue raises its incident and alert; the
	// selftest finding stays out of both.
	f.addAsset("web-1", "production", true)
	f.setFindings("stackurity-selftest-1", "web-1")
	f.tick()
	var linked int
	if err := f.st.Pool.QueryRow(ctx, `SELECT count(*) FROM findings WHERE asset_id = $1 AND incident_id IS NOT NULL`,
		f.asset["stackurity-selftest-1"]).Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 0 {
		t.Errorf("the selftest finding joined the real asset's incident")
	}
	if len(f.hook.events()) == 0 {
		t.Fatal("the real asset sent nothing")
	}
	for _, m := range f.hook.got {
		b, _ := json.Marshal(m)
		if strings.Contains(string(b), "stackurity-selftest") {
			t.Errorf("a message names the selftest asset: %s", b)
		}
	}
	// An asset that also has another identifier is not a selftest asset:
	// adding the scheme to a real asset cannot silence it.
	g := setup(t)
	g.everyEvent()
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: "web-2", Environment: "production",
			Identifiers: []model.Identifier{{Scheme: "test", Value: "web-2"}, {Scheme: store.SelftestScheme, Value: "x"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed, Scope: "runtime"}}
	b.Complete = true
	r, err := g.st.Ingest(store.AllowSelftest(ctx), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	rows, _, _ := g.st.ListInventory(ctx, store.InventoryFilter{AssetID: r.AssetID})
	g.inv["web-2"], g.asset["web-2"] = rows[0].ID, r.AssetID
	g.setFindings("web-2")
	g.ticks("web-2")
	if g.queued() == 0 {
		t.Error("an asset with a selftest identifier and another one was silenced")
	}
}
