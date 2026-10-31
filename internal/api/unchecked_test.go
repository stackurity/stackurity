package api_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestUncheckedByActor: GET /coverage/unchecked splits what the matcher
// could not check by who acts, from the reasons it really writes, and the
// inventory filter lists the components behind each count.
func TestUncheckedByActor(t *testing.T) {
	e := newEnv(t)
	e.user("viewer@x.io", auth.RoleViewer)
	viewer := e.login("viewer@x.io")
	bg := context.Background()
	sys := tenant.System(bg)
	ws := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	// Debian's source has synced, with advisories for Debian 12 only.
	if err := e.st.EnsureFeed(sys, "osv:Debian", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(sys, `UPDATE feeds SET last_success = now(), ecosystems = '{Debian:12}' WHERE name = 'osv:Debian'`); err != nil {
		t.Fatal(err)
	}
	ingest := func(kind model.AssetKind, name string, cov []model.CoverageItem, obs ...model.Observation) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "t-" + name, Method: "test"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}})
		b.Observations, b.Coverage, b.Complete = obs, cov, len(cov) == 0
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := e.st.Ingest(ws, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	ob := func(purl, loc string) model.Observation {
		return model.Observation{Purl: purl, Location: loc, Confidence: model.ConfidenceConfirmed}
	}
	repo := ingest(model.AssetRepository, "web", nil,
		ob("pkg:npm/left-pad", "web/package.json"),           // no version: the user commits the lockfile
		ob("pkg:npm/express@4.0.0", "web/package-lock.json"), // npm's source not set up yet: resolves on its own
		ob("pkg:cocoapods/Alamofire@5.0.0", "ios/Podfile.lock"))
	host := ingest(model.AssetHost, "db", nil,
		ob("pkg:deb/debian/openssl@3.0.0?distro=debian-14", "/var/lib/dpkg/status")) // no advisories for Debian 14
	app := ingest(model.AssetApplication, "shop",
		[]model.CoverageItem{{Scope: "app-permissions:/var/www/shop", Status: "unsupported", Reason: "the agent's user may not read /var/www/shop"}})
	ev := &intel.Evaluator{Store: e.st, Now: time.Now}
	if _, err := ev.Evaluate(ws, nil, 0); err != nil {
		t.Fatal(err)
	}

	var u store.Unchecked
	if code := viewer.do("GET", "/api/v1/coverage/unchecked", nil, &u); code != 200 {
		t.Fatalf("unchecked: %d", code)
	}
	if u.NeedYou != 2 || u.NotSupported != 1 || u.Waiting != 1 || u.NoAdvisories != 1 || u.Overdue {
		t.Errorf("counts: %+v", u)
	}
	actors := map[string]string{}
	for _, g := range u.Groups {
		actors[g.Reason] = g.Actor
	}
	want := map[string]string{"unreadable_version": "user", "unreadable_files": "user", "unsupported": "stackurity",
		"waiting_for_data": "automatic", "no_advisories": "none"}
	if fmt.Sprint(actors) != fmt.Sprint(want) {
		t.Errorf("actors: %v", actors)
	}
	if u.Groups[0].Reason != "unreadable_version" {
		t.Errorf("what needs the user comes first: %+v", u.Groups)
	}

	// One asset at a time.
	for id, wantReasons := range map[int64]string{repo: "unreadable_version unsupported waiting_for_data", host: "no_advisories", app: "unreadable_files"} {
		var one store.Unchecked
		if code := viewer.do("GET", fmt.Sprintf("/api/v1/coverage/unchecked?asset_id=%d", id), nil, &one); code != 200 {
			t.Fatalf("asset %d: %d", id, code)
		}
		var got []string
		for _, g := range one.Groups {
			got = append(got, g.Reason)
		}
		if strings.Join(got, " ") != wantReasons {
			t.Errorf("asset %d: %v, want %s", id, got, wantReasons)
		}
	}

	// The components behind a count, with the cause and the fix.
	var inv struct {
		Items []store.InventoryRow `json:"items"`
	}
	if code := viewer.do("GET", "/api/v1/inventory?unchecked=unreadable_version", nil, &inv); code != 200 {
		t.Fatalf("inventory: %d", code)
	}
	if len(inv.Items) != 1 || inv.Items[0].Name != "left-pad" || inv.Items[0].UncheckedActor != "user" ||
		inv.Items[0].UncheckedCause != "no_version" || !strings.Contains(inv.Items[0].UncheckedFix, "package-lock.json") {
		t.Errorf("unreadable versions: %+v", inv.Items)
	}
	if code := viewer.do("GET", fmt.Sprintf("/api/v1/assets/%d/inventory?unchecked=no_advisories", host), nil, &inv); code != 200 {
		t.Fatalf("asset inventory: %d", code)
	}
	if len(inv.Items) != 1 || inv.Items[0].UncheckedActor != "none" {
		t.Errorf("no advisories: %+v", inv.Items)
	}
	if code := viewer.do("GET", "/api/v1/inventory?unchecked=everything", nil, nil); code != 400 {
		t.Errorf("unknown reason: %d", code)
	}
}
