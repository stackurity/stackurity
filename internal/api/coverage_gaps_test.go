package api_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestAdminCoverageGaps: the instance-wide report counts what Stackurity
// cannot check by type, across workspaces, without naming any customer
// object.
func TestAdminCoverageGaps(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	owner, admin := e.login("owner@x.io"), e.login("admin@x.io")
	bg := context.Background()
	sys := tenant.System(bg)

	wsB, _, err := e.st.CreateWorkspace(sys, "Globex Secret Division", "", "b@globex.io", "", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	// endoflife.date's data: MongoDB and Electron without the package
	// identifiers their installs use, Elasticsearch without its 8.15 line.
	if err := e.st.ReplaceLifecycle(sys,
		[][]any{
			{"ubuntu", "Ubuntu", []string{}, "https://endoflife.date/ubuntu"},
			{"mongodb", "MongoDB Server", []string{"pkg:deb/ubuntu/mongodb"}, "https://endoflife.date/mongodb"},
			{"electron", "Electron", []string{}, "https://endoflife.date/electron"},
			{"elasticsearch", "Elasticsearch", []string{"pkg:deb/ubuntu/elasticsearch"}, "https://endoflife.date/elasticsearch"},
		},
		[][]any{
			{"ubuntu", "24.04", "24.04", nil, true, nil, time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC), false, "", nil},
			{"mongodb", "6.0", "6.0", nil, false, nil, time.Date(2025, 7, 31, 0, 0, 0, 0, time.UTC), true, "", nil},
			{"electron", "30", "30", nil, false, nil, time.Date(2024, 10, 15, 0, 0, 0, 0, time.UTC), true, "", nil},
			{"elasticsearch", "8.16", "8.16", nil, false, nil, nil, false, "", nil},
		}); err != nil {
		t.Fatal(err)
	}
	ingest := func(ws int64, kind model.AssetKind, name string, cov []model.CoverageItem, obs ...model.Observation) {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "t-" + name, Method: "test"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}})
		b.Observations, b.Coverage, b.Complete = obs, cov, true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		if _, err := e.st.Ingest(tenant.WithWorkspace(bg, ws), b, 0); err != nil {
			t.Fatal(err)
		}
	}
	ob := func(purl, kind string) model.Observation {
		o := model.Observation{Purl: purl, Confidence: model.ConfidenceConfirmed}
		if kind != "" {
			o.Evidence = map[string]string{"kind": kind}
		}
		return o
	}
	unread := func(scope string) []model.CoverageItem {
		return []model.CoverageItem{{Scope: scope, Status: "unsupported", Reason: "parser not implemented yet"}}
	}
	// Workspace 1: a database host with MongoDB's own package, and two
	// repositories with files nothing reads.
	ingest(tenant.DefaultWorkspace, model.AssetHost, "acme-db-prod-7", nil,
		ob("pkg:generic/ubuntu@24.04", "operating-system"),
		ob("pkg:deb/ubuntu/mongodb-org-server@6.0.18?arch=amd64&distro=ubuntu-24.04", ""),
		ob("pkg:deb/ubuntu/elasticsearch@8.15.0?arch=amd64&distro=ubuntu-24.04", ""))
	ingest(tenant.DefaultWorkspace, model.AssetRepository, "acme/payments-api", unread("hex:mix.lock:apps/acme_billing/mix.lock"),
		ob("pkg:npm/%40nestjs/core@10.4.4", ""))
	ingest(tenant.DefaultWorkspace, model.AssetRepository, "acme/ios-app", unread("swift:Package.resolved:AcmeApp.xcworkspace/Package.resolved"))
	// Workspace B: an Electron app with NestJS, a Gentoo host, and another
	// mix.lock.
	ingest(wsB.ID, model.AssetRepository, "globex/desktop", unread("hex:mix.lock:mix.lock"),
		ob("pkg:npm/electron@30.0.0", ""), ob("pkg:npm/%40nestjs/core@10.4.4", ""))
	ingest(wsB.ID, model.AssetHost, "GLOBEX-DC01", nil, ob("pkg:generic/gentoo@2.17", "operating-system"))

	for _, ws := range []int64{tenant.DefaultWorkspace, wsB.ID} {
		ev := &intel.Evaluator{Store: e.st, Now: func() time.Time { return time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC) }}
		if _, err := ev.Evaluate(tenant.WithWorkspace(bg, ws), nil, 0); err != nil {
			t.Fatal(err)
		}
	}

	if code := e.anon().do("GET", "/api/v1/admin/coverage-gaps", nil, nil); code != 401 {
		t.Errorf("anonymous: %d", code)
	}
	if code := admin.do("GET", "/api/v1/admin/coverage-gaps", nil, nil); code != 403 {
		t.Errorf("workspace admin: %d", code)
	}
	var raw json.RawMessage
	if code := owner.do("GET", "/api/v1/admin/coverage-gaps", nil, &raw); code != 200 {
		t.Fatalf("instance admin: %d", code)
	}
	body := string(raw)
	t.Logf("report: %s", body)
	for _, secret := range []string{"acme", "Acme", "globex", "GLOBEX", "Globex", "payments", "billing", "xcworkspace", "DC01", "mongodb-org-server", "%40nestjs"} {
		if strings.Contains(body, secret) {
			t.Errorf("report exposes %q", secret)
		}
	}
	var rep intel.GapReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Workspaces != 2 || rep.Assets != 5 || rep.OverlayVersion == "" {
		t.Errorf("totals: %d workspaces, %d assets, overlay %q", rep.Workspaces, rep.Assets, rep.OverlayVersion)
	}
	find := func(gaps []intel.Gap, kind string) intel.Gap {
		for _, g := range gaps {
			if g.Kind == kind {
				return g
			}
		}
		t.Errorf("no %s in %+v", kind, gaps)
		return intel.Gap{}
	}
	if g := find(rep.UnreadFiles, "hex:mix.lock"); g.Assets != 2 || g.Workspaces != 2 || g.Label != "mix.lock" {
		t.Errorf("mix.lock: %+v", g)
	}
	if g := find(rep.UnreadFiles, "swift:Package.resolved"); g.Assets != 1 || g.Workspaces != 1 {
		t.Errorf("Package.resolved: %+v", g)
	}
	if g := find(rep.NoVulnerabilitySource, "deb|vendor_build|MongoDB's repository (repo.mongodb.org)"); g.Assets != 1 || g.Components != 1 {
		t.Errorf("MongoDB vendor build: %+v", g)
	}
	if g := find(rep.NoLifecycle, "untracked|NestJS"); g.Assets != 2 || g.Workspaces != 2 {
		t.Errorf("NestJS: %+v", g)
	}
	if g := find(rep.NoLifecycle, "no_release_line|elasticsearch"); g.Assets != 1 || g.Label != "Elasticsearch" {
		t.Errorf("Elasticsearch 8.15: %+v", g)
	}
	if g := find(rep.NoLifecycle, "no_product|gentoo"); g.Assets != 1 || g.Workspaces != 1 {
		t.Errorf("Gentoo: %+v", g)
	}
	// Mapped by the overlay with a listed release line: not a gap.
	for _, g := range rep.NoLifecycle {
		if strings.Contains(g.Kind, "mongodb") || strings.Contains(g.Kind, "electron") || strings.Contains(g.Kind, "ubuntu") {
			t.Errorf("unexpected lifecycle gap %+v", g)
		}
	}
}
