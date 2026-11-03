package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// coverageFixture reports one repository and one Ubuntu server with a row
// in every segment, and a component checked on one asset and not on the
// other.
func coverageFixture(t *testing.T, ctx context.Context, s *store.Store) (repo, host int64) {
	t.Helper()
	sys := tenant.System(ctx)
	for _, f := range []string{"osv:PyPI", "osv:Ubuntu", "osv:npm"} {
		if err := s.EnsureFeed(sys, f, "vulnerability", time.Hour, 6*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Pool.Exec(sys, `UPDATE feeds SET last_success = now()`); err != nil {
		t.Fatal(err)
	}
	ingest := func(kind model.AssetKind, name string, purls ...string) int64 {
		b := model.NewBatch(model.Collector{ID: "t", Method: "test"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}})
		for _, p := range purls {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Location: "x", Confidence: model.ConfidenceConfirmed})
		}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		res, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return res.AssetID
	}
	repo = ingest(model.AssetRepository, "web",
		"pkg:npm/express@4.0.0", "pkg:npm/left-pad", "pkg:npm/lodash@4.17.21", "pkg:pypi/requests@2.0.0",
		"pkg:cocoapods/Alamofire@5.0.0", "pkg:cocoapods/SnapKit@5.0.0")
	host = ingest(model.AssetHost, "db1",
		"pkg:deb/ubuntu/openssl@3.0?distro=ubuntu-24.04", "pkg:deb/ubuntu/curl@8.0?distro=ubuntu-24.04",
		"pkg:npm/lodash", "pkg:deb/ubuntu/bash@5.2?distro=ubuntu-30.04")
	set := func(asset int64, states map[string][3]string) {
		rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
		if err != nil {
			t.Fatal(err)
		}
		var cov []store.RowCoverage
		for _, r := range rows {
			st, ok := states[r.Name]
			if !ok {
				continue // left awaiting
			}
			cov = append(cov, store.RowCoverage{InventoryID: r.ID, State: st[0], Reason: st[1], Feed: st[2]})
		}
		if err := s.SetCoverage(ctx, cov); err != nil {
			t.Fatal(err)
		}
	}
	set(repo, map[string][3]string{
		"express":   {store.CoverageEvaluated, "", "osv:npm"},
		"left-pad":  {store.CoverageNotEvaluated, "no installed version was reported", ""},
		"lodash":    {store.CoverageEvaluated, "", "osv:npm"},
		"requests":  {store.CoverageNotEvaluated, "vulnerability feed osv:PyPI has not completed a sync", ""},
		"Alamofire": {store.CoverageUnsupported, "CocoaPods packages have no vulnerability source: OSV publishes no CocoaPods advisories", ""},
		"SnapKit":   {store.CoverageUnsupported, "CocoaPods packages have no vulnerability source: OSV publishes no CocoaPods advisories", ""},
	})
	set(host, map[string][3]string{
		"openssl": {store.CoverageEvaluated, "", "osv:Ubuntu"},
		// curl is left awaiting: not evaluated yet.
		"lodash": {store.CoverageNotEvaluated, "no installed version was reported", ""},
		"bash":   {store.CoverageNotEvaluated, "osv:Ubuntu has no advisories for Ubuntu:30.04: the release is newer than the source's data", ""},
	})
	return repo, host
}

// TestCoverageSegmentsAddUp: every component is in one segment, the
// segments add up to the total, and each segment's component list has
// exactly its count.
func TestCoverageSegmentsAddUp(t *testing.T) {
	ctx, s := loopStore(t)
	empty, err := s.SummarizeCoverage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if empty.Total != 0 || len(empty.Segments) != 5 || len(empty.Ecosystems) != 0 {
		t.Errorf("empty workspace: %+v", empty)
	}
	coverageFixture(t, ctx, s)
	ov, err := s.SummarizeCoverage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{
		store.SegmentChecked:      2, // express, openssl
		store.SegmentNeedsYou:     2, // left-pad, and lodash (checked on web, no version on db1)
		store.SegmentWaiting:      2, // requests, curl
		store.SegmentNotSupported: 2, // Alamofire, SnapKit
		store.SegmentNoAdvisories: 1, // bash
	}
	var sum int64
	for seg, n := range want {
		if ov.Segments[seg] != n {
			t.Errorf("segment %s: %d, want %d", seg, ov.Segments[seg], n)
		}
		sum += ov.Segments[seg]
		list, total, err := s.ListComponents(ctx, store.ComponentFilter{Segment: seg})
		if err != nil {
			t.Fatal(err)
		}
		if total != ov.Segments[seg] || int64(len(list)) != total {
			t.Errorf("segment %s: list has %d (%d rows), headline %d", seg, total, len(list), ov.Segments[seg])
		}
	}
	if ov.Total != 9 || sum != ov.Total {
		t.Errorf("total %d, segments add up to %d", ov.Total, sum)
	}
	if _, _, err := s.ListComponents(ctx, store.ComponentFilter{Segment: "bogus"}); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("bogus segment: %v", err)
	}

	eco := map[string]store.EcosystemCoverage{}
	for _, e := range ov.Ecosystems {
		eco[e.Key] = e
	}
	if e := eco["cocoapods"]; e.Label != "CocoaPods" || e.Status != "not_supported" || e.Components != 2 || e.NotSupported != 2 {
		t.Errorf("cocoapods: %+v", e)
	}
	if e := eco["deb:ubuntu-24.04"]; e.Label != "Ubuntu 24.04" || e.Status != "partly" || e.Components != 2 || e.Checked != 1 {
		t.Errorf("ubuntu 24.04: %+v", e)
	}
	if e := eco["deb:ubuntu-30.04"]; e.Status != "checked" || e.Checked != 1 {
		t.Errorf("no advisories counts as checked: %+v", e)
	}
	if e := eco["npm"]; e.Status != "partly" || e.Components != 3 {
		t.Errorf("npm: %+v", e)
	}
	if ov.Ecosystems[0].Key != "npm" {
		t.Errorf("most components first: %s", ov.Ecosystems[0].Key)
	}
}

// TestAssetCoverageWorstFirst: the table's groups, counts by who acts, and
// order.
func TestAssetCoverageWorstFirst(t *testing.T) {
	ctx, s := loopStore(t)
	empty, err := s.ListAssetCoverage(ctx, "", store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if empty.Total != 0 || len(empty.Items) != 0 || len(empty.Groups) != 5 {
		t.Errorf("empty: %+v", empty)
	}
	repo, host := coverageFixture(t, ctx, s)
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET collection_status = 'stale' WHERE id = $1`, host); err != nil {
		t.Fatal(err)
	}
	l, err := s.ListAssetCoverage(ctx, "", store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if l.Total != 2 || l.Items[0].ID != host || l.Items[1].ID != repo {
		t.Fatalf("order: %+v", l.Items)
	}
	h, r := l.Items[0], l.Items[1]
	if h.Group != store.AssetGroupNotReporting || h.Components != 4 || h.Checked != 1 ||
		h.NotChecked[store.ActorUser] != 1 || h.NotChecked[store.ActorAutomatic] != 1 || h.NotChecked[store.ActorNone] != 1 {
		t.Errorf("host: %+v", h)
	}
	if r.Group != store.AssetGroupPartly || r.Components != 6 || r.Checked != 2 ||
		r.NotChecked[store.ActorUser] != 1 || r.NotChecked[store.ActorStackurity] != 2 || r.NotChecked[store.ActorAutomatic] != 1 {
		t.Errorf("repo: %+v", r)
	}
	if l.Groups[store.AssetGroupNotReporting] != 1 || l.Groups[store.AssetGroupPartly] != 1 {
		t.Errorf("groups: %v", l.Groups)
	}
	one, err := s.ListAssetCoverage(ctx, store.AssetGroupPartly, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if one.Total != 1 || one.Items[0].ID != repo || one.Groups[store.AssetGroupNotReporting] != 1 {
		t.Errorf("filtered: %+v", one)
	}
}

// TestSupportRequests: one per workspace and ecosystem, only for an
// ecosystem the workspace has unsupported components of, invisible to
// other workspaces, counted across workspaces for instance administrators.
func TestSupportRequests(t *testing.T) {
	ctx, s := loopStore(t)
	coverageFixture(t, ctx, s)
	uid := int64(0)
	if err := s.Pool.QueryRow(tenant.System(ctx), `SELECT id FROM users ORDER BY id LIMIT 1`).Scan(&uid); err != nil {
		uid = 0
	}
	var by *int64
	if uid > 0 {
		by = &uid
	}
	label, created, err := s.RequestSupport(ctx, "cocoapods", by)
	if err != nil || !created || label != "CocoaPods" {
		t.Fatalf("first request: %q %v %v", label, created, err)
	}
	if _, created, err := s.RequestSupport(ctx, "cocoapods", by); err != nil || created {
		t.Errorf("asking again: created %v, %v", created, err)
	}
	for _, bad := range []string{"npm", "deb:ubuntu-30.04", "haskell", ""} {
		if _, _, err := s.RequestSupport(ctx, bad, by); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	ov, err := s.SummarizeCoverage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ov.Ecosystems {
		if e.Requested != (e.Key == "cocoapods") {
			t.Errorf("%s requested %v", e.Key, e.Requested)
		}
	}

	// Another workspace with CocoaPods of its own.
	sys := tenant.System(ctx)
	if _, err := s.Pool.Exec(sys, `INSERT INTO workspaces (id, name, slug) VALUES (2, 'Other', 'other')`); err != nil {
		t.Fatal(err)
	}
	other := tenant.WithWorkspace(context.Background(), 2)
	var n int
	if err := s.Pool.QueryRow(other, `SELECT count(*) FROM support_requests`).Scan(&n); err != nil || n != 0 {
		t.Errorf("row-level security: workspace 2 sees %d requests (%v)", n, err)
	}
	if _, _, err := s.RequestSupport(other, "cocoapods", nil); !errors.Is(err, store.ErrInvalid) {
		t.Errorf("workspace 2 has no CocoaPods yet: %v", err)
	}
	if _, err := s.Pool.Exec(other, `INSERT INTO support_requests (workspace_id, ecosystem) VALUES (1, 'conan')`); err == nil {
		t.Error("row-level security: workspace 2 wrote a request for workspace 1")
	}
	coverageFixture(t, other, s)
	if _, created, err := s.RequestSupport(other, "cocoapods", nil); err != nil || !created {
		t.Fatalf("workspace 2: %v %v", created, err)
	}

	tot, err := s.SupportRequestTotals(sys)
	if err != nil {
		t.Fatal(err)
	}
	if len(tot) != 1 || tot[0].Ecosystem != "cocoapods" || tot[0].Workspaces != 2 || tot[0].Label != "CocoaPods" {
		t.Errorf("totals: %+v", tot)
	}
	// A disabled workspace's request no longer counts.
	if _, err := s.Pool.Exec(sys, `UPDATE workspaces SET disabled_at = now() WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if tot, err = s.SupportRequestTotals(sys); err != nil || len(tot) != 1 || tot[0].Workspaces != 1 {
		t.Errorf("after disabling: %+v %v", tot, err)
	}
}

func TestEcosystemLabel(t *testing.T) {
	for key, want := range map[string]string{
		"npm": "npm", "pypi": "PyPI", "deb:ubuntu-24.04": "Ubuntu 24.04", "rpm:rhel-9": "RHEL 9", "apk:alpine-3.20": "Alpine 3.20",
		"rpm:opensuse-leap-15.6": "openSUSE Leap 15.6", "deb:kali": "Kali", "windows": "Windows", "generic": "Other software",
		"cocoapods": "CocoaPods", "conan": "Conan",
	} {
		if got := store.EcosystemLabel(key); got != want {
			t.Errorf("%s: %q, want %q", key, got, want)
		}
	}
}
