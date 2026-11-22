package store_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// homeReport sends an application batch as an agent from 0.20.24 on does
// for a release layout: identified by the layout's directory (home), with
// app_home set and app_dir the current release it scanned.
func homeReport(t *testing.T, s *store.Store, ctx context.Context, host int64, hostName, app, home, release string, pkgs ...pkg) *store.IngestResult {
	t.Helper()
	time.Sleep(5 * time.Millisecond)
	b := model.NewBatch(model.Collector{ID: "linux-apps", Version: "0.20.24", Method: "agent"}, model.AssetRef{
		Kind: model.AssetApplication, Name: app + " on " + hostName,
		Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: home}},
		Attributes:  map[string]string{"app_dir": release, "app_home": home, "host": hostName},
	})
	for _, p := range pkgs {
		b.Observations = append(b.Observations, model.Observation{Purl: p.purl, Location: p.loc, Confidence: model.ConfidenceConfirmed,
			Evidence: map[string]string{"app_dir": release}})
	}
	b.Coverage = []model.CoverageItem{{Scope: "npm-installed:" + release + "/node_modules", Status: "checked"}}
	b.Complete = true
	b.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: hostName}}}}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	b.Asset.Identifiers[0].Value = fmt.Sprintf("host:%d:%s", host, home)
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// An upgraded agent reports a Ghost-CLI install by /var/www/ghost instead
// of its release: the release's asset takes the report, so its issue stays
// the same open issue, its project stays, it is named for the directory,
// and the host's app list (which names only /var/www/ghost) does not
// remove it although it still carries the release's identifier.
func TestReleaseLayoutReportKeepsAsset(t *testing.T) {
	ctx, s := loopStore(t)
	const home, rel = "/var/www/ghost", "/var/www/ghost/versions/6.52.0"
	express := pkg{"pkg:npm/express@4.21.2", rel + "/node_modules/express"}
	host := appHost(t, s, ctx, "blog", nil)
	cov := []model.CoverageItem{{Scope: "npm-installed:" + rel + "/node_modules", Status: "checked"}}
	old := appReport(t, s, ctx, host, "blog", "ghost", rel, cov, express).AssetID
	syncOpen(t, s, ctx, old, map[string]string{"CVE-X": "express"})
	before := findings(t, s, ctx, store.FindingFilter{AssetID: old, Key: "CVE-X"})
	p, err := s.CreateProject(ctx, "blog", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProjectAssets(ctx, p.ID, []int64{old}); err != nil {
		t.Fatal(err)
	}

	r := homeReport(t, s, ctx, host, "blog", "ghost", home, rel, express)
	if r.AssetID != old {
		t.Fatalf("report went to asset %d, want the release's %d", r.AssetID, old)
	}
	appHost(t, s, ctx, "blog", []string{home})
	a, err := s.GetAsset(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if a.CollectionStatus == store.AssetRemoved || a.Name != "ghost on blog" {
		t.Errorf("asset after the upgrade: status %s, name %q", a.CollectionStatus, a.Name)
	}
	syncOpen(t, s, ctx, old, map[string]string{"CVE-X": "express"})
	after := findings(t, s, ctx, store.FindingFilter{AssetID: old, Key: "CVE-X"})
	if len(before) != 1 || len(after) != 1 || after[0].ID != before[0].ID || after[0].Status != "open" {
		t.Errorf("issue before %+v, after %+v", before, after)
	}
	var inProject bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM project_assets WHERE project_id = $1 AND asset_id = $2)`, p.ID, old).Scan(&inProject); err != nil || !inProject {
		t.Errorf("project membership lost: %v %v", inProject, err)
	}
	// A deploy (a new release) reports the same directory: same asset.
	rel2 := "/var/www/ghost/versions/6.53.0"
	if r := homeReport(t, s, ctx, host, "blog", "ghost", home, rel2, pkg{"pkg:npm/express@4.21.2", rel2 + "/node_modules/express"}); r.AssetID != old {
		t.Errorf("next release went to asset %d", r.AssetID)
	}
	// A person's name stays.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET name = 'Blog', name_by_person = true WHERE id = $1`, old); err != nil {
		t.Fatal(err)
	}
	homeReport(t, s, ctx, host, "blog", "ghost", home, rel2)
	if a, _ = s.GetAsset(ctx, old); a.Name != "Blog" {
		t.Errorf("person's name changed to %q", a.Name)
	}
}

// Without a release in the layout, or from another host, a report by the
// directory is a new asset as before.
func TestReleaseLayoutReportWithoutPredecessor(t *testing.T) {
	ctx, s := loopStore(t)
	h1 := appHost(t, s, ctx, "one", nil)
	h2 := appHost(t, s, ctx, "two", nil)
	cov := []model.CoverageItem{{Scope: "npm-installed:/srv/ui/releases/1/node_modules", Status: "checked"}}
	other := appReport(t, s, ctx, h1, "one", "1", "/srv/ui/releases/1", cov).AssetID
	unrelated := appReport(t, s, ctx, h2, "two", "uix", "/srv/uix/releases/1", cov).AssetID
	r := homeReport(t, s, ctx, h2, "two", "ui", "/srv/ui", "/srv/ui/releases/2")
	if !r.NewAsset || r.AssetID == other || r.AssetID == unrelated {
		t.Errorf("report took asset %d (created %v); other host %d, other app %d", r.AssetID, r.NewAsset, other, unrelated)
	}
}

// Migration 0122 repairs hosts whose agent upgraded before the server took
// over release assets: the new asset's identity, name and projects go to
// the old one, the new asset is deleted, and the next report reopens the
// old asset's own issue.
func TestReleaseLayoutRepairMigration(t *testing.T) {
	ctx, s := loopStore(t)
	const home, rel = "/var/www/ghost", "/var/www/ghost/versions/6.52.0"
	express := pkg{"pkg:npm/express@4.21.2", rel + "/node_modules/express"}
	host := appHost(t, s, ctx, "blog", nil)
	cov := []model.CoverageItem{{Scope: "npm-installed:" + rel + "/node_modules", Status: "checked"}}
	old := appReport(t, s, ctx, host, "blog", "ghost", rel, cov, express).AssetID
	syncOpen(t, s, ctx, old, map[string]string{"CVE-X": "express"})
	issue := findings(t, s, ctx, store.FindingFilter{AssetID: old, Key: "CVE-X"})[0].ID

	// As 0.20.24 did before this fix: a new asset, the old one removed.
	time.Sleep(5 * time.Millisecond)
	var newID int64
	if err := s.Pool.QueryRow(ctx, `INSERT INTO assets (kind, name, attributes, first_seen, last_seen)
		VALUES ('application', 'ghost on blog', jsonb_build_object('app_home', $1::text, 'app_dir', $2::text, 'host', 'blog'), now(), now()) RETURNING id`,
		home, rel).Scan(&newID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `INSERT INTO asset_identifiers (scheme, value, asset_id) VALUES ('app-path', $1, $2)`,
		fmt.Sprintf("host:%d:%s", host, home), newID); err != nil {
		t.Fatal(err)
	}
	p, err := s.CreateProject(ctx, "blog", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddProjectAssets(ctx, p.ID, []int64{newID}); err != nil {
		t.Fatal(err)
	}
	appHost(t, s, ctx, "blog", []string{home})
	syncOpen(t, s, ctx, old, nil)
	if f := findings(t, s, ctx, store.FindingFilter{AssetID: old, Key: "CVE-X"}); f[0].Status != "resolved" {
		t.Fatalf("setup: old issue %s", f[0].Status)
	}

	sql, err := os.ReadFile("../db/migrations/0122_release_layout_assets.sql")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 { // idempotent
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.GetAsset(ctx, newID); err == nil {
		t.Error("the new asset is still there")
	}
	a, err := s.GetAsset(ctx, old)
	if err != nil || a.Name != "ghost on blog" {
		t.Fatalf("old asset: %+v %v", a, err)
	}
	var inProject bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM project_assets WHERE project_id = $1 AND asset_id = $2)`, p.ID, old).Scan(&inProject); err != nil || !inProject {
		t.Errorf("project not carried over: %v %v", inProject, err)
	}
	// The next report goes to the old asset and reopens its own issue.
	if r := homeReport(t, s, ctx, host, "blog", "ghost", home, rel, express); r.AssetID != old {
		t.Fatalf("next report went to %d", r.AssetID)
	}
	appHost(t, s, ctx, "blog", []string{home})
	syncOpen(t, s, ctx, old, map[string]string{"CVE-X": "express"})
	f := findings(t, s, ctx, store.FindingFilter{AssetID: old, Key: "CVE-X"})
	if len(f) != 1 || f[0].ID != issue || f[0].Status != "open" {
		t.Errorf("issue after repair: %+v", f)
	}
	if a, _ = s.GetAsset(ctx, old); a.CollectionStatus == store.AssetRemoved {
		t.Error("still removed after reporting")
	}
}
