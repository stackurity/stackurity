package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// appHost reports a host the way the agent's OS batch does, with the app
// list when dirs is not nil.
func appHost(t *testing.T, s *store.Store, ctx context.Context, name string, dirs []string) int64 {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "linux-agent", Version: "0.14.0", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}})
	b.Observations = append(b.Observations, model.Observation{Purl: "pkg:deb/ubuntu/bash@5.0", Location: "/var/lib/dpkg/status"})
	b.Cover("dpkg", "checked", "")
	b.Complete = true
	if dirs != nil {
		b.Apps = &model.AppList{Dirs: dirs}
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

type pkg struct{ purl, loc string }

// appReport sends an application batch as the agent's linux-apps collector
// does (the identifier already bound to the host, as POST /ingest does),
// with the coverage given, and returns the result.
func appReport(t *testing.T, s *store.Store, ctx context.Context, host int64, hostName, app, dir string, cov []model.CoverageItem, pkgs ...pkg) *store.IngestResult {
	t.Helper()
	time.Sleep(5 * time.Millisecond)
	b := model.NewBatch(model.Collector{ID: "linux-apps", Version: "0.13.1", Method: "agent"}, model.AssetRef{
		Kind: model.AssetApplication, Name: app + " on " + hostName,
		Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: dir}},
		Attributes:  map[string]string{"app_dir": dir, "host": hostName},
	})
	for _, p := range pkgs {
		b.Observations = append(b.Observations, model.Observation{Purl: p.purl, Location: p.loc, Confidence: model.ConfidenceConfirmed,
			Evidence: map[string]string{"app_dir": dir}})
	}
	b.Coverage = cov
	b.Complete = true
	for _, c := range cov {
		if c.Status != "checked" {
			b.Complete = false
		}
	}
	b.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: hostName}}}}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	b.Asset.Identifiers[0].Value = fmt.Sprintf("host:%d:%s", host, dir)
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func liveRows(t *testing.T, s *store.Store, ctx context.Context, asset int64) map[string]bool {
	t.Helper()
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		if r.RemovedAt == nil {
			out[r.Name+"@"+r.Version] = true
		}
	}
	return out
}

// The production case (DBC, 2026-10-28): phpMyAdmin 4.8.0 in
// /var/www/html/phpmyadmin was replaced by 5.2.3. Its tmp/twig cache
// directory belongs to the web server, so the agent (an unprivileged user)
// could not read it and every collection of the application was
// incomplete. Only complete collections removed rows, so twig 1.35.3,
// twig/extensions and jquery 3.3.1 stayed installed and their issues open
// for good. A collection now proves absence outside the paths it could not
// read, and rows an older server left behind go on the next collection.
func TestUpgradedAppWithUnreadableDirectory(t *testing.T) {
	ctx, s := loopStore(t)
	const dir = "/var/www/html/phpmyadmin"
	host := appHost(t, s, ctx, "DBC", nil)
	checked := []model.CoverageItem{
		{Scope: "composer-installed:" + dir + "/vendor/composer/installed.json", Status: "checked"},
		{Scope: "lockfile:" + dir + "/yarn.lock", Status: "checked"},
	}
	old := appReport(t, s, ctx, host, "DBC", "phpmyadmin", dir, checked,
		pkg{"pkg:composer/twig/twig@1.35.3", dir + "/vendor/twig/twig"},
		pkg{"pkg:composer/twig/extensions@1.5.1", dir + "/vendor/twig/extensions"},
		pkg{"pkg:npm/jquery@3.3.1", dir + "/yarn.lock"})
	app := old.AssetID
	syncFix(t, s, ctx, app, map[string]string{"CVE-TWIG": "twig", "CVE-JQ": "jquery", "CVE-EXT": "extensions"},
		map[string]string{"CVE-TWIG": "3.11.3", "CVE-JQ": "3.5.0"})

	unreadable := append(append([]model.CoverageItem{}, checked...),
		model.CoverageItem{Scope: "path:" + dir + "/tmp/twig", Status: "failed", Reason: "open tmp/twig: permission denied"})
	newer := []pkg{
		{"pkg:composer/twig/twig@3.11.3", dir + "/vendor/twig/twig"},
		{"pkg:npm/jquery@3.7.1", dir + "/yarn.lock"},
	}
	r := appReport(t, s, ctx, host, "DBC", "phpmyadmin", dir, unreadable, newer...)
	if r.AssetID != app || r.Removed != 3 {
		t.Fatalf("upgrade with an unreadable cache directory removed %d rows, want 3: %+v", r.Removed, r)
	}
	if got := liveRows(t, s, ctx, app); len(got) != 2 || !got["twig@3.11.3"] || !got["jquery@3.7.1"] {
		t.Errorf("installed after the upgrade: %v", got)
	}
	syncFix(t, s, ctx, app, nil, nil)
	for key, want := range map[string]string{"CVE-TWIG": store.ResolutionRemediated, "CVE-JQ": store.ResolutionRemediated, "CVE-EXT": store.ResolutionRemoved} {
		fs := findings(t, s, ctx, store.FindingFilter{AssetID: app, Key: key})
		if len(fs) != 1 || fs[0].Status != "resolved" || fs[0].ResolutionKind != want {
			t.Errorf("%s: %+v, want resolved %s", key, fs, want)
		}
	}

	// Rows an older server left installed (it removed nothing for such a
	// collection) go with the next one, without touching the database.
	if _, err := s.Pool.Exec(ctx, `UPDATE inventory SET removed_at = NULL WHERE asset_id = $1`, app); err != nil {
		t.Fatal(err)
	}
	r = appReport(t, s, ctx, host, "DBC", "phpmyadmin", dir, unreadable, newer...)
	if r.Removed != 3 {
		t.Errorf("rows left by an older server: removed %d, want 3", r.Removed)
	}

	// Rows inside what could not be read stay; so does everything when a
	// coverage problem names no path.
	appReport(t, s, ctx, host, "DBC", "phpmyadmin", dir, checked, append(newer, pkg{"pkg:npm/cache-thing@1.0.0", dir + "/tmp/twig/package-lock.json"})...)
	r = appReport(t, s, ctx, host, "DBC", "phpmyadmin", dir, unreadable, newer...)
	if r.Removed != 0 || !liveRows(t, s, ctx, app)["cache-thing@1.0.0"] {
		t.Errorf("a row in the unreadable directory was removed: %d", r.Removed)
	}
	r = appReport(t, s, ctx, host, "DBC", "phpmyadmin", dir,
		append(append([]model.CoverageItem{}, checked...), model.CoverageItem{Scope: "walk", Status: "partial", Reason: "too many entries"}))
	if r.Removed != 0 {
		t.Errorf("a collection that stopped early removed %d rows", r.Removed)
	}
}

// A check on an application whose collections are incomplete completes on
// the next report instead of waiting (and asking the agent again) for a
// week.
func TestCheckCompletesOnIncompleteReport(t *testing.T) {
	ctx, s := loopStore(t)
	const dir = "/srv/app"
	host := appHost(t, s, ctx, "web", nil)
	walk := []model.CoverageItem{{Scope: "walk", Status: "partial", Reason: "too many entries"}}
	app := appReport(t, s, ctx, host, "web", "app", dir, walk, pkg{"pkg:npm/lodash@4.17.15", dir + "/package-lock.json"}).AssetID
	syncOpen(t, s, ctx, app, map[string]string{"CVE-L": "lodash"})
	c, _, err := s.RequestCheck(ctx, store.CheckRequest{AssetID: app}, user)
	if err != nil {
		t.Fatal(err)
	}
	start, _ := s.DBNow(ctx)
	appReport(t, s, ctx, host, "web", "app", dir, walk, pkg{"pkg:npm/lodash@4.17.15", dir + "/package-lock.json"})
	if due, _ := s.AgentCheckDue(ctx, []int64{app}); due {
		t.Error("the agent is asked again after it reported")
	}
	if err := s.MarkEvaluated(ctx, app, start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE done_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if n, err := s.CompleteChecks(ctx); err != nil || n != 1 {
		t.Fatalf("complete: %d %v", n, err)
	}
	if c, _ = s.GetCheck(ctx, c.ID); c.Outcome != "incomplete" || c.Remaining != 1 {
		t.Errorf("check on an incomplete report: %+v", c)
	}
}

// An application whose directory is gone (deleted, or an old Ghost release
// next to current) is removed when its host's agent sends an app list
// without it: issues resolve as removed, the asset says so, and a check
// waiting on it is picked up by the host's agent and completes.
func TestAppMissingFromHostListIsRemoved(t *testing.T) {
	ctx, s := loopStore(t)
	const kept, gone = "/var/www/ghost/versions/6.52.0", "/var/www/ghost/versions/6.22.0"
	host := appHost(t, s, ctx, "blog", nil)
	cov := func(d string) []model.CoverageItem {
		return []model.CoverageItem{{Scope: "npm-installed:" + d + "/node_modules", Status: "checked"}}
	}
	cur := appReport(t, s, ctx, host, "blog", "ghost", kept, cov(kept), pkg{"pkg:npm/express@4.21.2", kept + "/node_modules/express"}).AssetID
	oldApp := appReport(t, s, ctx, host, "blog", "ghost", gone, cov(gone), pkg{"pkg:npm/express@4.18.0", gone + "/node_modules/express"}).AssetID
	syncOpen(t, s, ctx, oldApp, map[string]string{"CVE-X": "express"})
	c, _, err := s.RequestCheck(ctx, store.CheckRequest{AssetID: oldApp}, user)
	if err != nil {
		t.Fatal(err)
	}
	// The agent no longer reports the old release, but polls with its host.
	if due, err := s.AgentCheckDue(ctx, []int64{host, cur}); err != nil || !due {
		t.Fatalf("host's agent not asked about its application's check: %v %v", due, err)
	}

	// Without a list nothing changes (older agents).
	appHost(t, s, ctx, "blog", nil)
	if a, _ := s.GetAsset(ctx, oldApp); a.CollectionStatus == store.AssetRemoved {
		t.Fatal("removed without an app list")
	}
	time.Sleep(5 * time.Millisecond)
	start, _ := s.DBNow(ctx)
	appHost(t, s, ctx, "blog", []string{kept + "/"})
	a, err := s.GetAsset(ctx, oldApp)
	if err != nil {
		t.Fatal(err)
	}
	if a.CollectionStatus != store.AssetRemoved || len(liveRows(t, s, ctx, oldApp)) != 0 {
		t.Errorf("old release: status %s, rows %v", a.CollectionStatus, liveRows(t, s, ctx, oldApp))
	}
	if b, _ := s.GetAsset(ctx, cur); b.CollectionStatus == store.AssetRemoved || len(liveRows(t, s, ctx, cur)) != 1 {
		t.Errorf("current release touched: %s", b.CollectionStatus)
	}
	syncOpen(t, s, ctx, oldApp, nil)
	fs := findings(t, s, ctx, store.FindingFilter{AssetID: oldApp, Key: "CVE-X"})
	if len(fs) != 1 || fs[0].Status != "resolved" || fs[0].ResolutionKind != store.ResolutionRemoved {
		t.Errorf("finding on the removed release: %+v", fs)
	}
	if err := s.MarkEvaluated(ctx, oldApp, start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE jobs SET done_at = now() WHERE done_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CompleteChecks(ctx); err != nil {
		t.Fatal(err)
	}
	if c, _ = s.GetCheck(ctx, c.ID); c.Outcome != "passed" {
		t.Errorf("check on the removed release: %+v", c)
	}
	// It is not marked stale later, and a second list does not repeat it.
	if _, err := s.MarkStaleAssets(ctx, time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	if a, _ = s.GetAsset(ctx, oldApp); a.CollectionStatus != store.AssetRemoved {
		t.Errorf("removed application turned %s", a.CollectionStatus)
	}
	appHost(t, s, ctx, "blog", []string{kept})
	var n int
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM collections WHERE asset_id = $1`, oldApp).Scan(&n); err != nil || n != 2 {
		t.Errorf("collections of the removed release: %d %v", n, err)
	}
	// Reported again, it is present again.
	appReport(t, s, ctx, host, "blog", "ghost", gone, cov(gone), pkg{"pkg:npm/express@4.18.0", gone + "/node_modules/express"})
	if a, _ = s.GetAsset(ctx, oldApp); a.CollectionStatus != "ok" {
		t.Errorf("reported again: %s", a.CollectionStatus)
	}
}

// Copies of one application on a host that got the same name before names
// told them apart are renamed when either reports; a person's name stays.
func TestExistingAppCopiesGetDistinctNames(t *testing.T) {
	ctx, s := loopStore(t)
	host := appHost(t, s, ctx, "commmerceblog", nil)
	a := appReport(t, s, ctx, host, "commmerceblog", "ghost", "/var/www/ghost/versions/6.22.0", nil).AssetID
	b := appReport(t, s, ctx, host, "commmerceblog", "ghost", "/var/www/ghost/versions/6.52.0", nil).AssetID
	// As before 0.13: both carry the plain name.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET name = 'ghost on commmerceblog' WHERE id = ANY($1)`, []int64{a, b}); err != nil {
		t.Fatal(err)
	}
	appReport(t, s, ctx, host, "commmerceblog", "ghost", "/var/www/ghost/versions/6.52.0", nil)
	for id, want := range map[int64]string{a: "ghost (/6.22.0) on commmerceblog", b: "ghost (/6.52.0) on commmerceblog"} {
		if got, _ := s.GetAsset(ctx, id); got.Name != want {
			t.Errorf("asset %d = %q, want %q", id, got.Name, want)
		}
	}
	// A person's name is kept.
	if _, err := s.Pool.Exec(ctx, `UPDATE assets SET name = 'Blog', name_by_person = true WHERE id = $1`, b); err != nil {
		t.Fatal(err)
	}
	appReport(t, s, ctx, host, "commmerceblog", "ghost", "/var/www/ghost/versions/6.52.0", nil)
	if got, _ := s.GetAsset(ctx, b); got.Name != "Blog" {
		t.Errorf("person's name changed to %q", got.Name)
	}
}
