package store_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestSummarizeUnchecked: every reason the matcher writes lands with the
// actor who can act on it, and the counts lead with what needs the user.
func TestSummarizeUnchecked(t *testing.T) {
	ctx, s := loopStore(t)
	sys := tenant.System(ctx)
	for _, f := range []string{"osv:PyPI", "osv:Debian"} {
		if err := s.EnsureFeed(sys, f, "vulnerability", time.Hour, 6*time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	// PyPI last synced two days ago: past its 6-hour window.
	if _, err := s.Pool.Exec(sys, `UPDATE feeds SET last_success = now() - interval '2 days' WHERE name = 'osv:PyPI'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(sys, `UPDATE feeds SET last_success = now() WHERE name = 'osv:Debian'`); err != nil {
		t.Fatal(err)
	}

	b := model.NewBatch(model.Collector{ID: "t", Method: "test"},
		model.AssetRef{Kind: model.AssetRepository, Name: "web", Identifiers: []model.Identifier{{Scheme: "test", Value: "web"}}})
	obs := []struct{ purl, loc string }{
		{"pkg:npm/left-pad", "web/package.json"},
		{"pkg:npm/odd@banana", "web/package-lock.json"},
		{"pkg:deb/debian/bash@5.2", "/var/lib/dpkg/status"},
		{"pkg:cocoapods/Alamofire@5.0.0", "ios/Podfile.lock"},
		{"pkg:conan/zlib@1.3", "conan.lock"},
		{"pkg:npm/express@4.0.0", "web/package-lock.json"},
		{"pkg:pypi/requests@2.0.0", "requirements.txt"},
		{"pkg:deb/debian/openssl@3.0?distro=debian-14", "/var/lib/dpkg/status"},
		{"pkg:deb/debian/curl@8.0?distro=debian-12", "/var/lib/dpkg/status"},
		{"pkg:deb/debian/mongodb-org-server@7.0?distro=debian-12", "/var/lib/dpkg/status"},
	}
	for _, o := range obs {
		b.Observations = append(b.Observations, model.Observation{Purl: o.purl, Location: o.loc, Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	res, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The reasons intel.Evaluator writes, row by row.
	reasons := map[string][3]string{
		"left-pad":           {store.CoverageNotEvaluated, "no installed version was reported", ""},
		"odd":                {store.CoverageNotEvaluated, `installed version "banana" could not be compared using npm rules`, ""},
		"bash":               {store.CoverageNotEvaluated, "the distro release is unknown (no distro qualifier)", ""},
		"Alamofire":          {store.CoverageUnsupported, "CocoaPods packages have no vulnerability source: OSV publishes no CocoaPods advisories", ""},
		"zlib":               {store.CoverageUnsupported, "Conan packages have no vulnerability source: OSV publishes no ConanCenter advisories", ""},
		"express":            {store.CoverageNotEvaluated, "vulnerability feed osv:npm has not been set up yet", ""},
		"requests":           {store.CoverageEvaluated, "", "osv:PyPI"},
		"openssl":            {store.CoverageNotEvaluated, "osv:Debian has no advisories for Debian:14: the release is newer than the source's data, no longer covered by it, or not published there", ""},
		"curl":               {store.CoverageEvaluated, "", "osv:Debian"},
		"mongodb-org-server": {store.CoverageUnsupported, "built by MongoDB's repository (repo.mongodb.org), not by the distribution: the distribution's advisories do not cover it and no other vulnerability source is used for it", ""},
	}
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	var cov []store.RowCoverage
	for _, r := range rows {
		rc, ok := reasons[r.Name]
		if !ok {
			t.Fatalf("unexpected row %s", r.Name)
		}
		cov = append(cov, store.RowCoverage{InventoryID: r.ID, State: rc[0], Reason: rc[1], Feed: rc[2]})
	}
	if err := s.SetCoverage(ctx, cov); err != nil {
		t.Fatal(err)
	}
	// An application whose files the agent may not read.
	ab := model.NewBatch(model.Collector{ID: "linux-apps", Method: "agent"},
		model.AssetRef{Kind: model.AssetApplication, Name: "shop", Identifiers: []model.Identifier{{Scheme: "test", Value: "shop"}}})
	ab.Cover("app-permissions:/var/www/shop", "unsupported", "the agent's user may not read /var/www/shop")
	if err := ab.Validate(); err != nil {
		t.Fatal(err)
	}
	appRes, err := s.Ingest(ctx, ab, 0)
	if err != nil {
		t.Fatal(err)
	}

	u, err := s.SummarizeUnchecked(ctx, store.UncheckedFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if u.NeedYou != 4 || u.NotSupported != 3 || u.Waiting != 2 || u.NoAdvisories != 1 || !u.Overdue {
		t.Errorf("counts: need you %d, not supported %d, waiting %d, no advisories %d, overdue %v",
			u.NeedYou, u.NotSupported, u.Waiting, u.NoAdvisories, u.Overdue)
	}
	var order []string
	groups := map[string]store.UncheckedGroup{}
	for _, g := range u.Groups {
		order = append(order, g.Reason+"/"+g.Actor)
		groups[g.Reason] = g
	}
	if got := strings.Join(order, " "); got != "unreadable_version/user unreadable_files/user unsupported/stackurity waiting_for_data/automatic no_advisories/none" {
		t.Errorf("groups: %s", got)
	}
	item := func(reason, key string) store.UncheckedItem {
		for _, it := range groups[reason].Items {
			if it.Key == key {
				return it
			}
		}
		t.Errorf("%s: no item %s in %+v", reason, key, groups[reason].Items)
		return store.UncheckedItem{}
	}
	if it := item("unreadable_version", "no_version"); it.Components != 1 || it.Fix == "" || it.Label != "no version recorded" {
		t.Errorf("no version: %+v", it)
	}
	item("unreadable_version", "unparseable_version")
	item("unreadable_version", "unknown_release")
	if g := groups["unreadable_files"]; g.Assets != 1 || g.Items[0].Docs == "" || !strings.Contains(g.Items[0].Fix, "ACL") {
		t.Errorf("unreadable files: %+v", g)
	}
	if it := item("unsupported", "cocoapods|ecosystem"); it.Label != "CocoaPods packages" {
		t.Errorf("CocoaPods: %+v", it)
	}
	item("unsupported", "conan|ecosystem")
	if it := item("unsupported", "deb|vendor_build|MongoDB's repository (repo.mongodb.org)"); !strings.HasPrefix(it.Label, "vendor builds from MongoDB") {
		t.Errorf("vendor build: %+v", it)
	}
	// Not set up yet: resolves on its own. PyPI is two days old: overdue.
	if it := item("waiting_for_data", "osv:npm"); it.Overdue || it.Label != "npm" {
		t.Errorf("npm: %+v", it)
	}
	if it := item("waiting_for_data", "osv:PyPI"); !it.Overdue {
		t.Errorf("PyPI: %+v", it)
	}
	if it := item("no_advisories", "Debian:14"); it.Label != "Debian 14" {
		t.Errorf("Debian 14: %+v", it)
	}

	// The inventory filter and row fields agree with the breakdown.
	need, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID, Unchecked: store.UncheckedUnreadableVersion})
	if err != nil {
		t.Fatal(err)
	}
	if len(need) != 3 {
		t.Fatalf("unreadable versions: %d rows", len(need))
	}
	for _, r := range need {
		if r.UncheckedActor != store.ActorUser || r.UncheckedFix == "" {
			t.Errorf("%s: %+v", r.Name, r)
		}
		if r.Name == "left-pad" && !strings.Contains(r.UncheckedFix, "package-lock.json") {
			t.Errorf("left-pad's fix should name the lockfile: %q", r.UncheckedFix)
		}
	}
	waiting, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID, Unchecked: store.UncheckedWaitingForData})
	if err != nil {
		t.Fatal(err)
	}
	if len(waiting) != 2 {
		t.Errorf("waiting: %d rows", len(waiting))
	}
	all, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: res.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range all {
		if r.Name == "curl" && (r.UncheckedReason != "" || r.UncheckedActor != "") {
			t.Errorf("curl was checked: %+v", r)
		}
		if r.Name == "openssl" && r.UncheckedActor != store.ActorNone {
			t.Errorf("openssl: %+v", r)
		}
	}

	// One asset: the application's own breakdown has only its files.
	app, err := s.SummarizeUnchecked(ctx, store.UncheckedFilter{AssetID: appRes.AssetID})
	if err != nil {
		t.Fatal(err)
	}
	if app.NeedYou != 1 || len(app.Groups) != 1 || app.Groups[0].Reason != "unreadable_files" {
		t.Errorf("application: %+v", app)
	}

	// The instance report counts what has a source but was not checked.
	gaps, err := s.UncheckedGaps(sys)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int64{}
	for _, g := range gaps {
		kinds[g.Kind] = g.Components
	}
	for _, k := range []string{"unreadable_version|npm|no_version", "waiting_for_data|npm|osv:npm", "waiting_for_data|pypi|osv:PyPI",
		"no_advisories|deb|Debian:14", "unreadable_version|deb|unknown_release"} {
		if kinds[k] != 1 {
			t.Errorf("coverage-gap report: %s = %d (%v)", k, kinds[k], kinds)
		}
	}
}
