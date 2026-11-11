package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/upgrade"
)

// nvdCVEWith is an analysed NVD CVE with one configuration.
func nvdCVEWith(id string, cfg nvdConfig) nvdWrapped {
	return nvdWrapped{CVE: nvdCVE{ID: id, VulnStatus: "Analyzed", Published: "2025-03-01T00:00:00.000", LastModified: "2025-03-02T00:00:00.000",
		Descriptions: []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		}{{Lang: "en", Value: id + " test issue"}},
		Configurations: []nvdConfig{cfg}}}
}

func cpeRange(criteria, start, endExcl string) nvdConfig {
	return nvdConfig{Nodes: []nvdNode{{Operator: "OR", CPEMatch: []nvdCPEMatch{{Vulnerable: true, Criteria: criteria,
		VersionStartIncluding: start, VersionEndExcluding: endExcl}}}}}
}

// A vendor's build of a Linux package is matched by its upstream version
// against the upstream product's NVD records; the distribution's own
// builds, separately versioned packages and editions the catalogue does not
// read are not.
func TestVendorBuilds(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, _, nvd := setupPrograms(t)

	const (
		nginxOrg  = "pkg:deb/ubuntu/nginx@1.24.0-1~jammy?distro=ubuntu-22.04"
		phpCommon = "pkg:deb/ubuntu/php8.1-common@8.1.30-1+ubuntu22.04.1+deb.sury.org+1?distro=ubuntu-22.04&upstream=php8.1"
		phpCLI    = "pkg:deb/ubuntu/php8.1-cli@8.1.30-1+ubuntu22.04.1+deb.sury.org+1?distro=ubuntu-22.04&upstream=php8.1"
		phpRedis  = "pkg:deb/ubuntu/php8.1-redis@6.0.2-1+ubuntu22.04.1+deb.sury.org+1?distro=ubuntu-22.04"
		pg16      = "pkg:deb/ubuntu/postgresql-16@16.4-1.pgdg22.04+1?distro=ubuntu-22.04&upstream=postgresql-16"
		pgClient  = "pkg:deb/ubuntu/postgresql-client-16@16.4-1.pgdg22.04+1?distro=ubuntu-22.04&upstream=postgresql-16"
		consulEnt = "pkg:deb/ubuntu/consul@1.20.1+ent-1?distro=ubuntu-22.04"
		ubuntuNgx = "pkg:deb/ubuntu/nginx@1.18.0-6ubuntu14.4?distro=ubuntu-22.04"
	)
	host := ingest(t, st, model.AssetHost, "jammy-vendor", true, osRow("ubuntu", "22.04"),
		confirmed(nginxOrg, nil), confirmed(phpCommon, nil), confirmed(phpCLI, nil), confirmed(phpRedis, nil),
		confirmed(pg16, nil), confirmed(pgClient, nil), confirmed(consulEnt, nil))
	// Ubuntu's own nginx: the distribution's advisories apply, never NVD's.
	distro := ingest(t, st, model.AssetHost, "jammy-distro", true, osRow("ubuntu", "22.04"), confirmed(ubuntuNgx, nil))

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	if f, err := st.GetFeed(ctx, FeedVendorBuilds); err != nil || f.Kind != "vulnerability" {
		t.Fatalf("a vendor build must create the %s feed: %+v %v", FeedVendorBuilds, f, err)
	}

	windowsOnly := cpeRange("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.24.0", "1.26.3")
	windowsOnly.Operator = "AND"
	windowsOnly.Nodes = append(windowsOnly.Nodes, nvdNode{Operator: "OR", CPEMatch: []nvdCPEMatch{{Criteria: "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}}})
	nvd.extra["cpe:2.3:a:f5:nginx"] = []nvdWrapped{
		nvdCVEWith("CVE-2025-90001", cpeRange("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.24.0", "1.26.3")),
		nvdCVEWith("CVE-2025-90002", windowsOnly),
		nvdCVEWith("CVE-2025-90003", cpeRange("cpe:2.3:a:f5:nginx:*:*:*:*:plus:*:*:*", "1.0.0", "9.0.0")),
	}
	nvd.extra["cpe:2.3:a:php:php"] = []nvdWrapped{
		nvdCVEWith("CVE-2025-91001", cpeRange("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "8.1.0", "8.1.31")),
		// Another line's fix says nothing about 8.1.
		nvdCVEWith("CVE-2025-91002", cpeRange("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "8.3.0", "8.3.14")),
		nvdCVEWith("CVE-2025-91003", nvdConfig{Nodes: []nvdNode{{Operator: "OR", CPEMatch: []nvdCPEMatch{{Vulnerable: true,
			Criteria: "cpe:2.3:a:php:php:8.1.30:*:*:*:*:*:*:*"}}}}}),
	}
	nvd.extra["cpe:2.3:a:postgresql:postgresql"] = []nvdWrapped{
		nvdCVEWith("CVE-2025-92001", cpeRange("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", "16.0", "16.5")),
		nvdCVEWith("CVE-2025-92002", cpeRange("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", "17.0", "17.1")),
	}

	var reevaluate []int64
	sy.Changed = func(ctx context.Context, feed string, res *SyncResult) error {
		ids, err := ComponentsToEvaluate(ctx, st, feed, res)
		reevaluate = append(reevaluate, ids...)
		return err
	}
	res, err := sy.Sync(ctx, FeedVendorBuilds)
	if err != nil || res.Warning != "" {
		t.Fatalf("sync: %+v %v", res, err)
	}
	if len(reevaluate) == 0 {
		t.Error("the first vendor build sync queued nothing for re-evaluation")
	}
	asked := map[string]bool{}
	for _, r := range nvd.requests {
		asked[r.cpe] = true
	}
	for _, cpe := range []string{"cpe:2.3:a:f5:nginx", "cpe:2.3:a:nginx:nginx", "cpe:2.3:a:php:php", "cpe:2.3:a:postgresql:postgresql"} {
		if !asked[cpe] {
			t.Errorf("%s was not read: %v", cpe, nvd.requests)
		}
	}
	// Consul Enterprise's version is not read, and nobody has MongoDB.
	if asked["cpe:2.3:a:hashicorp:consul"] || asked["cpe:2.3:a:mongodb:mongodb"] {
		t.Errorf("a product with no readable vendor build was read: %v", nvd.requests)
	}

	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	found := map[string][]store.Finding{}
	for _, f := range allFindings(t, st, ctx, host) {
		name := strings.TrimPrefix(f.ComponentName, "ubuntu/")
		found[name] = append(found[name], f)
	}
	keys := func(name string) []string {
		var out []string
		for _, f := range found[name] {
			out = append(out, f.Key+"@"+f.FixedVersion)
		}
		return out
	}
	for name, want := range map[string]string{
		"nginx":         "CVE-2025-90001@1.26.3",
		"php8.1-common": "CVE-2025-91001@8.1.31 CVE-2025-91003@",
		"postgresql-16": "CVE-2025-92001@16.5",
		// Reported once per build, on the earliest package.
		"php8.1-cli":           "",
		"postgresql-client-16": "",
		"php8.1-redis":         "",
		"consul":               "",
	} {
		got := keys(name)
		var wantList []string
		if want != "" {
			wantList = strings.Fields(want)
		}
		if strings.Join(sortedCopy(got), " ") != strings.Join(sortedCopy(wantList), " ") {
			t.Errorf("%s findings %v, want %v", name, got, wantList)
		}
	}
	for _, f := range found["nginx"] {
		var e map[string]any
		_ = json.Unmarshal(f.Evidence, &e)
		if e["program"] != "vendor:nginx" || e["vendor_repository"] != "another repository" || e["program_version"] != "1.24.0" {
			t.Errorf("nginx evidence %v", e)
		}
	}
	if fs := allFindings(t, st, ctx, distro); len(fs) != 0 {
		t.Errorf("Ubuntu's own nginx matched NVD: %v", fs)
	}

	cov := rowCoverage(t, ctx, st, host)
	for purl, want := range map[string]struct{ state, words string }{
		nginxOrg:  {store.CoverageEvaluated, "matched as nginx 1.24.0 against NVD's records"},
		phpCommon: {store.CoverageEvaluated, "may carry fixes their maintainers backported"},
		phpCLI:    {store.CoverageEvaluated, "the same PHP 8.1.30 build as php8.1-common"},
		pgClient:  {store.CoverageEvaluated, "the same PostgreSQL 16.4 build as postgresql-16"},
		phpRedis:  {store.CoverageUnsupported, "built by another repository, not by the distribution"},
		consulEnt: {store.CoverageUnsupported, "is not in the form the vendor build catalogue reads"},
	} {
		r, ok := cov[purl]
		if !ok || r.Coverage != want.state || !strings.Contains(r.CoverageReason, want.words) {
			t.Errorf("%s: coverage %s %q, want %s with %q", purl, r.Coverage, r.CoverageReason, want.state, want.words)
		}
	}
	if r := cov[phpRedis]; r.Coverage == store.CoverageUnsupported && !strings.HasPrefix(r.CoverageReason, "built by ") {
		t.Errorf("php8.1-redis must stay grouped as a vendor build gap: %q", r.CoverageReason)
	}

	// Upgrade advice names the upstream release, from the vendor.
	ng := found["nginx"][0]
	rec, err := upgrade.ForFinding(ctx, st, &ng, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Basis != upgrade.BasisVendorUpstreamFixed || rec.Recommended != "1.26.3" ||
		!strings.Contains(strings.Join(rec.Rationale, " "), "install nginx 1.26.3 or later from another repository") {
		t.Errorf("nginx upgrade advice: %+v", rec)
	}

	// The action plan: one update per product and line.
	if _, err := planner.Rebuild(ctx, st, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: host, Kind: fixplan.ProgramUpdate})
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]fixplan.Group{}
	for _, r := range raw {
		var g fixplan.Group
		_ = json.Unmarshal(r, &g)
		groups[g.Component] = g
	}
	if g := groups["nginx"]; g.Title != "Update nginx to 1.26.3" || !strings.Contains(g.Action, "nginx.org's repository") {
		t.Errorf("nginx group %+v", g)
	}
	// CVE-2025-91003 names 8.1.30 alone, with no fix: not part of the update.
	if g := groups["PHP 8.1"]; g.Title != "Update PHP 8.1 to 8.1.31" || g.FindingCount != 1 {
		t.Errorf("PHP group %+v (groups %v)", g, keysOf(groups))
	}
	if g := groups["PostgreSQL 16"]; g.Title != "Update PostgreSQL 16 to 16.5" {
		t.Errorf("PostgreSQL group %+v", g)
	}

	// A later sync that finds nothing changed reads incrementally.
	nvd.requests = nil
	if _, err := sy.Sync(ctx, FeedVendorBuilds); err != nil {
		t.Fatal(err)
	}
	for _, r := range nvd.requests {
		if r.since == "" {
			t.Errorf("second sync read %s completely", r.cpe)
		}
	}
}

func sortedCopy(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func keysOf[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return sortedCopy(out)
}
