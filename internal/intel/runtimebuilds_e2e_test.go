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
)

// nginxRuntime is nginx as the agent reports a binary no package owns.
func nginxRuntime(version string, ev map[string]string) model.Observation {
	e := map[string]string{"kind": "runtime", "install": "unmanaged", "binary": "/usr/local/nginx/sbin/nginx", "detected_by": "version-output"}
	for k, v := range ev {
		e[k] = v
	}
	return model.Observation{Purl: "pkg:generic/nginx@" + version, Version: version, Location: e["binary"], Scope: "runtime",
		Confidence: model.ConfidenceConfirmed, Evidence: e}
}

// An nginx found outside a package manager (a source build, the nginx an
// ingress controller's image compiles in, a Homebrew keg) is matched by the
// release it reports against nginx Open Source's NVD records, as nginx.org's
// packages are; NGINX Plus and builds the agent could not tell apart are not.
// The records are CVE-2026-123007's as NVD publishes them: nginx Open Source
// under f5:nginx_open_source, 1.9.5 up to 1.30.7 and 1.31.0 up to 1.31.9,
// next to NGINX Plus's builds.
func TestRuntimeBuilds(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, _, nvd := setupPrograms(t)

	open := map[string]string{"edition": "open-source"}
	hosts := map[string]int64{}
	for name, o := range map[string]model.Observation{
		"stable-1.30.6":   nginxRuntime("1.30.6", open),
		"stable-1.30.7":   nginxRuntime("1.30.7", open),
		"mainline-1.31.8": nginxRuntime("1.31.8", open),
		"mainline-1.31.9": nginxRuntime("1.31.9", open),
		"image-1.31.8":    nginxRuntime("1.31.8", map[string]string{"edition": "open-source", "detected_by": "binary-strings"}),
		"plus-r35":        nginxRuntime("1.29.0", map[string]string{"edition": "nginx-plus"}),
		"tengine":         nginxRuntime("1.24.0", map[string]string{"edition": "tengine"}),
		"older-agent":     nginxRuntime("1.31.8", nil),
		"homebrew-1.31.8": {Purl: "pkg:generic/nginx@1.31.8", Version: "1.31.8", Confidence: model.ConfidenceConfirmed,
			Evidence: map[string]string{"kind": "runtime", "install": "homebrew"}},
	} {
		hosts[name] = ingest(t, st, model.AssetHost, name, true, osRow("ubuntu", "24.04"), o)
	}
	// Runtimes alone are enough to read nginx's records.
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	if f, err := st.GetFeed(ctx, FeedVendorBuilds); err != nil || f.Kind != "vulnerability" {
		t.Fatalf("an nginx runtime must create the %s feed: %+v %v", FeedVendorBuilds, f, err)
	}
	// Another runtime keeps lifecycle only, and nginx.org's own package is
	// matched against the same records.
	other := ingest(t, st, model.AssetHost, "other", true, osRow("ubuntu", "24.04"),
		confirmed("pkg:generic/haproxy@2.8.3", map[string]string{"kind": "runtime", "install": "unmanaged"}),
		confirmed("pkg:deb/ubuntu/nginx@1.30.6-1~noble?distro=ubuntu-24.04", nil))

	plus := func(start, end string) nvdCPEMatch {
		return nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx_plus:*:*:*:*:*:*:*:*", VersionStartIncluding: start, VersionEndExcluding: end}
	}
	oss := func(start, end string) nvdCPEMatch {
		return nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:f5:nginx_open_source:*:*:*:*:*:*:*:*", VersionStartIncluding: start, VersionEndExcluding: end}
	}
	nvd.extra["cpe:2.3:a:f5:nginx_open_source"] = []nvdWrapped{nvdCVEWith("CVE-2026-123007", nvdConfig{Nodes: []nvdNode{{Operator: "OR",
		CPEMatch: []nvdCPEMatch{plus("37.0.0", "37.0.8.1"), plus("37.1.0", "37.3.0.1"), oss("1.9.5", "1.30.7"), oss("1.31.0", "1.31.9")}}}})}

	var reevaluate []int64
	sy.Changed = func(ctx context.Context, feed string, res *SyncResult) error {
		ids, err := ComponentsToEvaluate(ctx, st, feed, res)
		reevaluate = append(reevaluate, ids...)
		return err
	}
	if res, err := sy.Sync(ctx, FeedVendorBuilds); err != nil || res.Warning != "" {
		t.Fatalf("sync: %+v %v", res, err)
	}
	nginxIDs, err := st.ComponentsWithPurlKey(ctx, "pkg:generic/nginx")
	if err != nil || len(nginxIDs) == 0 {
		t.Fatalf("nginx components %v %v", nginxIDs, err)
	}
	queued := map[int64]bool{}
	for _, id := range reevaluate {
		queued[id] = true
	}
	for _, id := range nginxIDs {
		if !queued[id] {
			t.Errorf("nginx runtime component %d was not queued for re-evaluation: %v", id, reevaluate)
		}
	}

	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	findings := func(asset int64) []string {
		var out []string
		for _, f := range allFindings(t, st, ctx, asset) {
			if f.Kind == "vulnerability" {
				out = append(out, f.Key+"@"+f.FixedVersion)
			}
		}
		return out
	}
	for name, want := range map[string]struct{ finding, state, words string }{
		"stable-1.30.6":   {"CVE-2026-123007@1.30.7", store.CoverageEvaluated, "installed outside a package manager (/usr/local/nginx/sbin/nginx): matched as nginx 1.30.6"},
		"stable-1.30.7":   {"", store.CoverageEvaluated, "matched as nginx 1.30.7"},
		"mainline-1.31.8": {"CVE-2026-123007@1.31.9", store.CoverageEvaluated, "matched as nginx 1.31.8"},
		"mainline-1.31.9": {"", store.CoverageEvaluated, "matched as nginx 1.31.9"},
		"image-1.31.8":    {"CVE-2026-123007@1.31.9", store.CoverageEvaluated, "matched as nginx 1.31.8"},
		"homebrew-1.31.8": {"CVE-2026-123007@1.31.9", store.CoverageEvaluated, "installed by Homebrew"},
		"plus-r35":        {"", store.CoverageUnsupported, "runtime installed outside a package manager: nginx is NGINX Plus"},
		"tengine":         {"", store.CoverageUnsupported, "nginx is Tengine"},
		"older-agent":     {"", store.CoverageUnsupported, "upgrade the agent"},
	} {
		got := strings.Join(findings(hosts[name]), " ")
		if got != want.finding {
			t.Errorf("%s: findings %q, want %q", name, got, want.finding)
		}
		var row store.InventoryRow
		for purl, r := range rowCoverage(t, ctx, st, hosts[name]) {
			if strings.HasPrefix(purl, "pkg:generic/nginx") {
				row = r
			}
		}
		if row.Coverage != want.state || !strings.Contains(row.CoverageReason, want.words) {
			t.Errorf("%s: coverage %s %q, want %s with %q", name, row.Coverage, row.CoverageReason, want.state, want.words)
		}
	}
	if got := strings.Join(findings(other), " "); got != "CVE-2026-123007@1.30.7" {
		t.Errorf("nginx.org's nginx 1.30.6 findings %q, want CVE-2026-123007 fixed in 1.30.7", got)
	}
	if r := rowCoverage(t, ctx, st, other)["pkg:generic/haproxy@2.8.3"]; r.Coverage != store.CoverageUnsupported ||
		!strings.Contains(r.CoverageReason, "lifecycle is tracked, vulnerabilities are not matched") {
		t.Errorf("haproxy coverage %s %q", r.Coverage, r.CoverageReason)
	}

	// Evidence and the action plan say how a runtime is updated.
	for _, f := range allFindings(t, st, ctx, hosts["mainline-1.31.8"]) {
		var e map[string]any
		_ = json.Unmarshal(f.Evidence, &e)
		if e["program"] != "runtime:nginx" || e["runtime_install"] != "unmanaged" || e["vendor_repository"] != nil || e["program_version"] != "1.31.8" {
			t.Errorf("runtime nginx evidence %v", e)
		}
	}
	if _, err := planner.Rebuild(ctx, st, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: hosts["mainline-1.31.8"], Kind: fixplan.ProgramUpdate})
	if err != nil || len(raw) != 1 {
		t.Fatalf("fix groups %d %v", len(raw), err)
	}
	var g fixplan.Group
	_ = json.Unmarshal(raw[0], &g)
	if g.Title != "Update nginx to 1.31.9" || !strings.Contains(g.Action, "not installed by a package manager") ||
		!strings.Contains(g.Action, "a reload keeps the old binary running") {
		t.Errorf("runtime nginx group %+v", g)
	}
}

// Apache Tomcat found outside a package manager (the official tomcat
// images unpack Apache's release into /usr/local/tomcat, tarballs in /opt)
// is matched by the release catalina.jar reports against Tomcat's NVD
// records; a vendor's build is not, and neither is a distribution's tomcat
// package, whose own advisories apply. The record is CVE-2026-66299's as
// NVD publishes it (9.0.89 up to 9.0.121, 10.1.24 up to 10.1.58, 11.0.1 up
// to 11.0.25, and 11.0.0 milestones listed one by one).
func TestRuntimeBuildsTomcat(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, _, nvd := setupPrograms(t)

	tomcat := func(version, home, edition string) model.Observation {
		e := map[string]string{"kind": "runtime", "install": "unmanaged", "binary": home + "/lib/catalina.jar", "detected_by": "server-info"}
		if edition != "" {
			e["edition"] = edition
		}
		return model.Observation{Purl: "pkg:generic/tomcat@" + version, Version: version, Location: home, Scope: "runtime",
			Confidence: model.ConfidenceConfirmed, Evidence: e}
	}
	hosts := map[string]int64{}
	for name, o := range map[string]model.Observation{
		"image-10.1.57":   tomcat("10.1.57", "/usr/local/tomcat", "apache"),
		"image-10.1.62":   tomcat("10.1.62", "/usr/local/tomcat", "apache"),
		"tarball-9.0.120": tomcat("9.0.120", "/opt/apache-tomcat-9.0.120", "apache"),
		"tarball-11.0.0":  tomcat("11.0.0", "/opt/tomcat", "apache"),
		"jws-9.0.100":     tomcat("9.0.100", "/opt/tomcat", "vendor-build"),
	} {
		hosts[name] = ingest(t, st, model.AssetHost, name, true, osRow("debian", "12"), o)
	}
	distro := ingest(t, st, model.AssetHost, "distro", true, osRow("debian", "12"),
		confirmed("pkg:deb/debian/tomcat10@10.1.40-1?distro=debian-12", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	if f, err := st.GetFeed(ctx, FeedVendorBuilds); err != nil || f.Kind != "vulnerability" {
		t.Fatalf("a Tomcat runtime must create the %s feed: %+v %v", FeedVendorBuilds, f, err)
	}
	rng := func(start, end string) nvdCPEMatch {
		return nvdCPEMatch{Vulnerable: true, Criteria: "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*", VersionStartIncluding: start, VersionEndExcluding: end}
	}
	nvd.extra["cpe:2.3:a:apache:tomcat"] = []nvdWrapped{nvdCVEWith("CVE-2026-66299", nvdConfig{Nodes: []nvdNode{{Operator: "OR",
		CPEMatch: []nvdCPEMatch{rng("9.0.89", "9.0.121"), rng("10.1.24", "10.1.58"), rng("11.0.1", "11.0.25"),
			{Vulnerable: true, Criteria: "cpe:2.3:a:apache:tomcat:11.0.0:milestone20:*:*:*:*:*:*"}}}}})}
	if res, err := sy.Sync(ctx, FeedVendorBuilds); err != nil || res.Warning != "" {
		t.Fatalf("sync: %+v %v", res, err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	findings := func(asset int64) string {
		var out []string
		for _, f := range allFindings(t, st, ctx, asset) {
			if f.Kind == "vulnerability" {
				out = append(out, f.Key+"@"+f.FixedVersion)
			}
		}
		return strings.Join(out, " ")
	}
	for name, want := range map[string]struct{ finding, state, words string }{
		"image-10.1.57":   {"CVE-2026-66299@10.1.58", store.CoverageEvaluated, "matched as Apache Tomcat 10.1.57"},
		"image-10.1.62":   {"", store.CoverageEvaluated, "matched as Apache Tomcat 10.1.62"},
		"tarball-9.0.120": {"CVE-2026-66299@9.0.121", store.CoverageEvaluated, "matched as Apache Tomcat 9.0.120"},
		// The release 11.0.0 is not the 11.0.0 milestones NVD lists.
		"tarball-11.0.0": {"", store.CoverageEvaluated, "matched as Apache Tomcat 11.0.0"},
		"jws-9.0.100":    {"", store.CoverageUnsupported, "Apache Tomcat is a vendor's build"},
	} {
		if got := findings(hosts[name]); got != want.finding {
			t.Errorf("%s: findings %q, want %q", name, got, want.finding)
		}
		var row store.InventoryRow
		for purl, r := range rowCoverage(t, ctx, st, hosts[name]) {
			if strings.HasPrefix(purl, "pkg:generic/tomcat") {
				row = r
			}
		}
		if row.Coverage != want.state || !strings.Contains(row.CoverageReason, want.words) {
			t.Errorf("%s: coverage %s %q, want %s with %q", name, row.Coverage, row.CoverageReason, want.state, want.words)
		}
	}
	if got := findings(distro); got != "" {
		t.Errorf("Debian's tomcat10 package matched against Apache's records: %q", got)
	}
	if _, err := planner.Rebuild(ctx, st, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: hosts["image-10.1.57"], Kind: fixplan.ProgramUpdate})
	if err != nil || len(raw) != 1 {
		t.Fatalf("fix groups %d %v", len(raw), err)
	}
	var g fixplan.Group
	_ = json.Unmarshal(raw[0], &g)
	if g.Title != "Update Apache Tomcat 10.1 to 10.1.58" || !strings.Contains(g.Action, "not installed by a package manager") {
		t.Errorf("runtime Tomcat group %+v", g)
	}
}
