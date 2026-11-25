package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The official nginx Alpine images install nginx.org's apk, which Alpine's
// advisories do not describe (nginx 1.27.5 compares as newer than Alpine
// 3.21's fixed 1.26.3-r4). It has no aports commit, so it is matched by its
// upstream version against NVD's nginx records. Alpine's own build, and a
// row from an agent that did not read the commit, are not.
func TestVendorBuildsAlpine(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, _, nvd := setupPrograms(t)

	const (
		nginxOrg = "pkg:apk/alpine/nginx@1.27.5-r1?arch=x86_64&distro=alpine-3.21.5&upstream=nginx"
		alpines  = "pkg:apk/alpine/nginx@1.26.3-r2?arch=x86_64&distro=alpine-3.21.5&upstream=nginx"
		oldAgent = "pkg:apk/alpine/nginx@1.24.0-r1?arch=x86_64&distro=alpine-3.17.10&upstream=nginx"
	)
	image := ingest(t, st, model.AssetImage, "nginx:1.27-alpine", true, osRow("alpine", "3.21.5"),
		confirmed(nginxOrg, map[string]string{"db": "apk", "build_commit": "none", "maintainer": "NGINX Packaging <nginx-packaging@f5.com>"}))
	own := ingest(t, st, model.AssetImage, "alpine-nginx", true, osRow("alpine", "3.21.5"),
		confirmed(alpines, map[string]string{"db": "apk", "build_commit": "a3223802c9b70ef9681eabb569f26bf65230a514", "maintainer": "Jakub Jirutka <jakub@jirutka.cz>"}))
	old := ingest(t, st, model.AssetImage, "old-agent", true, osRow("alpine", "3.17.10"),
		confirmed(oldAgent, map[string]string{"db": "apk"}))

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	nvd.extra["cpe:2.3:a:f5:nginx"] = []nvdWrapped{
		nvdCVEWith("CVE-2026-123007", cpeRange("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "1.9.5", "1.30.7")),
	}
	if res, err := sy.Sync(ctx, FeedVendorBuilds); err != nil || res.Warning != "" {
		t.Fatalf("sync: %+v %v", res, err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}

	fs := allFindings(t, st, ctx, image)
	if len(fs) != 1 || fs[0].Key != "CVE-2026-123007" || fs[0].FixedVersion != "1.30.7" {
		t.Fatalf("nginx.org's apk findings: %+v", fs)
	}
	var e map[string]any
	_ = json.Unmarshal(fs[0].Evidence, &e)
	if e["program"] != "vendor:nginx" || e["vendor_repository"] != "NGINX Packaging's repository" || e["program_version"] != "1.27.5" {
		t.Errorf("evidence %v", e)
	}
	if cov := rowCoverage(t, ctx, st, image)[nginxOrg]; !strings.Contains(cov.CoverageReason, "matched as nginx 1.27.5 against NVD's records") {
		t.Errorf("coverage %s %q", cov.Coverage, cov.CoverageReason)
	}
	for name, asset := range map[string]int64{"Alpine's own nginx": own, "a row without build_commit": old} {
		if fs := allFindings(t, st, ctx, asset); len(fs) != 0 {
			t.Errorf("%s matched NVD: %+v", name, fs)
		}
	}
	for purl, asset := range map[string]int64{alpines: own, oldAgent: old} {
		if r := rowCoverage(t, ctx, st, asset)[purl]; strings.HasPrefix(r.CoverageReason, "built by ") {
			t.Errorf("%s counted as another repository's build: %q", purl, r.CoverageReason)
		}
	}
}

func TestThirdPartyRepoApk(t *testing.T) {
	const purl = "pkg:apk/alpine/nginx@1.27.5-r1?distro=alpine-3.21.5"
	for _, c := range []struct {
		ev   map[string]string
		want string
	}{
		{map[string]string{"build_commit": "none", "maintainer": "NGINX Packaging <nginx-packaging@f5.com>"}, "NGINX Packaging's repository"},
		{map[string]string{"build_commit": "none"}, "another repository"},
		{map[string]string{"build_commit": "a3223802", "maintainer": "Jakub Jirutka <jakub@jirutka.cz>"}, ""},
		{nil, ""}, // an agent that did not read it
	} {
		if got := thirdPartyRepo(eoloverlay.Default(), "apk", "pkg:apk/alpine/nginx", purl, "1.27.5-r1", c.ev); got != c.want {
			t.Errorf("%v: %q, want %q", c.ev, got, c.want)
		}
	}
}
