package intel

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// endoflife.date data for the distribution-lifecycle cases, evaluated on
// 2026-10-26.
const distroEOL = `{"result":[
 {"name":"ubuntu","label":"Ubuntu","links":{"html":"https://endoflife.date/ubuntu"},"identifiers":[],
  "releases":[{"name":"24.04","label":"24.04 'Noble Numbat'","releaseDate":"2024-04-25","isLts":true,"isEol":false,"eolFrom":"2029-05-31"},
              {"name":"22.04","label":"22.04 'Jammy Jellyfish'","releaseDate":"2022-04-21","isLts":true,"isEol":false,"eolFrom":"2027-06-30"},
              {"name":"20.04","label":"20.04 'Focal Fossa'","releaseDate":"2020-04-23","isLts":true,"isEol":true,"eolFrom":"2025-05-31"}]},
 {"name":"rhel","label":"Red Hat Enterprise Linux","links":{"html":"https://endoflife.date/rhel"},"identifiers":[],
  "releases":[{"name":"9","label":"9","releaseDate":"2022-05-17","isEol":false,"eolFrom":"2032-05-31"}]},
 {"name":"alpine-linux","label":"Alpine Linux","links":{"html":"https://endoflife.date/alpine-linux"},"identifiers":[],
  "releases":[{"name":"3.21","label":"3.21","releaseDate":"2024-12-05","isEol":false,"eolFrom":"2026-11-01"}]},
 {"name":"nginx","label":"nginx","links":{"html":"https://endoflife.date/nginx"},"identifiers":[{"type":"purl","id":"pkg:deb/ubuntu/nginx"}],
  "releases":[{"name":"1.24","label":"1.24","releaseDate":"2023-04-11","isEol":true,"eolFrom":"2024-04-23"},
              {"name":"1.18","label":"1.18","releaseDate":"2020-04-21","isEol":true,"eolFrom":"2021-04-20"}]},
 {"name":"php","label":"PHP","links":{"html":"https://endoflife.date/php"},"identifiers":[{"type":"purl","id":"pkg:rpm/rhel/php"}],
  "releases":[{"name":"8.1","label":"8.1","releaseDate":"2021-11-25","isEol":true,"eolFrom":"2025-12-31"},
              {"name":"8.0","label":"8.0","releaseDate":"2020-11-26","isEol":true,"eolFrom":"2023-11-26"},
              {"name":"7.4","label":"7.4","releaseDate":"2019-11-28","isEol":true,"eolFrom":"2022-11-28"}]},
 {"name":"python","label":"Python","links":{"html":"https://endoflife.date/python"},"identifiers":[{"type":"purl","id":"pkg:deb/ubuntu/python3.10"}],
  "releases":[{"name":"3.10","label":"3.10","releaseDate":"2021-10-04","isEol":true,"eolFrom":"2026-10-01"}]},
 {"name":"mysql","label":"MySQL","links":{"html":"https://endoflife.date/mysql"},"identifiers":[{"type":"purl","id":"pkg:deb/ubuntu/mysql-server-8.0"}],
  "releases":[{"name":"8.0","label":"8.0","releaseDate":"2018-04-19","isEol":true,"eolFrom":"2026-04-30"}]},
 {"name":"nodejs","label":"Node.js","links":{"html":"https://endoflife.date/nodejs"},"identifiers":[{"type":"purl","id":"pkg:apk/alpine/nodejs"}],
  "releases":[{"name":"20","label":"20","releaseDate":"2023-04-18","isEol":true,"eolFrom":"2026-04-30"},
              {"name":"16","label":"16","releaseDate":"2021-04-20","isEol":true,"eolFrom":"2023-09-11"}]}]}`

func osRow(name, ver string) model.Observation {
	return confirmed("pkg:generic/"+name+"@"+ver, map[string]string{"kind": "operating-system"})
}

func TestDistributionMaintainedLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	jammy := ingest(t, st, model.AssetHost, "jammy", true,
		osRow("ubuntu", "22.04"),
		confirmed("pkg:deb/ubuntu/nginx@1.18.0-6ubuntu14.4?distro=ubuntu-22.04", nil),
		confirmed("pkg:deb/ubuntu/php8.1-common@8.1.2-1ubuntu2.14?distro=ubuntu-22.04&upstream=php8.1", nil),
		confirmed("pkg:deb/ubuntu/python3.10@3.10.12-1~22.04.10?distro=ubuntu-22.04", nil),
		confirmed("pkg:deb/ubuntu/mysql-server-8.0@8.0.39-0ubuntu0.22.04.1?distro=ubuntu-22.04&upstream=mysql-8.0", nil),
		// nvm's Node, outside the package manager: upstream dates apply.
		confirmed("pkg:generic/nodejs@16.20.2", map[string]string{"kind": "runtime", "install": "unmanaged"}),
	)
	noble := ingest(t, st, model.AssetHost, "noble", true, osRow("ubuntu", "24.04"),
		confirmed("pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7.1?distro=ubuntu-24.04", nil))
	sury := ingest(t, st, model.AssetHost, "jammy-sury", true, osRow("ubuntu", "22.04"),
		confirmed("pkg:deb/ubuntu/php8.1-common@8.1.30-1+ubuntu22.04.1+deb.sury.org+1?distro=ubuntu-22.04&upstream=php8.1", nil),
		confirmed("pkg:deb/ubuntu/nginx@1.24.0-1~jammy?distro=ubuntu-22.04", nil),
		confirmed("pkg:deb/ubuntu/mysql-server-8.0@8.0.39-1ubuntu22.04?distro=ubuntu-22.04", nil))
	focal := ingest(t, st, model.AssetHost, "focal", true, osRow("ubuntu", "20.04"),
		confirmed("pkg:deb/ubuntu/nginx@1.18.0-0ubuntu1.4?distro=ubuntu-20.04", nil),
		confirmed("pkg:deb/ubuntu/php7.4-common@7.4.3-4ubuntu2.24?distro=ubuntu-20.04&upstream=php7.4", nil))
	// An SBOM of a focal image with no operating system component: nothing
	// else would say the packages are past support, so the finding stays.
	sbom := ingest(t, st, model.AssetSBOM, "focal-image", true,
		confirmed("pkg:deb/ubuntu/nginx@1.18.0-0ubuntu1.4?distro=ubuntu-20.04", nil))
	rhel := ingest(t, st, model.AssetHost, "rhel9", true, osRow("rhel", "9.4"),
		confirmed("pkg:rpm/rhel/php@8.0.30-1.el9_2?distro=rhel-9.4", map[string]string{"evr": "8.0.30-1.el9_2"}))
	alpine := ingest(t, st, model.AssetHost, "alpine", true, osRow("alpine", "3.21.2"),
		confirmed("pkg:apk/alpine/nodejs@20.15.1-r0?distro=alpine-3.21.2&upstream=nodejs", nil))
	// A release the lifecycle data does not list: its support is unknown.
	unknown := ingest(t, st, model.AssetHost, "oracular", true,
		confirmed("pkg:deb/ubuntu/nginx@1.24.0-2ubuntu7?distro=ubuntu-24.10", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/eol.json", distroEOL)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	ev.Now = func() time.Time { return now }
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	eol := func(asset int64) []string {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Kind: "end_of_life"})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, f := range fs {
			keys = append(keys, f.Key)
		}
		sort.Strings(keys)
		return keys
	}
	notes := func(asset int64) map[string]map[string]any {
		rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]map[string]any{}
		for _, r := range rows {
			if r.LifecycleNote != nil {
				out[r.Name] = r.LifecycleNote
			}
		}
		return out
	}
	for _, c := range []struct {
		name  string
		asset int64
		want  []string // end-of-life finding keys
		notes map[string]string
	}{
		{"Ubuntu 22.04 packages: supported by Ubuntu", jammy, []string{"nodejs:16"}, map[string]string{
			"nginx":            "nginx 1.18 is end of life upstream since 2021-04-20; this is Ubuntu 22.04's own package, and Ubuntu 22.04 provides security updates until 2027-06-30.",
			"php8.1-common":    "PHP 8.1 is end of life upstream since 2025-12-31; this is Ubuntu 22.04's own package",
			"python3.10":       "Python 3.10 is end of life upstream since 2026-10-01; this is Ubuntu 22.04's own package",
			"mysql-server-8.0": "MySQL 8.0 is end of life upstream since 2026-04-30; this is Ubuntu 22.04's own package"}},
		{"Ubuntu 24.04 nginx", noble, nil, map[string]string{"nginx": "nginx 1.24 is end of life upstream since 2024-04-23; this is Ubuntu 24.04's own package, and Ubuntu 24.04 provides security updates until 2029-05-31."}},
		{"third-party builds keep upstream dates", sury, []string{"mysql:8.0", "nginx:1.24", "php:8.1"}, map[string]string{
			"php8.1-common": "not Ubuntu 22.04's own package", "nginx": "not Ubuntu 22.04's own package", "mysql-server-8.0": "not Ubuntu 22.04's own package"}},
		{"Ubuntu 20.04: one OS finding", focal, []string{"ubuntu:20.04"}, map[string]string{
			"nginx":         "Ubuntu 20.04 itself is end of life since 2025-05-31, so its packages no longer get free fixes: see the operating system's end-of-life finding.",
			"php7.4-common": "PHP 7.4 is end of life upstream since 2022-11-28; Ubuntu 20.04 itself is end of life"}},
		{"focal SBOM without an OS row", sbom, []string{"nginx:1.18"}, map[string]string{"nginx": "Ubuntu 20.04 itself is end of life since 2025-05-31, so its packages no longer get free fixes."}},
		{"RHEL 9 php", rhel, nil, map[string]string{"php": "PHP 8.0 is end of life upstream since 2023-11-26; this is Red Hat Enterprise Linux 9's own package, and Red Hat Enterprise Linux 9 provides security updates until 2032-05-31."}},
		{"Alpine 3.21 nodejs", alpine, nil, map[string]string{"nodejs": "Node.js 20 is end of life upstream since 2026-04-30; this is Alpine Linux 3.21's own package"}},
		{"distribution release not in the lifecycle data", unknown, []string{"nginx:1.24"}, map[string]string{}},
	} {
		if got := eol(c.asset); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: end-of-life findings %v, want %v", c.name, got, c.want)
		}
		got := notes(c.asset)
		if len(got) != len(c.notes) {
			t.Errorf("%s: notes %v, want %d", c.name, got, len(c.notes))
		}
		for pkg, want := range c.notes {
			if text, _ := got[pkg]["text"].(string); !strings.Contains(text, want) {
				t.Errorf("%s: %s note %q, want it to contain %q", c.name, pkg, text, want)
			}
		}
	}
	// A finding that stands says what the distribution adds.
	fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: sbom, Kind: "end_of_life"})
	if len(fs) != 1 || !strings.Contains(string(fs[0].Evidence), `"status": "distribution_ended"`) {
		t.Errorf("SBOM finding = %+v", fs)
	}

	// The action plan lists the focal packages under the release upgrade.
	if _, err := planner.Rebuild(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: focal})
	if err != nil || len(raw) != 1 {
		t.Fatalf("focal groups = %d %v", len(raw), err)
	}
	var g fixplan.Group
	_ = json.Unmarshal(raw[0], &g)
	if g.Kind != fixplan.ReleaseUpgrade || strings.Join(g.Packages, ",") != "nginx,php7.4-common,ubuntu" ||
		!strings.HasSuffix(g.Note, "which only the release's support kept patched: PHP 7.4, nginx 1.18.") {
		t.Errorf("focal release upgrade = %+v", g)
	}

	// Once Ubuntu 22.04 itself ends, its packages are covered by its OS
	// finding.
	now = time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC)
	if _, err := ev.Evaluate(ctx, nil, jammy); err != nil {
		t.Fatal(err)
	}
	if got := eol(jammy); strings.Join(got, ",") != "nodejs:16,ubuntu:22.04" {
		t.Errorf("jammy after its end of life: %v", got)
	}
}

func TestThirdPartyBuild(t *testing.T) {
	for _, c := range []struct {
		typ, v, rel string
		want        bool
	}{
		{"deb", "1.18.0-6ubuntu14.4", "22.04", false},
		{"deb", "8.0.39-0ubuntu0.22.04.1", "22.04", false},
		{"deb", "3.10.12-1~22.04.10", "22.04", false},
		{"deb", "1.22.1-9+deb12u1", "12", false},
		{"deb", "8.1.30-1+ubuntu22.04.1+deb.sury.org+1", "22.04", true},
		{"deb", "1.24.0-1~jammy", "22.04", true},
		{"deb", "5:27.3.1-1~ubuntu.22.04~jammy", "22.04", true},
		{"deb", "8.0.39-1ubuntu22.04", "22.04", true},
		{"deb", "8.0.39-1debian12", "12", true},
		{"deb", "16.20.2-1nodesource1", "22.04", true},
		{"deb", "16.4-1.pgdg22.04+1", "22.04", true},
		// An upstream pre-release is not a codename.
		{"deb", "2.0~beta", "22.04", false},
		{"deb", "1.4.0~rc1-2", "22.04", false},
		// redis.io's codename ends in a digit; the overlay recognises it.
		{"deb", "6:7.4.1-1rl1~jammy1", "22.04", false},
		{"rpm", "8.0.30-1.el9_2", "9.4", false},
		{"rpm", "8.1.30-1.el9.remi", "9.4", true},
		{"rpm", "1.26.2-1.el9.ngx", "9.4", true},
		{"apk", "20.15.1-r0", "3.21.2", false},
	} {
		if got := thirdPartyBuild(c.typ, c.v, c.rel); got != c.want {
			t.Errorf("%s %s = %v", c.typ, c.v, got)
		}
	}
	for distro, want := range map[string]string{"ubuntu-22.04": "ubuntu 22.04", "opensuse-leap-15.6": "opensuse 15.6", "rhel-9.4": "rhel 9.4",
		"alpine-3.21.2": "alpine-linux 3.21.2", "sles_sap-15.5": "sles 15.5", "amzn-2023": "amazon-linux 2023", "gentoo-2.17": " "} {
		p, r := distroProduct(distro)
		if got := p + " " + r; got != want {
			t.Errorf("distroProduct(%s) = %q, want %q", distro, got, want)
		}
	}
}
