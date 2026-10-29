package eoloverlay

import (
	"strings"
	"testing"
)

func TestEmbeddedOverlayParses(t *testing.T) {
	o := Default()
	if o.Version() == "" || len(o.Document().Products) == 0 || len(o.Document().Untracked) == 0 {
		t.Fatalf("embedded overlay looks empty: %+v", o.Document())
	}
	for _, e := range o.Document().Products {
		for _, s := range e.Sources {
			if !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
				t.Errorf("%s: source %q is not a URL", e.Product, s)
			}
		}
	}
}

func edlMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestPrecedence(t *testing.T) {
	o, err := Parse([]byte(`{"schema":1,"version":"t",
	 "namespace_families":[{"type":"rpm","namespaces":["redhat","rocky"],"why":"x"}],
	 "products":[
	  {"product":"ours","purls":["pkg:deb/*/thing"],"sources":["https://x"],"verified":"2026-10-28"},
	  {"product":"forced","purls":["pkg:npm/forced"],"override":true,"sources":["https://x"],"verified":"2026-10-28"},
	  {"product":"postgresql","purls":["pkg:deb/*/postgresql-{cycle}"],"sources":["https://x"],"verified":"2026-10-28"},
	  {"product":"corretto","purls":["pkg:deb/*/java-{cycle}-amazon-corretto-jdk"],"cycle_aliases":{"1.8.0":"8"},"vendor_only":"Amazon","sources":["https://x"],"verified":"2026-10-28"},
	  {"product":"redis","purls":["pkg:deb/*/redis-server"],"vendor_builds":[{"repository":"Redis","version":"rl\\d+~[a-z]+\\d*$"}],"sources":["https://x"],"verified":"2026-10-28"}],
	 "untracked":[{"label":"NestJS","purls":["pkg:npm/%40nestjs/core"],"why":"none","sources":["https://x"],"checked":"2026-10-28"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	edl := edlMap(map[string]string{
		"pkg:deb/ubuntu/thing": "theirs", // endoflife.date wins over a non-override entry
		"pkg:npm/forced":       "theirs",
		"pkg:rpm/redhat/nginx": "nginx",
	})
	cases := []struct {
		key, product, cycle, rule string
	}{
		{"pkg:deb/ubuntu/thing", "theirs", "", "endoflife.date"},
		{"pkg:deb/debian/thing", "ours", "", "overlay"},
		{"pkg:npm/forced", "forced", "", "overlay"},
		{"pkg:rpm/rocky/nginx", "nginx", "", "namespace_family"},
		{"pkg:deb/ubuntu/postgresql-16", "postgresql", "16", "overlay"},
		{"pkg:deb/ubuntu/postgresql-9.6", "postgresql", "9.6", "overlay"},
		{"pkg:deb/ubuntu/java-1.8.0-amazon-corretto-jdk", "corretto", "8", "overlay"},
		{"PKG:DEB/Ubuntu/Postgresql-15", "postgresql", "15", "overlay"},
	}
	for _, c := range cases {
		m, ok := o.Product(c.key, edl)
		if !ok || m.Product != c.product || m.Cycle != c.cycle || m.Rule != c.rule {
			t.Errorf("%s: got %+v %v, want %s %q %s", c.key, m, ok, c.product, c.cycle, c.rule)
		}
	}
	for _, key := range []string{"pkg:deb/ubuntu/postgresql-client-16", "pkg:deb/ubuntu/postgresql", "pkg:deb/thing", "pkg:rpm/amzn/nginx", "pkg:rpm/fedora/nginx", "nonsense"} {
		if m, ok := o.Product(key, edl); ok {
			t.Errorf("%s: unexpected match %+v", key, m)
		}
	}

	if repo, ok := o.VendorBuild("pkg:deb/ubuntu/redis-server", "6:7.4.1-1rl1~noble1"); !ok || repo != "Redis" {
		t.Errorf("redis.io build: %q %v", repo, ok)
	}
	if _, ok := o.VendorBuild("pkg:deb/ubuntu/redis-server", "5:7.0.15-1build2"); ok {
		t.Error("Ubuntu's redis-server is not a vendor build")
	}
	if repo, ok := o.VendorBuild("pkg:deb/debian/java-21-amazon-corretto-jdk", "1:21.0.5.11-1"); !ok || repo != "Amazon" {
		t.Errorf("vendor-only package: %q %v", repo, ok)
	}
	if l, ok := o.Untracked("pkg:npm/%40nestjs/core"); !ok || l != "NestJS" {
		t.Errorf("untracked: %q %v", l, ok)
	}
	if _, ok := o.Untracked("pkg:npm/%40nestjs/common"); ok {
		t.Error("only @nestjs/core counts NestJS")
	}
	likes := strings.Join(o.LikePatterns(), " ")
	for _, want := range []string{`pkg:deb/%/postgresql-%`, `pkg:npm/\%40nestjs/core`, `pkg:deb/%/redis-server`} {
		if !strings.Contains(likes, want) {
			t.Errorf("LikePatterns %s: missing %s", likes, want)
		}
	}
	fam := o.FamilyKeys([]string{"pkg:rpm/redhat/nginx", "pkg:npm/express"})
	if len(fam) != 1 || fam[0] != "pkg:rpm/rocky/nginx" {
		t.Errorf("FamilyKeys: %v", fam)
	}
}

func TestParseRejects(t *testing.T) {
	head := `{"schema":1,"version":"t","namespace_families":[],"untracked":[],"products":[`
	for name, body := range map[string]string{
		"schema":     `{"schema":2,"version":"t","products":[]}`,
		"no version": `{"schema":1,"products":[]}`,
		"unknown":    `{"schema":1,"version":"t","products":[],"extra":1}`,
		"no sources": head + `{"product":"p","purls":["pkg:npm/a"],"verified":"2026-10-28"}]}`,
		"bad date":   head + `{"product":"p","purls":["pkg:npm/a"],"sources":["https://x"],"verified":"soon"}]}`,
		"version":    head + `{"product":"p","purls":["pkg:npm/a@1"],"sources":["https://x"],"verified":"2026-10-28"}]}`,
		"two cycles": head + `{"product":"p","purls":["pkg:deb/*/a{cycle}-{cycle}"],"sources":["https://x"],"verified":"2026-10-28"}]}`,
		"bad regexp": head + `{"product":"p","purls":["pkg:deb/*/a"],"vendor_builds":[{"repository":"r","version":"("}],"sources":["https://x"],"verified":"2026-10-28"}]}`,
		"duplicate": head + `{"product":"p","purls":["pkg:npm/a"],"sources":["https://x"],"verified":"2026-10-28"},
		                      {"product":"q","purls":["pkg:npm/a"],"sources":["https://x"],"verified":"2026-10-28"}]}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestHashiCorpDistroBuilds: Debian and Ubuntu shipped their own consul and
// nomad (always versioned +dfsg or ~dfsg), so only HashiCorp's own version
// format marks a vendor build; the distributions' packages are still
// evaluated against their advisories.
func TestHashiCorpDistroBuilds(t *testing.T) {
	o := Default()
	for _, c := range []struct {
		key, version string
		vendor       bool
	}{
		{"pkg:deb/ubuntu/consul", "1.20.1-1", true},
		{"pkg:deb/debian/consul", "1.20.1", true},
		{"pkg:deb/ubuntu/consul", "1.8.7+dfsg1-3", false},            // Ubuntu 22.04
		{"pkg:deb/ubuntu/consul", "0.6.4~dfsg-3", false},             // Ubuntu 18.04
		{"pkg:deb/ubuntu/consul", "1.10.12+dfsg1-1ubuntu0.1", false}, // Ubuntu 23.10 security
		{"pkg:deb/debian/consul", "1.0.7~dfsg1-5+b21", false},        // Debian 10
		{"pkg:deb/debian/consul", "1.8.7+dfsg1-2+b3", false},         // Debian 11
		{"pkg:deb/ubuntu/nomad", "2.0.7-1", true},
		{"pkg:deb/ubuntu/nomad", "0.8.7+dfsg1-1ubuntu1", false}, // Ubuntu 20.04
		{"pkg:deb/ubuntu/nomad", "0.4.0+dfsg-1", false},         // Ubuntu 18.04
		{"pkg:deb/ubuntu/vault", "1.18.0-1", true},              // still vendor-only
	} {
		repo, ok := o.VendorBuild(c.key, c.version)
		if ok != c.vendor {
			t.Errorf("%s %s: vendor build %v (%q), want %v", c.key, c.version, ok, repo, c.vendor)
		}
	}
	for key, want := range map[string]string{"pkg:deb/ubuntu/consul": "consul", "pkg:deb/debian/nomad": "nomad"} {
		if m, ok := o.Product(key, nil); !ok || m.Product != want {
			t.Errorf("%s: %+v %v, want %s", key, m, ok, want)
		}
	}
}
