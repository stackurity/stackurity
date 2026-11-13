package vendorbuilds

import (
	"regexp"
	"strings"
	"testing"
)

func TestDefaultParses(t *testing.T) {
	c := Default()
	if c.Version() == "" || len(c.Products()) < 10 {
		t.Fatalf("catalogue %q with %d products", c.Version(), len(c.Products()))
	}
}

func TestIdentify(t *testing.T) {
	c := Default()
	for _, tc := range []struct {
		typ, name, want string
		rank            int
	}{
		{"deb", "nginx", "nginx", 0},
		{"rpm", "nginx", "nginx", 1},
		{"deb", "nodejs", "nodejs", 0},
		{"deb", "postgresql-16", "postgresql", 0},
		{"deb", "postgresql-client-16", "postgresql", 2},
		{"rpm", "postgresql16-server", "postgresql", 1},
		{"deb", "php8.3-common", "php", 0},
		{"deb", "php8.3-fpm", "php", 1},
		{"deb", "php8.3-mysql", "php", 3},
		{"rpm", "php-common", "php", 4},
		{"rpm", "php83-php-common", "php", 6},
		{"deb", "redis-server", "redis", 0},
		{"rpm", "MariaDB-server", "mariadb", 1},
		{"deb", "mysql-community-server", "mysql", 0},
		{"deb", "vault", "vault", 0},
		{"deb", "docker-ce", "docker-engine", 0},
		{"rpm", "docker-ce", "docker-engine", 1},
		{"deb", "docker-ce-cli", "docker-engine", 2},
		{"deb", "docker-ce-rootless-extras", "docker-engine", 4},
		{"deb", "containerd.io", "containerd", 0},
		{"rpm", "containerd.io", "containerd", 1},
		// Not the product's own version, or not listed.
		{"deb", "php8.3-redis", "", 0},
		{"deb", "php8.3-xdebug", "", 0},
		{"deb", "libpq5", "", 0},
		{"deb", "nginx-module-njs", "", 0},
		{"apk", "nginx", "", 0},
		{"deb", "docker.io", "", 0},
		{"deb", "containerd", "", 0},
		{"deb", "containerdXio", "", 0},
		{"deb", "docker-compose-plugin", "", 0},
		{"deb", "docker-buildx-plugin", "", 0},
	} {
		p, rank := c.Identify(tc.typ, tc.name)
		got := ""
		if p != nil {
			got = p.ID
		}
		if got != tc.want || (p != nil && rank != tc.rank) {
			t.Errorf("Identify(%s, %s) = %q rank %d, want %q rank %d", tc.typ, tc.name, got, rank, tc.want, tc.rank)
		}
	}
}

func TestUpstreamVersion(t *testing.T) {
	c := Default()
	for _, tc := range []struct{ product, installed, want string }{
		{"nginx", "1.26.2-1~jammy", "1.26.2"},
		{"nginx", "1.26.2-1.el9.ngx", "1.26.2"},
		{"nodejs", "20.18.0-1nodesource1", "20.18.0"},
		{"postgresql", "16.4-1.pgdg22.04+1", "16.4"},
		{"php", "8.3.13-1+ubuntu22.04.1+deb.sury.org+1", "8.3.13"},
		{"php", "8.3.13-1.el9.remi", "8.3.13"},
		{"redis", "6:7.4.1-1rl1~jammy1", "7.4.1"},
		{"mariadb", "1:11.4.3+maria~ubu2404", "11.4.3"},
		{"mariadb", "11.4.3-1.el9", "11.4.3"},
		{"mysql", "8.0.39-1ubuntu22.04", "8.0.39"},
		{"elasticsearch", "8.15.2", "8.15.2"},
		{"consul", "1.20.1-1", "1.20.1"},
		{"docker-engine", "5:29.9.3-1~ubuntu.24.04~noble", "29.9.3"},
		{"docker-engine", "29.9.3-1.el9", "29.9.3"},
		{"containerd", "2.4.2-3~ubuntu.24.04~noble", "2.4.2"},
		{"containerd", "2.4.2-4.el9", "2.4.2"},
		// Editions and pre-releases are not read.
		{"consul", "1.20.1+ent-1", ""},
		{"vault", "1.18.1+ent-1", ""},
		{"nodejs", "23.0.0~rc1-1nodesource1", ""},
		{"nginx", "", ""},
	} {
		got, err := c.Product(tc.product).UpstreamVersion(tc.installed)
		if got != tc.want || (tc.want == "") != (err != nil) {
			t.Errorf("%s %q: %q, %v; want %q", tc.product, tc.installed, got, err, tc.want)
		}
	}
}

// The database query's pattern selects every name Identify reads.
func TestNamePattern(t *testing.T) {
	c := Default()
	re := regexp.MustCompile("(?i)" + c.NamePattern())
	for _, n := range []string{"nginx", "nodejs", "postgresql-16", "postgresql16-server", "php8.3-common", "php83-php-fpm",
		"libapache2-mod-php8.1", "MariaDB-server", "mysql-community-server", "vault", "terraform",
		"docker-ce", "docker-ce-cli", "containerd.io"} {
		if !re.MatchString(n) {
			t.Errorf("NamePattern does not select %s", n)
		}
	}
	if re.MatchString("php8.3-redis") || re.MatchString("nginx-extras") || re.MatchString("containerdXio") {
		t.Error("NamePattern selects packages Identify does not read")
	}
}

func TestOwnsCPE(t *testing.T) {
	c := Default()
	node, ngx, vault, dock := c.Product("nodejs"), c.Product("nginx"), c.Product("vault"), c.Product("docker-engine")
	for _, tc := range []struct {
		p        *Product
		criteria string
		want     bool
	}{
		{node, "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:*:*:*", true},
		{node, "cpe:2.3:a:nodejs:node.js:*:*:*:*:lts:*:*:*", true},
		{ngx, "cpe:2.3:a:f5:nginx:*:*:*:*:open_source:*:*:*", true},
		{ngx, "cpe:2.3:a:f5:nginx:*:*:*:*:plus:*:*:*", false},
		{vault, "cpe:2.3:a:hashicorp:vault:*:*:*:*:-:*:*:*", true},
		{vault, "cpe:2.3:a:hashicorp:vault:*:*:*:*:enterprise:*:*:*", false},
		{node, "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:windows:*:*", false},
		{node, "cpe:2.3:a:nodejs:node.js:*:*:*:*:-:linux:*:*", true},
		{dock, "cpe:2.3:a:docker:engine:*:*:*:*:*:*:*:*", true},
		{dock, "cpe:2.3:a:mobyproject:moby:*:*:*:*:*:*:*:*", true},
		{dock, "cpe:2.3:a:docker:docker:*:*:*:*:community:*:*:*", true},
		{dock, "cpe:2.3:a:docker:docker:*:*:*:*:enterprise:*:*:*", false},
		{dock, "cpe:2.3:a:docker:docker:*:*:*:*:community:windows:*:*", false},
		{dock, "cpe:2.3:a:mobyproject:moby\\/v2:2.0.0:beta0:*:*:*:*:*:*", false},
	} {
		if got := tc.p.OwnsCPE(tc.criteria); got != tc.want {
			t.Errorf("%s OwnsCPE(%s) = %v", tc.p.ID, tc.criteria, got)
		}
	}
}

func TestPlatformAllows(t *testing.T) {
	p := Default().Product("php")
	for crit, want := range map[string]bool{
		"cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*":         true,
		"cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:*:*:*:*": true,
		"cpe:2.3:o:debian:debian_linux:12.0:*:*:*:*:*:*:*":     true,
		"cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*":      true,
		"cpe:2.3:o:*:*:*:*:*:*:*:*:*:*":                        true,
		"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*":          false,
		"cpe:2.3:o:apple:macos:-:*:*:*:*:*:*:*":                false,
		"cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*":              false,
	} {
		if got := p.PlatformAllows(crit); got != want {
			t.Errorf("PlatformAllows(%s) = %v", crit, got)
		}
	}
}

func TestParseRejects(t *testing.T) {
	base := `{"schema":1,"version":"t","products":[{"id":"x","label":"X","packages":[PKG],"cpes":["cpe:2.3:a:x:x"],"sources":["s"],"verified":"2026-11-11"VER}]}`
	for name, doc := range map[string]string{
		"unanchored": strings.NewReplacer("PKG", `"deb/x"`, "VER", "").Replace(base),
		"apk":        strings.NewReplacer("PKG", `"^apk/x$"`, "VER", "").Replace(base),
		"no group":   strings.NewReplacer("PKG", `"^deb/x$"`, "VER", `,"version":"^\\d+$"`).Replace(base),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := Parse([]byte(strings.NewReplacer("PKG", `"^deb/x$"`, "VER", "").Replace(base))); err != nil {
		t.Errorf("valid document: %v", err)
	}
}
