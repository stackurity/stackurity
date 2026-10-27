package apps

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

type tree struct {
	t    *testing.T
	root string
}

func newTree(t *testing.T) *tree { return &tree{t: t, root: t.TempDir()} }

func (tr *tree) file(p, data string) {
	full := filepath.Join(tr.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) link(p, target string) {
	full := filepath.Join(tr.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *tree) npm(dir, name, version string) {
	tr.file(filepath.Join(dir, "package.json"), `{"name":"`+name+`","version":"`+version+`"}`)
}

func purls(obs []model.Observation) map[string]model.Observation {
	m := map[string]model.Observation{}
	for _, o := range obs {
		m[o.Purl] = o
	}
	return m
}

func keys(m map[string]model.Observation) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestScanNodeApp(t *testing.T) {
	tr := newTree(t)
	app := "srv/shop"
	tr.file(app+"/package.json", `{"name":"shop","dependencies":{"express":"^4","@aws-sdk/client-s3":"^3"},"devDependencies":{"jest":"^29"}}`)
	// The lockfile says 4.18.2 but 4.17.1 is what is installed: installed wins.
	tr.file(app+"/package-lock.json", `{"lockfileVersion":3,"packages":{"":{"dependencies":{"express":"^4"}},
		"node_modules/express":{"version":"4.18.2"}}}`)
	tr.npm(app+"/node_modules/express", "express", "4.17.1")
	tr.npm(app+"/node_modules/express/node_modules/qs", "qs", "6.7.0")
	tr.npm(app+"/node_modules/@aws-sdk/client-s3", "@aws-sdk/client-s3", "3.500.0")
	tr.npm(app+"/node_modules/jest", "jest", "29.7.0")
	tr.file(app+"/node_modules/.package-lock.json", `{"packages":{"node_modules/jest":{"version":"29.7.0","dev":true}}}`)
	tr.link(app+"/node_modules/local-lib", "../../lib") // npm link: the project's own code
	tr.file(app+"/.git/config", "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://user:secret@github.com/acme/shop.git\n")

	s := &Scanner{Root: tr.root}
	a := s.ScanApp(context.Background(), "/srv/shop")
	m := purls(a.Observations)
	want := []string{"pkg:npm/express@4.17.1", "pkg:npm/qs@6.7.0", "pkg:npm/%40aws-sdk/client-s3@3.500.0", "pkg:npm/jest@29.7.0"}
	for _, w := range want {
		if _, ok := m[w]; !ok {
			t.Errorf("missing %s; have %v", w, keys(m))
		}
	}
	if len(m) != len(want) {
		t.Errorf("lockfile entry should yield to the installed tree; have %v", keys(m))
	}
	if o := m["pkg:npm/express@4.17.1"]; o.Direct == nil || !*o.Direct || o.Location != "/srv/shop/node_modules/express" || o.Evidence["app_dir"] != "/srv/shop" {
		t.Errorf("express = %+v", o)
	}
	if o := m["pkg:npm/qs@6.7.0"]; o.Direct == nil || *o.Direct {
		t.Errorf("nested qs should be transitive: %+v", o)
	}
	if m["pkg:npm/jest@29.7.0"].Scope != "dev" {
		t.Errorf("jest scope = %q", m["pkg:npm/jest@29.7.0"].Scope)
	}
	if a.Name != "shop" || a.GitURL != "https://github.com/acme/shop.git" {
		t.Errorf("name %q git %q", a.Name, a.GitURL)
	}
	validate(t, a)
}

func TestScanPythonComposerAndLockfileFallback(t *testing.T) {
	tr := newTree(t)
	tr.file("srv/api/requirements.txt", "flask==2.0.0\n")
	tr.file("srv/api/.venv/lib/python3.12/site-packages/Flask-2.0.1.dist-info/METADATA", "Metadata-Version: 2.1\nName: Flask\nVersion: 2.0.1\n\nName: not-a-header\n")
	tr.file("srv/api/.venv/lib/python3.12/site-packages/zope.interface-6.0.dist-info/METADATA", "Name: zope.interface\nVersion: 6.0\n")
	tr.file("srv/api/worker/go.mod", "module example.com/worker\n\ngo 1.22\n\nrequire github.com/gin-gonic/gin v1.9.0\n")
	tr.file("var/www/site/composer.lock", `{"packages":[{"name":"laravel/framework","version":"v10.0.0"}]}`)
	tr.file("var/www/site/vendor/composer/installed.json", `{"packages":[{"name":"laravel/framework","version":"v10.1.0"},
		{"name":"phpunit/phpunit","version":"10.0.0"}],"dev-package-names":["phpunit/phpunit"]}`)

	s := &Scanner{Root: tr.root}
	api := purls(s.ScanApp(context.Background(), "/srv/api").Observations)
	for _, w := range []string{"pkg:pypi/flask@2.0.1", "pkg:pypi/zope-interface@6.0", "pkg:golang/github.com/gin-gonic/gin@v1.9.0"} {
		if _, ok := api[w]; !ok {
			t.Errorf("api missing %s; have %v", w, keys(api))
		}
	}
	if _, ok := api["pkg:pypi/flask@2.0.0"]; ok {
		t.Error("requirements.txt should yield to the installed virtualenv")
	}
	site := s.ScanApp(context.Background(), "/var/www/site")
	sm := purls(site.Observations)
	if len(sm) != 2 || sm["pkg:composer/phpunit/phpunit@10.0.0"].Scope != "dev" {
		t.Errorf("site = %v", keys(sm))
	}
	if _, ok := sm["pkg:composer/laravel/framework@10.1.0"]; !ok {
		t.Errorf("installed laravel missing: %v", keys(sm))
	}
	validate(t, site)
}

// A webroot holding another application (phpMyAdmin under a CodeIgniter
// site) must not report the inner one's libraries as its own.
func TestNestedAppReportedOnce(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/html/composer.json", `{"name":"codeigniter/framework"}`)
	tr.file("var/www/html/composer.lock", `{"packages":[{"name":"psr/log","version":"1.1.0"}]}`)
	tr.file("var/www/html/phpmyadmin/composer.json", `{"name":"phpmyadmin/phpmyadmin"}`)
	tr.file("var/www/html/phpmyadmin/yarn.lock", "jquery@3.3.1:\n  version \"3.3.1\"\n")
	tr.npm("var/www/html/demo/pma/node_modules/jquery", "jquery", "3.3.1")
	tr.file("var/www/html/demo/pma/package.json", `{"name":"pma","dependencies":{"jquery":"3.3.1"}}`)

	s := &Scanner{Root: tr.root, Apps: []string{"/var/www/html", "/var/www/html/phpmyadmin", "/var/www/html/demo/pma"}}
	outer := purls(s.ScanApp(context.Background(), "/var/www/html").Observations)
	if len(outer) != 1 {
		t.Errorf("webroot should report only its own psr/log, got %v", keys(outer))
	}
	for _, dir := range []string{"/var/www/html/phpmyadmin", "/var/www/html/demo/pma"} {
		if _, ok := purls(s.ScanApp(context.Background(), dir).Observations)["pkg:npm/jquery@3.3.1"]; !ok {
			t.Errorf("%s lost its own jquery", dir)
		}
	}
	// Without the list of applications the webroot still sees everything.
	if all := purls((&Scanner{Root: tr.root}).ScanApp(context.Background(), "/var/www/html").Observations); len(all) < 2 {
		t.Errorf("unscoped scan = %v", keys(all))
	}
}

func TestPnpmLayout(t *testing.T) {
	tr := newTree(t)
	tr.file("srv/web/package.json", `{"name":"web","dependencies":{"next":"14"}}`)
	tr.npm("srv/web/node_modules/.pnpm/next@14.1.0/node_modules/next", "next", "14.1.0")
	tr.npm("srv/web/node_modules/.pnpm/@swc+helpers@0.5.2/node_modules/@swc/helpers", "@swc/helpers", "0.5.2")
	tr.link("srv/web/node_modules/.pnpm/next@14.1.0/node_modules/@swc/helpers", "../../../@swc+helpers@0.5.2/node_modules/@swc/helpers")
	tr.link("srv/web/node_modules/next", ".pnpm/next@14.1.0/node_modules/next")
	m := purls((&Scanner{Root: tr.root}).ScanApp(context.Background(), "/srv/web").Observations)
	if len(m) != 2 {
		t.Errorf("pnpm = %v", keys(m))
	}
}

func TestDiscoverAndReleases(t *testing.T) {
	tr := newTree(t)
	tr.file("srv/shop/package.json", `{"name":"shop"}`)
	tr.file("srv/shop/packages/ui/package.json", `{"name":"ui"}`) // inside a found app: not separate
	tr.file("var/www/blog/releases/1/composer.lock", `{"packages":[]}`)
	tr.file("var/www/blog/releases/2/composer.lock", `{"packages":[]}`)
	tr.link("var/www/blog/current", "releases/2")
	tr.file("home/deploy/apps/api/requirements.txt", "flask==2.0.0\n")
	tr.file("opt/empty/README", "")
	got := (&Scanner{Root: tr.root}).Discover()
	want := []string{"/srv/shop", "/var/www/blog/releases/2", "/home/deploy/apps/api"}
	if len(got) != len(want) {
		t.Fatalf("discovered %v", got)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			t.Errorf("missing %s in %v", w, got)
		}
	}
}

func TestGlobalSkipsOSOwned(t *testing.T) {
	tr := newTree(t)
	tr.npm("usr/lib/node_modules/npm", "npm", "9.2.0")
	tr.npm("usr/local/lib/node_modules/pm2", "pm2", "5.3.0")
	tr.file("usr/lib/python3/dist-packages/requests-2.28.1.dist-info/METADATA", "Name: requests\nVersion: 2.28.1\n")
	tr.file("usr/local/lib/python3.11/dist-packages/urllib3-1.26.0.dist-info/METADATA", "Name: urllib3\nVersion: 1.26.0\n")
	owned := map[string]bool{"/usr/lib/node_modules/npm/package.json": true, "/usr/lib/python3/dist-packages/requests-2.28.1.dist-info": true}
	s := &Scanner{Root: tr.root, Owned: func(p string) bool { return owned[p] }}
	obs, cov := s.ScanGlobal()
	m := purls(obs)
	if len(m) != 2 || m["pkg:npm/pm2@5.3.0"].Evidence["global"] != "true" {
		t.Errorf("global = %v", keys(m))
	}
	if _, ok := m["pkg:pypi/urllib3@1.26.0"]; !ok {
		t.Errorf("pip-installed urllib3 missing: %v", keys(m))
	}
	for _, c := range cov {
		if c.Status != "checked" {
			t.Errorf("coverage %+v", c)
		}
	}
}

func TestMissingAppDir(t *testing.T) {
	a := (&Scanner{Root: t.TempDir()}).ScanApp(context.Background(), "/srv/gone")
	if len(a.Coverage) != 1 || a.Coverage[0].Status != "failed" {
		t.Errorf("coverage = %+v", a.Coverage)
	}
}

func validate(t *testing.T, a App) {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication, Name: a.Name,
		Identifiers: []model.Identifier{{Scheme: "x", Value: "y"}}})
	b.Observations, b.Coverage = a.Observations, a.Coverage
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}
