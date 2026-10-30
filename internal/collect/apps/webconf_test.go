package apps

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// copyTree copies a fixture under testdata into a new scanner root, so a
// test can add the links a checkout may not keep.
func copyTree(t *testing.T, fixture string) *tree {
	t.Helper()
	tr := newTree(t)
	src := filepath.Join("testdata", fixture)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		tr.file(rel, string(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestParseApache(t *testing.T) {
	for _, tc := range []struct {
		name, conf     string
		roots, include []string
	}{
		{"plain and quoted", "DocumentRoot /var/www/a\n  DocumentRoot \"/var/www/b c\"\ndocumentroot '/var/www/d/'\n",
			[]string{"/var/www/a", "/var/www/b c", "/var/www/d/"}, nil},
		{"comments", "# DocumentRoot /var/www/old\n   #DocumentRoot /x\nDocumentRoot /var/www/new\n", []string{"/var/www/new"}, nil},
		{"alias target, not AliasMatch or ScriptAlias", "Alias /static /srv/static\nAliasMatch ^/i/(.*)$ /srv/img/$1\nScriptAlias /cgi-bin/ /usr/lib/cgi-bin/\n",
			[]string{"/srv/static"}, nil},
		{"continuation", "Alias /s \\\n    \"/srv/static site\"\n", []string{"/srv/static site"}, nil},
		{"variables are passed on as written", "DocumentRoot ${SITE}/public\n", []string{"${SITE}/public"}, nil},
		{"includes", "Include ports.conf\nIncludeOptional sites-enabled/*.conf\ninclude \"/etc/httpd/extra/*.conf\"\n", nil,
			[]string{"ports.conf", "sites-enabled/*.conf", "/etc/httpd/extra/*.conf"}},
		{"crlf and a missing argument", "DocumentRoot\r\nDocumentRoot /var/www/x\r\n", []string{"/var/www/x"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, aliases, includes := parseApache(tc.conf)
			if roots = append(roots, aliases...); !reflect.DeepEqual(roots, tc.roots) || !reflect.DeepEqual(includes, tc.include) {
				t.Errorf("roots %q includes %q", roots, includes)
			}
		})
	}
}

func TestParseNginx(t *testing.T) {
	for _, tc := range []struct {
		name, conf     string
		roots, include []string
	}{
		{"server and location", "server { root /var/www/a; location /b { alias /srv/b/; } }", []string{"/var/www/a", "/srv/b/"}, nil},
		{"quotes and comments", "root '/var/www/a b'; # root /x;\n#root /y;\nroot \"/var/www/c\";", []string{"/var/www/a b", "/var/www/c"}, nil},
		{"a string holding a directive", `location / { return 200 "root /fake;"; }`, nil, nil},
		{"variables are passed on as written", "root $document_root;", []string{"$document_root"}, nil},
		{"includes", "include /etc/nginx/conf.d/*.conf; include mime.types;", nil, []string{"/etc/nginx/conf.d/*.conf", "mime.types"}},
		{"names in other directives", "types { text/html html; } fastcgi_param root /x; index root;", nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, aliases, includes := parseNginx(tc.conf)
			if roots = append(roots, aliases...); !reflect.DeepEqual(roots, tc.roots) || !reflect.DeepEqual(includes, tc.include) {
				t.Errorf("roots %q includes %q", roots, includes)
			}
		})
	}
}

// Alias targets are told from document roots: they serve part of a site.
func TestParseAliases(t *testing.T) {
	if r, a, _ := parseApache("DocumentRoot /a\nAlias /x /b\n"); !reflect.DeepEqual(r, []string{"/a"}) || !reflect.DeepEqual(a, []string{"/b"}) {
		t.Errorf("apache roots %q aliases %q", r, a)
	}
	if r, a, _ := parseNginx("root /a; location /x { alias /b/; }"); !reflect.DeepEqual(r, []string{"/a"}) || !reflect.DeepEqual(a, []string{"/b/"}) {
		t.Errorf("nginx roots %q aliases %q", r, a)
	}
}

// webHost is the testdata/webhost fixture under a scanner root (as when
// the agent scans a mounted filesystem), with its links.
func webHost(t *testing.T) *tree {
	tr := copyTree(t, "webhost")
	tr.link("etc/apache2/sites-enabled/000-default.conf", "../sites-available/000-default.conf")
	tr.link("etc/apache2/sites-enabled/vwoods.conf", "/etc/apache2/sites-available/vwoods.conf") // absolute: inside the root
	tr.link("etc/apache2/sites-enabled/insta.conf", "../sites-available/insta.conf")
	tr.link("etc/nginx/sites-enabled/escape", "../../../../../../../../outside.conf")
	// A link to a file outside the root is resolved inside it, where there
	// is nothing.
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, "out.conf"), []byte("server { root /outside/public; }"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr.link("etc/nginx/sites-enabled/outside", filepath.Join(other, "out.conf"))
	tr.link("data/linksite", "../outside/public")
	tr.link("data/rel/current", "releases/3")
	return tr
}

func TestDiscoverWebServerRoots(t *testing.T) {
	tr := webHost(t)
	found, full := (&Scanner{Root: tr.root}).DiscoverSites()
	got := map[string][]string{}
	for _, d := range found {
		got[d.Dir] = d.By
	}
	want := map[string][]string{
		// The walk; a configuration naming the same site adds itself.
		"/srv/blog":                           {"composer.json", "nginx:/etc/nginx/sites-enabled/shop"},
		"/var/www/html/phpmyadmin":            {"composer.json"},
		"/var/www/insta-solutions.com/public": {"index.html", "apache:/etc/apache2/sites-enabled/insta.conf"},
		"/var/www/vwoods.in/public":           {"index.php", "apache:/etc/apache2/sites-enabled/vwoods.conf"},
		"/var/www/wp":                         {"wp-config.php"},
		// Only in the configuration.
		"/var/www/html":               {"apache:/etc/apache2/sites-enabled/000-default.conf"},
		"/data/static site":           {"apache:/etc/apache2/sites-enabled/vwoods.conf"},
		"/data/level2":                {"apache:/etc/apache2/extra/level2.conf"},
		"/data/shop/public":           {"nginx:/etc/nginx/sites-enabled/shop"},
		"/data/laravel":               {"nginx:/etc/nginx/conf.d/laravel.conf"}, // public/'s parent has the manifest
		"/data/rel/releases/3/public": {"nginx:/etc/nginx/sites-enabled/shop"},
	}
	if !full || !reflect.DeepEqual(got, want) {
		var dirs []string
		for d, by := range got {
			dirs = append(dirs, d+" "+strings.Join(by, ","))
		}
		sort.Strings(dirs)
		t.Errorf("discovered (full %v):\n%s", full, strings.Join(dirs, "\n"))
	}
}

// Plain PHP and HTML sites have no manifest: an index file marks them,
// except where it says nothing about a site.
func TestDiscoverWebRoots(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"site with a Composer project inside", map[string]string{
			"var/www/vwoods.in/public/index.php":          "<?php",
			"var/www/vwoods.in/public/mail/composer.lock": `{"packages":[]}`,
		}, []string{"/var/www/vwoods.in/public"}},
		{"index.htm", map[string]string{"srv/old/index.htm": "<html>"}, []string{"/srv/old"}},
		{"not in a base itself", map[string]string{"var/www/index.html": "<html>", "home/deploy/index.php": "<?php",
			"var/www/shop/package.json": "{}"}, []string{"/var/www/shop"}},
		{"distribution default page", map[string]string{
			"var/www/html/index.html":               "<title>Apache2 Ubuntu Default Page: It works</title>",
			"var/www/html/phpmyadmin/composer.json": "{}",
		}, []string{"/var/www/html/phpmyadmin"}},
		{"default page next to a PHP index", map[string]string{
			"var/www/html/index.html": "<h1>It works!</h1>", "var/www/html/index.php": "<?php",
		}, []string{"/var/www/html"}},
		{"documentation and examples", map[string]string{"opt/tool/docs/index.html": "<html>", "opt/tool/doc/html/index.html": "<html>",
			"srv/lib/examples/index.php": "<?php"}, nil},
		{"WordPress plugins are part of the site", map[string]string{
			"var/www/wp/wp-config.php":                           "<?php",
			"var/www/wp/wp-content/plugins/forms/index.php":      "<?php",
			"var/www/wp/wp-content/plugins/mailer/composer.json": "{}",
		}, []string{"/var/www/wp"}},
		{"a manifest still wins", map[string]string{"srv/app/package.json": "{}", "srv/app/index.html": "<html>"}, []string{"/srv/app"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTree(t)
			for p, data := range tc.files {
				tr.file(p, data)
			}
			got := (&Scanner{Root: tr.root}).Discover()
			sort.Strings(got)
			if len(got) != len(tc.want) || len(got) > 0 && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("discovered %v, want %v", got, tc.want)
			}
		})
	}
	// An index file reached through a link is not a marker, and a linked
	// directory is not entered.
	tr := newTree(t)
	tr.file("elsewhere/index.php", "<?php")
	tr.link("var/www/site/index.php", "../../../elsewhere/index.php")
	tr.link("var/www/linked", "../../elsewhere")
	if got := (&Scanner{Root: tr.root}).Discover(); len(got) != 0 {
		t.Errorf("followed links: %v", got)
	}
}

// The vwoods.in layout end to end: the site at public/ is one application,
// with its copied jQuery and Bootstrap and the Composer project under
// mail/ as part of it; the default page yields no libraries.
func TestWebRootSiteInventory(t *testing.T) {
	tr := webHost(t)
	s := &Scanner{Root: tr.root}
	s.Apps = s.Discover()
	n := 0
	for _, d := range s.Apps {
		if strings.HasPrefix(d, "/var/www/vwoods.in") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("vwoods.in should be one application: %v", s.Apps)
	}
	app := s.ScanApp(context.Background(), "/var/www/vwoods.in/public")
	m := purls(app.Observations)
	for _, w := range []string{"pkg:npm/jquery@2.2.1", "pkg:npm/bootstrap@3.3.6", "pkg:composer/sendgrid/sendgrid@5.6.2", "pkg:composer/sendgrid/php-http-client@3.9.6"} {
		if _, ok := m[w]; !ok {
			t.Errorf("missing %s; have %v", w, keys(m))
		}
	}
	if o := m["pkg:npm/jquery@2.2.1"]; o.Evidence["source"] != "vendored" || o.Location != "/var/www/vwoods.in/public/js/jquery-2.2.1.min.js" {
		t.Errorf("jquery = %+v", o)
	}
	validate(t, app)

	// The default page has nothing to report, and phpMyAdmin below it is
	// reported once, by itself.
	if def := s.ScanApp(context.Background(), "/var/www/html"); len(def.Observations) != 0 {
		t.Errorf("default page reported %v", keys(purls(def.Observations)))
	}
	if pma := purls(s.ScanApp(context.Background(), "/var/www/html/phpmyadmin").Observations); len(pma) != 1 {
		t.Errorf("phpmyadmin = %v", keys(pma))
	}
	// A site only the configuration names is read like any other.
	if insta := purls(s.ScanApp(context.Background(), "/var/www/insta-solutions.com/public").Observations); len(insta) != 1 {
		t.Errorf("insta-solutions.com = %v", keys(insta))
	}
}

// Configuration is bounded: files beyond maxConfFiles per web server,
// and includes more than maxIncludeDepth levels down, are not read, and
// discovery then says it did not see everything. One web server's many
// files do not keep the other's from being read.
func TestConfigRootsBounded(t *testing.T) {
	tr := newTree(t)
	for i := range maxConfFiles + 10 {
		tr.file(fmt.Sprintf("etc/apache2/sites-enabled/s%03d.conf", i), "DocumentRoot /srv/x\n")
	}
	tr.file("etc/nginx/conf.d/shop.conf", "server { root /data/shop; }")
	tr.file("data/shop/index.php", "<?php")
	s := &Scanner{Root: tr.root}
	got, complete := s.configRoots()
	if len(got) != maxConfFiles+1 || complete {
		t.Errorf("read %d roots, complete %v", len(got), complete)
	}
	found, full := s.DiscoverSites()
	if full || len(found) != 1 || found[0].Dir != "/data/shop" {
		t.Errorf("discovered %v (full %v)", found, full)
	}
	// Within the limits everything is read, and discovery is complete.
	tr = newTree(t)
	tr.file("etc/nginx/nginx.conf", "include nginx.conf; root /srv/x;") // a file including itself is read once
	if got, complete := (&Scanner{Root: tr.root}).configRoots(); len(got) != 1 || !complete {
		t.Errorf("self include: %v (complete %v)", got, complete)
	}
	if _, full := (&Scanner{Root: tr.root}).DiscoverSites(); !full {
		t.Error("discovery within the limits is not full")
	}
	// A file larger than maxConfSize is read in part.
	tr = newTree(t)
	tr.file("etc/nginx/nginx.conf", "root /srv/x;\n"+strings.Repeat("#", maxConfSize))
	if got, complete := (&Scanner{Root: tr.root}).configRoots(); len(got) != 1 || complete {
		t.Errorf("large file: %v (complete %v)", got, complete)
	}
}

// Below a site found by its index file, other applications stay their own
// (a WordPress blog, an app with a virtual host of its own, a cPanel addon
// domain); a project with only a manifest is part of the site. Index files
// do not count in any discovery base, however it is reached.
func TestDiscoverInsideSites(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"apps under a custom /var/www/html", map[string]string{
			"var/www/html/index.php":            "<?php",
			"var/www/html/app/composer.json":    `{"name":"acme/app"}`,
			"var/www/html/app/public/index.php": "<?php",
			"etc/nginx/conf.d/app.conf":         "server { root /var/www/html/app/public; }",
			"var/www/html/blog/wp-config.php":   "<?php",
			"var/www/html/mail/composer.lock":   `{"packages":[]}`,
			"var/www/html/admin/index.php":      "<?php",
			"var/www/html/pma/index.php":        "<?php",
			"var/www/html/pma/composer.json":    `{"name":"phpmyadmin/phpmyadmin"}`,
		}, []string{"/var/www/html", "/var/www/html/app", "/var/www/html/blog", "/var/www/html/pma"}},
		{"cPanel addon domains", map[string]string{
			"home/u/public_html/index.php":                    "<?php",
			"home/u/public_html/addon.com/index.php":          "<?php",
			"home/u/public_html/sub/index.php":                "<?php",
			"etc/apache2/sites-enabled/addon.conf":            "DocumentRoot /home/u/public_html/addon.com\n",
			"home/u/public_html/addon.com/deep/x/a/index.php": "<?php",
			"etc/apache2/sites-enabled/deep.conf":             "DocumentRoot /home/u/public_html/addon.com/deep/x/a\nAlias /img /home/u/public_html/img\n",
			"home/u/public_html/img/a.png":                    "",
		}, []string{"/home/u/public_html", "/home/u/public_html/addon.com", "/home/u/public_html/addon.com/deep/x/a"}},
		{"a home's www is a base", map[string]string{
			"home/alice/www/index.php":           "<?php",
			"home/alice/www/site1/wp-config.php": "<?php",
			"home/alice/www/site2/composer.json": `{"name":"acme/site2"}`,
		}, []string{"/home/alice/www/site1", "/home/alice/www/site2"}},
		{"a manifest still ends the walk", map[string]string{
			"srv/shop/package.json":        `{"name":"shop"}`,
			"srv/shop/public/index.html":   "<html>",
			"srv/shop/admin/wp-config.php": "<?php",
		}, []string{"/srv/shop"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTree(t)
			for p, data := range tc.files {
				tr.file(p, data)
			}
			got := (&Scanner{Root: tr.root}).Discover()
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("discovered %v, want %v", got, tc.want)
			}
		})
	}
	// The site's scan leaves the applications inside it to themselves.
	tr := newTree(t)
	tr.file("var/www/html/index.php", `<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>`)
	tr.file("var/www/html/blog/wp-config.php", "<?php")
	tr.file("var/www/html/blog/index.php", `<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>`)
	s := &Scanner{Root: tr.root}
	s.Apps = s.Discover()
	if m := purls(s.ScanApp(context.Background(), "/var/www/html").Observations); len(m) != 1 {
		t.Errorf("site = %v", keys(m))
	}
	if m := purls(s.ScanApp(context.Background(), "/var/www/html/blog").Observations); len(m) != 1 {
		t.Errorf("blog = %v", keys(m))
	}
}
