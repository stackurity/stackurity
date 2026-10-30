//go:build unix

package apps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// unreadable takes all permissions from p under the tree until the test
// ends. Root reads everything, so the tests are skipped under root.
func (tr *tree) unreadable(p string) {
	tr.t.Helper()
	if os.Geteuid() == 0 {
		tr.t.Skip("permissions do not apply to root")
	}
	full := filepath.Join(tr.root, p)
	if err := os.Chmod(full, 0); err != nil {
		tr.t.Fatal(err)
	}
	tr.t.Cleanup(func() { os.Chmod(full, 0o755) })
}

func permissionGap(t *testing.T, a App, status string) model.CoverageItem {
	t.Helper()
	var found []model.CoverageItem
	for _, c := range a.Coverage {
		if strings.HasPrefix(c.Scope, PermissionScope) {
			found = append(found, c)
		}
		if strings.Contains(c.Reason, "permission denied") && !strings.HasPrefix(c.Scope, PermissionScope) &&
			!strings.HasPrefix(c.Scope, "npm-installed:") {
			t.Errorf("permission error listed on its own: %+v", c)
		}
	}
	if len(found) != 1 || found[0].Status != status || found[0].Scope != PermissionScope+a.Dir {
		t.Fatalf("want one %s %s item, coverage %+v", status, PermissionScope, a.Coverage)
	}
	return found[0]
}

func TestUnreadableFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(tr *tree)
		status string // of the item; "" for none
		root   bool   // App.Unreadable
		reason string // the start of the item's reason
		more   int    // further paths counted
		want   []string
	}{
		{"app directory", func(tr *tree) { tr.unreadable("var/www/site") }, "unsupported", true,
			"cannot read /var/www/site: permission denied (agent runs as ", 0, nil},
		{"js directory", func(tr *tree) { tr.unreadable("var/www/site/js") }, "partial", false, "cannot read /var/www/site/js: ", 0,
			[]string{"pkg:npm/bootstrap@3.3.6"}},
		{"a file that cannot be opened", func(tr *tree) { tr.unreadable("var/www/site/js/jquery.min.js") }, "partial", false,
			"cannot read /var/www/site/js/jquery.min.js: ", 0, []string{"pkg:npm/bootstrap@3.3.6"}},
		{"a lockfile and many files, counted", func(tr *tree) {
			for i := range 40 {
				tr.file(fmt.Sprintf("var/www/site/lib/f%02d.js", i), "x")
				tr.unreadable(fmt.Sprintf("var/www/site/lib/f%02d.js", i))
			}
			tr.unreadable("var/www/site/mail/composer.lock")
		}, "unsupported", false, "cannot read /var/www/site/lib/f00.js: ", 40, []string{"pkg:npm/bootstrap@3.3.6", "pkg:npm/jquery@2.2.1"}},
		{"node_modules", func(tr *tree) {
			tr.npm("var/www/site/node_modules/lodash", "lodash", "4.17.20")
			tr.unreadable("var/www/site/node_modules")
		}, "unsupported", false, "cannot read /var/www/site/node_modules: ", 0, nil},
		// Hardened WordPress: wp-config.php and .env are not readable by
		// others, and nothing reads them; neither are uploads or a cache.
		{"files nothing reads", func(tr *tree) {
			tr.file("var/www/site/wp-config.php", "<?php")
			tr.file("var/www/site/.env", "APP_KEY=x")
			tr.file("var/www/site/wp-content/uploads/2024/a.php", "<?php")
			tr.file("var/www/site/wp-content/cache/page.html", "<html>")
			tr.file("var/www/site/logs/x.log", "")
			tr.unreadable("var/www/site/wp-config.php")
			tr.unreadable("var/www/site/.env")
			tr.unreadable("var/www/site/wp-content/uploads")
			tr.unreadable("var/www/site/wp-content/cache")
			tr.unreadable("var/www/site/logs")
		}, "", false, "", 0, []string{"pkg:npm/bootstrap@3.3.6", "pkg:npm/jquery@2.2.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTree(t)
			tr.file("var/www/site/index.php", "<?php")
			tr.file("var/www/site/js/jquery.min.js", "/*! jQuery v2.2.1 | (c) jQuery Foundation */\n")
			tr.file("var/www/site/bootstrap.min.js", "/*!\n * Bootstrap v3.3.6\n */\n")
			tr.file("var/www/site/mail/composer.lock", `{"packages":[{"name":"sendgrid/sendgrid","version":"5.6.2"}]}`)
			tc.setup(tr)
			a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/var/www/site")
			if a.Unreadable != tc.root {
				t.Errorf("Unreadable = %v", a.Unreadable)
			}
			m := purls(a.Observations)
			for _, w := range tc.want {
				if _, ok := m[w]; !ok {
					t.Errorf("missing %s; have %v", w, keys(m))
				}
			}
			validate(t, a)
			if tc.status == "" {
				for _, c := range a.Coverage {
					if strings.HasPrefix(c.Scope, PermissionScope) || c.Status == "failed" {
						t.Errorf("coverage %+v", c)
					}
				}
				return
			}
			c := permissionGap(t, a, tc.status)
			if !strings.HasPrefix(c.Reason, tc.reason) {
				t.Errorf("reason %q", c.Reason)
			}
			if more := fmt.Sprintf("; %d more paths", tc.more); tc.more > 0 != strings.Contains(c.Reason, more) {
				t.Errorf("reason %q, want %d more", c.Reason, tc.more)
			}
		})
	}
}

// Discovery reports a site it may not read, from the walk and from the
// web server configuration, instead of missing it; other directories only
// their owner may list are not sites.
func TestDiscoverUnreadable(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/vwoods.in/public/index.php", "<?php")
	tr.file("var/www/open/index.php", "<?php")
	tr.file("var/www/group/deep/x", "")
	tr.file("opt/containerd/bin/x", "")
	tr.file("srv/lost+found/x", "")
	tr.file("home/bob/Maildir/new/x", "")
	tr.file("home/bob/public_html/index.php", "<?php")
	tr.file("home/site/public_html/index.php", "<?php")
	tr.file("etc/nginx/conf.d/site.conf", "server { root /home/site/public_html; }")
	for _, p := range []string{"var/www/vwoods.in", "var/www/group/deep", "opt/containerd", "srv/lost+found", "home/bob/Maildir",
		"home/bob/public_html", "home/site"} {
		tr.unreadable(p)
	}
	s := &Scanner{Root: tr.root}
	found, _ := s.DiscoverSites()
	got := map[string]string{}
	for _, d := range found {
		got[d.Dir] = strings.Join(d.By, ",")
	}
	want := map[string]string{
		"/var/www/open":          "index.php",
		"/var/www/vwoods.in":     "unreadable",
		"/home/bob/public_html":  "unreadable",
		"/home/site/public_html": "nginx:/etc/nginx/conf.d/site.conf",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("discovered %v, want %v", got, want)
	}
	for _, d := range []string{"/var/www/vwoods.in", "/home/site/public_html"} {
		a := s.ScanApp(context.Background(), d)
		if c := permissionGap(t, a, "unsupported"); !strings.Contains(c.Reason, "cannot read "+d+":") || !a.Unreadable {
			t.Errorf("%s: %q", d, c.Reason)
		}
	}
	// A tool under /opt with one directory only root may read is not an
	// application the agent may not read.
	tr.file("opt/tool/package.json", `{"name":"tool"}`)
	tr.file("opt/tool/secret/x", "")
	tr.unreadable("opt/tool/secret")
	if a := s.ScanApp(context.Background(), "/opt/tool"); a.Unreadable || len(a.Observations) != 0 {
		t.Errorf("/opt/tool: unreadable %v, %v", a.Unreadable, a.Coverage)
	}
}

// A configuration file the agent may not read leaves the list of sites
// incomplete.
func TestUnreadableConfig(t *testing.T) {
	tr := newTree(t)
	tr.file("etc/nginx/conf.d/a.conf", "server { root /srv/a; }")
	tr.file("etc/nginx/conf.d/b.conf", "server { root /srv/b; }")
	tr.unreadable("etc/nginx/conf.d/b.conf")
	s := &Scanner{Root: tr.root}
	if got, complete := s.configRoots(); len(got) != 1 || complete {
		t.Errorf("roots %v, complete %v", got, complete)
	}
	if _, full := s.DiscoverSites(); full {
		t.Error("discovery is full")
	}
}

// Credentials files a CMS keeps from other users are not gaps.
func TestUnreadableSecrets(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php")
	tr.file("var/www/site/sites/default/settings.php", "<?php")
	tr.file("var/www/site/configuration.php", "<?php")
	tr.unreadable("var/www/site/sites/default/settings.php")
	tr.unreadable("var/www/site/configuration.php")
	for _, c := range (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/var/www/site").Coverage {
		if strings.HasPrefix(c.Scope, PermissionScope) {
			t.Errorf("coverage %+v", c)
		}
	}
}
