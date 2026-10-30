//go:build unix

package apps

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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

func permissionGap(t *testing.T, a App) model.CoverageItem {
	t.Helper()
	var found []model.CoverageItem
	for _, c := range a.Coverage {
		if strings.HasPrefix(c.Scope, PermissionScope) {
			found = append(found, c)
		}
		if strings.Contains(c.Reason, "permission denied") && !strings.HasPrefix(c.Scope, PermissionScope) {
			t.Errorf("permission error listed on its own: %+v", c)
		}
	}
	if len(found) != 1 || found[0].Status != "unsupported" || found[0].Scope != PermissionScope+a.Dir || !a.Unreadable() {
		t.Fatalf("want one unsupported %s item, coverage %+v", PermissionScope, a.Coverage)
	}
	return found[0]
}

func TestUnreadableFiles(t *testing.T) {
	for _, tc := range []struct {
		name   string
		setup  func(tr *tree)
		reason string // the start of the item's reason
		more   int    // further paths counted
		want   []string
	}{
		{"app directory", func(tr *tree) { tr.unreadable("var/www/site") }, "cannot read /var/www/site: permission denied (agent runs as ", 0, nil},
		{"js directory", func(tr *tree) { tr.unreadable("var/www/site/js") }, "cannot read /var/www/site/js: ", 0,
			[]string{"pkg:npm/bootstrap@3.3.6"}},
		{"a file that cannot be opened", func(tr *tree) { tr.unreadable("var/www/site/js/jquery.min.js") }, "cannot read /var/www/site/js/jquery.min.js: ", 0,
			[]string{"pkg:npm/bootstrap@3.3.6"}},
		{"a lockfile and many files, counted", func(tr *tree) {
			for i := range 40 {
				tr.file(fmt.Sprintf("var/www/site/lib/f%02d.js", i), "x")
				tr.unreadable(fmt.Sprintf("var/www/site/lib/f%02d.js", i))
			}
			tr.unreadable("var/www/site/mail/composer.lock")
		}, "cannot read /var/www/site/lib/f00.js: ", 40, []string{"pkg:npm/bootstrap@3.3.6", "pkg:npm/jquery@2.2.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTree(t)
			tr.file("var/www/site/index.php", "<?php")
			tr.file("var/www/site/js/jquery.min.js", "/*! jQuery v2.2.1 | (c) jQuery Foundation */\n")
			tr.file("var/www/site/bootstrap.min.js", "/*!\n * Bootstrap v3.3.6\n */\n")
			tr.file("var/www/site/mail/composer.lock", `{"packages":[{"name":"sendgrid/sendgrid","version":"5.6.2"}]}`)
			tc.setup(tr)
			a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/var/www/site")
			c := permissionGap(t, a)
			if !strings.HasPrefix(c.Reason, tc.reason) {
				t.Errorf("reason %q", c.Reason)
			}
			if more := fmt.Sprintf("; %d more paths", tc.more); tc.more > 0 != strings.Contains(c.Reason, more) {
				t.Errorf("reason %q, want %d more", c.Reason, tc.more)
			}
			m := purls(a.Observations)
			for _, w := range tc.want {
				if _, ok := m[w]; !ok {
					t.Errorf("missing %s; have %v", w, keys(m))
				}
			}
			validate(t, a)
		})
	}
	// Nothing unreadable: no item.
	tr := newTree(t)
	tr.file("var/www/site/index.php", "<?php")
	if a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/var/www/site"); a.Unreadable() {
		t.Errorf("coverage %+v", a.Coverage)
	}
}

// Discovery reports a site it may not read, from the walk and from the
// web server configuration, instead of missing it.
func TestDiscoverUnreadable(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/vwoods.in/public/index.php", "<?php")
	tr.file("var/www/open/index.php", "<?php")
	tr.file("opt/containerd/bin/x", "")
	tr.file("home/site/public_html/index.php", "<?php")
	tr.file("etc/nginx/conf.d/site.conf", "server { root /home/site/public_html; }")
	tr.unreadable("var/www/vwoods.in")
	tr.unreadable("opt/containerd")
	tr.unreadable("home/site")
	s := &Scanner{Root: tr.root}
	found, _ := s.DiscoverSites()
	got := map[string]string{}
	for _, d := range found {
		got[d.Dir] = strings.Join(d.By, ",")
	}
	want := map[string]string{
		"/var/www/open":          "index.php",
		"/var/www/vwoods.in":     "unreadable",
		"/home/site/public_html": "nginx:/etc/nginx/conf.d/site.conf",
	}
	if len(got) != len(want) {
		t.Fatalf("discovered %v", got)
	}
	for d, by := range want {
		if got[d] != by {
			t.Errorf("%s: %q, want %q (all %v)", d, got[d], by, got)
		}
	}
	for _, d := range []string{"/var/www/vwoods.in", "/home/site/public_html"} {
		if c := permissionGap(t, s.ScanApp(context.Background(), d)); !strings.Contains(c.Reason, "cannot read "+d+":") {
			t.Errorf("%s: %q", d, c.Reason)
		}
	}
}
