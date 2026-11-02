package apps

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// Built at run time so that no key-shaped string is committed.
var testToken = "gh" + "p_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, data := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func secretPlaces(t *testing.T, s *Scanner, dir string) []string {
	t.Helper()
	app := s.ScanApp(context.Background(), dir)
	if app.Secrets == nil {
		t.Fatal("no secret scan")
	}
	var out []string
	for _, f := range app.Secrets.Findings {
		if f.Exposure != "public" || f.Severity != "critical" {
			t.Errorf("%s: %s %s", f.Location, f.Exposure, f.Severity)
		}
		out = append(out, f.Location)
	}
	sort.Strings(out)
	return out
}

// Only files the web server sends as they are count: a front-end build, a
// .env or backup in a site's document root. The application's own
// configuration outside them is where credentials belong.
func TestServedSecrets(t *testing.T) {
	root := t.TempDir()
	token := "TOKEN=" + testToken + "\n"
	writeFiles(t, root, map[string]string{
		// A Laravel-style application: the document root is public/.
		"srv/shop/.env":                     token,
		"srv/shop/config/services.php":      "<?php return ['t' => '" + testToken + "'];",
		"srv/shop/public/index.php":         "<?php",
		"srv/shop/public/js/app.js":         "const t='" + testToken + "';",
		"srv/shop/public/js/app.js.map":     `{"sourcesContent":["const t='` + testToken + `'"]}`,
		"srv/shop/dist/server.js":           "const t='" + testToken + "';", // compiled server code: no index.html
		"srv/shop/storage/logs/laravel.log": token,
		// A static site served from its own directory.
		"var/www/site/index.html":           "<html>",
		"var/www/site/.env":                 token,
		"var/www/site/backup.sql":           "INSERT INTO t VALUES ('" + testToken + "');",
		"var/www/site/wp-config.php":        "<?php define('T', '" + testToken + "');",
		"var/www/site/.git/config":          token,
		"var/www/site/node_modules/x/a.js":  "const t='" + testToken + "';",
		"var/www/site/build/index.html":     "<html>",
		"var/www/site/build/static/main.js": "const t='" + testToken + "';",
	})
	s := &Scanner{Root: root}
	got := secretPlaces(t, s, "/srv/shop")
	want := []string{"public/js/app.js", "public/js/app.js.map"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("shop: got %v, want %v", got, want)
	}
	got = secretPlaces(t, s, "/var/www/site")
	want = []string{".env", "backup.sql", "build/static/main.js"}
	if len(got) != len(want) {
		t.Fatalf("site: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("site: got %v, want %v", got, want)
		}
	}
}
