//go:build unix

package apps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// Keys are assembled at run time so this file is not itself reported.
var (
	testStripe = strings.Join([]string{"sk", "_live_", "51HqT9xK2mLr8VbN4cWzP7yJd3"}, "")
	testGoogle = strings.Join([]string{"AIza", "SyC8mQ2xL7vB4nR8wZ3cY6pH1jF5dG0sA2e"}, "")
)

func TestLeaks(t *testing.T) {
	tr := newTree(t)
	tr.file("etc/nginx/sites-enabled/shop", "server { root /var/www/shop/public; }\n")
	tr.file("var/www/shop/.env", "DB_PASSWORD=Kq7v9Lm2xZ!\n")
	tr.file("var/www/shop/config/secrets.yml", "api_token: Rt5#wq9Zp2Lm\n")
	tr.file("var/www/shop/public/.env", "DB_PASSWORD=Kq7v9Lm2xZ!\n")
	tr.file("var/www/shop/public/index.php", "<?php $stripe = '"+testStripe+"';\n")
	tr.file("var/www/shop/public/js/maps.js", "var k = '"+testGoogle+"';\n")
	tr.file("var/www/shop/public/wp-config.php.bak", "define('DB_PASSWORD', 'Rt5#wq9Zp2');\n")
	tr.file("var/www/shop/admin/.env", "DB_PASSWORD=Kq7v9Lm2xZ!\n") // its own application
	if err := os.Chmod(filepath.Join(tr.root, "var/www/shop/config/secrets.yml"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &Scanner{Root: tr.root, Apps: []string{"/var/www/shop", "/var/www/shop/admin"}}
	scan := s.Leaks(context.Background(), "/var/www/shop")
	if !scan.Complete {
		t.Fatalf("scan %+v", scan)
	}
	got := map[string]string{}
	for _, l := range scan.Found {
		got[l.Path] = l.Severity + " " + l.Exposure
	}
	want := map[string]string{
		"/var/www/shop/.env":                     "medium world_readable",   // where it belongs, but any account can read it
		"/var/www/shop/config/secrets.yml":       "low ",                    // where it belongs
		"/var/www/shop/public/.env":              "critical served",         // anyone may download it
		"/var/www/shop/public/index.php":         "critical world_readable", // run as PHP, but a live key in code
		"/var/www/shop/public/js/maps.js":        "critical served",
		"/var/www/shop/public/wp-config.php.bak": "critical served", // a copy is sent as text
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for p, w := range want {
		if got[p] != w {
			t.Errorf("%s: got %q, want %q", p, got[p], w)
		}
	}
	b := model.NewBatch(model.Collector{ID: "linux-apps"}, model.AssetRef{Kind: model.AssetApplication, Name: "shop",
		Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: "/var/www/shop"}}})
	b.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: "m"}}}}
	b.Leaks = scan
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}
