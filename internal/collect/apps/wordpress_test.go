package apps

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// versionPHP is the head of a real wp-includes/version.php.
func versionPHP(assign string) string {
	return "<?php\n/**\n * WordPress Version\n *\n * Contains version information for the current WordPress release.\n *\n" +
		" * @package WordPress\n * @since 1.2.0\n */\n\n/**\n * The WordPress version string.\n *\n" +
		" * Holds the current version number for WordPress core. Used to bust caches\n" +
		" * and to enable development mode for scripts when running from the /src directory.\n *\n" +
		" * @global string $wp_version\n */\n" + assign + "\n\n/**\n * Holds the WordPress DB revision, increments when changes are made to the WordPress DB schema.\n" +
		" *\n * @global int $wp_db_version\n */\n$wp_db_version = 58975;\n"
}

func TestParseWPVersion(t *testing.T) {
	for assign, want := range map[string]string{
		"$wp_version = '6.8.1';":               "6.8.1",
		"$wp_version = '6.5';":                 "6.5",
		"$wp_version = '6.5-RC1';":             "6.5-RC1",
		"$wp_version = '6.6-beta2';":           "6.6-beta2",
		"$wp_version = '6.7-alpha-58576-src';": "6.7-alpha-58576-src",
		"\t$wp_version=\"4.6.3\" ;":            "4.6.3",
		// PHP runs the last assignment; commented-out ones are not code.
		"/*\n$wp_version = '3.0';\n*/\n$wp_version = '6.8.1';": "6.8.1",
		"$wp_version = '6.8.1';\n/*\n$wp_version = '3.0';\n*/": "6.8.1",
		"$wp_version = '6.8.1';\n// $wp_version = '3.0';":      "6.8.1",
		"$wp_version = '6.8.1';\n# $wp_version = '3.0';":       "6.8.1",
		"$wp_version = '6.5.3';\n$wp_version = '6.5.14';":      "6.5.14",
		"$wp_version = '6.8.1';\n$wp_version = 'unknown';":     "",
		// Not a release WordPress writes, or not the assignment itself.
		"$wp_version = '6';":                                 "",
		"$wp_version = 'latest';":                            "",
		"$wp_version = '6.4.2 or so';":                       "",
		"$wp_version = $other;":                              "",
		"// $wp_version = '6.4.2';":                          "",
		"$wp_version_old = '6.4.2';":                         "",
		"$wp_version = '" + strings.Repeat("6.", 40) + "1';": "",
	} {
		got, ok := parseWPVersion([]byte(versionPHP(assign)))
		if got != want || ok != (want != "") {
			t.Errorf("%s = %q %v, want %q", assign, got, ok, want)
		}
	}
}

// Sites at a supported and at an ended WordPress release, and pre-release
// and development builds, report their core as pkg:generic/wordpress, read
// from wp-includes/version.php with confirmed confidence.
func TestWordPressCoreVersion(t *testing.T) {
	tr := newTree(t)
	sites := map[string]string{
		"var/www/current": "6.8.1",
		"var/www/old":     "4.6.3",
		"var/www/next":    "6.9-RC1",
		"var/www/dev":     "7.2-alpha-61234-src",
	}
	for dir, v := range sites {
		tr.file(dir+"/wp-config.php", "<?php define('DB_NAME', 'wp');")
		tr.file(dir+"/wp-includes/version.php", versionPHP("$wp_version = '"+v+"';"))
	}
	s := &Scanner{Root: tr.root}
	for dir, v := range sites {
		a := s.ScanApp(context.Background(), "/"+dir)
		var core []model.Observation
		for _, o := range a.Observations {
			if strings.HasPrefix(o.Purl, "pkg:generic/") {
				core = append(core, o)
			}
		}
		if len(core) != 1 {
			t.Fatalf("%s: %+v", dir, a.Observations)
		}
		o := core[0]
		if o.Purl != "pkg:generic/wordpress@"+v || o.Version != v || o.Location != "/"+dir+"/wp-includes/version.php" ||
			o.Confidence != model.ConfidenceConfirmed || o.Evidence["kind"] != KindCMS || o.Evidence["product"] != "WordPress core" ||
			o.Evidence["source"] != "version-file" || o.Evidence["app_dir"] != "/"+dir {
			t.Errorf("%s: %+v", dir, o)
		}
		validate(t, a)
	}
}

// version.php is read only as a regular file, in a real wp-includes
// directory, within its first 8 KB, and not when an OS package installed
// it; a WordPress install that is an application of its own is reported by
// that application only.
func TestWordPressCoreNotRead(t *testing.T) {
	tr := newTree(t)
	tr.file("secret/wp-includes/version.php", versionPHP("$wp_version = '1.0.0';"))
	tr.file("srv/linked-file/wp-includes/js/x.js", "")
	tr.link("srv/linked-file/wp-includes/version.php", tr.root+"/secret/wp-includes/version.php")
	tr.link("srv/linked-dir/wp-includes", tr.root+"/secret/wp-includes")
	tr.file("srv/padded/wp-includes/version.php", "<?php\n"+strings.Repeat("// padding\n", 1000)+"$wp_version = '6.8.1';\n")
	tr.file("srv/garbled/wp-includes/version.php", "<?php\n$wp_version = '6.8.1\x00';\n")
	tr.file("usr/share/wordpress/wp-includes/version.php", versionPHP("$wp_version = '6.1.1';"))
	tr.file("srv/outer/wp-config.php", "<?php")
	tr.file("srv/outer/blog/wp-includes/version.php", versionPHP("$wp_version = '6.8.1';"))
	s := &Scanner{Root: tr.root, Owned: func(p string) bool { return strings.HasPrefix(p, "/usr/share/wordpress/") },
		Apps: []string{"/srv/outer", "/srv/outer/blog"}}
	for _, dir := range []string{"/srv/linked-file", "/srv/linked-dir", "/srv/padded", "/srv/garbled", "/usr/share/wordpress", "/srv/outer"} {
		for _, o := range s.ScanApp(context.Background(), dir).Observations {
			if strings.HasPrefix(o.Purl, "pkg:generic/wordpress") {
				t.Errorf("%s: reported %s from %s", dir, o.Purl, o.Location)
			}
		}
	}
	if _, ok := purls(s.ScanApp(context.Background(), "/srv/outer/blog").Observations)["pkg:generic/wordpress@6.8.1"]; !ok {
		t.Error("/srv/outer/blog: WordPress core missing")
	}
}
