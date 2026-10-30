package apps

import (
	"context"
	"fmt"
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

// Plugins, must-use plugins and themes are read from their header comment,
// as WordPress reads them, and reported by slug; those not updated from
// wordpress.org say why.
func TestWordPressPluginsAndThemes(t *testing.T) {
	tr := newTree(t)
	wp := "var/www/shop"
	tr.file(wp+"/wp-config.php", "<?php")
	tr.file(wp+"/wp-includes/version.php", versionPHP("$wp_version = '6.8.1';"))
	pl := wp + "/wp-content/plugins/"
	// A WooCommerce-like plugin: its main file is <slug>.php; other
	// top-level files have no header.
	tr.file(pl+"woocommerce/includes/class-wc.php", "<?php\n/**\n * Plugin Name: Not The Main File\n * Version: 0.0.1\n */")
	tr.file(pl+"woocommerce/uninstall.php", "<?php // nothing")
	tr.file(pl+"woocommerce/woocommerce.php", "<?php\r\n/**\r\n * Plugin Name: WooCommerce\r\n * Plugin URI: https://woocommerce.com/\r\n"+
		" * Description: An ecommerce toolkit.\r\n * Version: 9.9.5\r\n * Author: Automattic\r\n * Requires at least: 6.6\r\n */")
	// A single-file plugin, and one whose main file is not named after it.
	tr.file(pl+"hello.php", "<?php\n/*\nPlugin Name: Hello Dolly\nVersion: 1.7.2\n*/")
	tr.file(pl+"classic-editor/main.php", "<?php\n/**\n * Plugin Name:  Classic Editor \n * Version:      1.6.7 */")
	// A premium plugin updated from its vendor, one that turns updates off,
	// and one that names wordpress.org.
	tr.file(pl+"acme-pro/acme-pro.php", "<?php\n/**\n * Plugin Name: Acme Pro\n * Version: 3.2.1\n * Update URI: https://updates.acme.example/acme-pro\n */")
	tr.file(pl+"in-house/in-house.php", "<?php\n/* Plugin Name: In House\n * Version: 2.0\n * Update URI: false */")
	tr.file(pl+"akismet/akismet.php", "<?php\n/* Plugin Name: Akismet Anti-spam: Spam Protection\n * Version: 5.3\n * Update URI: https://wordpress.org/plugins/akismet/ */")
	// A folder name wordpress.org would not use.
	tr.file(pl+"My_Custom/My_Custom.php", "<?php\n/* Plugin Name: Mine\n * Version: 1.0.0 */")
	// Not plugins: no header, no version, a header past 8 KB, a link.
	tr.file(pl+"assets-only/readme.txt", "Plugin Name: Nope\nVersion: 1.0")
	tr.file(pl+"no-version/no-version.php", "<?php\n/* Plugin Name: No Version */")
	tr.file(pl+"padded/padded.php", "<?php\n"+strings.Repeat("// padding\n", 1000)+"/* Plugin Name: Padded\n * Version: 1.0 */")
	tr.file("srv/elsewhere/elsewhere.php", "<?php\n/* Plugin Name: Elsewhere\n * Version: 1.0 */")
	tr.link(pl+"linked", tr.root+"/srv/elsewhere")
	// Must-use plugins: only top-level files load.
	tr.file(wp+"/wp-content/mu-plugins/loader.php", "<?php\n/* Plugin Name: Site Loader\n * Version: 1.0.0 */")
	tr.file(wp+"/wp-content/mu-plugins/sub/inner.php", "<?php\n/* Plugin Name: Inner\n * Version: 1.0.0 */")
	// Themes, a child theme, and a theme folder without style.css.
	tr.file(wp+"/wp-content/themes/astra/style.css", "/*\nTheme Name: Astra\nVersion: 4.6.0\nRequires PHP: 5.3\n*/\nbody{}")
	tr.file(wp+"/wp-content/themes/astra-child/style.css", "/*\n Theme Name: Astra Child\n Template: astra\n Version: 1.0.0\n*/")
	tr.file(wp+"/wp-content/themes/broken/index.php", "<?php")

	a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/"+wp)
	got := map[string]model.Observation{}
	for _, o := range a.Observations {
		if strings.HasPrefix(o.Purl, "pkg:generic/wordpress-") {
			got[o.Purl] = o
		}
	}
	want := map[string]struct{ name, file, notOrg string }{
		"pkg:generic/wordpress-plugin/woocommerce@9.9.5":    {"WooCommerce", pl + "woocommerce/woocommerce.php", ""},
		"pkg:generic/wordpress-plugin/hello-dolly@1.7.2":    {"Hello Dolly", pl + "hello.php", ""},
		"pkg:generic/wordpress-plugin/classic-editor@1.6.7": {"Classic Editor", pl + "classic-editor/main.php", ""},
		"pkg:generic/wordpress-plugin/acme-pro@3.2.1":       {"Acme Pro", pl + "acme-pro/acme-pro.php", "its Update URI header says it is updated from updates.acme.example"},
		"pkg:generic/wordpress-plugin/in-house@2.0":         {"In House", pl + "in-house/in-house.php", "its Update URI header is false: updates from wordpress.org are turned off"},
		"pkg:generic/wordpress-plugin/akismet@5.3":          {"Akismet Anti-spam: Spam Protection", pl + "akismet/akismet.php", ""},
		"pkg:generic/wordpress-plugin/My_Custom@1.0.0":      {"Mine", pl + "My_Custom/My_Custom.php", "its folder name is not a wordpress.org slug"},
		"pkg:generic/wordpress-plugin/loader@1.0.0": {"Site Loader", wp + "/wp-content/mu-plugins/loader.php",
			"a must-use plugin, which WordPress does not update from wordpress.org"},
		"pkg:generic/wordpress-theme/astra@4.6.0":       {"Astra", wp + "/wp-content/themes/astra/style.css", ""},
		"pkg:generic/wordpress-theme/astra-child@1.0.0": {"Astra Child", wp + "/wp-content/themes/astra-child/style.css", ""},
	}
	for p, w := range want {
		o, ok := got[p]
		if !ok {
			t.Errorf("%s missing; have %v", p, keys(got))
			continue
		}
		kind := WPPlugin
		if strings.Contains(p, WPTheme) {
			kind = WPTheme
		}
		if o.Location != "/"+w.file || o.Evidence["kind"] != kind || o.Evidence["name"] != w.name || o.Confidence != model.ConfidenceConfirmed ||
			o.Evidence["wordpress_org_reason"] != w.notOrg || (w.notOrg != "") != (o.Evidence["wordpress_org"] == "no") {
			t.Errorf("%s: %+v", p, o)
		}
	}
	if got["pkg:generic/wordpress-plugin/loader@1.0.0"].Evidence["must_use"] != "true" ||
		got["pkg:generic/wordpress-theme/astra-child@1.0.0"].Evidence["template"] != "astra" {
		t.Errorf("must-use or child theme evidence: %+v", got)
	}
	if len(got) != len(want) {
		t.Errorf("reported %v", keys(got))
	}
	validate(t, a)
}

func TestWPHeader(t *testing.T) {
	for data, want := range map[string]string{
		"<?php\n/**\n * Plugin Name: WooCommerce\n */":       "WooCommerce",
		"<?php /* Plugin Name: One Line */ ?>":               "One Line",
		"# Plugin Name: Hash\n":                              "Hash",
		"<?php\n * plugin name: lower case\n":                "lower case",
		"<?php\n$x = 'Plugin Name: in code';\n":              "",
		"<?php\n * Plugin Name: \x01Control\x7f Chars\n":     "Control Chars",
		"<?php\n * Plugin Name:\n * Version: 1\n":            "",
		"<?php\n * Plugin Name: " + strings.Repeat("x", 300): strings.Repeat("x", 200),
	} {
		if got := wpHeader([]byte(data), "Plugin Name"); got != want {
			t.Errorf("%q = %q, want %q", data, got, want)
		}
	}
	for uri, want := range map[string]string{"": "", "https://wordpress.org/plugins/x/": "", "w.org/plugin/x": "",
		"https://updates.example.com/x": "updates.example.com", "false": "false", "example.com": "example.com"} {
		if got := updateURIElsewhere(uri); got != want {
			t.Errorf("Update URI %q = %q, want %q", uri, got, want)
		}
	}
}

// A folder whose own <slug>.php has a header is that plugin; otherwise each
// top-level file with a header is one, as WordPress lists them.
func TestWordPressPluginFolders(t *testing.T) {
	tr := newTree(t)
	wp := "srv/site"
	tr.file(wp+"/wp-includes/version.php", versionPHP("$wp_version = '6.8.1';"))
	pl := wp + "/wp-content/plugins/"
	tr.file(pl+"jetpack/a-helper.php", "<?php\n/* Plugin Name: Jetpack Helper\n * Version: 0.1 */")
	tr.file(pl+"jetpack/jetpack.php", "<?php\n/* Plugin Name: Jetpack\n * Version: 14.0 */")
	tr.file(pl+"bundle/one.php", "<?php\n/* Plugin Name: Bundle One\n * Version: 1.0 */")
	tr.file(pl+"bundle/two.php", "<?php\n/* Plugin Name: Bundle Two\n * Version: 2.0 */")
	got := map[string]string{}
	for _, o := range (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/"+wp).Observations {
		if strings.HasPrefix(o.Purl, "pkg:generic/wordpress-plugin/") {
			got[o.Purl] = o.Evidence["name"]
		}
	}
	want := map[string]string{"pkg:generic/wordpress-plugin/jetpack@14.0": "Jetpack",
		"pkg:generic/wordpress-plugin/bundle@1.0": "Bundle One", "pkg:generic/wordpress-plugin/bundle@2.0": "Bundle Two"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for p, n := range want {
		if got[p] != n {
			t.Errorf("%s = %q, want %q", p, got[p], n)
		}
	}
}

// Plugins, must-use plugins and themes have budgets of their own; what a
// budget leaves out is a partial coverage item, never silent.
func TestWordPressExtensionBudgets(t *testing.T) {
	defer func(p, m, th int) { maxWPPlugins, maxWPMustUse, maxWPThemes = p, m, th }(maxWPPlugins, maxWPMustUse, maxWPThemes)
	maxWPPlugins, maxWPMustUse, maxWPThemes = 2, 1, 5
	tr := newTree(t)
	wp := "srv/big"
	tr.file(wp+"/wp-includes/version.php", versionPHP("$wp_version = '6.8.1';"))
	for i := 0; i < 4; i++ {
		tr.file(fmt.Sprintf("%s/wp-content/plugins/p%d/p%d.php", wp, i, i), fmt.Sprintf("<?php\n/* Plugin Name: P%d\n * Version: 1.0 */", i))
	}
	for i := 0; i < 3; i++ {
		tr.file(fmt.Sprintf("%s/wp-content/mu-plugins/m%d.php", wp, i), fmt.Sprintf("<?php\n/* Plugin Name: M%d\n * Version: 1.0 */", i))
	}
	tr.file(wp+"/wp-content/themes/child/style.css", "/* Theme Name: Child\nTemplate: parent\nVersion: 1.0 */")
	a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/"+wp)
	n := map[string]int{}
	for _, o := range a.Observations {
		switch {
		case o.Evidence["must_use"] == "true":
			n["mu"]++
		case o.Evidence["kind"] == WPPlugin:
			n["plugins"]++
		case o.Evidence["kind"] == WPTheme:
			n["themes"]++
		}
	}
	if n["plugins"] != 2 || n["mu"] != 1 || n["themes"] != 1 {
		t.Errorf("reported %v", n)
	}
	reasons := map[string]bool{}
	for _, c := range a.Coverage {
		if c.Scope == wpExtScope+"/"+wp && c.Status == "partial" {
			reasons[c.Reason] = true
		}
	}
	if !reasons["stopped after 2 plugins; 2 more were not read"] || !reasons["stopped after 1 must-use plugins; 2 more were not read"] || len(reasons) != 2 {
		t.Errorf("coverage %+v", a.Coverage)
	}
	validate(t, a)
}
