package apps

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func TestParseCDNURL(t *testing.T) {
	cases := []struct{ url, name, version string }{
		{"https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js", "bootstrap", "4.3.1"},
		{"//cdn.jsdelivr.net/npm/@popperjs/core@2.11.8/dist/umd/popper.min.js", "@popperjs/core", "2.11.8"},
		{"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js", "jquery", "3.3.1"},
		{"https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.1/js/bootstrap.min.js", "bootstrap", "4.3.1"},
		{"https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.11/lodash.min.js", "lodash", "4.17.11"},
		{"https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.min.js", "chart.js", "2.9.4"},
		{"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css", "font-awesome", "4.7.0"},
		{"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css", "@fortawesome/fontawesome-free", "5.15.4"},
		{"https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment.min.js?v=1#x", "moment", "2.24.0"},
		{"https://unpkg.com/react@16.8.0/umd/react.production.min.js", "react", "16.8.0"},
		{"https://unpkg.com/vue@3.0.0-rc.5/dist/vue.global.js", "vue", "3.0.0-rc.5"},
		{"https://code.jquery.com/jquery-1.12.4.min.js", "jquery", "1.12.4"},
		{"https://code.jquery.com/jquery-3.5.1.slim.min.js", "jquery", "3.5.1"},
		{"https://code.jquery.com/jquery-migrate-3.0.0.min.js", "jquery-migrate", "3.0.0"},
		{"https://code.jquery.com/ui/1.12.1/jquery-ui.min.js", "jquery-ui", "1.12.1"},
		{"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js", "bootstrap", "4.3.1"},
		{"https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css", "font-awesome", "4.7.0"},
		{"https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js", "jquery", "3.3.1"},
		{"https://ajax.googleapis.com/ajax/libs/angularjs/1.7.8/angular.min.js", "angular", "1.7.8"},
		{"https://ajax.googleapis.com/ajax/libs/jqueryui/1.12.1/jquery-ui.min.js", "jquery-ui", "1.12.1"},
		{"HTTP://CDNJS.CLOUDFLARE.COM/ajax/libs/jquery/3.3.1/jquery.min.js", "jquery", "3.3.1"},
		{"https://cdn.ckeditor.com/4.11.4/standard/ckeditor.js", "ckeditor4", "4.11.4"},
		{"https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js", "datatables.net", "1.10.19"},
		// Not an exact release, or not a known package: skipped.
		{"https://cdn.jsdelivr.net/npm/bootstrap@latest/dist/js/bootstrap.min.js", "", ""},
		{"https://cdn.jsdelivr.net/npm/bootstrap@4/dist/js/bootstrap.min.js", "", ""},
		{"https://cdn.jsdelivr.net/npm/bootstrap/dist/js/bootstrap.min.js", "", ""},
		{"https://cdn.jsdelivr.net/gh/jquery/jquery@3.3.1/dist/jquery.min.js", "", ""},
		{"https://unpkg.com/react/umd/react.production.min.js", "", ""},
		{"https://unpkg.com/@popperjs/core", "", ""},
		{"https://code.jquery.com/jquery-latest.min.js", "", ""},
		{"https://code.jquery.com/jquery-3.x-git.min.js", "", ""},
		{"https://cdnjs.cloudflare.com/ajax/libs/some-unknown-lib/1.0.0/x.js", "", ""},
		{"https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3/jquery.min.js", "", ""},
		{"https://cdn.ckeditor.com/ckeditor5/35.0.0/classic/ckeditor.js", "", ""},
		{"https://cdn.datatables.net/buttons/1.5.6/js/dataTables.buttons.min.js", "", ""},
		{"https://example.com/npm/bootstrap@4.3.1/x.js", "", ""},
		// A stylesheet is the library only for a stylesheet library: Bootstrap's
		// CSS or a jQuery UI theme says nothing about the scripts.
		{"https://cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/3.3.7/css/bootstrap.min.css", "", ""},
		{"https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css?v=2", "", ""},
		{"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css", "", ""},
		{"https://code.jquery.com/ui/1.12.1/themes/smoothness/jquery-ui.css", "", ""},
		{"https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css", "font-awesome", "4.7.0"},
		{"https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.4.0/css/all.min.css", "@fortawesome/fontawesome-free", "6.4.0"},
	}
	for _, c := range cases {
		name, version, ok := parseCDNURL(c.url)
		if ok != (c.name != "") || name != c.name || version != c.version {
			t.Errorf("%s = %q %q %v, want %q %q", c.url, name, version, ok, c.name, c.version)
		}
	}
}

func TestParseBanner(t *testing.T) {
	cases := []struct {
		file, head string
		want       string // "name@version", "" for none
	}{
		{"jquery.min.js", "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(e,t){", "jquery@3.3.1"},
		{"jquery.js", "/*!\n * jQuery JavaScript Library v1.12.4\n * http://jquery.com/\n", "jquery@1.12.4"},
		{"jquery-ui.min.js", "/*! jQuery UI - v1.12.1 - 2016-09-14\n* http://jqueryui.com", "jquery-ui@1.12.1"},
		{"jquery-ui.js", "/*!\n * jQuery UI 1.8.16\n *\n", "jquery-ui@1.8.16"},
		{"widget.js", "/*!\n * jQuery UI Widget 1.12.1\n", ""},
		{"jquery-migrate.min.js", "/*! jQuery Migrate v3.0.0 | (c) jQuery Foundation and other contributors */", "jquery-migrate@3.0.0"},
		{"jquery.validate.min.js", "/*!\n * jQuery Validation Plugin v1.19.0\n", "jquery-validation@1.19.0"},
		{"bootstrap.min.js", "/*!\n  * Bootstrap v4.3.1 (https://getbootstrap.com/)\n", "bootstrap@4.3.1"},
		{"bootstrap.js", "/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n", "bootstrap@3.3.7"},
		// Stylesheets of script libraries are not the library.
		{"bootstrap.min.css", "/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n", ""},
		{"jquery-ui-rtl.css", "/*! jQuery UI - v1.11.4 - 2016-01-05\n* http://jqueryui.com", ""},
		{"jquery-ui.css", "/*! jQuery UI - v1.12.1 - 2016-09-14\n* http://jqueryui.com\n* Includes: core.css", ""},
		{"bootstrap-datepicker.js", "/*!\n * Datepicker for Bootstrap v1.9.0 (https://github.com/uxsolutions/bootstrap-datepicker)\n", ""},
		{"bootstrap-select.min.js", "/*!\n * Bootstrap-select v1.13.1 (https://developer.snapappointments.com/bootstrap-select)\n", "bootstrap-select@1.13.1"},
		{"angular.min.js", "/*\n AngularJS v1.7.8\n (c) 2010-2018 Google, Inc. http://angularjs.org\n", "angular@1.7.8"},
		{"angular.js", "/**\n * @license AngularJS v1.5.0\n", "angular@1.5.0"},
		{"vue.min.js", "/*!\n * Vue.js v2.6.10\n * (c) 2014-2019 Evan You\n", "vue@2.6.10"},
		{"vue.global.prod.js", "/**\n* vue v3.2.31\n* (c) 2018-present Yuxi (Evan) You and Vue contributors\n", "vue@3.2.31"},
		{"react.production.min.js", "/** @license React v16.8.0\n * react.production.min.js\n *\n", "react@16.8.0"},
		{"react-dom.production.min.js", "/** @license React v16.8.0\n * react-dom.production.min.js\n *\n", "react-dom@16.8.0"},
		{"react.min.js", "/**\n * React v15.6.2\n */\n", "react@15.6.2"},
		{"react.production.min.js", "/**\n * @license React\n * react.production.min.js\n", ""}, // 18: no version
		{"lodash.js", "/**\n * @license\n * Lodash <https://lodash.com/>\n * Copyright OpenJS Foundation\n */\n;(function() {\n  var undefined;\n  var VERSION = '4.17.15';\n", "lodash@4.17.15"},
		{"lodash.min.js", "/**\n * @license\n * lodash 3.10.1 (Custom Build) lodash.com/license\n", "lodash@3.10.1"},
		{"lodash.min.js", "/**\n * @license\n * Lodash lodash.com/license | Underscore.js 1.8.3 underscorejs.org/LICENSE\n */", ""},
		{"underscore-min.js", "//     Underscore.js 1.9.1\n//     http://underscorejs.org\n", "underscore@1.9.1"},
		{"moment.js", "//! moment.js\n//! version : 2.24.0\n//! authors : Tim Wood\n", "moment@2.24.0"},
		{"handlebars.min.js", "/**!\n\n @license\n handlebars v4.0.11\n\nCopyright (C) 2011-2017 by Yehuda Katz\n", "handlebars@4.0.11"},
		{"knockout.js", "/*!\n * Knockout JavaScript library v3.4.2\n", "knockout@3.4.2"},
		{"tinymce.min.js", "/**\n * TinyMCE version 6.3.1 (2022-12-06)\n */\n", "tinymce@6.3.1"},
		{"tinymce.min.js", "/**\n * Copyright (c) Tiny Technologies, Inc. All rights reserved.\n * Licensed under the LGPL or a commercial license.\n *\n * Version: 5.10.2 (2021-11-17)\n */", "tinymce@5.10.2"},
		{"tinymce.min.js", "// 4.9.11 (2020-07-13)\n!function(V){\"use strict\";", "tinymce@4.9.11"},
		{"tinymce.min.js", `!function(){var e={majorVersion:"4",minorVersion:"7.4",releaseDate:"2017-12-05"}`, "tinymce@4.7.4"},
		{"other.min.js", "// 4.9.11 (2020-07-13)\n", ""}, // the bare TinyMCE 4 form needs the file name
		{"ckeditor.js", `window.CKEDITOR||(window.CKEDITOR=function(){var a=/(^|.*[\\\/])ckeditor\.js(?:\?.*|;.*)?$/i,d={timestamp:"J1EB",version:"4.11.4 (Standard)",revision:"7"}`, "ckeditor4@4.11.4"},
		{"jquery.dataTables.min.js", "/*!\n Copyright 2008-2018 SpryMedia Ltd.\n\n DataTables 1.10.19\n ©2008-2018 SpryMedia Ltd\n*/", "datatables.net@1.10.19"},
		{"select2.min.js", "/*! Select2 4.0.13 | https://github.com/select2/select2/blob/master/LICENSE.md */", "select2@4.0.13"},
		{"Chart.min.js", "/*!\n * Chart.js v2.9.4\n * https://www.chartjs.org\n", "chart.js@2.9.4"},
		{"d3.min.js", "// https://d3js.org v5.16.0 Copyright 2020 Mike Bostock\n", "d3@5.16.0"},
		{"axios.min.js", "/* axios v0.21.1 | (c) 2020 by Matt Zabriskie */", "axios@0.21.1"},
		{"purify.min.js", "/*! @license DOMPurify 2.3.3 | (c) Cure53 and other contributors */", "dompurify@2.3.3"},
		{"highlight.min.js", "/*! highlight.js v9.18.1 | BSD3 License | git.io/hljslicense */", "highlight.js@9.18.1"},
		{"prism.js", "/* PrismJS 1.15.0\nhttps://prismjs.com/download.html#themes=prism */", "prismjs@1.15.0"},
		{"summernote.min.js", "/**\n * Super simple wysiwyg editor v0.8.12\n * https://summernote.org\n", "summernote@0.8.12"},
		{"font-awesome.min.css", "/*!\n *  Font Awesome 4.7.0 by @davegandy - http://fontawesome.io - @fontawesome\n", "font-awesome@4.7.0"},
		{"all.min.css", "/*!\n * Font Awesome Free 5.15.4 by @fontawesome - https://fontawesome.com\n", "@fortawesome/fontawesome-free@5.15.4"},
		// Unknown libraries and versions that are not exact are ignored.
		{"app.js", "/*! MyWidget v1.2.3 */", ""},
		{"jquery.min.js", "/*! jQuery v1.7 jquery.com | jquery.org/license */", ""},
		{"plugin.js", "/*\n * Requires jQuery v1.3.2 or later\n */", ""},
	}
	for _, c := range cases {
		var got []string
		for _, m := range parseBanner(c.file, []byte(c.head)) {
			got = append(got, m[0]+"@"+m[1])
		}
		if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || got[0] != c.want) {
			t.Errorf("%s %q = %v, want %q", c.file, c.head, got, c.want)
		}
	}
}

// A PHP site with no package manager: CDN tags in its templates, copies of
// libraries in its asset directories, and the things that must be skipped.
func TestScanWebAssets(t *testing.T) {
	tr := newTree(t)
	site := "var/www/site"
	tr.file(site+"/index.php", `<?php include 'header.php'; ?>`)
	tr.file(site+"/header.php", `<html><head>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css">
<script src="//code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@latest/dist/js/bootstrap.min.js"></script>
<!-- <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/1.4.2/jquery.min.js"></script> -->
<?php wp_enqueue_script('moment', 'https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment.min.js'); ?>
</head>`)
	tr.file(site+"/footer.php", `<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>`) // reported once
	tr.file(site+"/views/home.blade.php", `<script src="https://unpkg.com/vue@2.6.10/dist/vue.min.js"></script>`)
	tr.file(site+"/assets/js/bootstrap.min.js", "/*!\n  * Bootstrap v4.3.1 (https://getbootstrap.com/)\n  */\n!function(t,e){}")
	tr.file(site+"/assets/vendor/tinymce/tinymce.min.js", "// 4.9.11 (2020-07-13)\n!function(V){}")
	tr.file(site+"/assets/js/app.js", "/*! MyWidget v1.2.3 */")
	tr.file(site+"/assets/js/huge.js", strings.Repeat("x", 8<<10)+"/*! jQuery v3.0.0 */") // beyond the banner read
	tr.file(site+"/.cache/jquery.min.js", "/*! jQuery v2.0.0 | (c) */")
	tr.file(site+"/node_modules/.bin/x.js", "/*! jQuery v2.1.0 | (c) */")
	tr.file("elsewhere/jquery.min.js", "/*! jQuery v2.2.0 | (c) */")
	tr.link(site+"/assets/js/linked.min.js", "../../../../../elsewhere/jquery.min.js")
	tr.link(site+"/linkdir", "../../../elsewhere")

	a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/"+site)
	m := purls(a.Observations)
	want := map[string]string{
		"pkg:npm/bootstrap@4.3.1": "/var/www/site/assets/js/bootstrap.min.js", // the copy, read first
		"pkg:npm/jquery@1.12.4":   "/var/www/site/footer.php",
		"pkg:npm/moment@2.24.0":   "/var/www/site/header.php",
		"pkg:npm/vue@2.6.10":      "/var/www/site/views/home.blade.php",
		"pkg:npm/tinymce@4.9.11":  "/var/www/site/assets/vendor/tinymce/tinymce.min.js",
	}
	if len(m) != len(want) {
		t.Errorf("found %v", keys(m))
	}
	for p, loc := range want {
		o, ok := m[p]
		if !ok {
			t.Errorf("missing %s; have %v", p, keys(m))
			continue
		}
		if o.Location != loc || o.Evidence["app_dir"] != "/var/www/site" || o.Direct == nil || !*o.Direct {
			t.Errorf("%s = %+v", p, o)
		}
	}
	if o := m["pkg:npm/moment@2.24.0"]; o.Evidence["source"] != "cdn" || !strings.Contains(o.Evidence["url"], "moment.js/2.24.0") {
		t.Errorf("moment evidence = %v", o.Evidence)
	}
	if o := m["pkg:npm/tinymce@4.9.11"]; o.Evidence["source"] != "vendored" {
		t.Errorf("tinymce evidence = %v", o.Evidence)
	}
	found := false
	for _, c := range a.Coverage {
		found = found || c.Scope == "web-assets:/var/www/site" && c.Status == "checked"
	}
	if !found {
		t.Errorf("coverage = %+v", a.Coverage)
	}
	validate(t, a)
}

// A library a manifest already reports is not reported again from a copy
// of it (a build step copying node_modules/bootstrap to public/), but a
// copy of another version is: that is what the site serves.
func TestWebAssetsYieldToManifest(t *testing.T) {
	tr := newTree(t)
	app := "srv/shop"
	tr.file(app+"/package.json", `{"name":"shop","dependencies":{"bootstrap":"^4.3.1","jquery":"^3.5.0"}}`)
	tr.npm(app+"/node_modules/bootstrap", "bootstrap", "4.3.1")
	tr.file(app+"/node_modules/bootstrap/dist/js/bootstrap.min.js", "/*!\n  * Bootstrap v4.3.1 (https://getbootstrap.com/)\n")
	tr.file(app+"/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/bootstrap":{"version":"4.3.1"}}}`)
	tr.file(app+"/public/build/bootstrap.min.js", "/*!\n  * Bootstrap v4.3.1 (https://getbootstrap.com/)\n")
	tr.file(app+"/public/legacy/jquery.min.js", "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */")
	tr.file(app+"/views/index.ejs", `<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js"></script>`)
	// A Python app's lockfile names only PyPI packages: nothing to yield to.
	tr.file("srv/api/requirements.txt", "flask==2.0.0\n")
	tr.file("srv/api/templates/base.html", `<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>`)

	s := &Scanner{Root: tr.root}
	shop := s.ScanApp(context.Background(), "/srv/shop")
	m := purls(shop.Observations)
	if len(m) != 2 {
		t.Errorf("shop = %v", keys(m))
	}
	if o := m["pkg:npm/bootstrap@4.3.1"]; o.Evidence["source"] != "installed" {
		t.Errorf("bootstrap should come from node_modules: %+v", o)
	}
	if o := m["pkg:npm/jquery@1.12.4"]; o.Evidence["source"] != "vendored" || o.Location != "/srv/shop/public/legacy/jquery.min.js" {
		t.Errorf("legacy jquery = %+v", o)
	}
	if _, ok := purls(s.ScanApp(context.Background(), "/srv/api").Observations)["pkg:npm/jquery@3.3.1"]; !ok {
		t.Error("api lost its CDN jquery")
	}
}

// Nested applications, Composer's vendor/ and the per-application limits.
func TestWebAssetsBounded(t *testing.T) {
	tr := newTree(t)
	tr.file("var/www/html/composer.json", `{"name":"site/site"}`)
	tr.file("var/www/html/vendor/autoload.php", "<?php")
	tr.file("var/www/html/vendor/twbs/bootstrap/dist/js/bootstrap.js", "/*!\n  * Bootstrap v4.0.0 (https://getbootstrap.com/)\n")
	tr.file("var/www/html/phpmyadmin/composer.json", `{"name":"phpmyadmin/phpmyadmin"}`)
	tr.file("var/www/html/phpmyadmin/js/jquery.min.js", "/*! jQuery v3.3.1 | (c) */")
	s := &Scanner{Root: tr.root, Apps: []string{"/var/www/html", "/var/www/html/phpmyadmin"}}
	if m := purls(s.ScanApp(context.Background(), "/var/www/html").Observations); len(m) != 0 {
		t.Errorf("outer site = %v", keys(m))
	}
	if _, ok := purls(s.ScanApp(context.Background(), "/var/www/html/phpmyadmin").Observations)["pkg:npm/jquery@3.3.1"]; !ok {
		t.Error("phpMyAdmin lost its jquery")
	}

	defer func(f, b int) { webFiles, webBytes = f, b }(webFiles, webBytes)
	webFiles = 20
	tr2 := newTree(t)
	for i := range webFiles + 5 {
		tr2.file(fmt.Sprintf("srv/big/js/%05d.js", i), "x")
	}
	a := (&Scanner{Root: tr2.root}).ScanApp(context.Background(), "/srv/big")
	partial := false
	for _, c := range a.Coverage {
		partial = partial || c.Scope == "web-assets:/srv/big" && c.Status == "partial"
	}
	if !partial {
		t.Errorf("coverage = %+v", a.Coverage)
	}
	for _, c := range a.Coverage {
		if c.Scope == "web-assets:/srv/big" && c.Reason != "stopped after 20 files of templates and scripts" {
			t.Errorf("reason = %q", c.Reason)
		}
	}
}

// A WordPress site has no manifest: wp-config.php or wp-includes/version.php
// makes it an application, and its core, plugins and themes are read as
// part of it, never as applications of their own.
func TestWordPressSite(t *testing.T) {
	tr := newTree(t)
	wp := "var/www/blog"
	tr.file(wp+"/wp-config.php", "<?php define('DB_NAME', 'blog');")
	tr.file(wp+"/wp-includes/version.php", "<?php\n$wp_version = '6.4.2';\n")
	tr.file(wp+"/wp-includes/js/jquery/jquery.min.js", "/*! jQuery v3.7.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */")
	tr.file(wp+"/wp-content/plugins/contact/composer.json", `{"name":"acme/contact"}`)
	tr.file(wp+"/wp-content/plugins/contact/assets/js/select2.min.js", "/*! Select2 4.0.13 | https://github.com/select2/select2/blob/master/LICENSE.md */")
	tr.file(wp+"/wp-content/plugins/gallery/package.json", `{"name":"gallery","version":"1.0.0"}`)
	tr.file(wp+"/wp-content/themes/twenty/header.php",
		`<?php wp_enqueue_script('bs', 'https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js'); ?>`)
	tr.file(wp+"/wp-includes/js/tinymce/tinymce.min.js", "// 4.9.11 (2020-07-13)\n!function(V){}")
	// wp-config.php one level above the install, as WordPress allows.
	tr.file("var/www/shop/wp-config.php", "<?php")
	tr.file("var/www/shop/public/wp-includes/version.php", "<?php\n$wp_version = '5.8.1';\n")
	tr.file("var/www/shop/public/wp-includes/js/jquery/jquery.js", "/*!\n * jQuery JavaScript Library v3.6.0\n")
	// Only version.php: still a site.
	tr.file("srv/press/wp-includes/version.php", "<?php\n$wp_version = '6.0.0';\n")

	s := &Scanner{Root: tr.root}
	got, full := s.DiscoverAll()
	want := map[string]bool{"/var/www/blog": true, "/var/www/shop": true, "/srv/press": true}
	if len(got) != len(want) || !full {
		t.Fatalf("discovered %v (full %v)", got, full)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("unexpected application %s in %v", g, got)
		}
	}
	s.Apps = got
	blog := s.ScanApp(context.Background(), "/var/www/blog")
	m := purls(blog.Observations)
	for p, loc := range map[string]string{
		"pkg:npm/jquery@3.7.1":        "/var/www/blog/wp-includes/js/jquery/jquery.min.js",
		"pkg:npm/select2@4.0.13":      "/var/www/blog/wp-content/plugins/contact/assets/js/select2.min.js",
		"pkg:npm/bootstrap@4.3.1":     "/var/www/blog/wp-content/themes/twenty/header.php",
		"pkg:npm/tinymce@4.9.11":      "/var/www/blog/wp-includes/js/tinymce/tinymce.min.js",
		"pkg:generic/wordpress@6.4.2": "/var/www/blog/wp-includes/version.php",
	} {
		if o, ok := m[p]; !ok || o.Location != loc {
			t.Errorf("%s = %+v; have %v", p, o, keys(m))
		}
	}
	// Copies WordPress core maintains need validation; a plugin's own do not.
	for p, conf := range map[string]model.Confidence{"pkg:npm/jquery@3.7.1": model.ConfidenceInferred,
		"pkg:npm/tinymce@4.9.11": model.ConfidenceInferred, "pkg:npm/select2@4.0.13": model.ConfidenceConfirmed} {
		if o := m[p]; o.Confidence != conf || (conf == model.ConfidenceInferred) != (o.Evidence["bundled_with"] == "WordPress") {
			t.Errorf("%s: confidence %s, evidence %v", p, o.Confidence, o.Evidence)
		}
	}
	if blog.Name != "blog" || len(m) != 5 {
		t.Errorf("blog %q: %v", blog.Name, keys(m))
	}
	validate(t, blog)
	shop := purls(s.ScanApp(context.Background(), "/var/www/shop").Observations)
	if _, ok := shop["pkg:npm/jquery@3.6.0"]; !ok {
		t.Error("shop: jquery below public/ missing")
	}
	if o := shop["pkg:generic/wordpress@5.8.1"]; o.Location != "/var/www/shop/public/wp-includes/version.php" {
		t.Errorf("shop: WordPress core below public/ = %+v; have %v", o, keys(shop))
	}
	if _, ok := purls(s.ScanApp(context.Background(), "/srv/press").Observations)["pkg:generic/wordpress@6.0.0"]; !ok {
		t.Error("press: WordPress core missing")
	}
}

func TestJSScript(t *testing.T) {
	cases := []struct {
		tag  string
		want bool
	}{
		{`<script>`, true},
		{`<script src="https://code.jquery.com/jquery-3.5.1.min.js">`, true},
		{`<script type="text/javascript">`, true},
		{`<script type="text/javascript; charset=utf-8">`, true},
		{`<script type='text/javascript;charset=utf-8'>`, true},
		{`<script TYPE=application/javascript>`, true},
		{`<script type="text/ecmascript">`, true},
		{`<script type="application/x-javascript">`, true},
		{`<script type=module>`, true},
		{"<script\ttype=\"text/javascript\">", true},
		// Not an attribute named type: data-type=, or ?type= in the address.
		{`<script data-type="text/template">`, true},
		{`<script src="/x.js?type=text/template">`, true},
		{`<script src="/x.js?v=1&type=json" data-type=json>`, true},
		// Templates and data.
		{`<script type="text/template">`, false},
		{`<script type="text/x-handlebars-template">`, false},
		{`<script type="application/json">`, false},
		{`<script type="application/ld+json">`, false},
		{`<script data-type="x" type="text/template">`, false},
	}
	for _, c := range cases {
		if got := jsScript([]byte(c.tag)); got != c.want {
			t.Errorf("%s = %v, want %v", c.tag, got, c.want)
		}
	}
}

func TestStripComments(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"a.php", "<?php // old: https://code.jquery.com/jquery-1.8.3.min.js\n$x = 1;", "<?php \n$x = 1;"},
		{"a.php", "<?php // old ?><script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>", "<?php ?><script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>"},
		{"a.php", "<?php $u = 'https://code.jquery.com/jquery-3.5.1.min.js'; // note\n", "<?php $u = 'https://code.jquery.com/jquery-3.5.1.min.js'; \n"},
		{"a.php", `<?php $u = "//code.jquery.com/jquery-3.5.1.min.js";`, `<?php $u = "//code.jquery.com/jquery-3.5.1.min.js";`},
		{"a.php", `<?php $s = 'it\'s // not a comment';`, `<?php $s = 'it\'s // not a comment';`},
		{"a.php", "<p>Don't</p>\n<?php // https://code.jquery.com/jquery-1.8.3.min.js\n", "<p>Don't</p>\n<?php \n"},
		{"a.php", "<?php /* https://unpkg.com/react@16.0.0/x.js */ $a = 1;", "<?php   $a = 1;"},
		// PHP # comments; a # inside a string or an attribute stays.
		{"a.php", "<?php # https://code.jquery.com/jquery-1.5.0.min.js\n$a = 1;", "<?php \n$a = 1;"},
		{"a.php", "<?php preg_match('#^//#', $u); ?>", "<?php preg_match('#^//#', $u); ?>"},
		{"a.php", "<?php #[Attr]\nfunction f() {}", "<?php #[Attr]\nfunction f() {}"},
		// HTML and CSS around the code are text, not code.
		{"a.php", "<p>Use glob src/*.js here</p>", "<p>Use glob src/*.js here</p>"},
		{"a.php", "<style>.a{background:url(//example.com/x.png)}</style>", "<style>.a{background:url(//example.com/x.png)}</style>"},
		{"a.php", "<style>@import url(//fonts.googleapis.com/css?family=Roboto);</style>", "<style>@import url(//fonts.googleapis.com/css?family=Roboto);</style>"},
		// Inline scripts are code.
		{"a.php", "<script>\n// https://code.jquery.com/jquery-1.5.0.min.js\nvar a = 1;</script>", "<script>\n\nvar a = 1;</script>"},
		{"a.php", "<script>s.replace(/^\\/*/, '')</script>", "<script>s.replace(/^\\/*/, '')</script>"},
		{"a.php", "<script>var u = \"<?php echo 'x' ?>\"; // https://code.jquery.com/jquery-1.5.0.min.js\n</script>", "<script>var u = \"<?php echo 'x' ?>\"; \n</script>"},
		// Script files: where a comment can start.
		{"a.js", "f(url(//example.com/x.png)); g('src/*.js'); r = /\\/\\//; q = /\\/*/;", "f(url(//example.com/x.png)); g('src/*.js'); r = /\\/\\//; q = /\\/*/;"},
		{"a.js", "a /* https://unpkg.com/react@16.0.0/x.js */ b", "a   b"},
		{"a.js", "x /* never closed https://unpkg.com/react@16.0.0/x.js", "x /* never closed https://unpkg.com/react@16.0.0/x.js"},
		{"a.jsx", "const a = 1; // https://unpkg.com/vue@2.0.0/dist/vue.js\n", "const a = 1; \n"},
		// Inline scripts in HTML templates are code; the HTML around them,
		// and scripts that hold templates or data, are not.
		{"a.html", "<script>// https://unpkg.com/vue@2.0.0/dist/vue.js\n</script>", "<script>\n</script>"},
		{"a.htm", "<p>a // b</p><SCRIPT type=\"text/javascript\">/* https://unpkg.com/vue@2.0.0/x.js */ go();</SCRIPT>", "<p>a // b</p><SCRIPT type=\"text/javascript\">  go();</SCRIPT>"},
		{"a.twig", "{# x #}<script>\n  // old: https://code.jquery.com/jquery-1.8.3.min.js\n</script>", "{# x #}<script>\n  \n</script>"},
		{"a.vue", "<template><a href=\"//x\">x</a></template>\n<script>\n// https://unpkg.com/vue@2.0.0/x.js\nexport default {}\n</script>", "<template><a href=\"//x\">x</a></template>\n<script>\n\nexport default {}\n</script>"},
		{"a.erb", "<script>var a = 1; // https://code.jquery.com/jquery-1.8.3.min.js\n</script>", "<script>var a = 1; \n</script>"},
		{"a.ejs", "<script type=module>// https://unpkg.com/vue@2.0.0/x.js\n</script>", "<script type=module>\n</script>"},
		{"a.hbs", "<script type=\"text/x-handlebars-template\"><a href= //x>{{y}}</a></script>", "<script type=\"text/x-handlebars-template\"><a href= //x>{{y}}</a></script>"},
		{"a.html", "<style>.a{background:url(//example.com/x.png)}</style>", "<style>.a{background:url(//example.com/x.png)}</style>"},
		{"a.erb", "<p>text // with slashes</p>", "<p>text // with slashes</p>"},
		// PHP heredoc and nowdoc are strings: "#fff" or "//" in them is text.
		{"a.php", "<?php\necho <<<HTML\n<style>a{color: #fff}</style><script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>\nHTML;\n# https://code.jquery.com/jquery-1.5.0.min.js\n",
			"<?php\necho <<<HTML\n<style>a{color: #fff}</style><script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>\nHTML;\n\n"},
		{"a.php", "<?php\n$a = [<<<'EOT'\n  a // b\n  EOT, 1]; // c\n", "<?php\n$a = [<<<'EOT'\n  a // b\n  EOT, 1]; \n"},
		{"a.php", "<?php\nf(<<<\"X\"\n # y\n    X);", "<?php\nf(<<<\"X\"\n # y\n    X);"},
		{"a.php", "<?php\n$s = <<<HTML\nHTMLX is not the end # z\nHTML;", "<?php\n$s = <<<HTML\nHTMLX is not the end # z\nHTML;"},
		{"a.php", "<?php\n$s = <<<HTML\n// never closed", "<?php\n$s = <<<HTML\n// never closed"},
		{"a.php", "<?php $x = $a <<< 2; // c\n", "<?php $x = $a <<< 2; \n"},
	}
	for _, c := range cases {
		if got := string(stripComments(c.name, []byte(c.in))); got != c.want {
			t.Errorf("%s %q\n got %q\nwant %q", c.name, c.in, got, c.want)
		}
	}
}

// The review's probes on a real WordPress site: text in HTML and CSS, and
// regular expressions in inline scripts, must not hide the addresses after
// them.
func TestParseTemplateKeepsLoadedAddresses(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"a.php", "<p>Use glob src/*.js here</p>\n<script src=\"https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment.min.js\"></script>", "moment@2.24.0"},
		{"a.php", "<script>s.replace(/^\\/*/, '')</script>\n<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js\"></script>", "bootstrap@4.6.2"},
		{"a.php", "<style>.a{background:url(//example.com/x.png)}</style><script src=\"https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.21/lodash.min.js\"></script>", "lodash@4.17.21"},
		{"a.php", "<style>@import url(//fonts.googleapis.com/css?family=Roboto);</style>\n<script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>", "jquery@3.5.1"},
		{"a.php", "<?php\n# https://code.jquery.com/jquery-1.5.0.min.js\n?>", ""},
		{"a.php", "<?php\n/* unclosed\n?>\n<script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>", "jquery@3.5.1"},
		// A heredoc's "#fff" must not hide the address after it on that line.
		{"a.php", "<?php\necho <<<HTML\n<style>a{color: #fff}</style><script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>\nHTML;\n", "jquery@3.5.1"},
		{"a.php", "<?php\necho <<<'EOT'\n  <a href=\"x\">// x</a><script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>\n  EOT;\n", "jquery@3.5.1"},
		// Commented addresses in inline scripts of HTML templates are not loaded.
		{"a.html", "<script>\n// <script src=\"https://code.jquery.com/jquery-1.8.3.min.js\">\n</script>\n<script src=\"https://code.jquery.com/jquery-3.5.1.min.js\"></script>", "jquery@3.5.1"},
		{"a.vue", "<script>\n/* import 'https://unpkg.com/vue@2.0.0/dist/vue.js' */\n</script>", ""},
		{"a.twig", "<script>loadScript('https://unpkg.com/vue@2.6.10/dist/vue.js'); // was 2.0.0\n</script>", "vue@2.6.10"},
		{"a.html", "<script type=\"text/javascript; charset=utf-8\">\n// https://code.jquery.com/jquery-1.8.3.min.js\n</script>", ""},
		{"a.html", "<script src=\"/app.js?type=x\" data-type=\"tpl\">\n// https://code.jquery.com/jquery-1.8.3.min.js\n</script>", ""},
	}
	for _, c := range cases {
		var got []string
		for _, m := range parseTemplate(c.name, []byte(c.in)) {
			got = append(got, m[0]+"@"+m[1])
		}
		if c.want == "" && len(got) != 0 || c.want != "" && (len(got) != 1 || got[0] != c.want) {
			t.Errorf("%q = %v, want %q", c.in, got, c.want)
		}
	}
}

// What a site never loads is not reported: addresses in code comments, a
// library's own examples, docs and tests, and page caches (which would
// also use up the per-application limits).
func TestWebAssetsNotLoaded(t *testing.T) {
	defer func(f, b int) { webFiles, webBytes = f, b }(webFiles, webBytes)
	webFiles = 50
	tr := newTree(t)
	site := "var/www/site"
	tr.file(site+"/wp-config.php", "<?php")
	tr.file(site+"/header.php", "<?php // old: https://code.jquery.com/jquery-1.8.3.min.js\n"+
		"/* wp_enqueue_script('x', 'https://unpkg.com/react@15.0.0/dist/react.min.js'); */\n"+
		"wp_enqueue_script('jq', 'https://code.jquery.com/jquery-3.5.1.min.js?ver=1#top'); ?>\n"+
		`<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.24.0/moment.min.js"></script>`)
	tr.file(site+"/app.jsx", "// import from https://unpkg.com/vue@2.0.0/dist/vue.js\nconst u = 'https://unpkg.com/vue@2.6.10/dist/vue.js';")
	tr.file(site+"/wp-content/plugins/tables/datatables/examples/basic.html", `<script src="https://code.jquery.com/jquery-1.11.3.min.js"></script>`)
	tr.file(site+"/wp-content/plugins/tables/docs/index.html", `<script src="https://code.jquery.com/jquery-1.10.0.min.js"></script>`)
	tr.file(site+"/wp-content/plugins/tables/tests/jquery.js", "/*! jQuery v1.9.1 | (c) */")
	tr.file(site+"/wp-content/plugins/tables/js/select2.min.js", "/*! Select2 4.0.13 | https://github.com/select2/select2 */")
	tr.file(site+"/wp-content/uploads/2020/jquery.min.js", "/*! jQuery v1.6.4 | (c) */")
	// A page cache far larger than the limits, walked before the plugins.
	for i := range 200 {
		tr.file(fmt.Sprintf(site+"/wp-content/cache/supercache/site/page%03d/index.html", i),
			`<script src="https://code.jquery.com/jquery-1.7.2.min.js"></script>`+strings.Repeat("x", 4096))
	}
	// A copy patched by WordPress, outside wp-includes.
	tr.file(site+"/wp-content/plugins/old/jquery.js", "/*! jQuery v1.12.4-wp | (c) jQuery Foundation */")

	a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/"+site)
	m := purls(a.Observations)
	want := []string{"pkg:npm/jquery@3.5.1", "pkg:npm/moment@2.24.0", "pkg:npm/vue@2.6.10", "pkg:npm/select2@4.0.13", "pkg:npm/jquery@1.12.4-wp"}
	if len(m) != len(want) {
		t.Errorf("found %v, want %v", keys(m), want)
	}
	for _, w := range want {
		if _, ok := m[w]; !ok {
			t.Errorf("missing %s; have %v", w, keys(m))
		}
	}
	if u := m["pkg:npm/jquery@3.5.1"].Evidence["url"]; u != "https://code.jquery.com/jquery-3.5.1.min.js" {
		t.Errorf("stored url %q", u)
	}
	if o := m["pkg:npm/jquery@1.12.4-wp"]; o.Confidence != model.ConfidenceInferred || o.Evidence["bundled_with"] != "WordPress" {
		t.Errorf("-wp copy = %+v", o)
	}
	for _, c := range a.Coverage {
		if strings.HasPrefix(c.Scope, "web-assets:") && c.Status != "checked" {
			t.Errorf("the cache used up the limits: %+v", c)
		}
	}
}
