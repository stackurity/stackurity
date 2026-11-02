package apps

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// The fixtures in testdata/bundles are small synthetic builds whose
// library code has the shape of the libraries' published, minified files.
const bundleFixtures = "testdata/bundles"

// TestCodeSignatures runs each signature on the shapes it must recognise
// and on near misses it must not: application code with a library's name,
// a version-looking constant without the library's code around it.
func TestCodeSignatures(t *testing.T) {
	cases := []struct {
		name, code string
		want       string // "npm@version", "" for nothing
	}{
		// React 16.0 to 19, minified and with Vite 8's backticks.
		{"react 18", `t.useTransition=function(){return U.current.useTransition()},t.version="18.2.0"`, "react@18.2.0"},
		{"react 19", "e.useTransition=function(){return T.H.useTransition()},e.version=`19.1.0`", "react@19.1.0"},
		{"react 17", `exports.useState=function(a){return S().useState(a)};exports.version="17.0.2";`, "react@17.0.2"},
		{"react 16.2", `createFactory:function(a){},isValidElement:K,version:"16.2.0",__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED:{ReactCurrentOwner:G}`, "react@16.2.0"},
		{"react: own store", `t.useTransition=function(){return store.useTransition()},t.version="2.1.0"`, ""},
		{"react: name only", `const title="Built with React";const cfg={name:"React",version:"18.2.0"}`, ""},
		{"react-dom", `s({findFiberByHostInstance:pb,bundleType:0,version:"16.2.0",rendererPackageName:"react-dom"})`, "react-dom@16.2.0"},
		{"react-dom: other renderer", `{bundleType:0,version:"0.9.1",rendererPackageName:"react-three-fiber"}`, ""},
		// React 18.2.0's UMD build reports a reconciler pre-release, not a release.
		{"react-dom: not a release", `{bundleType:0,version:"18.2.0-next-9e3b772b8-20220608",rendererPackageName:"react-dom"}`, ""},
		{"vue 3", `const fs="3.3.4",ps=null;function cr(){return{_uid:a++,_component:n,_props:o,_container:null,_context:r,_instance:null,version:fs,get config(){}}}`, "vue@3.3.4"},
		{"vue 3 literal", `{_container:null,_context:r,_instance:null,version:"3.4.21",get config(){}}`, "vue@3.4.21"},
		{"vue 3: two values", `var fs="3.3.4";fs="1.0.0";x={_context:r,_instance:null,version:fs}`, ""},
		{"vue 2", `Object.defineProperty(lo,"FunctionalRenderContext",{value:En}),lo.version="2.7.14";`, "vue@2.7.14"},
		{"vue 2 identifier", `var pn="2.7.14";Object.defineProperty(Cr,"FunctionalRenderContext",{value:Hn}),Cr.version=pn;`, "vue@2.7.14"},
		{"angular", `var Xe=new Ab("17.0.4");function Ru(t,n){Su(n,t,["ng-version",Xe.full])}`, "@angular/core@17.0.4"},
		{"angular: ambiguous", `var Xe=new Ab("1.0.0");Xe=new Ab("2.0.0");el.setAttribute("ng-version",Xe.full)`, ""},
		{"angular: no constant", `el.setAttribute("ng-version",cfg.full)`, ""},
		{"angularjs errors", `c="["+(a?a+":":"")+d+"] http://errors.angularjs.org/1.8.2/"+(a?a+"/":"")+d`, "angular@1.8.2"},
		{"angularjs version", `Pe={full:"1.8.2",major:1,minor:8,dot:2,codeName:"meteoric-mining"};`, "angular@1.8.2"},
		{"angularjs: other errors URL", `var u="https://errors.example.org/1.2.3/"`, ""},
		{"jquery 3", `var f="3.6.0",S=function(e,t){return new S.fn.init(e,t)};S.fn=S.prototype={jquery:f}`, "jquery@3.6.0"},
		{"jquery 3.7", `var r="3.7.1",i=/HTML$/i,ce=function(e,t){return new ce.fn.init(e,t)};`, "jquery@3.7.1"},
		{"jquery slim", `var f="3.6.0 -ajax,-ajax/jsonp,-effects",E=function(e,t){return new E.fn.init(e,t)};`, "jquery@3.6.0"},
		{"jquery unminified", "\tversion = \"1.12.4\",\n\n\t// Define a local copy of jQuery\n\tjQuery = function( selector, context ) {\n\n\t\t// comment\n\t\treturn new jQuery.fn.init( selector, context );\n\t}", "jquery@1.12.4"},
		{"jquery: config", `var config={VERSION:"3.6.0"};var x=function(a,b){return new Thing(a,b)}`, ""},
		{"jquery ui", `(function(V){"use strict";V.ui=V.ui||{};V.ui.version="1.13.2";var n})`, "jquery-ui@1.13.2"},
		{"jquery ui 1.12", "$.ui = $.ui || {};\n\nvar version = $.ui.version = \"1.12.1\";", "jquery-ui@1.12.1"},
		{"jquery ui: own namespace", `app.ui.version="1.13.2";`, ""},
		{"bootstrap 5", "static get VERSION(){return\"5.3.2\"}static get DATA_KEY(){return`bs.${this.NAME}`}", "bootstrap@5.3.2"},
		{"bootstrap 5 esm", "const VERSION = '5.3.2';\nclass BaseComponent {\n  static get VERSION() {\n    return VERSION;\n  }\n  static get DATA_KEY() {\n    return `bs.${this.NAME}`;\n  }\n}", "bootstrap@5.3.2"},
		{"bootstrap 4", `l(t,null,[{key:"VERSION",get:function(){return"4.6.2"}}]),t}();o.default(document).on("click.bs.alert.data-api",'[data-dismiss="alert"]'`, "bootstrap@4.6.2"},
		{"bootstrap 4 unminified", "  var VERSION$a = '4.6.2';\n  var DATA_KEY$a = 'bs.alert';", "bootstrap@4.6.2"},
		{"bootstrap: getter only", `[{key:"VERSION",get:function(){return"4.6.2"}}];x.on("click.app.menu")`, ""},
		{"lodash", `var X,nn="4.17.21",tn=200,rn="Unsupported core-js use. Try https://npms.io/search?q=ponyfill.",en="Expected a function"`, "lodash@4.17.21"},
		{"lodash unminified", "  var VERSION = '4.17.21';\n\n  /** Used as the size to enable large array optimizations. */\n  var LARGE_ARRAY_SIZE = 200;\n\n  /** Error message constants. */\n  var CORE_ERROR_TEXT = 'Unsupported core-js use. Try https://npms.io/search?q=ponyfill.',", "lodash@4.17.21"},
		{"lodash 4.17.4", `{chain:false}),On.VERSION="4.17.4",u("bind bindKey curry curryRight partial partialRight".split(" "),function(n){`, "lodash@4.17.4"},
		{"lodash: bare VERSION", `var VERSION="4.17.21";var size=200;`, ""},
		{"moment", `f.version="2.29.4",H=W,f.fn=i,f.min=function(){return Rt("isBefore",[].slice.call(arguments,0))}`, "moment@2.29.4"},
		{"moment unminified", "    hooks.version = '2.29.4';\n\n    setHookCallback(createLocal);\n\n    hooks.fn = proto;\n    hooks.min = min;", "moment@2.29.4"},
		{"moment: other library", `lib.version="2.29.4",x=1,lib.go=i;`, ""},
		{"handlebars", `n="4.7.7";b.VERSION=n;var o=8;b.COMPILER_REVISION=o;`, "handlebars@4.7.7"},
		{"handlebars inlined", `t.VERSION="4.7.8";t.COMPILER_REVISION=8;`, "handlebars@4.7.8"},
		{"dompurify", `const o=e=>t(e);if(o.version="3.0.6",o.removed=[],!n||!n.document)return o`, "dompurify@3.0.6"},
		{"dompurify unminified", "    DOMPurify.version = '3.0.6';\n    /**\n     * Array of elements that DOMPurify removed during sanitation.\n     */\n\n    DOMPurify.removed = [];", "dompurify@3.0.6"},
		{"axios", `var Ne="1.6.0",xe={};["object","boolean","number","function","string","symbol"].forEach(((e,t)=>{`, "axios@1.6.0"},
		{"next app router", `window.next={version:"14.2.3",appDir:!0};`, "next@14.2.3"},
		{"next pages router", `let o="13.5.6",a,i=(0,s.default)(),l=e=>[].slice.call(e),c,u;`, "next@13.5.6"},
		{"chart.js 4", `static registry=en;static version="4.4.0";static getChart=Dn;`, "chart.js@4.4.0"},
		{"chart.js 3", `Chart.registry=registry,Chart.version="3.9.1",Chart.getChart=getChart`, "chart.js@3.9.1"},
	}
	for _, c := range cases {
		var got []string
		for _, s := range codeSigs {
			if m, ok := s.find([]byte(c.code)); ok {
				got = append(got, m.npm+"@"+m.version)
			}
		}
		want := []string{}
		if c.want != "" {
			want = []string{c.want}
		}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: found %v, want %v", c.name, got, want)
		}
	}
}

// TestLooseSignatureMatchesNegative is the negative control: each negative
// case above is a near miss, which a signature loosened by the part that
// makes it precise would report. If this fails, the negative case no
// longer tests anything.
func TestLooseSignatureMatchesNegative(t *testing.T) {
	cases := []struct{ loose, code string }{
		// React without the hook dispatcher (.current / .H).
		{`\.useTransition\s*=\s*function\s*\(\)\s*\{\s*return\s+[\w$.]+\.useTransition\(\)\s*\}\s*[,;]\s*[\w$]+\.version\s*=\s*` + lit,
			`t.useTransition=function(){return store.useTransition()},t.version="2.1.0"`},
		// ReactDOM without the package name.
		{`version\s*:\s*` + lit + `\s*,\s*rendererPackageName`, `{bundleType:0,version:"0.9.1",rendererPackageName:"react-three-fiber"}`},
		// jQuery UI without its namespace line.
		{`\.ui\.version\s*=\s*` + lit, `app.ui.version="1.13.2";`},
		// Bootstrap 4's getter without a data-api event.
		{`key\s*:\s*` + q + `VERSION` + q + `\s*,\s*get\s*:\s*function\s*\(\)\s*\{\s*return\s*` + lit, `[{key:"VERSION",get:function(){return"4.6.2"}}];x.on("click.app.menu")`},
		// lodash's VERSION without its neighbours.
		{`VERSION\s*=\s*` + lit, `var VERSION="4.17.21";var size=200;`},
		// moment without fn and min.
		{`\.version\s*=\s*` + lit, `lib.version="2.29.4",x=1,lib.go=i;`},
		// A banner anywhere, not only in a licence comment.
		{`Bootstrap v` + ver + ` \(https://getbootstrap\.com/\)`, `var msg="Bootstrap v4.6.2 (https://getbootstrap.com/) is loaded";`},
	}
	for _, c := range cases {
		if !regexp.MustCompile(c.loose).MatchString(c.code) {
			t.Errorf("loosened %q does not match %q: the negative case tests nothing", c.loose, c.code)
		}
	}
	// And with the real signature set, the negative fixture is clean.
	data, err := os.ReadFile(filepath.Join(bundleFixtures, "srv/lookalike/public/assets/app-1a2b3c4d.js"))
	if err != nil {
		t.Fatal(err)
	}
	if m := scanBundle("app-1a2b3c4d.js", data); len(m) != 0 {
		t.Errorf("negative fixture matched %+v", m)
	}
}

func TestLegalBanners(t *testing.T) {
	cases := []struct {
		code string
		want string
	}{
		{`!function(){};/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors | jquery.org/license */!function(e,t){}`, "jquery@3.6.0"},
		{"x();/**\n * @license AngularJS v1.8.2\n * (c) 2010-2020 Google LLC. http://angularjs.org\n */", "angular@1.8.2"},
		{"a();/*!\n * Bootstrap v5.3.2 (https://getbootstrap.com/)\n */", "bootstrap@5.3.2"},
		{"//! moment.js\n//! version : 2.29.4\n", "moment@2.29.4"},
		{"/*! @license DOMPurify 3.0.6 | (c) Cure53 */", "dompurify@3.0.6"},
		// Ordinary comments and strings are the application's own.
		{"/* uses jQuery v3.6.0 from the CDN */ // jQuery v3.6.0 is required\n", ""},
		{`var msg="Bootstrap v4.6.2 (https://getbootstrap.com/) is loaded";`, ""},
		{"/*! MyWidget v1.2.3 | (c) Example Ltd */", ""},
		// A @license that is not inside a comment.
		{`var s="@license jQuery v3.6.0";`, ""},
	}
	for _, c := range cases {
		var got []string
		for _, m := range legalBanners("bundle.js", []byte(c.code)) {
			got = append(got, m.npm+"@"+m.version)
		}
		if strings.Join(got, ",") != c.want {
			t.Errorf("%q: found %v, want %q", c.code, got, c.want)
		}
	}
}

func TestSourceMapPackages(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(bundleFixtures, "srv/shop/build/static/js/main.3f2a1b9c.js.map"))
	if err != nil {
		t.Fatal(err)
	}
	versioned, unversioned, err := sourceMapPackages(data)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range versioned {
		got = append(got, v[0]+":"+v[1]+"@"+v[2])
	}
	want := "npm:@floating-ui/dom@1.5.3,npm:chart.js@4.4.0,npm:uuid@9.0.1,npm:zod@3.22.4"
	if strings.Join(got, ",") != want {
		t.Errorf("versioned = %v, want %s", got, want)
	}
	// jQuery is only mentioned in the application's own source text.
	if u := strings.Join(unversioned, ","); u != "@tanstack/react-query,axios,not-a-package-json,react,react-dom" {
		t.Errorf("unversioned = %s", u)
	}
	pub := []byte(`{"version":3,"sources":["org-dartlang-sdk:///lib/core/core.dart","../../../../.pub-cache/hosted/pub.dev/http-1.2.2/lib/src/client.dart","packages/provider/provider.dart"]}`)
	versioned, unversioned, _ = sourceMapPackages(pub)
	if len(versioned) != 1 || versioned[0] != [3]string{"pub", "http", "1.2.2"} || len(unversioned) != 0 {
		t.Errorf("pub map = %v %v", versioned, unversioned)
	}
	if _, _, err := sourceMapPackages([]byte("not json")); err == nil {
		t.Error("a broken map should fail")
	}
}

func coverageOf(a App, scope string) (model.CoverageItem, bool) {
	for _, c := range a.Coverage {
		if c.Scope == scope {
			return c, true
		}
	}
	return model.CoverageItem{}, false
}

// The real case: a Flutter web build deployed to /var/www/chat.
func TestScanFlutterWebBuild(t *testing.T) {
	s := &Scanner{Root: bundleFixtures}
	a := s.ScanApp(context.Background(), "/var/www/chat")
	validate(t, a)
	m := purls(a.Observations)
	o, ok := m["pkg:generic/flutter-engine@18818009497c581ede5d8a3b8b833b81d00cebb7"]
	if !ok || len(m) != 1 {
		t.Fatalf("observations = %v", keys(m))
	}
	if o.Confidence != model.ConfidenceConfirmed || o.Location != "/var/www/chat/flutter_bootstrap.js" ||
		o.Evidence["source"] != "flutter-build" || o.Evidence["renderer"] != "canvaskit, skwasm" || o.Evidence["signature"] == "" {
		t.Errorf("engine = %+v", o)
	}
	c, ok := coverageOf(a, "flutter:/var/www/chat")
	if !ok || c.Status != "partial" || !strings.Contains(c.Reason, "dart2js; renderer canvaskit, skwasm") ||
		!strings.Contains(c.Reason, "Dart packages compiled into main.dart.js are not recorded") {
		t.Errorf("coverage = %+v", a.Coverage)
	}

	// Before flutter_bootstrap.js, only main.dart.js names the engine.
	a = s.ScanApp(context.Background(), "/srv/legacy-flutter/web")
	validate(t, a)
	if o, ok := purls(a.Observations)["pkg:generic/flutter-engine@c4cd48e186460b32d44585ce3c103271ab676355"]; !ok ||
		o.Location != "/srv/legacy-flutter/web/main.dart.js" {
		t.Errorf("legacy = %+v", a.Observations)
	}

	// A build that names no engine: said, not left at 0.
	a = s.ScanApp(context.Background(), "/srv/flutter-norev")
	if len(a.Observations) != 0 {
		t.Errorf("norev = %v", a.Observations)
	}
	if c, ok := coverageOf(a, "flutter:/srv/flutter-norev"); !ok || !strings.Contains(c.Reason, "no engine revision found") {
		t.Errorf("norev coverage = %+v", a.Coverage)
	}
}

func TestScanJSBundles(t *testing.T) {
	s := &Scanner{Root: bundleFixtures}
	type want struct {
		conf      model.Confidence
		source    string
		signature string // a part of it
		location  string
	}
	check := func(dir string, wants map[string]want) App {
		t.Helper()
		a := s.ScanApp(context.Background(), dir)
		validate(t, a)
		m := purls(a.Observations)
		if len(m) != len(wants) {
			t.Errorf("%s: found %v", dir, keys(m))
		}
		for p, w := range wants {
			o, ok := m[p]
			if !ok {
				t.Errorf("%s: missing %s; have %v", dir, p, keys(m))
				continue
			}
			if o.Confidence != w.conf || o.Evidence["source"] != w.source || !strings.Contains(o.Evidence["signature"], w.signature) ||
				o.Location != w.location || o.Evidence["app_dir"] != dir {
				t.Errorf("%s: %s = %+v", dir, p, o)
			}
			if w.source == "bundle" && o.Evidence["match"] == "" {
				t.Errorf("%s: %s has no matched text", dir, p)
			}
		}
		return a
	}
	const cra = "/srv/shop/build/static/js/main.3f2a1b9c.js"
	shop := check("/srv/shop/build", map[string]want{
		"pkg:npm/react@18.2.0":             {model.ConfidenceConfirmed, "bundle", "React version export", cra},
		"pkg:npm/react-dom@18.2.0":         {model.ConfidenceConfirmed, "bundle", "ReactDOM renderer version", cra},
		"pkg:npm/lodash@4.17.21":           {model.ConfidenceConfirmed, "bundle", "lodash VERSION", cra},
		"pkg:npm/moment@2.29.4":            {model.ConfidenceConfirmed, "bundle", "moment version", cra},
		"pkg:npm/handlebars@4.7.7":         {model.ConfidenceConfirmed, "bundle", "Handlebars VERSION", cra},
		"pkg:npm/bootstrap@4.6.2":          {model.ConfidenceConfirmed, "bundle", "licence banner", cra + ".LICENSE.txt"},
		"pkg:npm/dompurify@2.4.0":          {model.ConfidenceConfirmed, "bundle", "licence banner", cra + ".LICENSE.txt"},
		"pkg:npm/chart.js@4.4.0":           {model.ConfidenceInferred, "source-map", "package path", cra + ".map"},
		"pkg:npm/%40floating-ui/dom@1.5.3": {model.ConfidenceInferred, "source-map", "package path", cra + ".map"},
		"pkg:npm/zod@3.22.4":               {model.ConfidenceInferred, "source-map", "package path", cra + ".map"},
		"pkg:npm/uuid@9.0.1":               {model.ConfidenceInferred, "source-map", "package path", cra + ".map"},
	})
	if c, ok := coverageOf(shop, "bundles:/srv/shop/build"); !ok || c.Status != "partial" || !strings.Contains(c.Reason, "11 component(s) identified") {
		t.Errorf("shop bundles coverage = %+v", shop.Coverage)
	}
	if c, ok := coverageOf(shop, "source-maps:/srv/shop/build"); !ok || c.Status != "partial" ||
		!strings.Contains(c.Reason, "3 npm package(s)") || !strings.Contains(c.Reason, "@tanstack/react-query, axios, not-a-package-json") {
		t.Errorf("shop source map coverage = %+v", shop.Coverage)
	}

	const vite, vendor = "/srv/dash/dist/assets/index-Dk53Pw_R.js", "/srv/dash/dist/assets/vendor-BX1a2c3d.js"
	dash := check("/srv/dash/dist", map[string]want{
		"pkg:npm/react@19.1.0":     {model.ConfidenceConfirmed, "bundle", "React version export", vite},
		"pkg:npm/react-dom@19.1.0": {model.ConfidenceConfirmed, "bundle", "ReactDOM", vite},
		"pkg:npm/next@14.2.3":      {model.ConfidenceConfirmed, "bundle", "window.next", vite},
		"pkg:npm/chart.js@4.4.0":   {model.ConfidenceConfirmed, "bundle", "Chart.js", vite},
		"pkg:npm/jquery@3.6.0":     {model.ConfidenceConfirmed, "bundle", "licence banner", vite},
		"pkg:npm/jquery-ui@1.13.2": {model.ConfidenceConfirmed, "bundle", "jQuery UI", vite},
		"pkg:npm/vue@3.3.4":        {model.ConfidenceInferred, "bundle", "Vue 3 application version (through fs)", vendor},
		"pkg:npm/bootstrap@5.3.2":  {model.ConfidenceConfirmed, "bundle", "Bootstrap", vendor},
		"pkg:npm/dompurify@3.0.6":  {model.ConfidenceConfirmed, "bundle", "DOMPurify", vendor},
		"pkg:npm/axios@1.6.0":      {model.ConfidenceConfirmed, "bundle", "axios", vendor},
	})
	// jQuery is named by its banner and its constant: one component.
	if c, ok := coverageOf(dash, "bundles:/srv/dash/dist"); !ok || !strings.Contains(c.Reason, "10 component(s) identified") {
		t.Errorf("dash bundles coverage = %+v", dash.Coverage)
	}
	check("/srv/admin/dist/browser", map[string]want{
		"pkg:npm/%40angular/core@17.0.4": {model.ConfidenceInferred, "bundle", "ng-version", "/srv/admin/dist/browser/main-ABCD1234.js"},
	})
	check("/srv/legacy", map[string]want{
		"pkg:npm/angular@1.5.8": {model.ConfidenceConfirmed, "bundle", "AngularJS", "/srv/legacy/public/js/app.bundle.js"},
	})
}

// Compiled output in which nothing is identifiable reports so, rather
// than an application with no components.
func TestBundleNothingIdentifiable(t *testing.T) {
	a := (&Scanner{Root: bundleFixtures}).ScanApp(context.Background(), "/srv/lookalike")
	validate(t, a)
	if len(a.Observations) != 0 {
		t.Errorf("lookalike reported %v", keys(purls(a.Observations)))
	}
	c, ok := coverageOf(a, "bundles:/srv/lookalike")
	if !ok || c.Status != "unsupported" || !strings.HasPrefix(c.Reason, "compiled front-end bundle, components not identifiable") {
		t.Errorf("coverage = %+v", a.Coverage)
	}
}

// A library a manifest reports is not reported again from the bundle; a
// WordPress core bundle is the copy WordPress maintains.
func TestBundleYieldsToManifestAndWordPress(t *testing.T) {
	tr := newTree(t)
	tr.file("srv/app/package.json", `{"name":"app","dependencies":{"react":"18.2.0"}}`)
	tr.npm("srv/app/node_modules/react", "react", "18.2.0")
	tr.file("srv/app/dist/main.0a1b2c3d.js", `t.useTransition=function(){return U.current.useTransition()},t.version="18.2.0"`)
	a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/srv/app")
	if o := purls(a.Observations)["pkg:npm/react@18.2.0"]; o.Evidence["source"] != "installed" || len(a.Observations) != 1 {
		t.Errorf("react = %+v (all %v)", o, keys(purls(a.Observations)))
	}

	tr.file("var/www/wp/wp-config.php", "<?php")
	tr.file("var/www/wp/wp-includes/js/dist/vendor/react.min.js",
		`/*! This file is auto-generated */`+"\n"+`(()=>{var __webpack_require__={};t.useTransition=function(){return U.current.useTransition()},t.version="18.3.1"})();`)
	a = (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/var/www/wp")
	o := purls(a.Observations)["pkg:npm/react@18.3.1"]
	if o.Confidence != model.ConfidenceInferred || o.Evidence["bundled_with"] != "WordPress" {
		t.Errorf("wordpress react = %+v", o)
	}
}

func TestBundleBounds(t *testing.T) {
	defer func(s, f, h int) { bundleSize, bundleFiles, bundleHostBytes = s, f, h }(bundleSize, bundleFiles, bundleHostBytes)

	// A file larger than the cap is not read, and that is said.
	bundleSize = 1 << 10
	tr := newTree(t)
	tr.file("srv/big/assets/index-0a1b2c3d.js", "/*! For license information please see x */\n"+strings.Repeat("a", 2<<10)+
		`t.useTransition=function(){return U.current.useTransition()},t.version="18.2.0"`)
	tr.file("srv/big/assets/small-1a2b3c4d.js", `e.useTransition=function(){return T.H.useTransition()},e.version="19.0.0"`)
	a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/srv/big")
	validate(t, a)
	if m := purls(a.Observations); len(m) != 1 || m["pkg:npm/react@19.0.0"].Purl == "" {
		t.Errorf("observations = %v", keys(m))
	}
	c, ok := coverageOf(a, "bundle-limits:/srv/big")
	if !ok || c.Status != "partial" || c.Reason != "1 file(s) larger than 1 KiB not read (/srv/big/assets/index-0a1b2c3d.js)" {
		t.Errorf("coverage = %+v", a.Coverage)
	}

	// The number of files per application.
	bundleSize, bundleFiles = maxBundleSize, 1
	a = (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/srv/big")
	if c, ok := coverageOf(a, "bundle-limits:/srv/big"); !ok || c.Reason != "stopped after 1 compiled bundles and source maps" {
		t.Errorf("file limit coverage = %+v", a.Coverage)
	}
	if len(a.Observations) != 1 {
		t.Errorf("file limit observations = %v", keys(purls(a.Observations)))
	}

	// The bytes read across a host's applications.
	bundleFiles, bundleHostBytes = maxBundleFiles, 3<<10
	tr.file("srv/other/assets/index-2a3b4c5d.js", strings.Repeat("b", 2<<10))
	s := &Scanner{Root: tr.root}
	s.ScanApp(context.Background(), "/srv/big") // reads about 2.1 KiB
	a = s.ScanApp(context.Background(), "/srv/other")
	if c, ok := coverageOf(a, "bundle-limits:/srv/other"); !ok || c.Reason != "stopped after reading 3 KiB of compiled bundles on this host" {
		t.Errorf("host limit coverage = %+v", a.Coverage)
	}
}

// A plain site's scripts are not read whole: only build output is.
func TestBundleFile(t *testing.T) {
	cases := []struct {
		rel, head string
		want      bool
	}{
		{"static/js/main.3f2a1b9c.js", "", true},
		{"assets/index-dk53pw_r.js", "", true},
		{"_next/static/chunks/framework.js", "", true},
		{"js/app.bundle.js", "", true},
		{"js/site.js", "(()=>{var __webpack_modules__={}})()", true},
		{"js/site.js", "jQuery(function($){ $('.menu').show() })", false},
		{"js/jquery-3.6.0.min.js", "", false},
		{"js/bootstrap.bundle.min.js", "", false},
		{"js/custom-template.js", "", false},
	}
	for _, c := range cases {
		if got := bundleFile(c.rel, filepath.Base(c.rel), []byte(c.head)); got != c.want {
			t.Errorf("%s = %v, want %v", c.rel, got, c.want)
		}
	}
}
