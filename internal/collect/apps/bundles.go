package apps

// Compiled front-end output: webpack, Vite, Rollup and esbuild bundles, and
// Flutter web builds. A deployed single-page application often has no
// manifest, lockfile or node_modules next to it, only the files the build
// wrote, and the libraries compiled into them lose their package metadata.
// What survives is read here, and only what names a library and its exact
// release with little room for doubt:
//
//   - a library's licence banner, kept by minifiers (/*! jQuery v3.6.0 */,
//     /** @license ... */) or extracted to main.js.LICENSE.txt;
//   - a version constant in the library's own code shape, where the
//     surrounding code is the library's and not someone's (React's
//     version export after useTransition, ReactDOM's rendererPackageName,
//     lodash's "Unsupported core-js use", AngularJS's errors URL);
//   - a source map next to a bundle, whose source paths name the packages
//     compiled in, with a version only where the path or an embedded
//     package.json carries one;
//   - a Flutter web build's engine revision (flutter_bootstrap.js,
//     main.dart.js).
//
// Anything else in a bundle is not identifiable, and that is reported as
// coverage rather than left as an application with no components.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Limits on reading compiled output. A bundle is read whole, unlike a
// library file's banner, so these are tighter than a site's templates.
const (
	maxBundleSize     = 16 << 20  // a bundle, source map or Flutter file larger than this is not read
	maxBundleFiles    = 1000      // bundles and source maps read per application
	maxBundleHostSize = 256 << 20 // bytes read from bundles per host scan, all applications together
	maxNeedleHits     = 4000      // places one signature is tried per file
	bundlesScopeID    = "bundles:"
)

// bundleSize, bundleFiles and bundleHostBytes are the limits; tests lower them.
var bundleSize, bundleFiles, bundleHostBytes = maxBundleSize, maxBundleFiles, maxBundleHostSize

// q is a JavaScript string quote: minifiers emit ', " or ` (Vite 8).
const q = "[\"'`]"

// ws is whitespace and comments between tokens of unminified output.
const ws = `(?:\s|//[^\n]*\n|/\*(?:[^*]|\*[^/]){0,400}\*/)*`

// lit is a version literal, captured as v; ident an identifier holding
// one, captured as id and resolved (see codeSig.resolve).
const (
	lit   = q + `(?P<v>\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?)` + q
	ident = `(?P<id>[A-Za-z_$][\w$]*)`
)

// jqLit is jQuery's version: a custom build (slim) adds the modules it
// leaves out ("3.6.0 -ajax,-ajax/jsonp,...").
const jqLit = q + `(?P<v>\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?)(?: [-+][\w/,+-]{1,800})?` + q

// codeSig is one library's version constant in the shape of its own code.
// Each pattern is tried only near an occurrence of needle, in the window
// before and after it, so one file is never searched end to end per
// pattern and the context the version needs is close by.
type codeSig struct {
	npm, name     string
	needle        string
	before, after int
	res           []*regexp.Regexp
	// resolve finds the literal an identifier match points to: a format
	// with %s for the identifier; "" for a plain assignment.
	resolve string
}

func sig(npm, name, needle string, before, after int, res ...string) codeSig {
	s := codeSig{npm: npm, name: name, needle: needle, before: before, after: after}
	for _, r := range res {
		s.res = append(s.res, regexp.MustCompile(r))
	}
	return s
}

// codeSigs are the version constants recognised in bundles. Each was
// checked against the library's published files (minified and not) and
// has a test fixture; a version-looking constant without this context is
// never reported.
var codeSigs = []codeSig{
	// React 16.8 to 19: the last export of react is version, after the
	// hooks (useTransition from 18, useState before). React 16.0-16.7 keep
	// it in an object beside the secret internals.
	sig("react", "React version export", "useTransition", 40, 260,
		`\.useTransition\s*=\s*function\s*\(\)\s*\{`+ws+`return\s+[\w$]+(?:\.current|\.H|\(\))\.useTransition\(\)\s*;?`+ws+`\}\s*[,;]`+ws+`[\w$]+\.version\s*=\s*`+lit),
	sig("react", "React version export", "useState", 40, 260,
		`\.useState\s*=\s*function\s*\(\s*[\w$]+\s*\)\s*\{`+ws+`return\s+[\w$]+(?:\.current|\.H|\(\))\.useState\(\s*[\w$]+\s*\)\s*;?`+ws+`\}\s*[,;]`+ws+`[\w$]+\.version\s*=\s*`+lit),
	sig("react", "React version beside its internals", "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED", 60, 10,
		`[{,]\s*version\s*:\s*`+lit+`\s*,\s*__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED\s*:`),
	sig("react-dom", "ReactDOM renderer version", "rendererPackageName", 80, 40,
		`version\s*:\s*`+lit+`\s*,\s*rendererPackageName\s*:\s*`+q+`react-dom`+q),
	sig("vue", "Vue 3 application version", "_instance", 80, 80,
		`_context\s*:\s*[\w$]+\s*,\s*_instance\s*:\s*null\s*,\s*version\s*:\s*(?:`+lit+`|`+ident+`)`,
		`_context\s*:\s*[\w$]+\s*,\s*_instance\s*:\s*null\s*,\s*(?P<id>version)\s*,`),
	sig("vue", "Vue 2 version", "FunctionalRenderContext", 10, 160,
		q+`FunctionalRenderContext`+q+`\s*,\s*\{\s*value\s*:\s*[\w$]+\s*\}\s*\)\s*[,;]`+ws+`[\w$]+\.version\s*=\s*(?:`+lit+`|`+ident+`)`),
	{npm: "@angular/core", name: "Angular ng-version attribute", needle: "ng-version", before: 10, after: 60,
		res:     []*regexp.Regexp{regexp.MustCompile(q + `ng-version` + q + `\s*,\s*` + ident + `\.full\b`)},
		resolve: `(?:^|[^\w$.])%s\s*=\s*new\s+[\w$.]+\(\s*` + lit + `\s*\)`},
	sig("angular", "AngularJS errors address", "errors.angularjs.org/", 10, 40,
		`errors\.angularjs\.org/(?P<v>\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?)/`),
	sig("angular", "AngularJS version object", "codeName", 120, 10,
		`\{\s*full\s*:\s*`+lit+`\s*,\s*major\s*:\s*\d+\s*,\s*minor\s*:\s*\d+\s*,\s*dot\s*:\s*\d+\s*,\s*codeName\s*:`),
	// jQuery 1 to 3: the version beside the jQuery function itself (3.7
	// adds a regular expression between them).
	sig("jquery", "jQuery version constant", ".fn.init(", 1200, 10,
		jqLit+`\s*,`+ws+`(?:[\w$]+\s*=\s*/[^/\n]{1,40}/[a-z]*\s*,`+ws+`)?[\w$]+\s*=\s*function\s*\(\s*[\w$]+\s*,\s*[\w$]+\s*\)\s*\{`+ws+`return\s+new\s+[\w$]+\.fn\.init\(`),
	sig("jquery-ui", "jQuery UI version", ".ui.version", 80, 40,
		`\.ui\s*=\s*[\w$]+\.ui\s*\|\|\s*\{\}\s*[;,]`+ws+`(?:return\s+|var\s+[\w$]+\s*=\s*)?[\w$]+\.ui\.version\s*=\s*`+lit),
	// Bootstrap 5 components, 4's unminified (VERSION then DATA_KEY) and
	// minified (the VERSION getter then a data-api event) forms.
	sig("bootstrap", "Bootstrap component VERSION", "DATA_KEY", 140, 60,
		`get\s+VERSION\s*\(\)\s*\{`+ws+`return\s*(?:`+lit+`|`+ident+`)\s*;?`+ws+`\}`+ws+`(?:static\s+)?get\s+DATA_KEY\s*\(\)\s*\{`+ws+`return\s*`+q+`?bs\.`,
		lit+`\s*;?`+ws+`(?:var|const|let)\s+DATA_KEY[\w$]*\s*=\s*`+q+`bs\.[a-z]+`+q),
	sig("bootstrap", "Bootstrap component VERSION", "VERSION", 10, 600,
		`\{\s*key\s*:\s*`+q+`VERSION`+q+`\s*,\s*get\s*:\s*function(?:\s+[\w$]+)?\s*\(\)\s*\{\s*return\s*`+lit+`\s*;?\s*\}\s*\}(?s:.{0,500}?)`+q+`[a-z]+\.bs\.[a-z]+\.data-api`),
	{npm: "lodash", name: "lodash VERSION", needle: "Unsupported core-js use", before: 300, after: 30,
		res: []*regexp.Regexp{regexp.MustCompile(lit + `\s*[,;]` + ws + `(?:var\s+)?[\w$]+\s*=\s*200\s*[,;]` + ws + `(?:var\s+)?[\w$]+\s*=\s*` + q + `Unsupported core-js use`)}},
	sig("lodash", "lodash VERSION", "bindKey", 200, 40,
		`\.VERSION\s*=\s*`+lit+`\s*[,;]`+ws+`[\w$.]+\(\s*(?:`+q+`bind bindKey|\[\s*`+q+`bind`+q+`\s*,\s*`+q+`bindKey)`),
	sig("moment", "moment version", ".version", 10, 200,
		`\.version\s*=\s*`+lit+`\s*[,;][^;,]{0,60}[,;]\s*[\w$]+\.fn\s*=\s*[\w$]+\s*[,;]\s*[\w$]+\.min\s*=`),
	sig("handlebars", "Handlebars VERSION", "COMPILER_REVISION", 200, 10,
		lit+`\s*;?`+ws+`[\w$]+\.VERSION\s*=\s*[\w$]+\s*[;,]`+ws+`(?:var\s+)?[\w$]+\s*=\s*\d+\s*[;,]`+ws+`[\w$]+\.COMPILER_REVISION\s*=`,
		`\.VERSION\s*=\s*`+lit+`\s*[;,]`+ws+`[\w$]+\.COMPILER_REVISION\s*=`),
	sig("dompurify", "DOMPurify version", ".removed", 500, 30,
		`\.version\s*=\s*`+lit+`\s*[,;]`+ws+`[\w$]+\.removed\s*=\s*\[\]`),
	sig("axios", "axios VERSION", "symbol", 600, 30,
		lit+`\s*[,;]`+ws+`(?:(?:var|let|const)\s+)?[\w$]+\s*=\s*\{\}\s*[,;]`+ws+`\[\s*`+q+`object`+q+`\s*,\s*`+q+`boolean`+q+`\s*,\s*`+q+`number`+q+`\s*,\s*`+q+`function`+q+`\s*,\s*`+q+`string`+q+`\s*,\s*`+q+`symbol`+q+`\s*\]\s*\.forEach`),
	// Next.js: the app router's window.next, and the pages router's
	// client module (version, router, emitter, looseToArray).
	sig("next", "Next.js window.next version", "window.next", 10, 60,
		`window\.next\s*=\s*\{\s*version\s*:\s*`+lit,
		`window\.next\s*=\s*\{\s*(?P<id>version)\s*,`),
	sig("next", "Next.js client version", "slice.call(", 300, 20,
		lit+`\s*[,;]`+ws+`(?:let\s+)?[\w$]+\s*[,;]`+ws+`(?:const\s+)?[\w$]+\s*=\s*\(\s*0\s*,\s*[\w$]+\.default\s*\)\(\)\s*[,;]`+ws+`(?:const\s+)?[\w$]+\s*=\s*(?:\(\s*[\w$]+\s*\)|[\w$]+)\s*=>\s*\[\]\.slice\.call\(`),
	sig("chart.js", "Chart.js version", "getChart", 120, 20,
		`static\s+version\s*=\s*(?:`+lit+`|`+ident+`)\s*;?\s*static\s+getChart\s*=`,
		`\.version\s*=\s*(?:`+lit+`|`+ident+`)\s*[,;]\s*[\w$]+\.getChart\s*=`),
}

// legalNeedles start the comments minifiers keep: /*! and //! by
// convention, and any comment with @license or @preserve.
var legalNeedles = []string{"/*!", "//!", "@license", "@preserve"}

// bundleMarkers in the first bytes of a script say a bundler wrote it.
var bundleMarkers = []string{"__webpack_require__", "__webpack_modules__", "__webpack_exports__", "webpackChunk", "webpackJsonp", "/*! For license information please see",
	"__vite__", "__vitePreload", "System.register(", "=Object.create,", "=Object.defineProperty,"}

// hashedName is a build's content-hashed file name: main.3f2a1b9c.js,
// index-Dk53Pw_R.js, framework-2c79e2a64abdb08b.js.
var hashedName = regexp.MustCompile(`[.-]([0-9a-z_-]{8,})(?:\.chunk|\.bundle)?(?:\.min)?\.m?js$`)

var bundleNames = map[string]bool{"bundle.js": true, "main.js": true, "app.js": true, "vendor.js": true, "vendors.js": true,
	"runtime.js": true, "polyfills.js": true, "chunk-vendors.js": true, "index.js": true}

// bundleFile reports whether a script (rel: its path in the application)
// looks like a bundler's output and is worth reading whole.
func bundleFile(rel, name string, head []byte) bool {
	if bundleNames[name] || strings.HasSuffix(name, ".bundle.js") || strings.HasSuffix(name, ".chunk.js") {
		return true
	}
	if m := hashedName.FindStringSubmatch(name); m != nil && strings.ContainsAny(m[1], "0123456789") {
		return true
	}
	for _, d := range []string{"/_next/static/", "/static/js/"} {
		if strings.Contains("/"+rel, d) {
			return true
		}
	}
	for _, m := range bundleMarkers {
		if bytes.Contains(head, []byte(m)) {
			return true
		}
	}
	return false
}

// bundleMatch is one library found in compiled output.
type bundleMatch struct {
	npm, version, signature, snippet string
	confidence                       model.Confidence
}

// scanBundle finds the libraries in a compiled script.
func scanBundle(name string, data []byte) []bundleMatch {
	out := legalBanners(name, data)
	for _, s := range codeSigs {
		if m, ok := s.find(data); ok {
			out = append(out, m)
		}
	}
	return out
}

func (s codeSig) find(data []byte) (bundleMatch, bool) {
	needle := []byte(s.needle)
	for i, hits := 0, 0; hits < maxNeedleHits; hits++ {
		j := bytes.Index(data[i:], needle)
		if j < 0 {
			break
		}
		at := i + j
		lo, hi := max(at-s.before, 0), min(at+len(needle)+s.after, len(data))
		win := data[lo:hi]
		for _, re := range s.res {
			m := re.FindSubmatchIndex(win)
			if m == nil {
				continue
			}
			snippet := string(win[m[0]:m[1]])
			if v := group(re, win, m, "v"); v != "" {
				if exactVersion.MatchString(v) {
					return bundleMatch{npm: s.npm, version: v, signature: s.name, snippet: snippet, confidence: model.ConfidenceConfirmed}, true
				}
				continue
			}
			if id := group(re, win, m, "id"); id != "" {
				if v, ok := s.resolveIdent(data, id); ok {
					return bundleMatch{npm: s.npm, version: v, signature: s.name + " (through " + id + ")", snippet: snippet,
						confidence: model.ConfidenceInferred}, true
				}
			}
		}
		i = at + len(needle)
	}
	return bundleMatch{}, false
}

func group(re *regexp.Regexp, data []byte, m []int, name string) string {
	i := re.SubexpIndex(name)
	if i < 0 || m[2*i] < 0 {
		return ""
	}
	return string(data[m[2*i]:m[2*i+1]])
}

// resolveIdent finds the version literal an identifier is assigned. A
// minified bundle reuses short names in other scopes, so every assignment
// of a version-like literal to the name must agree, and there must be at
// least one.
func (s codeSig) resolveIdent(data []byte, id string) (string, bool) {
	format := s.resolve
	if format == "" {
		format = `(?:^|[^\w$.])%s\s*=\s*` + lit
	}
	re, err := regexp.Compile(fmt.Sprintf(format, regexp.QuoteMeta(id)))
	if err != nil {
		return "", false
	}
	found := ""
	for _, m := range re.FindAllSubmatchIndex(data, 64) {
		v := group(re, data, m, "v")
		if !exactVersion.MatchString(v) || found != "" && v != found {
			return "", false
		}
		found = v
	}
	return found, found != ""
}

// legalBanners reads the licence comments a minifier kept in a bundle or
// extracted to its .LICENSE.txt, with the same banners as a library's own
// file (webLibs). Ordinary comments are not read: in unminified output
// they are the application's own ("// needs jQuery v3.6.0").
func legalBanners(name string, data []byte) (out []bundleMatch) {
	seen := map[int]bool{}
	for _, n := range legalNeedles {
		needle := []byte(n)
		for i, hits := 0, 0; hits < maxNeedleHits; hits++ {
			j := bytes.Index(data[i:], needle)
			if j < 0 {
				break
			}
			at := i + j
			i = at + len(needle)
			start := at
			if n == "@license" || n == "@preserve" {
				// The comment holding it: /* or /** up to 300 bytes before.
				k := bytes.LastIndex(data[max(at-300, 0):at], []byte("/*"))
				if k < 0 || bytes.Contains(data[max(at-300, 0)+k:at], []byte("*/")) {
					continue
				}
				start = max(at-300, 0) + k
			}
			if seen[start] {
				continue
			}
			seen[start] = true
			end := min(start+2048, len(data))
			if !strings.HasPrefix(n, "//") {
				if k := bytes.Index(data[start+2:end], []byte("*/")); k >= 0 {
					end = start + 2 + k + 2
				}
			} else {
				end = min(start+400, len(data))
			}
			comment := data[start:end]
			for _, m := range parseBanner(name, comment) {
				out = append(out, bundleMatch{npm: m[0], version: m[1], signature: "licence banner", snippet: firstLine(comment, m[0]),
					confidence: model.ConfidenceConfirmed})
			}
		}
	}
	return out
}

// firstLine is the banner line naming the library, for the evidence.
func firstLine(comment []byte, npm string) string {
	for _, l := range strings.Split(string(comment), "\n") {
		if strings.ContainsAny(l, "0123456789") && len(strings.Trim(l, " */!\t")) > 3 {
			return strings.TrimSpace(l)
		}
	}
	return npm
}

// Flutter web builds.
var (
	flutterBuildConfig = regexp.MustCompile(`_flutter\.buildConfig\s*=\s*\{\s*"engineRevision"\s*:\s*"([0-9a-f]{40})"`)
	flutterRenderer    = regexp.MustCompile(`"renderer"\s*:\s*"([a-z]+)"`)
	flutterTarget      = regexp.MustCompile(`"compileTarget"\s*:\s*"([a-z0-9]+)"`)
	flutterCanvasKit   = regexp.MustCompile(`gstatic\.com/flutter-canvaskit/([0-9a-f]{40})\b`)
)

// flutterBuild is what one Flutter web build directory shows.
type flutterBuild struct {
	revision, revFile, revSignature string
	renderers, targets              map[string]bool
	mainJS                          bool // main.dart.js written by dart2js
}

// sourceMap paths that carry a version.
var (
	pnpmPath = regexp.MustCompile(`node_modules/\.pnpm/((?:@[^/+]+\+)?[^/@+]+)@(\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?)(?:[_(][^/]*)?/node_modules/`)
	yarnPath = regexp.MustCompile(`-npm-(\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)??)-[0-9a-f]+(?:-[0-9a-f]+)?\.zip/node_modules/((?:@[^/]+/)?[^/]+)/`)
	pubPath  = regexp.MustCompile(`/hosted/pub\.(?:dev|dartlang\.org)/([a-z0-9_]+)-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?)/`)
	nmPath   = regexp.MustCompile(`node_modules/((?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*)/`)
)

// sourceMapPackages reads a source map's sources: packages with the
// version their path or embedded package.json gives (pnpm and Yarn keep
// it in the path, pub's cache too), and the npm packages it names without
// one.
func sourceMapPackages(data []byte) (versioned [][3]string, unversioned []string, err error) {
	var sm struct {
		Sources []string `json:"sources"`
	}
	if err := json.Unmarshal(data, &sm); err != nil {
		return nil, nil, err
	}
	have := map[string]bool{}
	named := map[string]bool{}
	pkgJSON := map[int]string{} // index in sources -> package whose package.json it is
	for i, src := range sm.Sources {
		if len(versioned) >= MaxPackagesPerApp {
			break
		}
		if m := pnpmPath.FindStringSubmatch(src); m != nil {
			name := strings.Replace(m[1], "+", "/", 1)
			if npmName.MatchString(name) && !have["npm:"+name+"@"+m[2]] {
				have["npm:"+name+"@"+m[2]] = true
				versioned = append(versioned, [3]string{"npm", name, m[2]})
			}
			continue
		}
		if m := yarnPath.FindStringSubmatch(src); m != nil {
			if npmName.MatchString(m[2]) && !have["npm:"+m[2]+"@"+m[1]] {
				have["npm:"+m[2]+"@"+m[1]] = true
				versioned = append(versioned, [3]string{"npm", m[2], m[1]})
			}
			continue
		}
		if m := pubPath.FindStringSubmatch(src); m != nil {
			if !have["pub:"+m[1]+"@"+m[2]] {
				have["pub:"+m[1]+"@"+m[2]] = true
				versioned = append(versioned, [3]string{"pub", m[1], m[2]})
			}
			continue
		}
		all := nmPath.FindAllStringSubmatchIndex(src, -1)
		if len(all) == 0 {
			continue
		}
		last := all[len(all)-1]
		name := src[last[2]:last[3]]
		if !npmName.MatchString(name) {
			continue
		}
		named[name] = true
		if src[last[1]:] == "package.json" {
			pkgJSON[i] = name
		}
	}
	if len(pkgJSON) > 0 {
		var sc struct {
			Content []*string `json:"sourcesContent"`
		}
		if json.Unmarshal(data, &sc) == nil {
			for i, name := range pkgJSON {
				if i >= len(sc.Content) || sc.Content[i] == nil {
					continue
				}
				var pj struct{ Name, Version string }
				if json.Unmarshal([]byte(*sc.Content[i]), &pj) == nil && pj.Name == name && exactVersion.MatchString(pj.Version) &&
					!have["npm:"+name+"@"+pj.Version] {
					have["npm:"+name+"@"+pj.Version] = true
					versioned = append(versioned, [3]string{"npm", name, pj.Version})
				}
			}
		}
	}
	for name := range named {
		found := false
		for _, v := range versioned {
			found = found || v[0] == "npm" && v[1] == name
		}
		if !found {
			unversioned = append(unversioned, name)
		}
	}
	sort.Strings(unversioned)
	sort.Slice(versioned, func(i, j int) bool { return versioned[i][1]+versioned[i][2] < versioned[j][1]+versioned[j][2] })
	return versioned, unversioned, nil
}

// bundles is one application's compiled output, read during the walk.
type bundles struct {
	files     int             // bundles, licence files and source maps read
	read      int             // of them, scripts read whole
	oversize  []string        // host paths not read: larger than bundleSize
	limit     string          // the limit that stopped reading, "" when none did
	found     map[string]bool // purls identified in compiled output
	flutter   map[string]*flutterBuild
	unversion map[string]bool // npm packages a source map names without a version
	maps      int
}

// flutterDir is the build directory a Flutter file belongs to (canvaskit/
// and canvaskit/chromium/ hold the renderer).
func flutterDir(host string) string {
	d := path.Dir(host)
	for path.Base(d) == "canvaskit" || path.Base(d) == "chromium" {
		d = path.Dir(d)
	}
	return d
}

func (b *bundles) build(dir string) *flutterBuild {
	if b.flutter == nil {
		b.flutter = map[string]*flutterBuild{}
	}
	f := b.flutter[dir]
	if f == nil {
		f = &flutterBuild{renderers: map[string]bool{}, targets: map[string]bool{}}
		b.flutter[dir] = f
	}
	return f
}

// budget reports whether one more file of size bytes may be read, noting
// the limit that stops it.
func (w *webAssets) budget(host string, size int64) bool {
	b := &w.b
	switch {
	case size > int64(bundleSize):
		b.oversize = append(b.oversize, host)
		return false
	case b.files >= bundleFiles:
		b.limit = fmt.Sprintf("stopped after %d compiled bundles and source maps", bundleFiles)
		return false
	case w.s.bundleRead+int(size) > bundleHostBytes:
		b.limit = fmt.Sprintf("stopped after reading %s of compiled bundles on this host", sizeText(bundleHostBytes))
		return false
	}
	return true
}

// readRest reads the rest of a file whose head was read, within the budget.
func (w *webAssets) readRest(f *os.File, host string, head []byte) ([]byte, bool) {
	fi, err := f.Stat()
	if err != nil {
		return nil, false
	}
	if !w.budget(host, fi.Size()) {
		return nil, false
	}
	rest, err := io.ReadAll(io.LimitReader(f, int64(bundleSize)-int64(len(head))+1))
	if err != nil {
		return nil, false
	}
	data := append(head[:len(head):len(head)], rest...)
	if len(data) > bundleSize {
		w.b.oversize = append(w.b.oversize, host)
		return nil, false
	}
	w.b.files++
	w.s.bundleRead += len(data)
	return data, true
}

// readWhole reads a file not otherwise read (a source map, a licence file,
// flutter_bootstrap.js) within the budget.
func (w *webAssets) readWhole(full, host string) ([]byte, bool) {
	f, err := openRegular(full)
	if err != nil {
		w.denied.note(host, err)
		return nil, false
	}
	defer f.Close()
	return w.readRest(f, host, nil)
}

// bundleScript reads a script whose head is read: a Flutter file, or a
// bundle when it looks like one. f is positioned after head.
func (w *webAssets) bundleScript(f *os.File, host, rel, name string, head []byte, wpCore bool) {
	switch {
	case name == "flutter_bootstrap.js":
		data, ok := w.readRest(f, host, head)
		if !ok {
			return
		}
		fb := w.b.build(path.Dir(host))
		if m := flutterBuildConfig.FindSubmatch(data); m != nil {
			fb.revision, fb.revFile, fb.revSignature = string(m[1]), host, "_flutter.buildConfig engineRevision"
		}
		for _, m := range flutterRenderer.FindAllSubmatch(data, 8) {
			fb.renderers[string(m[1])] = true
		}
		for _, m := range flutterTarget.FindAllSubmatch(data, 8) {
			fb.targets[string(m[1])] = true
		}
		return
	case name == "main.dart.js" && bytes.HasPrefix(bytes.TrimSpace(head), []byte("(function dartProgram(){")):
		fb := w.b.build(path.Dir(host))
		fb.mainJS = true
		fb.targets["dart2js"] = true
		if fb.revision != "" {
			return // flutter_bootstrap.js, read first, named it
		}
		data, ok := w.readRest(f, host, head)
		if !ok {
			return
		}
		w.b.read++
		if m := flutterCanvasKit.FindSubmatch(data); m != nil {
			fb.revision, fb.revFile, fb.revSignature = string(m[1]), host, "CanvasKit address in main.dart.js"
		}
		return
	case !bundleFile(rel, name, head):
		return
	}
	data, ok := w.readRest(f, host, head)
	if !ok {
		return
	}
	w.b.read++
	w.addBundle(host, name, scanBundle(name, data), wpCore)
}

func (w *webAssets) addBundle(host, name string, found []bundleMatch, wpCore bool) {
	for _, m := range found {
		ev := map[string]string{"source": "bundle", "signature": m.signature, "match": clip(oneLine(m.snippet, 200))}
		conf := m.confidence
		if wpCore {
			ev["bundled_with"] = "WordPress"
			conf = model.ConfidenceInferred
		}
		w.identified(npmPurl(m.npm, m.version))
		w.addObs(model.Observation{Purl: npmPurl(m.npm, m.version), Version: m.version, Location: clip(host), Scope: "runtime",
			Confidence: conf, Evidence: ev})
	}
}

// compiledOutput reports whether a file that is not a script is compiled
// output bundleOther reads or notes.
func compiledOutput(name string) bool {
	for _, suf := range []string{".js.license.txt", ".mjs.license.txt", ".js.map", ".mjs.map"} {
		if strings.HasSuffix(name, suf) {
			return true
		}
	}
	switch name {
	case "canvaskit.wasm", "skwasm.wasm", "skwasm_heavy.wasm", "main.dart.wasm", "main.dart.mjs":
		return true
	}
	return false
}

// bundleOther handles the compiled output that is not a script: licence
// files, source maps and Flutter's renderer files. It reports whether the
// file was one of them.
func (w *webAssets) bundleOther(full, host, name string, wpCore bool) bool {
	switch {
	case strings.HasSuffix(name, ".js.license.txt") || strings.HasSuffix(name, ".mjs.license.txt"):
		if data, ok := w.readWhole(full, host); ok {
			w.addBundle(host, name, legalBanners(name, data), wpCore)
		}
	case strings.HasSuffix(name, ".js.map") || strings.HasSuffix(name, ".mjs.map"):
		data, ok := w.readWhole(full, host)
		if !ok {
			return true
		}
		versioned, unversioned, err := sourceMapPackages(data)
		if err != nil {
			return true
		}
		w.b.maps++
		for _, p := range versioned {
			purl := npmPurl(p[1], p[2])
			if p[0] == "pub" {
				purl = "pkg:pub/" + p[1] + "@" + p[2]
			}
			w.identified(purl)
			w.addObs(model.Observation{Purl: purl, Version: p[2], Location: clip(host), Scope: "runtime", Confidence: model.ConfidenceInferred,
				Evidence: map[string]string{"source": "source-map", "signature": "package path"}})
		}
		if w.b.unversion == nil {
			w.b.unversion = map[string]bool{}
		}
		for _, n := range unversioned {
			w.b.unversion[n] = true
		}
	case name == "canvaskit.wasm" || name == "skwasm.wasm" || name == "skwasm_heavy.wasm":
		fb := w.b.build(flutterDir(host))
		fb.renderers[strings.TrimSuffix(strings.TrimSuffix(name, ".wasm"), "_heavy")] = true
	case name == "main.dart.wasm" || name == "main.dart.mjs":
		w.b.build(path.Dir(host)).targets["dart2wasm"] = true
	default:
		return false
	}
	return true
}

// identified notes a component found in compiled output, which may
// already have been reported from elsewhere (a copied file's banner).
func (w *webAssets) identified(purl string) {
	if w.b.found == nil {
		w.b.found = map[string]bool{}
	}
	w.b.found[purl] = true
}

// addObs keeps the first place each package and version was seen.
func (w *webAssets) addObs(o model.Observation) {
	if w.seen[o.Purl] {
		return
	}
	w.seen[o.Purl] = true
	w.obs = append(w.obs, o)
}

func oneLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// bundleResults are the Flutter engines found and the coverage of the
// compiled output: what could not be identified is said, never left as an
// application with no components.
func (w *webAssets) bundleResults() (obs []model.Observation, cov []model.CoverageItem) {
	b := w.b
	dirs := make([]string, 0, len(b.flutter))
	for d := range b.flutter {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	flutterBuilds := 0
	for _, d := range dirs {
		fb := b.flutter[d]
		if !fb.mainJS && fb.revision == "" && !fb.targets["dart2wasm"] {
			continue // a stray canvaskit/ without a Flutter build
		}
		flutterBuilds++
		var build []string
		if t := sortedKeys(fb.targets); len(t) > 0 {
			build = append(build, strings.Join(t, ", "))
		}
		if r := sortedKeys(fb.renderers); len(r) > 0 {
			build = append(build, "renderer "+strings.Join(r, ", "))
		}
		reason := "Flutter web build"
		if len(build) > 0 {
			reason += " (" + strings.Join(build, "; ") + ")"
		}
		reason += ": "
		if fb.revision != "" {
			purl := "pkg:generic/flutter-engine@" + fb.revision
			if !w.seen[purl] {
				w.seen[purl] = true
				ev := map[string]string{"source": "flutter-build", "signature": fb.revSignature, "engine_revision": fb.revision}
				if r := sortedKeys(fb.renderers); len(r) > 0 {
					ev["renderer"] = strings.Join(r, ", ")
				}
				obs = append(obs, model.Observation{Purl: purl, Version: fb.revision, Location: clip(fb.revFile), Scope: "runtime",
					Confidence: model.ConfidenceConfirmed, Evidence: ev})
			}
			reason += "the engine revision is reported (no vulnerability source matches a Flutter engine); "
		} else {
			reason += "no engine revision found; "
		}
		reason += "the Flutter release, the Dart SDK and the Dart packages compiled into main.dart.js are not recorded in the build and are not reported"
		cov = append(cov, model.CoverageItem{Scope: clipScope("flutter:" + d), Status: "partial", Reason: clipScope(reason)})
	}
	if b.read > 0 || b.maps > 0 {
		c := model.CoverageItem{Scope: clipScope(bundlesScopeID + w.dir)}
		switch {
		case len(b.found) == 0 && flutterBuilds == 0:
			c.Status = "unsupported"
			c.Reason = fmt.Sprintf("compiled front-end bundle, components not identifiable: %d file(s) read, no licence banner, known version constant or versioned source map found", b.read+b.maps)
		case len(b.found) == 0:
			c.Status = "partial"
			c.Reason = "compiled front-end output: no JavaScript library identified in it"
		default:
			c.Status = "partial"
			c.Reason = fmt.Sprintf("compiled front-end bundles: %d component(s) identified by licence banner, version constant or source map; other code compiled in is not identifiable", len(b.found))
		}
		cov = append(cov, c)
	}
	if len(b.unversion) > 0 {
		names := sortedKeys(b.unversion)
		var missing []string
		for _, n := range names {
			if !w.reportedNPM(n) {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			list := missing
			if len(list) > 10 {
				list = list[:10]
			}
			cov = append(cov, model.CoverageItem{Scope: clipScope("source-maps:" + w.dir), Status: "partial", Reason: clipScope(fmt.Sprintf(
				"source maps name %d npm package(s) compiled into the bundles without their versions, not reported: %s%s",
				len(missing), strings.Join(list, ", "), map[bool]string{true: ", …", false: ""}[len(missing) > 10]))})
		}
	}
	if len(b.oversize) > 0 || b.limit != "" {
		var parts []string
		if len(b.oversize) > 0 {
			list := b.oversize
			if len(list) > 5 {
				list = list[:5]
			}
			parts = append(parts, fmt.Sprintf("%d file(s) larger than %s not read (%s)", len(b.oversize), sizeText(bundleSize), strings.Join(list, ", ")))
		}
		if b.limit != "" {
			parts = append(parts, b.limit)
		}
		cov = append(cov, model.CoverageItem{Scope: clipScope("bundle-limits:" + w.dir), Status: "partial", Reason: clipScope(strings.Join(parts, "; "))})
	}
	return obs, cov
}

// reportedNPM reports whether an npm package was found with a version.
func (w *webAssets) reportedNPM(name string) bool {
	prefix := strings.TrimSuffix(npmPurl(name, "0"), "@0") + "@"
	for p := range w.seen {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func sizeText(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d KiB", n>>10)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
