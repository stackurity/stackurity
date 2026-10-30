package apps

// Front-end libraries outside a package manager. PHP, WordPress and older
// sites load Bootstrap, jQuery, TinyMCE and the like from a CDN address in
// a template, or from a copy of the library's file kept with the site.
// Neither shows up in a manifest. Both name an exact release: the CDN
// address in its path, the copied file in the banner its build writes at
// the top. They are reported as the npm packages they were published as,
// so the usual npm advisories and latest-release checks apply.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
)

// Limits on reading an application's templates and scripts. A WordPress
// site with its plugins has tens of thousands of .php and .js files.
const (
	bannerSize       = 4 << 10   // read from the top of each .js or .css file
	maxTemplateSize  = 256 << 10 // read from each template
	maxWebFiles      = 50_000    // files opened per application
	maxWebBytes      = 256 << 20 // bytes read per application, in total
	webAssetsScopeID = "web-assets:"
)

// webFiles and webBytes are maxWebFiles and maxWebBytes; tests lower them.
var webFiles, webBytes = maxWebFiles, maxWebBytes

// ver is an exact release: three numbers, optionally a pre-release. A
// shorter or open version ("3", "3.x", "latest") is not reported.
const ver = `(\d+\.\d+\.\d+(?:-[0-9A-Za-z][0-9A-Za-z.]*)?)`

var exactVersion = regexp.MustCompile(`^` + ver + `$`)

// lineStart anchors a banner to the start of a comment line, so a plugin
// that mentions "for Bootstrap v4.3.1" is not taken for Bootstrap.
const lineStart = `(?m)^[\t /*!]*`

// webLib is one library that is recognised outside a package manager.
type webLib struct {
	npm string
	// hint is in every banner of the library or in its file name (lower
	// case); the banners are only tried on a file that has it.
	hint string
	// cdn lists the library's names on cdnjs, Google Hosted Libraries and
	// BootstrapCDN, which differ from npm in places.
	cdn []string
	// npm5 is the npm package of versions 5 and later, when the library
	// moved (Font Awesome is @fortawesome/fontawesome-free from 5.0).
	npm5 string
	// css: the library is a stylesheet (Font Awesome), so a .css file or
	// address is the library itself. For the others a stylesheet is only
	// the styling (a jQuery UI theme, Bootstrap's CSS without its scripts)
	// and says nothing about the code the advisories are about.
	css     bool
	banners []banner
}

// banner finds the version at the head of a file. The version is the
// regexp's groups joined with "." (TinyMCE keeps it as majorVersion "5"
// and minorVersion "10.2").
type banner struct {
	re   *regexp.Regexp
	file string // the file name must contain this; "" for any .js or .css file
}

func b(re string) banner        { return banner{re: regexp.MustCompile(re)} }
func bf(file, re string) banner { return banner{re: regexp.MustCompile(re), file: file} }
func bs(res ...string) (out []banner) {
	for _, re := range res {
		out = append(out, b(re))
	}
	return out
}

// webLibs are the libraries recognised by banner or by a CDN's own name
// for them: widely used, with a history of advisories. A banner of any
// other library is ignored. An address on jsDelivr or unpkg names the npm
// package itself, so any package there is reported.
var webLibs = []webLib{
	{npm: "jquery", hint: "jquery", cdn: []string{"jquery"}, banners: bs(lineStart + `jQuery (?:JavaScript Library )?v` + ver)},
	{npm: "jquery-ui", hint: "jquery", cdn: []string{"jqueryui"}, banners: bs(lineStart + `jQuery UI (?:- )?v?` + ver)},
	{npm: "jquery-migrate", hint: "jquery", cdn: []string{"jquery-migrate"}, banners: bs(lineStart + `jQuery Migrate (?:- )?v` + ver)},
	{npm: "jquery-validation", hint: "jquery", cdn: []string{"jquery-validate"}, banners: bs(lineStart + `jQuery Validation Plugin (?:- )?v` + ver)},
	{npm: "bootstrap", hint: "bootstrap", cdn: []string{"twitter-bootstrap", "bootstrap"}, banners: bs(lineStart + `Bootstrap v` + ver)},
	{npm: "bootstrap-select", hint: "bootstrap", cdn: []string{"bootstrap-select"}, banners: bs(lineStart + `Bootstrap-select v` + ver)},
	{npm: "angular", hint: "angularjs", cdn: []string{"angular.js", "angularjs"}, banners: bs(lineStart + `(?:@license )?AngularJS v` + ver)},
	{npm: "vue", hint: "vue", cdn: []string{"vue"}, banners: bs(lineStart+`Vue\.js v`+ver, lineStart+`vue v`+ver)},
	// React 16 and 17 share one banner line between packages; the next line
	// names the file. React 18 has no version in its banner.
	{npm: "react", hint: "react", cdn: []string{"react"}, banners: bs(
		lineStart+`@license React v`+ver+`\s*\n[\t /*]*react\.(?:production|development)`,
		lineStart+`React v`+ver+`[\t ]*$`)},
	{npm: "react-dom", hint: "react", cdn: []string{"react-dom"}, banners: bs(
		lineStart+`@license React v`+ver+`\s*\n[\t /*]*react-dom\.(?:production|development)`,
		lineStart+`ReactDOM v`+ver)},
	{npm: "lodash", hint: "lodash", cdn: []string{"lodash.js"}, banners: bs(
		lineStart+`lodash v?`+ver,
		`(?s)[Ll]odash <https://lodash\.com/>.{0,1000}?var VERSION = '`+ver+`'`)},
	{npm: "underscore", hint: "underscore.js", cdn: []string{"underscore.js"}, banners: bs(lineStart + `Underscore\.js ` + ver)},
	{npm: "moment", hint: "moment.js", cdn: []string{"moment.js"}, banners: bs(`(?m)^//! moment\.js\s*\n//! version : ` + ver)},
	{npm: "handlebars", hint: "handlebars", cdn: []string{"handlebars.js"}, banners: bs(lineStart + `handlebars v` + ver)},
	{npm: "knockout", hint: "knockout", cdn: []string{"knockout"}, banners: bs(lineStart + `Knockout JavaScript library v` + ver)},
	{npm: "tinymce", hint: "tiny", cdn: []string{"tinymce"}, banners: []banner{
		b(lineStart + `TinyMCE version ` + ver),              // 6 and later
		b(`(?s)Tiny Technologies.{0,512}?Version: ` + ver),   // 5
		bf("tinymce", `(?m)^// `+ver+` \(\d{4}-\d\d-\d\d\)`), // 4
		bf("tinymce", `majorVersion\s*:\s*["'](\d+)["']\s*,\s*minorVersion\s*:\s*["'](\d+\.\d+)["']`),
	}},
	{npm: "ckeditor4", hint: "ckeditor", cdn: []string{"ckeditor"}, banners: []banner{
		bf("ckeditor", `(?s)CKEDITOR.{0,1000}?version\s*:\s*["']`+ver),
	}},
	{npm: "datatables.net", hint: "datatables", cdn: []string{"datatables"}, banners: bs(lineStart + `DataTables ` + ver)},
	{npm: "select2", hint: "select2", cdn: []string{"select2"}, banners: bs(lineStart + `Select2 ` + ver)},
	{npm: "chart.js", hint: "chart.js", cdn: []string{"chart.js"}, banners: bs(lineStart + `Chart\.js v?` + ver)},
	{npm: "d3", hint: "d3js", cdn: []string{"d3"}, banners: bs(lineStart + `https://d3js\.org v` + ver)},
	{npm: "axios", hint: "axios", cdn: []string{"axios"}, banners: bs(lineStart + `[Aa]xios v` + ver)},
	{npm: "dompurify", hint: "dompurify", cdn: []string{"dompurify"}, banners: bs(lineStart + `@license DOMPurify v?` + ver)},
	{npm: "highlight.js", hint: "highlight.js", cdn: []string{"highlight.js"}, banners: bs(lineStart + `[Hh]ighlight\.js v?` + ver)},
	{npm: "prismjs", hint: "prismjs", cdn: []string{"prism"}, banners: bs(lineStart + `PrismJS ` + ver)},
	{npm: "summernote", hint: "wysiwyg", cdn: []string{"summernote"}, banners: bs(lineStart + `Super simple (?:WYSIWYG|wysiwyg) editor v` + ver)},
	{npm: "font-awesome", hint: "font awesome", cdn: []string{"font-awesome"}, npm5: "@fortawesome/fontawesome-free", css: true, banners: bs(lineStart + `Font Awesome ` + ver)},
	{npm: "@fortawesome/fontawesome-free", hint: "font awesome", css: true, banners: bs(lineStart + `Font Awesome Free ` + ver)},
}

// cdnNames maps a CDN's library name (lower case) to its entry in webLibs.
var cdnNames = func() map[string]*webLib {
	m := map[string]*webLib{}
	for i := range webLibs {
		for _, n := range webLibs[i].cdn {
			m[n] = &webLibs[i]
		}
	}
	return m
}()

// cssLibs are the npm packages whose stylesheet is the library.
var cssLibs = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range webLibs {
		if l.css {
			m[l.npm] = true
			if l.npm5 != "" {
				m[l.npm5] = true
			}
		}
	}
	return m
}()

// fromCDNName returns the npm package of a library the CDN calls name.
func fromCDNName(name, version string) (string, bool) {
	l, ok := cdnNames[strings.ToLower(name)]
	if !ok {
		return "", false
	}
	if l.npm5 != "" {
		if major, _, _ := strings.Cut(version, "."); len(major) > 1 || major >= "5" {
			return l.npm5, true
		}
	}
	return l.npm, true
}

var (
	npmName       = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	jqueryFile    = regexp.MustCompile(`^jquery-` + ver + `(?:\.slim)?(?:\.min)?\.js$`)
	jqMigrateFile = regexp.MustCompile(`^jquery-migrate-` + ver + `(?:\.min)?\.js$`)
)

// parseCDNURL returns the npm package and exact version a CDN address
// loads. An address without an exact version (@latest, a major only, none),
// of an unknown library, or of a stylesheet of a library that is not one
// (see webLib.css) gives ok false.
func parseCDNURL(raw string) (name, version string, ok bool) {
	name, version, ok = parseCDNPath(raw)
	if ok && !cssLibs[name] && strings.HasSuffix(strings.ToLower(cdnPath(raw)), ".css") {
		return "", "", false
	}
	return name, version, ok
}

// cdnPath is raw without its scheme, query and fragment.
func cdnPath(raw string) string {
	u := raw
	if i := strings.Index(u, "//"); i >= 0 && i <= len("https:") {
		u = u[i+2:]
	}
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return u
}

func parseCDNPath(raw string) (name, version string, ok bool) {
	host, p, _ := strings.Cut(cdnPath(raw), "/")
	host = strings.ToLower(host)
	seg := strings.Split(p, "/")
	switch host {
	case "cdn.jsdelivr.net":
		if len(seg) < 2 || seg[0] != "npm" {
			return "", "", false // gh/, combine/, wp/: not an npm package
		}
		return npmSpec(seg[1:])
	case "unpkg.com":
		return npmSpec(seg)
	case "cdnjs.cloudflare.com", "ajax.googleapis.com":
		if len(seg) < 4 || seg[0] != "ajax" || seg[1] != "libs" {
			return "", "", false
		}
		return cdnLib(seg[2], seg[3])
	case "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com", "netdna.bootstrapcdn.com":
		if len(seg) < 3 {
			return "", "", false
		}
		return cdnLib(seg[0], seg[1])
	case "code.jquery.com":
		if len(seg) >= 3 && seg[0] == "ui" && exactVersion.MatchString(seg[1]) {
			return "jquery-ui", seg[1], true
		}
		if len(seg) == 1 {
			if m := jqueryFile.FindStringSubmatch(seg[0]); m != nil {
				return "jquery", m[1], true
			}
			if m := jqMigrateFile.FindStringSubmatch(seg[0]); m != nil {
				return "jquery-migrate", m[1], true
			}
		}
	case "cdn.ckeditor.com":
		// cdn.ckeditor.com/4.11.4/standard/ckeditor.js; CKEditor 5 builds
		// (ckeditor5/...) are several npm packages and are not reported.
		if len(seg) >= 3 && strings.HasPrefix(seg[0], "4.") && exactVersion.MatchString(seg[0]) {
			return "ckeditor4", seg[0], true
		}
	case "cdn.datatables.net":
		// cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js; extensions
		// (buttons/1.5.6/...) and bundles (v/dt/...) are other packages.
		if len(seg) >= 3 && exactVersion.MatchString(seg[0]) {
			return "datatables.net", seg[0], true
		}
	}
	return "", "", false
}

// npmSpec reads "name@version" or "@scope/name@version" from the start of
// a jsDelivr or unpkg path.
func npmSpec(seg []string) (string, string, bool) {
	spec := seg[0]
	if strings.HasPrefix(spec, "@") {
		if len(seg) < 2 {
			return "", "", false
		}
		spec += "/" + seg[1]
	}
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return "", "", false // no version: the CDN serves the latest
	}
	name, version := strings.ToLower(spec[:at]), spec[at+1:]
	if !npmName.MatchString(name) || !exactVersion.MatchString(version) {
		return "", "", false
	}
	return name, version, true
}

func cdnLib(lib, version string) (string, string, bool) {
	if !exactVersion.MatchString(version) {
		return "", "", false
	}
	if name, ok := fromCDNName(lib, version); ok {
		return name, version, true
	}
	return "", "", false
}

// parseBanner returns the libraries whose banner is in head, the first
// bytes of a file called name. A stylesheet counts only for a library that
// is one (see webLib.css).
func parseBanner(name string, head []byte) (out [][2]string) {
	name = strings.ToLower(name)
	css := strings.HasSuffix(name, ".css")
	lower := bytes.ToLower(head)
	for i := range webLibs {
		l := &webLibs[i]
		if css && !l.css || !bytes.Contains(lower, []byte(l.hint)) && !strings.Contains(name, l.hint) {
			continue
		}
		for _, bn := range l.banners {
			if bn.file != "" && !strings.Contains(name, bn.file) {
				continue
			}
			m := bn.re.FindSubmatch(head)
			if m == nil {
				continue
			}
			var parts []string
			for _, g := range m[1:] {
				if len(g) > 0 {
					parts = append(parts, string(g))
				}
			}
			if v := strings.Join(parts, "."); exactVersion.MatchString(v) {
				out = append(out, [2]string{l.npm, v})
				break
			}
		}
	}
	return out
}

// cdnAddress finds addresses on the CDNs parseCDNURL reads, with or without
// a scheme, anywhere in a template: in a script or link tag, or passed to
// wp_enqueue_script and the like.
var cdnAddress = regexp.MustCompile(`(?i)(?:https?:)?//(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|code\.jquery\.com|` +
	`(?:stackpath|maxcdn|netdna)\.bootstrapcdn\.com|ajax\.googleapis\.com|cdn\.ckeditor\.com|cdn\.datatables\.net)/[^\s"'<>()\\` + "`" + `]+`)

var htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

// templateExts are the files read for CDN addresses (.blade.php is a .php).
var templateExts = []string{".html", ".htm", ".php", ".phtml", ".twig", ".erb", ".ejs", ".hbs", ".vue", ".jsx", ".tsx"}

// parseTemplate returns the CDN addresses in a template called name that
// name a package, each once, with the address's query and fragment
// removed. Addresses in HTML comments, and in code comments (see
// stripComments), are ignored.
func parseTemplate(name string, data []byte) (out [][3]string) {
	data = stripComments(name, htmlComment.ReplaceAll(data, nil))
	seen := map[string]bool{}
	for _, m := range cdnAddress.FindAll(data, -1) {
		u := string(m)
		if name, version, ok := parseCDNURL(u); ok && !seen[name+"@"+version] {
			seen[name+"@"+version] = true
			if i := strings.IndexAny(u, "?#"); i >= 0 {
				u = u[:i] // a query may carry a key or a cache-buster
			}
			out = append(out, [3]string{name, version, u})
		}
	}
	return out
}

// codeRegion is the kind of code stripCode reads, which decides where it
// ends and which comments it knows.
type codeRegion int

const (
	jsFile      codeRegion = iota // a whole .js, .jsx or .tsx file
	phpBlock                      // <?php ... ?> (or to the end of the file)
	scriptBlock                   // <script ...> ... </script>
)

// markupExts are templates that are HTML with inline scripts; only their
// <script> elements are code.
var markupExts = []string{".html", ".htm", ".twig", ".vue", ".erb", ".ejs", ".hbs"}

// stripComments removes code comments from a template, where an old
// address is often left behind ("// old: https://code.jquery.com/...").
// Only code is touched: PHP blocks in a .php or .phtml file, and inline
// scripts in it and in the HTML templates (markupExts); the HTML and CSS
// around them are left alone, since a "//" or "/*" there is text
// (url(//fonts...), "src/*.js"). A .js, .jsx or .tsx file is code
// throughout.
func stripComments(name string, data []byte) []byte {
	name = strings.ToLower(name)
	switch {
	case strings.HasSuffix(name, ".php") || strings.HasSuffix(name, ".phtml"):
		return stripMarkup(data, true)
	case strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".jsx") || strings.HasSuffix(name, ".tsx"):
		out, _ := stripCode(make([]byte, 0, len(data)), data, 0, jsFile)
		return out
	}
	for _, e := range markupExts {
		if strings.HasSuffix(name, e) {
			return stripMarkup(data, false)
		}
	}
	return data
}

// scriptType reads the type attribute of a <script ...> tag ("" if none).
var scriptType = regexp.MustCompile(`(?i)\btype\s*=\s*["']?([^"'\s>]+)`)

// jsScript reports whether a <script> tag holds JavaScript, not a template
// (text/template, text/x-handlebars-template) or data (application/json),
// whose "//" is text.
func jsScript(tag []byte) bool {
	m := scriptType.FindSubmatch(tag)
	if m == nil {
		return true
	}
	switch strings.ToLower(string(m[1])) {
	case "text/javascript", "application/javascript", "module", "text/babel":
		return true
	}
	return false
}

// stripMarkup removes the comments of the code in an HTML template: its
// inline scripts and, if php, its PHP blocks.
func stripMarkup(data []byte, php bool) []byte {
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		switch {
		case php && hasAt(data, i, "<?php", true):
			out = append(out, data[i:i+5]...)
			out, i = stripCode(out, data, i+5, phpBlock)
		case php && hasAt(data, i, "<?=", false):
			out = append(out, data[i:i+3]...)
			out, i = stripCode(out, data, i+3, phpBlock)
		case hasAt(data, i, "<script", true):
			j := bytes.IndexByte(data[i:], '>')
			if j < 0 {
				return append(out, data[i:]...)
			}
			tag := data[i : i+j+1]
			out = append(out, tag...)
			i += j + 1
			if jsScript(tag) {
				out, i = stripCode(out, data, i, scriptBlock)
			}
		default:
			out = append(out, data[i])
			i++
		}
	}
	return out
}

// stripCode copies the code region starting at data[i] to out without its
// comments and returns where the region ends (its "?>" or "</script", not
// copied). Comments are // and /* */, and # in PHP, and only where a
// comment can start: at the start of the region or after whitespace or one
// of ;{},= . So "url(//", "src/*.js", "\/*" and "/\/\//" stay. A /* that
// is never closed is not a comment. Quoted strings are copied as they are,
// and end at a line break too, so a stray apostrophe cannot hide the rest
// of the file. PHP inside an inline script, and a PHP heredoc or nowdoc
// (see heredocEnd), are copied as they are.
func stripCode(out, data []byte, i int, region codeRegion) ([]byte, int) {
	start := i
	var quote byte
	ends := func(i int) bool {
		return region == phpBlock && quote == 0 && hasAt(data, i, "?>", false) ||
			region == scriptBlock && hasAt(data, i, "</script", true)
	}
	for i < len(data) {
		if ends(i) {
			return out, i
		}
		c := data[i]
		if quote != 0 {
			out = append(out, c)
			switch {
			case c == '\\' && i+1 < len(data):
				i++
				out = append(out, data[i])
			case c == quote || c == '\n' && quote != '`':
				quote = 0
			}
			i++
			continue
		}
		canStart := i == start || commentBoundary(data[i-1])
		switch {
		case c == '"' || c == '\'' || c == '`':
			quote = c
		case region == phpBlock && hasAt(data, i, "<<<", false):
			if end := heredocEnd(data, i); end > i {
				out = append(out, data[i:end]...)
				i = end
				continue
			}
		case region == scriptBlock && hasAt(data, i, "<?", false):
			j := bytes.Index(data[i:], []byte("?>"))
			if j < 0 {
				return append(out, data[i:]...), len(data)
			}
			out = append(out, data[i:i+j+2]...)
			i += j + 2
			continue
		case canStart && (hasAt(data, i, "//", false) || region == phpBlock && c == '#' && !hasAt(data, i, "#[", false)):
			for i < len(data) && data[i] != '\n' && !ends(i) {
				i++
			}
			continue
		case canStart && hasAt(data, i, "/*", false):
			if j := bytes.Index(data[i+2:], []byte("*/")); j >= 0 {
				out = append(out, ' ')
				i += j + 4
				continue
			}
		}
		out = append(out, c)
		i++
	}
	return out, i
}

var heredocStart = regexp.MustCompile(`^<<<[ \t]*(["']?)([A-Za-z_][A-Za-z0-9_]*)(["']?)\r?\n`)

// heredocEnd returns where the PHP heredoc or nowdoc starting at data[i]
// (<<<ID, <<<"ID" or <<<'ID') ends: after its closing identifier, which
// since PHP 7.3 may be indented and followed by anything that cannot
// continue the name (";", ",", ")"). The text in between is a string, so
// a "#fff" or "//" in it is not a comment. A heredoc that is never closed
// runs to the end of the data; i when data[i] does not start one.
func heredocEnd(data []byte, i int) int {
	m := heredocStart.FindSubmatchIndex(data[i:])
	if m == nil {
		return i
	}
	open, closing := string(data[i+m[2]:i+m[3]]), string(data[i+m[6]:i+m[7]])
	if open != closing {
		return i
	}
	id := data[i+m[4] : i+m[5]]
	for p := i + m[1]; p < len(data); {
		line := p
		for line < len(data) && (data[line] == ' ' || data[line] == '\t') {
			line++
		}
		if bytes.HasPrefix(data[line:], id) {
			after := line + len(id)
			if after == len(data) || !identChar(data[after]) {
				return after
			}
		}
		nl := bytes.IndexByte(data[p:], '\n')
		if nl < 0 {
			break
		}
		p += nl + 1
	}
	return len(data)
}

func identChar(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= 0x80
}

func commentBoundary(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\r', ';', '{', '}', ',', '=':
		return true
	}
	return false
}

// hasAt reports whether data has s at i, ignoring ASCII case if fold.
func hasAt(data []byte, i int, s string, fold bool) bool {
	if i+len(s) > len(data) {
		return false
	}
	if fold {
		return bytes.EqualFold(data[i:i+len(s)], []byte(s))
	}
	return string(data[i:i+len(s)]) == s
}

// webAssets collects one application's CDN and copied libraries.
type webAssets struct {
	s     *Scanner
	dir   string // the application's host path
	files int
	bytes int
	limit string // the limit that stopped reading, "" when none did
	seen  map[string]bool
	obs   []model.Observation
}

// skipWebDir: directories whose files are not what the application loads,
// besides hidden ones: other package managers' trees, virtualenvs,
// generated or uploaded content (a page cache writes one .html per URL,
// WordPress keeps uploads), and a library's own examples, documentation
// and tests, which load other versions from a CDN and are never served
// as part of the site.
var skipWebDir = map[string]bool{
	"node_modules": true, "venv": true, "__pycache__": true, "site-packages": true, "dist-packages": true,
	"cache": true, "tmp": true, "logs": true, "uploads": true,
	"examples": true, "example": true, "demo": true, "demos": true, "docs": true, "doc": true,
	"test": true, "tests": true, "spec": true, "samples": true,
}

// consider reads one file if it is a template or a script or stylesheet.
// full is its path under the scanner's root.
func (w *webAssets) consider(full string, d fs.DirEntry) {
	if !d.Type().IsRegular() {
		return // a link is never followed, in or out of the application
	}
	name := strings.ToLower(d.Name())
	isAsset := strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".css")
	isTemplate := false
	for _, e := range templateExts {
		isTemplate = isTemplate || strings.HasSuffix(name, e)
	}
	if !isAsset && !isTemplate {
		return
	}
	host := w.s.hostPath(full)
	rel := strings.TrimPrefix(host, w.dir+"/")
	if strings.Count(rel, "/") >= lockfile.MaxWalkDepth {
		return
	}
	for _, part := range strings.Split(path.Dir(rel), "/") {
		if strings.HasPrefix(part, ".") && part != "." || skipWebDir[part] {
			return
		}
	}
	if w.s.Owned != nil && w.s.Owned(host) {
		return
	}
	switch {
	case w.files >= webFiles:
		w.limit = fmt.Sprintf("stopped after %d files of templates and scripts", webFiles)
		return
	case w.bytes >= webBytes:
		w.limit = fmt.Sprintf("stopped after reading %d MiB of templates and scripts", webBytes>>20)
		return
	}
	limit := int64(bannerSize)
	if isTemplate {
		limit = maxTemplateSize
	}
	f, err := openRegular(full)
	if err != nil {
		return
	}
	data, _ := io.ReadAll(io.LimitReader(f, limit))
	f.Close()
	w.files++
	w.bytes += len(data)
	// WordPress core keeps its own copies of jQuery, TinyMCE and others in
	// wp-includes, some patched in place ("1.12.4-wp"), and updates them
	// with WordPress: the version alone does not say what the copy fixes.
	wpCore := false
	for _, part := range strings.Split(rel, "/") {
		wpCore = wpCore || part == "wp-includes"
	}
	if isTemplate {
		for _, m := range parseTemplate(name, data) {
			w.add(m[0], m[1], host, false, map[string]string{"source": "cdn", "url": clip(m[2])})
		}
		return
	}
	for _, m := range parseBanner(name, data) {
		ev := map[string]string{"source": "vendored"}
		bundled := wpCore || strings.HasSuffix(m[1], "-wp")
		if bundled {
			ev["bundled_with"] = "WordPress"
		}
		w.add(m[0], m[1], host, bundled, ev)
	}
}

// add keeps the first place each package and version was seen. The
// address or banner names the exact release, as package.json does for a
// package in node_modules, so the version is confirmed; a copy WordPress
// core maintains (bundled) needs validation.
func (w *webAssets) add(name, version, location string, bundled bool, ev map[string]string) {
	purl := npmPurl(name, version)
	if w.seen[purl] {
		return
	}
	w.seen[purl] = true
	conf := model.ConfidenceConfirmed
	if bundled {
		conf = model.ConfidenceInferred
	}
	w.obs = append(w.obs, model.Observation{Purl: purl, Version: version, Location: clip(location), Direct: boolp(true),
		Scope: "runtime", Confidence: conf, Evidence: ev})
}

// walk reads the web assets below one directory (host path) that the main
// walk does not enter: a front-end vendor/ directory, which is not
// Composer's.
func (w *webAssets) walk(ctx context.Context, dir string) {
	_ = filepath.WalkDir(w.s.path(dir), func(full string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if host := w.s.hostPath(full); host != dir && (skipWebDir[d.Name()] || strings.HasPrefix(d.Name(), ".") || w.s.nestedApp(w.dir, host)) {
				return fs.SkipDir
			}
			return nil
		}
		w.consider(full, d)
		return nil
	})
}

// composerVendor reports whether vendor directory full (under the root)
// is Composer's rather than a site's own copies of front-end libraries.
func composerVendor(full string) bool {
	for _, p := range []string{"composer", "autoload.php"} {
		if _, err := os.Lstat(filepath.Join(full, p)); err == nil {
			return true
		}
	}
	return false
}

// unlisted returns the observations whose package and version none of
// manifest has: a copy of a library the application also installs through
// npm (a build step copying it to public/) is reported once, from npm.
func unlisted(found, manifest []model.Observation) []model.Observation {
	have := map[string]bool{}
	for _, o := range manifest {
		if p, err := packageurl.FromString(o.Purl); err == nil && p.Type == "npm" {
			have[npmPurl(path.Join(p.Namespace, p.Name), firstNonEmpty(p.Version, o.Version))] = true
		}
	}
	var out []model.Observation
	for _, o := range found {
		if !have[o.Purl] {
			out = append(out, o)
		}
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
