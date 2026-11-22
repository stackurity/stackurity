package lockfile

// Reachability of lockfile packages: does first-party source import them?
// (docs/reachability.md). Source files are read as data, never run or
// built, within the same walk limits as the lockfiles. Only what can be
// shown is claimed: a package is "not imported" only when every source file
// of its language was read, none imports it, and nothing names it in a way
// that loads it without an import; otherwise it stays unknown.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	goparser "go/parser"
	"go/token"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

// Limits of the import scan, on top of the walk's.
const (
	MaxReachFiles     = 50_000    // source files read
	MaxReachFileBytes = 1 << 20   // bytes read of one file
	MaxReachBytes     = 256 << 20 // bytes read in total
)

// ReachScope is the coverage scope of the import scan.
const ReachScope = "reachability"

var (
	jsExts     = map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true, ".vue": true, ".svelte": true, ".astro": true, ".mdx": true}
	configExts = map[string]bool{".json": true, ".yml": true, ".yaml": true, ".toml": true, ".xml": true, ".neon": true}
	// Lockfiles and manifests list every package: being named there says
	// nothing about use. package.json is read separately (its scripts).
	notConfig = map[string]bool{"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true, "composer.json": true,
		"composer.lock": true, "yarn.lock": true, "pnpm-lock.yaml": true, "Pipfile.lock": true, "poetry.lock": true, "pubspec.lock": true,
		"packages.lock.json": true, "Gemfile.lock": true, "go.sum": true, "bun.lock": true, "deno.lock": true}

	// Templates, pages and scripts can load a package by its path in
	// node_modules or run it with npx.
	textExts       = map[string]bool{".html": true, ".htm": true, ".ejs": true, ".hbs": true, ".handlebars": true, ".pug": true, ".njk": true, ".twig": true, ".liquid": true, ".mustache": true, ".erb": true, ".sh": true, ".bash": true}
	textNames      = map[string]bool{"Makefile": true, "makefile": true, "GNUmakefile": true, "Dockerfile": true, "Containerfile": true, "Procfile": true, "Justfile": true, "justfile": true}
	styleExts      = map[string]bool{".css": true, ".scss": true, ".sass": true, ".less": true, ".styl": true}
	nodeRequireRef = regexp.MustCompile(`(?:^|[\s"'=])(?:-r|--require|--import|--loader|--experimental-loader)[=\s]+['"]?((?:@[\w.-]+/)?[\w.-]+)`)
	styleImportRef = regexp.MustCompile(`@(?:import|use|forward|plugin)\s+(?:url\()?['"]~?((?:@[\w.-]+/)?[\w.-]+)`)
	wordRe         = regexp.MustCompile(`[\w@][\w.@/-]*`)
	nodeModulesRef = regexp.MustCompile(`node_modules/((?:@[\w.-]+/)?[\w.-]+)`)
	npxRef         = regexp.MustCompile(`\b(?:npx|bunx|pnpm\s+dlx|yarn\s+dlx|pnpx)\s+(?:--?[\w-]+(?:=\S+)?\s+)*((?:@[\w.-]+/)?[\w.-]+)`)
	jsImport       = regexp.MustCompile(`(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bexport\s*\*\s*from\s*)['"]([^'"\n]+)['"]`)
	// A require or import() whose argument is not a string literal: the
	// imports of this tree cannot all be read.
	jsDynamic = regexp.MustCompile(`\b(?:require|import)\s*\(\s*[^'"\s)]`)
	quoted    = regexp.MustCompile("['\"`](@?[a-z0-9][a-z0-9._~-]*(?:/[a-z0-9][a-z0-9._~-]*)*)['\"`]")
	phpName   = regexp.MustCompile(`\\?\\?([A-Za-z_][A-Za-z0-9_]*(?:\\{1,2}[A-Za-z_][A-Za-z0-9_]*)+)`)
	pyImport  = regexp.MustCompile(`(?m)^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_]*)[\s.]|import\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*))`)
)

// ReadsExt reports whether the import walk reads files with extension ext
// (lower case, with the dot): a repository clone must check them out even
// when the leak scan skips them (stylesheets).
func ReadsExt(ext string) bool {
	return jsExts[ext] || configExts[ext] || textExts[ext] || styleExts[ext] || ext == ".go" || ext == ".php" || ext == ".py"
}

// importIndex is what the walk learnt about the tree's first-party source.
type importIndex struct {
	partial string // why the scan is incomplete; "" when every file was read

	jsFiles, goFiles, phpFiles, pyFiles int

	npm       map[string]string // package -> first file importing it
	npmNamed  map[string]string // package -> first file naming it as a string (loaded by name)
	npmDyn    string            // first file with a computed require or import()
	npmBundle string            // first minified bundle, which may hold packages inlined
	words     map[string]string // word in scripts, Makefiles, Dockerfiles, .env -> first file (programs run by name)
	goImports map[string]goImport
	php       map[string]string // namespace-qualified name prefix -> first file
	py        map[string]string // top-level module -> first file
}

type goImport struct{ file, testFile string }

// annotateReach reads the first-party source under fsys and sets each
// lockfile observation's reachability. It returns the coverage item that
// says what was read. Its status is always "checked", with any limit in
// the reason: reachability says nothing about whether the package list is
// whole, and a "partial" or "skipped" here would count as an inventory
// gap (asset health, gap alerts, the trust badge). A limit shows instead
// as packages left unknown.
func annotateReach(ctx context.Context, fsys fs.FS, ignored map[string]bool, obs []model.Observation) model.CoverageItem {
	if len(obs) == 0 {
		return model.CoverageItem{Scope: ReachScope, Status: "checked", Reason: "no packages to assess"}
	}
	ix := indexImports(ctx, fsys, ignored)
	comp := composerAutoload(fsys, obs)
	g := readDepGraphs(fsys, obs)
	for i := range obs {
		obs[i].Reachability = ix.decide(&obs[i], comp, g)
	}
	reason := fmt.Sprintf("read %d JavaScript/TypeScript, %d Go, %d PHP and %d Python source files", ix.jsFiles, ix.goFiles, ix.phpFiles, ix.pyFiles)
	if ix.partial != "" {
		return model.CoverageItem{Scope: ReachScope, Status: "checked", Reason: clip("partial: " + reason + "; " + ix.partial + ": no package is reported as not imported")}
	}
	return model.CoverageItem{Scope: ReachScope, Status: "checked", Reason: reason}
}

func indexImports(ctx context.Context, fsys fs.FS, ignored map[string]bool) *importIndex {
	ix := &importIndex{npm: map[string]string{}, npmNamed: map[string]string{}, goImports: map[string]goImport{},
		php: map[string]string{}, py: map[string]string{}}
	files, total, entries := 0, 0, 0
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			ix.partial = "the scan's deadline passed"
			return fs.SkipAll
		}
		if entries++; entries > walkEntries {
			ix.partial = fmt.Sprintf("stopped after %d files and directories", walkEntries)
			return fs.SkipAll
		}
		if err != nil {
			ix.partial = "a file or directory could not be read"
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			if strings.Count(p, "/")+1 > MaxWalkDepth {
				ix.partial = "the tree is deeper than the walk goes"
				return fs.SkipDir
			}
			// Skipped directories that may hold first-party source make the
			// reading partial: generated code (protobuf, GraphQL, Prisma) is
			// often ignored, and a nested checkout is another tree.
			// Third-party code the lockfile graph covers (installed
			// node_modules, Go's and Composer's vendor), version control,
			// Python environments and build output are skipped first, so an
			// installed checkout (after npm ci), where they are gitignored,
			// is not partial.
			switch {
			case d.Name() == "vendor" && !thirdPartyVendor(fsys, p), d.Name() == "bower_components":
				ix.skipped(p + " was not read")
				return fs.SkipDir
			case skipDirs[d.Name()]:
				return fs.SkipDir
			case nestedCheckout(fsys, p):
				ix.skipped("a nested checkout (" + p + ") was not read")
				return fs.SkipDir
			case ignored[p]:
				ix.skipped("gitignored files under " + p + " were not read")
				return fs.SkipDir
			}
			return nil
		}
		name, ext := d.Name(), strings.ToLower(path.Ext(d.Name()))
		if ignored[p] {
			// A gitignored .env holds settings, not source: it is not read,
			// and does not make the reading partial.
			if jsExts[ext] || ext == ".go" || ext == ".php" || ext == ".py" || textExts[ext] || textNames[name] {
				ix.skipped("gitignored source (" + p + ") was not read")
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// Not followed (it may leave the tree): source behind it is
			// unread, so nothing is claimed.
			if st, err := fs.Stat(fsys, p); err == nil && (st.IsDir() || jsExts[ext] || ext == ".go" || ext == ".php" || ext == ".py") {
				ix.partial = "a symbolic link to source (" + p + ") was not followed"
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		lang := ""
		switch {
		case jsExts[ext]:
			lang = "js"
		case ext == ".go":
			lang = "go"
		case ext == ".php":
			lang = "php"
		case ext == ".py":
			lang = "py"
		case name == "package.json", configExts[ext] && !notConfig[name], strings.HasPrefix(name, ".") && strings.HasSuffix(name, "rc"):
			lang = "config"
		case textExts[ext], textNames[name], strings.HasSuffix(name, ".dockerfile"), envFile(name), styleExts[ext]:
			lang = "text"
		default:
			return nil
		}
		if files++; files > MaxReachFiles {
			ix.partial = fmt.Sprintf("more than %d source files", MaxReachFiles)
			return fs.SkipAll
		}
		data, rerr := readCapped(fsys, p)
		if rerr != nil {
			ix.partial = "a source file could not be read"
			return nil
		}
		if total += len(data); total > MaxReachBytes {
			ix.partial = fmt.Sprintf("more than %d MiB of source", MaxReachBytes>>20)
			return fs.SkipAll
		}
		if len(data) > MaxReachFileBytes {
			ix.partial = fmt.Sprintf("a source file is larger than %d MiB", MaxReachFileBytes>>20)
			data = data[:MaxReachFileBytes]
		}
		switch lang {
		case "js":
			ix.jsFiles++
			ix.readJS(p, data)
			if ix.npmBundle == "" && minified(name, data) {
				ix.npmBundle = p
			}
		case "text":
			ix.readRefs(p, data)
			if !styleExts[ext] {
				ix.readWords(p, data)
			}
		case "go":
			ix.goFiles++
			ix.readGo(p, data)
		case "php":
			ix.phpFiles++
			ix.readPHP(p, data)
		case "py":
			ix.pyFiles++
			for _, m := range pyImport.FindAllSubmatch(data, -1) {
				mods := string(m[1])
				if mods == "" {
					mods = string(m[2])
				}
				for _, mod := range strings.Split(mods, ",") {
					first(ix.py, strings.ToLower(strings.TrimSpace(mod)), p)
				}
			}
		case "config":
			ix.readRefs(p, data)
			ix.readWords(p, data)
			if name == "package.json" {
				ix.readPackageJSON(p, data)
			} else {
				ix.readNames(p, data)
				ix.readPHPNames(p, data)
			}
		}
		return nil
	})
	return ix
}

func readCapped(fsys fs.FS, p string) ([]byte, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxReachFileBytes+1))
}

func first(m map[string]string, k, file string) {
	if _, ok := m[k]; !ok && k != "" {
		m[k] = file
	}
}

// npmSpecPackage returns the package an import specifier names ("lodash/fp" ->
// "lodash", "@a/b/c" -> "@a/b"), or "" for a relative path or a built-in.
func npmSpecPackage(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.Contains(spec, ":") {
		return ""
	}
	parts := strings.SplitN(spec, "/", 3)
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return ""
		}
		return strings.ToLower(parts[0] + "/" + parts[1])
	}
	return strings.ToLower(parts[0])
}

// readRefs records packages named by path or run by a command in any
// text: <script src="/node_modules/x/x.js">, npx x in a Makefile.
func (ix *importIndex) readRefs(p string, data []byte) {
	for _, re := range []*regexp.Regexp{nodeModulesRef, npxRef, nodeRequireRef, styleImportRef} {
		for _, m := range re.FindAllSubmatch(data, -1) {
			first(ix.npmNamed, npmSpecPackage(string(m[1])), p)
		}
	}
}

// readWords records every word of a script or configuration file, so a
// package's program run by its own name (tsc, from typescript) is found.
func (ix *importIndex) readWords(p string, data []byte) {
	if ix.words == nil {
		ix.words = map[string]string{}
	}
	for _, w := range wordRe.FindAll(data, -1) {
		if len(ix.words) >= maxWords {
			ix.skipped("too many words in scripts and configuration")
			return
		}
		first(ix.words, string(w), p)
	}
}

// skipped notes the first reason the reading is not whole.
func (ix *importIndex) skipped(why string) {
	if ix.partial == "" {
		ix.partial = why
	}
}

// thirdPartyVendor: p is Go's vendor directory (modules.txt) or
// Composer's (autoload.php), whose code the lockfile graph covers.
func thirdPartyVendor(fsys fs.FS, p string) bool {
	for _, f := range []string{"modules.txt", "autoload.php", "composer/installed.json"} {
		if _, err := fs.Stat(fsys, path.Join(p, f)); err == nil {
			return true
		}
	}
	return false
}

func envFile(name string) bool { return name == ".env" || strings.HasPrefix(name, ".env.") }

// minified: a bundler's output, which carries the packages it bundled
// without a require or import of them.
func minified(name string, data []byte) bool {
	if strings.Contains(name, ".min.") || strings.Contains(name, ".bundle.") {
		return true
	}
	for len(data) > 0 {
		n := bytes.IndexByte(data, '\n')
		if n < 0 {
			n = len(data)
		}
		if n > minifiedLine {
			return true
		}
		data = data[min(n+1, len(data)):]
	}
	return false
}

func (ix *importIndex) readJS(p string, data []byte) {
	for _, m := range jsImport.FindAllSubmatch(data, -1) {
		first(ix.npm, npmSpecPackage(string(m[1])), p)
	}
	if ix.npmDyn == "" && jsDynamic.Match(data) {
		ix.npmDyn = p
	}
	ix.readNames(p, data)
	ix.readRefs(p, data)
}

// readNames records every quoted string that could be a package name: a
// package named in source or configuration ({client: 'pg'}, a plugin list)
// may be loaded by name without an import.
func (ix *importIndex) readNames(p string, data []byte) {
	for _, m := range quoted.FindAllSubmatch(data, -1) {
		first(ix.npmNamed, npmSpecPackage(string(m[1])), p)
	}
}

// readPackageJSON records packages named in package.json outside its
// dependency lists: scripts run their command-line tools, and other
// sections (jest, eslintConfig, babel, prettier) load plugins by name.
func (ix *importIndex) readPackageJSON(p string, data []byte) {
	var top map[string]json.RawMessage
	if json.Unmarshal(data, &top) != nil {
		ix.readNames(p, data)
		return
	}
	for k, v := range top {
		switch k {
		case "dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "bundleDependencies",
			"bundledDependencies", "overrides", "resolutions", "name", "version", "description", "workspaces":
			continue
		case "scripts":
			var scripts map[string]string
			_ = json.Unmarshal(v, &scripts)
			for _, s := range scripts {
				for _, w := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '&' || r == '|' || r == ';' || r == '(' || r == ')' }) {
					first(ix.npmNamed, npmSpecPackage(w), p)
				}
			}
		default:
			// Values and keys alike: {"preset": "ts-jest"}, {"plugins": {"tailwindcss": {}}}.
			ix.readNames(p, v)
		}
	}
}

func (ix *importIndex) readGo(p string, data []byte) {
	f, err := goparser.ParseFile(token.NewFileSet(), p, data, goparser.ImportsOnly)
	if err != nil {
		ix.partial = "a Go file could not be parsed"
		return
	}
	test := strings.HasSuffix(p, "_test.go")
	for _, imp := range f.Imports {
		ip, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		g := ix.goImports[ip]
		if test && g.testFile == "" {
			g.testFile = p
		} else if !test && g.file == "" {
			g.file = p
		}
		ix.goImports[ip] = g
	}
}

func (ix *importIndex) readPHP(p string, data []byte) { ix.readPHPNames(p, data) }

// readPHPNames records every namespace-qualified name (use statements,
// new, static calls, strings naming a class in configuration).
func (ix *importIndex) readPHPNames(p string, data []byte) {
	for _, m := range phpName.FindAllSubmatch(data, -1) {
		n := strings.ToLower(strings.ReplaceAll(string(m[1]), `\\`, `\`))
		// Every prefix, so a package's namespace matches however deep the
		// name goes: Foo\Bar\Baz -> foo\, foo\bar\, foo\bar\baz\.
		for i := 0; i < len(n); i++ {
			if n[i] == '\\' {
				first(ix.php, n[:i+1], p)
			}
		}
		first(ix.php, n+`\`, p)
	}
}

type composerAutoloadPkg struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Autoload struct {
		PSR4     map[string]json.RawMessage `json:"psr-4"`
		PSR0     map[string]json.RawMessage `json:"psr-0"`
		Files    []string                   `json:"files"`
		Classmap []string                   `json:"classmap"`
	} `json:"autoload"`
	Extra map[string]json.RawMessage `json:"extra"`
}

// composerInfo is what composer.lock says about how a package is loaded.
type composerInfo struct {
	namespaces []string // lower-case, ending in a backslash
	shown      []string // as written, for the evidence
	why        string   // when set, the package can be loaded without being named: unknown
}

func composerAutoload(fsys fs.FS, obs []model.Observation) map[string]composerInfo {
	out := map[string]composerInfo{}
	seen := map[string]bool{}
	for _, o := range obs {
		if !strings.HasPrefix(o.Purl, "pkg:composer/") || seen[o.Location] || path.Base(o.Location) != "composer.lock" {
			continue
		}
		seen[o.Location] = true
		data, err := readLimited(fsys, o.Location)
		if err != nil {
			continue
		}
		var lock struct {
			Packages    []composerAutoloadPkg `json:"packages"`
			PackagesDev []composerAutoloadPkg `json:"packages-dev"`
		}
		if json.Unmarshal(data, &lock) != nil {
			continue
		}
		for _, p := range append(lock.Packages, lock.PackagesDev...) {
			var ci composerInfo
			root := false
			add := func(ns string) {
				ns = strings.Trim(ns, `\`)
				if ns == "" {
					root = true
					return
				}
				ci.namespaces = append(ci.namespaces, strings.ToLower(ns)+`\`)
				ci.shown = append(ci.shown, ns)
			}
			for ns := range p.Autoload.PSR4 {
				add(ns)
			}
			for ns := range p.Autoload.PSR0 {
				add(strings.ReplaceAll(ns, "_", `\`))
			}
			_, laravel := p.Extra["laravel"]
			switch {
			case root:
				ci.why = "it autoloads classes from the root namespace, so there is no namespace to look for"
			case len(p.Autoload.Files) > 0:
				ci.why = "it loads files on every request (autoload files)"
			case p.Type == "composer-plugin" || p.Type == "symfony-bundle" || laravel:
				ci.why = "frameworks or Composer load it without the application naming it"
			case len(p.Autoload.Classmap) > 0 && len(ci.namespaces) == 0:
				ci.why = "it is autoloaded by class map, without a namespace to look for"
			case len(ci.namespaces) == 0:
				ci.why = "it has no namespace to look for"
			}
			out[strings.ToLower(p.Name)] = ci
		}
	}
	return out
}

// decide sets one observation's reachability from the index.
func (ix *importIndex) decide(o *model.Observation, comp map[string]composerInfo, g depGraphs) *model.Reachability {
	pu, err := packageurl.FromString(o.Purl)
	if err != nil {
		return nil
	}
	unknown := func(why string) *model.Reachability {
		return &model.Reachability{Status: model.ReachUnknown, Evidence: []string{clip(why)}}
	}
	reachable := func(name, file string) *model.Reachability {
		return &model.Reachability{Status: model.ReachReachable, Evidence: []string{clip(name + " is imported by " + file)}}
	}
	// Not imported is claimed only for a direct dependency that no other
	// package in its lockfile depends on: a transitive one runs whenever
	// the package that needs it does (body-parser under express), whatever
	// first-party code imports.
	notImported := func(name, line string) *model.Reachability {
		switch {
		case o.Direct == nil || !*o.Direct:
			return unknown(name + " is not a direct dependency: it runs whenever a package that depends on it does, so not imported cannot be shown")
		case !g.graphed[o.Location]:
			return unknown(o.Location + " does not record which packages depend on which, so a package that uses " + name + " cannot be ruled out")
		case g.outside[o.Location] != "":
			return unknown(fmt.Sprintf("first-party code outside the scanned tree (%s, in %s) was not read", g.outside[o.Location], o.Location))
		case g.dependents[g.key(o.Location, name)] != "":
			return unknown(fmt.Sprintf("%s depends on %s (%s), so it runs when that package does", g.dependents[g.key(o.Location, name)], name, o.Location))
		}
		for _, b := range g.bins[g.key(o.Location, name)] {
			if f, ok := ix.words[b]; ok {
				return unknown(fmt.Sprintf("its program %s is named in %s, so it may be run", b, f))
			}
		}
		ev := []string{clip(line), clip("no other package in " + o.Location + " depends on it")}
		if o.Scope == "dev" {
			ev = append(ev, "development dependency")
		}
		return &model.Reachability{Status: model.ReachNotImported, Evidence: ev}
	}
	switch pu.Type {
	case "npm":
		name := strings.ToLower(pu.Name)
		if pu.Namespace != "" {
			name = strings.ToLower(pu.Namespace) + "/" + name
		}
		if f, ok := ix.npm[name]; ok {
			return reachable(name, f)
		}
		switch {
		case ix.jsFiles == 0:
			return unknown("no JavaScript or TypeScript source files to check")
		case ix.partial != "":
			return unknown("not every source file was read: " + ix.partial)
		case ix.npmDyn != "":
			return unknown("a computed require or import() in " + ix.npmDyn + " means imports cannot all be read")
		case ix.npmBundle != "":
			return unknown("the minified bundle " + ix.npmBundle + " may hold packages without importing them")
		}
		if f, ok := ix.npmNamed[name]; ok {
			return unknown(name + " is named in " + f + ", so it may be loaded by name without an import")
		}
		return notImported(name, fmt.Sprintf("no import or require of %s in %d JavaScript/TypeScript files, and not named in scripts, templates or configuration", name, ix.jsFiles))
	case "golang":
		mod := pu.Name
		if pu.Namespace != "" {
			mod = pu.Namespace + "/" + pu.Name
		}
		if mod == "stdlib" || mod == "go" || mod == "toolchain" {
			return nil
		}
		for ip, gi := range ix.goImports {
			if (ip == mod || strings.HasPrefix(ip, mod+"/")) && gi.file != "" {
				return reachable(mod, gi.file)
			}
		}
		// go.mod and go.sum do not record which module requires which, so
		// a module the program uses may use this one: never not imported.
		return unknown("go.mod does not record which modules use " + mod + ", so not imported cannot be shown")
	case "composer":
		name := strings.ToLower(pu.Namespace + "/" + pu.Name)
		ci, ok := comp[name]
		if !ok {
			return unknown("its autoload namespaces could not be read from composer.lock")
		}
		for i, ns := range ci.namespaces {
			if f, ok := ix.php[ns]; ok {
				return &model.Reachability{Status: model.ReachReachable,
					Evidence: []string{clip(fmt.Sprintf("%s (namespace %s) is referenced in %s", name, ci.shown[i], f))}}
			}
		}
		switch {
		case ci.why != "":
			return unknown(name + ": " + ci.why)
		case ix.phpFiles == 0:
			return unknown("no PHP source files to check")
		case ix.partial != "":
			return unknown("not every source file was read: " + ix.partial)
		}
		return notImported(name, fmt.Sprintf("no reference to the namespace %s in %d PHP files or configuration", ci.shown[0], ix.phpFiles))
	case "pypi":
		mod := strings.NewReplacer("-", "_", ".", "_").Replace(strings.ToLower(pu.Name))
		if f, ok := ix.py[mod]; ok {
			return reachable(pu.Name, f)
		}
		// A distribution's import name can differ from its name (PyYAML is
		// yaml): an absent import proves nothing.
		return unknown("Python import names can differ from package names, so not imported cannot be shown")
	}
	return nil
}

// minifiedLine: a line longer than this is a bundler's, not a person's.
const minifiedLine = 5000

// maxWords caps the words kept from scripts and configuration.
const maxWords = 200000

// depGraphs says, for lockfiles that record the dependency graph, which
// packages another (third-party) package depends on.
type depGraphs struct {
	graphed    map[string]bool     // lockfile -> its graph was read
	dependents map[string]string   // key(lockfile, package) -> first package depending on it
	outside    map[string]string   // lockfile -> first-party code outside the tree, which was not read
	bins       map[string][]string // key(lockfile, package) -> its programs (npm "bin")
}

func (depGraphs) key(lockfile, pkg string) string { return lockfile + "\x00" + strings.ToLower(pkg) }

// readDepGraphs reads the graph of each package-lock.json or
// npm-shrinkwrap.json (lockfile version 2 or 3) and composer.lock the
// observations come from. Other lockfiles (yarn, pnpm, npm version 1)
// are not read, so nothing from them is claimed not imported.
func readDepGraphs(fsys fs.FS, obs []model.Observation) depGraphs {
	g := depGraphs{graphed: map[string]bool{}, dependents: map[string]string{}, outside: map[string]string{}, bins: map[string][]string{}}
	done := map[string]bool{}
	for _, o := range obs {
		loc := o.Location
		if done[loc] {
			continue
		}
		done[loc] = true
		switch path.Base(loc) {
		case "package-lock.json", "npm-shrinkwrap.json":
			g.readNpm(fsys, loc)
		case "composer.lock":
			g.readComposer(fsys, loc)
		}
	}
	return g
}

// outsideTree: a path relative to the lockfile's directory ("../x",
// "./../x", "a/../../x") or absolute, that leaves the scanned tree.
func outsideTree(p string) bool {
	if p == "" {
		return false
	}
	if path.IsAbs(p) || strings.HasPrefix(p, "file:/") {
		return true
	}
	c := path.Clean(strings.TrimPrefix(p, "file:"))
	return c == ".." || strings.HasPrefix(c, "../")
}

func (g depGraphs) add(loc, dependent, pkg string) {
	if k := g.key(loc, pkg); g.dependents[k] == "" {
		g.dependents[k] = dependent
	}
}

func (g depGraphs) readNpm(fsys fs.FS, loc string) {
	data, err := readLimited(fsys, loc)
	if err != nil {
		return
	}
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
			Bin                  json.RawMessage   `json:"bin"`
			Link                 bool              `json:"link"`
			Resolved             string            `json:"resolved"`
		} `json:"packages"`
	}
	if json.Unmarshal(data, &lock) != nil || lock.LockfileVersion < 2 || len(lock.Packages) == 0 {
		return
	}
	for key, p := range lock.Packages {
		// "" is the project and paths outside node_modules are its
		// workspaces: first-party code, whose dependencies are direct.
		i := strings.LastIndex(key, "node_modules/")
		if i < 0 {
			// A workspace (or file: dependency) outside the scanned tree is
			// first-party code that was not read.
			if outsideTree(key) {
				g.outside[loc] = key
			}
			continue
		}
		name := key[i+len("node_modules/"):]
		if p.Link && outsideTree(p.Resolved) {
			g.outside[loc] = p.Resolved
		}
		var bins map[string]string
		if json.Unmarshal(p.Bin, &bins) == nil {
			for b := range bins {
				k := g.key(loc, name)
				g.bins[k] = append(g.bins[k], b)
			}
		}
		for _, deps := range []map[string]string{p.Dependencies, p.OptionalDependencies, p.PeerDependencies} {
			for d := range deps {
				g.add(loc, name, d)
			}
		}
	}
	g.graphed[loc] = true
}

func (g depGraphs) readComposer(fsys fs.FS, loc string) {
	data, err := readLimited(fsys, loc)
	if err != nil {
		return
	}
	type pkg struct {
		Name    string            `json:"name"`
		Require map[string]string `json:"require"`
		Provide map[string]string `json:"provide"`
		Replace map[string]string `json:"replace"`
		Dist    struct {
			Type string `json:"type"`
			URL  string `json:"url"`
		} `json:"dist"`
	}
	var lock struct {
		Packages    []pkg `json:"packages"`
		PackagesDev []pkg `json:"packages-dev"`
	}
	if json.Unmarshal(data, &lock) != nil || lock.Packages == nil {
		return
	}
	for _, p := range append(lock.Packages, lock.PackagesDev...) {
		for d := range p.Require {
			g.add(loc, p.Name, d)
		}
		// A package that provides or replaces another (guzzle provides
		// psr/http-client-implementation) is used by packages that require
		// what it provides, without naming it.
		for v := range p.Provide {
			g.add(loc, "packages that require "+v+", which it provides", p.Name)
		}
		for v := range p.Replace {
			g.add(loc, "packages that require "+v+", which it replaces", p.Name)
		}
		if p.Dist.Type == "path" && outsideTree(p.Dist.URL) {
			g.outside[loc] = p.Dist.URL
		}
	}
	g.graphed[loc] = true
}
