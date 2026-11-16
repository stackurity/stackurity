package lockfile

// Reachability of lockfile packages: does first-party source import them?
// (docs/reachability.md). Source files are read as data, never run or
// built, within the same walk limits as the lockfiles. Only what can be
// shown is claimed: a package is "not imported" only when every source file
// of its language was read, none imports it, and nothing names it in a way
// that loads it without an import; otherwise it stays unknown.

import (
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
	jsExts     = map[string]bool{".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".mts": true, ".cts": true, ".vue": true, ".svelte": true, ".astro": true}
	configExts = map[string]bool{".json": true, ".yml": true, ".yaml": true, ".toml": true, ".xml": true, ".neon": true}
	// Lockfiles and manifests list every package: being named there says
	// nothing about use. package.json is read separately (its scripts).
	notConfig = map[string]bool{"package.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true, "composer.json": true,
		"composer.lock": true, "yarn.lock": true, "pnpm-lock.yaml": true, "Pipfile.lock": true, "poetry.lock": true, "pubspec.lock": true,
		"packages.lock.json": true, "Gemfile.lock": true, "go.sum": true, "bun.lock": true, "deno.lock": true}

	jsImport = regexp.MustCompile(`(?:\bfrom\s*|\bimport\s*|\brequire\s*\(\s*|\bimport\s*\(\s*|\bexport\s*\*\s*from\s*)['"]([^'"\n]+)['"]`)
	// A require or import() whose argument is not a string literal: the
	// imports of this tree cannot all be read.
	jsDynamic = regexp.MustCompile(`\b(?:require|import)\s*\(\s*[^'"\s)]`)
	quoted    = regexp.MustCompile("['\"`](@?[a-z0-9][a-z0-9._~-]*(?:/[a-z0-9][a-z0-9._~-]*)*)['\"`]")
	phpName   = regexp.MustCompile(`\\?\\?([A-Za-z_][A-Za-z0-9_]*(?:\\{1,2}[A-Za-z_][A-Za-z0-9_]*)+)`)
	pyImport  = regexp.MustCompile(`(?m)^\s*(?:from\s+([A-Za-z_][A-Za-z0-9_]*)[\s.]|import\s+([A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*))`)
)

// importIndex is what the walk learnt about the tree's first-party source.
type importIndex struct {
	partial string // why the scan is incomplete; "" when every file was read

	jsFiles, goFiles, phpFiles, pyFiles int

	npm       map[string]string // package -> first file importing it
	npmNamed  map[string]string // package -> first file naming it as a string (loaded by name)
	npmDyn    string            // first file with a computed require or import()
	goImports map[string]goImport
	php       map[string]string // namespace-qualified name prefix -> first file
	py        map[string]string // top-level module -> first file
}

type goImport struct{ file, testFile string }

// annotateReach reads the first-party source under fsys and sets each
// lockfile observation's reachability. It returns the coverage item that
// says what was read.
func annotateReach(ctx context.Context, fsys fs.FS, ignored map[string]bool, obs []model.Observation) model.CoverageItem {
	if len(obs) == 0 {
		return model.CoverageItem{Scope: ReachScope, Status: "skipped", Reason: "no packages to assess"}
	}
	ix := indexImports(ctx, fsys, ignored)
	comp := composerAutoload(fsys, obs)
	for i := range obs {
		obs[i].Reachability = ix.decide(&obs[i], comp)
	}
	reason := fmt.Sprintf("read %d JavaScript/TypeScript, %d Go, %d PHP and %d Python source files", ix.jsFiles, ix.goFiles, ix.phpFiles, ix.pyFiles)
	if ix.partial != "" {
		return model.CoverageItem{Scope: ReachScope, Status: "partial", Reason: clip(reason + "; " + ix.partial + ": no package is reported as not imported")}
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
			if skipDirs[d.Name()] || ignored[p] || nestedCheckout(fsys, p) {
				return fs.SkipDir
			}
			return nil
		}
		if ignored[p] || d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		name, ext := d.Name(), strings.ToLower(path.Ext(d.Name()))
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

func (ix *importIndex) readJS(p string, data []byte) {
	for _, m := range jsImport.FindAllSubmatch(data, -1) {
		first(ix.npm, npmSpecPackage(string(m[1])), p)
	}
	if ix.npmDyn == "" && jsDynamic.Match(data) {
		ix.npmDyn = p
	}
	ix.readNames(p, data)
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
func (ix *importIndex) decide(o *model.Observation, comp map[string]composerInfo) *model.Reachability {
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
	notImported := func(line string) *model.Reachability {
		ev := []string{clip(line)}
		if o.Scope == "dev" {
			ev = append(ev, "development dependency")
		}
		if o.Direct != nil && !*o.Direct {
			ev = append(ev, "transitive dependency: it may still run through a package that imports it")
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
		}
		if f, ok := ix.npmNamed[name]; ok {
			return unknown(name + " is named in " + f + ", so it may be loaded by name without an import")
		}
		return notImported(fmt.Sprintf("no import or require of %s in %d JavaScript/TypeScript files, and not named in scripts or configuration", name, ix.jsFiles))
	case "golang":
		mod := pu.Name
		if pu.Namespace != "" {
			mod = pu.Namespace + "/" + pu.Name
		}
		if mod == "stdlib" || mod == "go" || mod == "toolchain" {
			return nil
		}
		test := ""
		for ip, g := range ix.goImports {
			if ip != mod && !strings.HasPrefix(ip, mod+"/") {
				continue
			}
			if g.file != "" {
				return reachable(mod, g.file)
			}
			if test == "" {
				test = g.testFile
			}
		}
		switch {
		case ix.goFiles == 0:
			return unknown("no Go source files to check")
		case ix.partial != "":
			return unknown("not every source file was read: " + ix.partial)
		case test != "":
			return notImported(fmt.Sprintf("only test files import %s (first: %s), so it is not in the built program", mod, test))
		}
		return notImported(fmt.Sprintf("no import of a package of %s in %d Go files", mod, ix.goFiles))
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
		return notImported(fmt.Sprintf("no reference to the namespace %s in %d PHP files or configuration", ci.shown[0], ix.phpFiles))
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
