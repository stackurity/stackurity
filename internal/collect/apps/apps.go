// Package apps inventories applications deployed on a host: the libraries an
// application actually has installed (node_modules, Python site-packages,
// Composer's vendor directory) and, where nothing is installed, its
// lockfiles. Repositories describe what a project declares; a deployed
// directory shows what runs, which can differ (an old release, a manual
// install, a package added on the server).
//
// Everything is read as data. No package manager, script or application
// code is run, and symbolic links are only followed for a release layout's
// "current" link.
package apps

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
)

// Limits keep one huge or hostile tree from stalling the agent.
const (
	MaxPackagesPerApp = 100_000
	maxManifestSize   = 1 << 20
	maxNodeDepth      = 32
)

// Scanner reads applications under Root ("/" on a live host).
type Scanner struct {
	Root string
	// Owned reports whether an OS package installed the file at a host
	// path; such libraries are already inventoried through the package
	// database. Nil means nothing is owned.
	Owned func(hostPath string) bool
	// Packs read files the core cannot (deployed JARs, Cargo.lock, ...): the
	// stack packs installed on the server.
	Packs []lockfile.Extension
}

// App is one deployed application and what it has installed.
type App struct {
	Dir          string // host path
	Name         string
	GitURL       string // origin remote, when the directory is a Git checkout
	Observations []model.Observation
	Coverage     []model.CoverageItem
	Truncated    bool
}

func (s *Scanner) path(hostPath string) string { return filepath.Join(s.Root, hostPath) }

// markers identify a project directory during discovery.
var markers = []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.json", "composer.lock",
	"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "Gemfile.lock", "go.mod", "Cargo.lock", "pubspec.lock"}

// DiscoverBases are searched by Discover. Home directories are included
// because many servers deploy under a service user's home.
var DiscoverBases = []string{"/srv", "/var/www", "/opt", "/app", "/home/*", "/home/*/apps", "/home/*/www"}

// Discover returns project directories up to three levels below the usual
// deployment bases. A release layout (releases/ plus a current link) yields
// only the current release.
func (s *Scanner) Discover() []string {
	seen := map[string]bool{}
	var out []string
	for _, pattern := range DiscoverBases {
		bases, _ := filepath.Glob(s.path(pattern))
		sort.Strings(bases)
		for _, base := range bases {
			s.discoverIn(s.hostPath(base), 0, seen, &out)
		}
	}
	return out
}

func (s *Scanner) discoverIn(dir string, depth int, seen map[string]bool, out *[]string) {
	if depth > 3 || seen[dir] {
		return
	}
	if cur, ok := s.currentRelease(dir); ok {
		dir = cur
		if seen[dir] {
			return
		}
	}
	for _, m := range markers {
		if fi, err := os.Lstat(s.path(path.Join(dir, m))); err == nil && fi.Mode().IsRegular() {
			seen[dir] = true
			*out = append(*out, dir)
			return // lockfiles below are found by the app scan itself
		}
	}
	entries, err := os.ReadDir(s.path(dir))
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.IsDir() || skipDiscover[e.Name()] || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		s.discoverIn(path.Join(dir, e.Name()), depth+1, seen, out)
	}
}

var skipDiscover = map[string]bool{"node_modules": true, "vendor": true, "releases": true, "shared": true, "cache": true, "tmp": true, "logs": true}

// currentRelease follows Capistrano/Deployer-style layouts, where old
// releases stay on disk but only "current" runs.
func (s *Scanner) currentRelease(dir string) (string, bool) {
	if fi, err := os.Stat(s.path(path.Join(dir, "releases"))); err != nil || !fi.IsDir() {
		return "", false
	}
	target, err := os.Readlink(s.path(path.Join(dir, "current")))
	if err != nil {
		return "", false
	}
	if !path.IsAbs(target) {
		target = path.Join(dir, target)
	}
	target = path.Clean(target)
	if !strings.HasPrefix(target, dir+"/") {
		return "", false // a release must live under the application
	}
	return target, true
}

func (s *Scanner) hostPath(p string) string {
	rel, err := filepath.Rel(s.Root, p)
	if err != nil {
		return p
	}
	return "/" + filepath.ToSlash(rel)
}

// ScanApp inventories one application directory.
func (s *Scanner) ScanApp(ctx context.Context, dir string) App {
	dir = path.Clean("/" + dir)
	if cur, ok := s.currentRelease(dir); ok {
		dir = cur
	}
	app := App{Dir: dir, Name: path.Base(dir)}
	fi, err := os.Stat(s.path(dir))
	if err != nil || !fi.IsDir() {
		reason := "not a directory"
		if err != nil {
			reason = err.Error()
		}
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: "app:" + dir, Status: "failed", Reason: reason})
		return app
	}
	if n := s.packageName(dir); n != "" {
		app.Name = n
	}
	app.GitURL = s.gitOrigin(dir)

	// Installed trees, per project directory inside the application.
	installed := map[string]map[string]bool{} // project dir -> purl types read from installed metadata
	note := func(projectDir, typ string) {
		if installed[projectDir] == nil {
			installed[projectDir] = map[string]bool{}
		}
		installed[projectDir][typ] = true
	}
	add := func(obs []model.Observation) {
		for _, o := range obs {
			if len(app.Observations) >= MaxPackagesPerApp {
				app.Truncated = true
				return
			}
			app.Observations = append(app.Observations, o)
		}
	}
	err = filepath.WalkDir(s.path(dir), func(full string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		host := s.hostPath(full)
		name := d.Name()
		switch {
		case name == "node_modules":
			project := path.Dir(host)
			obs, cov := s.scanNodeModules(project, host)
			add(obs)
			app.Coverage = append(app.Coverage, cov)
			if len(obs) > 0 {
				note(project, "npm")
			}
			return fs.SkipDir
		case name == "site-packages" || name == "dist-packages":
			project := pythonProject(host)
			obs, cov := s.scanSitePackages(host)
			add(obs)
			app.Coverage = append(app.Coverage, cov)
			if len(obs) > 0 {
				note(project, "pypi")
			}
			return fs.SkipDir
		case name == "vendor":
			if _, err := os.Stat(path.Join(full, "composer", "installed.json")); err == nil {
				project := path.Dir(host)
				obs, cov := s.scanComposerInstalled(host)
				add(obs)
				app.Coverage = append(app.Coverage, cov)
				if len(obs) > 0 {
					note(project, "composer")
				}
			}
			return fs.SkipDir
		case name == ".git" || name == "releases" && host != dir:
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: "app:" + dir, Status: "failed", Reason: err.Error()})
	}

	// Lockfiles fill in ecosystems that have nothing installed (for example
	// a Go or Rust service, or a PHP app deployed without vendor/).
	locks, lcov, err := lockfile.ScanWith(ctx, os.DirFS(s.path(dir)), s.Packs)
	if err != nil {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: "lockfiles:" + dir, Status: "failed", Reason: err.Error()})
	}
	var kept []model.Observation
	for _, o := range locks {
		lockDir := path.Join(dir, path.Dir(o.Location))
		if installed[lockDir][purlType(o.Purl)] {
			continue // the installed tree is what runs
		}
		o.Location = path.Join(dir, o.Location)
		if o.Evidence == nil {
			o.Evidence = map[string]string{}
		}
		o.Evidence["source"] = "lockfile"
		o.Evidence["app_dir"] = dir
		kept = append(kept, o)
	}
	add(kept)
	for _, c := range lcov {
		if i := strings.Index(c.Scope, ":"); i > 0 {
			c.Scope = c.Scope[:i+1] + path.Join(dir, c.Scope[i+1:])
		}
		app.Coverage = append(app.Coverage, c)
	}
	if len(app.Coverage) == 0 {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: "app:" + dir, Status: "skipped", Reason: "no installed libraries or supported lockfiles found"})
	}
	if app.Truncated {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: "app:" + dir, Status: "partial",
			Reason: fmt.Sprintf("stopped after %d packages", MaxPackagesPerApp)})
	}
	for i := range app.Observations {
		app.Observations[i].Evidence["app_dir"] = dir
	}
	return app
}

// GlobalDirs hold libraries installed for the whole host rather than one
// application: global npm packages and system-wide pip installs.
var GlobalDirs = []string{
	"/usr/lib/node_modules", "/usr/local/lib/node_modules",
	"/root/.nvm/versions/node/*/lib/node_modules", "/home/*/.nvm/versions/node/*/lib/node_modules",
	"/usr/local/lib/python3*/site-packages", "/usr/local/lib/python3*/dist-packages",
	"/usr/lib/python3/dist-packages", "/usr/lib/python3*/site-packages",
}

// ScanGlobal inventories host-wide libraries that no OS package owns.
func (s *Scanner) ScanGlobal() ([]model.Observation, []model.CoverageItem) {
	var obs []model.Observation
	var cov []model.CoverageItem
	for _, pattern := range GlobalDirs {
		dirs, _ := filepath.Glob(s.path(pattern))
		sort.Strings(dirs)
		for _, full := range dirs {
			host := s.hostPath(full)
			var o []model.Observation
			var c model.CoverageItem
			if strings.HasSuffix(host, "node_modules") {
				o, c = s.scanNodeModules("", host)
			} else {
				o, c = s.scanSitePackages(host)
			}
			for i := range o {
				o[i].Evidence["global"] = "true"
				o[i].Direct = boolp(true)
			}
			obs = append(obs, o...)
			cov = append(cov, c)
		}
	}
	return obs, cov
}

// --- npm

type packageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Private         bool              `json:"private"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	OptionalDeps    map[string]string `json:"optionalDependencies"`
}

// scanNodeModules reads every installed package's package.json. project is
// the directory that owns node_modules ("" for a global install); its
// package.json decides which packages are direct, and npm's hidden lockfile
// (node_modules/.package-lock.json) which are dev-only.
func (s *Scanner) scanNodeModules(project, nm string) ([]model.Observation, model.CoverageItem) {
	scope := "npm-installed:" + nm
	direct := map[string]bool{}
	if project != "" {
		var root packageJSON
		if readJSON(s.path(path.Join(project, "package.json")), &root) == nil {
			for _, m := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDeps} {
				for n := range m {
					direct[n] = true
				}
			}
		}
	}
	dev := map[string]bool{}
	var hidden struct {
		Packages map[string]struct {
			Dev bool `json:"dev"`
		} `json:"packages"`
	}
	if readJSON(s.path(path.Join(nm, ".package-lock.json")), &hidden) == nil {
		for k, p := range hidden.Packages {
			if p.Dev {
				dev[path.Join(path.Dir(nm), k)] = true
			}
		}
	}

	var obs []model.Observation
	var failed []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxNodeDepth || len(obs) >= MaxPackagesPerApp {
			return
		}
		entries, err := os.ReadDir(s.path(dir))
		if err != nil {
			failed = append(failed, err.Error())
			return
		}
		for _, e := range entries {
			name := e.Name()
			if strings.HasPrefix(name, ".") || !e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
				continue
			}
			if e.Type()&fs.ModeSymlink != 0 {
				continue // npm link / workspace packages are the project's own code
			}
			if strings.HasPrefix(name, "@") {
				scoped, err := os.ReadDir(s.path(path.Join(dir, name)))
				if err != nil {
					continue
				}
				for _, se := range scoped {
					if se.IsDir() {
						s.readNodePackage(path.Join(dir, name, se.Name()), project, nm, direct, dev, &obs, walk, depth)
					}
				}
				continue
			}
			s.readNodePackage(path.Join(dir, name), project, nm, direct, dev, &obs, walk, depth)
		}
	}
	walk(nm, 0)
	// pnpm keeps real package directories in node_modules/.pnpm/<id>/node_modules/
	// and links them into place; read the real ones.
	if entries, err := os.ReadDir(s.path(path.Join(nm, ".pnpm"))); err == nil {
		for _, e := range entries {
			if !e.IsDir() || e.Name() == "node_modules" {
				continue
			}
			inner := path.Join(nm, ".pnpm", e.Name(), "node_modules")
			pkgs, err := os.ReadDir(s.path(inner))
			if err != nil {
				continue
			}
			for _, pe := range pkgs {
				dirs := []string{path.Join(inner, pe.Name())}
				if strings.HasPrefix(pe.Name(), "@") {
					dirs = nil
					scoped, _ := os.ReadDir(s.path(path.Join(inner, pe.Name())))
					for _, se := range scoped {
						if se.IsDir() {
							dirs = append(dirs, path.Join(inner, pe.Name(), se.Name()))
						}
					}
				} else if !pe.IsDir() {
					continue // symlinks are the package's dependencies, read via their own entry
				}
				for _, d := range dirs {
					s.readNodePackage(d, "", "", direct, dev, &obs, func(string, int) {}, maxNodeDepth) // direct is unknown in this layout
				}
			}
		}
	}
	return obs, coverage(scope, failed, len(obs) >= MaxPackagesPerApp)
}

func (s *Scanner) readNodePackage(pkgDir, project, nm string, direct, dev map[string]bool, obs *[]model.Observation,
	walk func(string, int), depth int) {
	manifest := path.Join(pkgDir, "package.json")
	var p packageJSON
	if err := readJSON(s.path(manifest), &p); err != nil || p.Name == "" || p.Version == "" {
		return
	}
	if s.Owned != nil && s.Owned(manifest) {
		return // installed by an OS package (e.g. Debian's npm)
	}
	top := path.Dir(pkgDir) == nm || path.Dir(path.Dir(pkgDir)) == nm && strings.HasPrefix(path.Base(path.Dir(pkgDir)), "@")
	var d *bool
	if project != "" {
		d = boolp(top && direct[p.Name])
	}
	scope := "runtime"
	if dev[pkgDir] {
		scope = "dev"
	}
	*obs = append(*obs, model.Observation{
		Purl:       npmPurl(p.Name, p.Version),
		Version:    p.Version,
		Location:   pkgDir,
		Direct:     d,
		Scope:      scope,
		Confidence: model.ConfidenceConfirmed,
		Evidence:   map[string]string{"source": "installed", "manifest": "package.json"},
	})
	if fi, err := os.Stat(s.path(path.Join(pkgDir, "node_modules"))); err == nil && fi.IsDir() {
		walk(path.Join(pkgDir, "node_modules"), depth+1)
	}
}

func npmPurl(name, version string) string {
	ns := ""
	if strings.HasPrefix(name, "@") {
		if scope, rest, ok := strings.Cut(name, "/"); ok {
			ns, name = scope, rest
		}
	}
	return packageurl.NewPackageURL("npm", ns, name, version, nil, "").ToString()
}

// --- Python

var pep503 = regexp.MustCompile(`[-_.]+`)

// pythonProject maps .../venv/lib/python3.12/site-packages to the directory
// holding the virtual environment.
func pythonProject(sitePackages string) string {
	p := sitePackages
	for i := 0; i < 4; i++ {
		p = path.Dir(p)
	}
	return p
}

// scanSitePackages reads *.dist-info/METADATA and *.egg-info/PKG-INFO.
func (s *Scanner) scanSitePackages(dir string) ([]model.Observation, model.CoverageItem) {
	scope := "python-installed:" + dir
	entries, err := os.ReadDir(s.path(dir))
	if err != nil {
		return nil, coverage(scope, []string{err.Error()}, false)
	}
	var obs []model.Observation
	for _, e := range entries {
		var meta string
		switch {
		case strings.HasSuffix(e.Name(), ".dist-info"):
			meta = path.Join(dir, e.Name(), "METADATA")
		case strings.HasSuffix(e.Name(), ".egg-info"):
			meta = path.Join(dir, e.Name(), "PKG-INFO")
			if !e.IsDir() {
				meta = path.Join(dir, e.Name()) // a single-file egg-info
			}
		default:
			continue
		}
		if s.Owned != nil && (s.Owned(meta) || s.Owned(path.Join(dir, e.Name()))) {
			continue
		}
		name, version := readPythonMetadata(s.path(meta))
		if name == "" || version == "" {
			continue
		}
		obs = append(obs, model.Observation{
			Purl:       packageurl.NewPackageURL("pypi", "", strings.ToLower(pep503.ReplaceAllString(name, "-")), version, nil, "").ToString(),
			Version:    version,
			Location:   path.Join(dir, e.Name()),
			Scope:      "runtime",
			Confidence: model.ConfidenceConfirmed,
			Evidence:   map[string]string{"source": "installed", "manifest": path.Base(meta)},
		})
		if len(obs) >= MaxPackagesPerApp {
			break
		}
	}
	return obs, coverage(scope, nil, len(obs) >= MaxPackagesPerApp)
}

// readPythonMetadata reads Name and Version from the RFC 822 header block.
func readPythonMetadata(file string) (name, version string) {
	f, err := os.Open(file)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxManifestSize))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers; the description follows
		}
		if v, ok := strings.CutPrefix(line, "Name: "); ok {
			name = strings.TrimSpace(v)
		} else if v, ok := strings.CutPrefix(line, "Version: "); ok {
			version = strings.TrimSpace(v)
		}
	}
	return name, version
}

// --- Composer

// scanComposerInstalled reads vendor/composer/installed.json (Composer 1
// and 2), the record of what composer install put in vendor/.
func (s *Scanner) scanComposerInstalled(vendor string) ([]model.Observation, model.CoverageItem) {
	file := path.Join(vendor, "composer", "installed.json")
	scope := "composer-installed:" + file
	data, err := readLimited(s.path(file), 64<<20)
	if err != nil {
		return nil, coverage(scope, []string{err.Error()}, false)
	}
	type pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	var v2 struct {
		Packages        []pkg    `json:"packages"`
		DevPackageNames []string `json:"dev-package-names"`
	}
	var list []pkg
	devNames := map[string]bool{}
	if err := json.Unmarshal(data, &v2); err == nil && v2.Packages != nil {
		list = v2.Packages
		for _, n := range v2.DevPackageNames {
			devNames[n] = true
		}
	} else if err := json.Unmarshal(data, &list); err != nil {
		return nil, coverage(scope, []string{"parse installed.json: " + err.Error()}, false)
	}
	var obs []model.Observation
	for _, p := range list {
		vendorName, name, ok := strings.Cut(p.Name, "/")
		if !ok || p.Version == "" {
			continue
		}
		version := strings.TrimPrefix(p.Version, "v")
		conf := model.ConfidenceConfirmed
		if strings.HasPrefix(version, "dev-") {
			conf = model.ConfidenceLow
		}
		scope := "runtime"
		if devNames[p.Name] {
			scope = "dev"
		}
		obs = append(obs, model.Observation{
			Purl:       packageurl.NewPackageURL("composer", vendorName, name, version, nil, "").ToString(),
			Version:    version,
			Location:   path.Join(vendor, p.Name),
			Scope:      scope,
			Confidence: conf,
			Evidence:   map[string]string{"source": "installed", "manifest": "vendor/composer/installed.json"},
		})
	}
	return obs, coverage(scope, nil, false)
}

// --- helpers

func (s *Scanner) packageName(dir string) string {
	var p packageJSON
	if readJSON(s.path(path.Join(dir, "package.json")), &p) == nil && p.Name != "" {
		return p.Name
	}
	var c struct {
		Name string `json:"name"`
	}
	if readJSON(s.path(path.Join(dir, "composer.json")), &c) == nil && c.Name != "" {
		return c.Name
	}
	return ""
}

var remoteURL = regexp.MustCompile(`^\s*url\s*=\s*(\S+)\s*$`)

// gitOrigin reads the origin remote from .git/config, without running git.
// Credentials embedded in the URL are dropped.
func (s *Scanner) gitOrigin(dir string) string {
	data, err := readLimited(s.path(path.Join(dir, ".git", "config")), 256<<10)
	if err != nil {
		return ""
	}
	inOrigin := false
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			inOrigin = t == `[remote "origin"]`
			continue
		}
		if m := remoteURL.FindStringSubmatch(line); inOrigin && m != nil {
			return stripCredentials(m[1])
		}
	}
	return ""
}

func stripCredentials(u string) string {
	if scheme, rest, ok := strings.Cut(u, "://"); ok {
		if at := strings.LastIndex(strings.SplitN(rest, "/", 2)[0], "@"); at >= 0 {
			rest = rest[at+1:]
		}
		return scheme + "://" + rest
	}
	return u
}

func purlType(p string) string {
	t, _, _ := strings.Cut(strings.TrimPrefix(p, "pkg:"), "/")
	return t
}

func coverage(scope string, failed []string, truncated bool) model.CoverageItem {
	switch {
	case len(failed) > 0:
		reason := failed[0]
		if len(failed) > 1 {
			reason = fmt.Sprintf("%s (and %d more)", reason, len(failed)-1)
		}
		return model.CoverageItem{Scope: scope, Status: "partial", Reason: reason}
	case truncated:
		return model.CoverageItem{Scope: scope, Status: "partial", Reason: fmt.Sprintf("stopped after %d packages", MaxPackagesPerApp)}
	}
	return model.CoverageItem{Scope: scope, Status: "checked"}
}

func readJSON(file string, v any) error {
	data, err := readLimited(file, maxManifestSize)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func readLimited(file string, max int64) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("file too large")
	}
	return data, nil
}

func boolp(b bool) *bool { return &b }
