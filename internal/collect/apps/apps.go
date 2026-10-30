// Package apps inventories applications deployed on a host: the libraries an
// application actually has installed (node_modules, Python site-packages,
// Composer's vendor directory) and, where nothing is installed, its
// lockfiles. Front-end libraries a site loads from a CDN or keeps a copy of
// are read from its templates and file banners (webassets.go).
// Repositories describe what a project declares; a deployed directory shows
// what runs, which can differ (an old release, a manual install, a package
// added on the server).
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
	"slices"
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
	// Discovery reads at most this many directories and reports at most
	// this many applications per run, however many home directories or
	// checkouts a server has.
	maxDiscoverDirs = 20_000
	MaxDiscoverApps = 200
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
	// Apps lists every application directory being reported on this host.
	// An application inside another (phpMyAdmin under a site's webroot)
	// belongs only to itself: the outer scan skips it, so one library is
	// never reported twice.
	Apps []string
}

// nestedApp reports whether host path p is another application below dir.
func (s *Scanner) nestedApp(dir, p string) bool {
	for _, a := range s.Apps {
		a = path.Clean("/" + a)
		if a != dir && strings.HasPrefix(a, dir+"/") && (p == a || strings.HasPrefix(p, a+"/")) {
			return true
		}
	}
	return false
}

// App is one deployed application and what it has installed.
type App struct {
	Dir          string // host path
	Name         string
	GitURL       string // origin remote, when the directory is a Git checkout
	Observations []model.Observation
	Coverage     []model.CoverageItem
	Truncated    bool
	// Unreadable: the agent's user may not read the directory itself, so
	// nothing in it was inventoried (see PermissionScope).
	Unreadable bool
}

func (s *Scanner) path(hostPath string) string { return filepath.Join(s.Root, hostPath) }

// markers identify a project directory during discovery. A WordPress site
// usually has no manifest: its wp-config.php (which may sit one level above
// the install) or wp-includes/version.php marks it. Its plugins and themes
// under wp-content are part of the site, never applications of their own:
// discovery does not look below a directory a marker here has found (an
// index file is different, see webIndexes).
var markers = []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.json", "composer.lock",
	"requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock", "Gemfile.lock", "go.mod", "Cargo.lock", "pubspec.lock",
	"wp-config.php", "wp-includes/version.php"}

// webIndexes mark a plain PHP or HTML site, which has no manifest. They do
// not count in a discovery base (/var/www, a home directory, /home/*/www),
// in a directory whose name says it is documentation, examples or tests
// (skipWebDir), or for a web server's or distribution's placeholder page
// (Debian's /var/www/html/index.html): discovery goes on below such a
// directory as before.
//
// Unlike a manifest, an index file does not end the walk: a site's
// directory often holds other applications (a WordPress blog under /blog,
// a Laravel app served by a virtual host of its own, a cPanel addon
// domain). Below a site, a directory is an application of its own when it
// is a WordPress site, a document root of its own in the web server
// configuration (or holds one), or has a manifest and an entry point of
// its own (appEntry); a library the site's code uses, with only a
// manifest (a mail library under public/mail with its composer.lock and
// vendor/), is part of the site and read by its scan.
var webIndexes = []string{"index.php", "index.html", "index.htm"}

// wpMarkers are the markers of a WordPress site.
var wpMarkers = []string{"wp-config.php", "wp-includes/version.php"}

// unreadableSites are directory names that hold a site in shared hosting
// (cPanel, Plesk, XAMPP). One the agent may not list is reported, as is one
// directly below /var/www or /srv.
var unreadableSites = map[string]bool{"public_html": true, "htdocs": true, "httpdocs": true}

// DiscoverBases are searched by Discover. Home directories are included
// because many servers deploy under a service user's home.
var DiscoverBases = []string{"/srv", "/var/www", "/opt", "/app", "/home/*", "/home/*/apps", "/home/*/www"}

// Discovered is an application directory found by discovery and what
// found it: the marker file ("composer.json", "index.php"), "unreadable"
// for a directory the agent's user may not list, and the web server
// configuration files naming it as a document root
// ("nginx:/etc/nginx/sites-enabled/shop").
type Discovered struct {
	Dir string
	By  []string
	// site: found by an index file or as a document root, so other
	// applications below it stay their own.
	site bool
}

// Discover returns project directories up to three levels below the usual
// deployment bases, and the document roots Apache and nginx serve
// (webconf.go). A release layout (releases/ or versions/ plus a current
// link) yields only the current release.
//
// It only lists directories, checks for marker files and reads web server
// configuration and placeholder pages: nothing else is opened or run,
// symbolic links to directories are not followed, hidden and dependency
// directories are skipped, and the walk stops after maxDiscoverDirs
// directories or MaxDiscoverApps applications.
func (s *Scanner) Discover() []string {
	dirs, _ := s.DiscoverAll()
	return dirs
}

// DiscoverAll is Discover, and whether the walk saw everything: false when
// it stopped at its limits, so an application missing from the list may
// still be on disk.
func (s *Scanner) DiscoverAll() ([]string, bool) {
	found, full := s.DiscoverSites()
	dirs := make([]string, len(found))
	for i, d := range found {
		dirs[i] = d.Dir
	}
	return dirs, full
}

// DiscoverSites is DiscoverAll with what found each directory.
func (s *Scanner) DiscoverSites() ([]Discovered, bool) {
	return s.discover(maxDiscoverDirs, MaxDiscoverApps)
}

// walk is the state of one discovery walk.
type walk struct {
	seen    map[string]bool
	out     []Discovered
	budget  int
	maxApps int
	full    bool
	bases   map[string]bool
	docs    []string // document roots (not aliases) from the configuration
}

func (s *Scanner) discover(maxDirs, maxApps int) ([]Discovered, bool) {
	bases := s.discoverBases()
	// Document roots from the web server configuration, checked first: the
	// walk needs to know which directories a virtual host serves.
	conf, complete := s.configRoots()
	type root struct {
		dir, source string
		alias       bool
	}
	var roots []root
	w := &walk{seen: map[string]bool{}, budget: maxDirs, maxApps: maxApps, full: complete, bases: map[string]bool{}}
	for _, r := range conf {
		if dir, ok := s.siteDir(r.dir, bases); ok {
			roots = append(roots, root{dir, r.source, r.alias})
			if !r.alias {
				w.docs = append(w.docs, dir)
			}
		}
	}
	for _, b := range bases {
		w.bases[b] = true
	}
	for _, base := range bases {
		s.discoverIn(w, base, base, 0, "")
	}
	// A document root the walk found is that application. One inside an
	// application found by its manifest (Laravel's public/), and an alias
	// target inside any application, are part of it. Otherwise a document
	// root is a site of its own, also inside another site (an addon
	// domain), whose scan then leaves it out (Apps); outer ones are taken
	// first.
	sort.SliceStable(roots, func(i, j int) bool { return len(roots[i].dir) < len(roots[j].dir) })
	for _, r := range roots {
		in := -1
		for i, d := range w.out {
			if (d.Dir == r.dir || strings.HasPrefix(r.dir, d.Dir+"/")) && (in < 0 || len(d.Dir) > len(w.out[in].Dir)) {
				in = i
			}
		}
		if in >= 0 && (w.out[in].Dir == r.dir || !w.out[in].site || r.alias) {
			if !slices.Contains(w.out[in].By, r.source) {
				w.out[in].By = append(w.out[in].By, r.source)
			}
			continue
		}
		if len(w.out) >= maxApps {
			w.full = false
			break
		}
		w.out = append(w.out, Discovered{Dir: r.dir, By: []string{r.source}, site: !r.alias})
	}
	return w.out, w.full
}

// discoverIn walks dir, depth levels below base. site is the site (found
// by its index file) dir is in, "" when none.
func (s *Scanner) discoverIn(w *walk, base, dir string, depth int, site string) {
	if depth > 3 || w.seen[dir] {
		return
	}
	if w.budget <= 0 || len(w.out) >= w.maxApps {
		w.full = false
		return
	}
	w.budget--
	if cur, ok := s.currentRelease(dir); ok {
		dir = cur
		if w.seen[dir] {
			return
		}
	}
	manifest := s.marker(dir, markers)
	index := ""
	if !w.bases[dir] {
		index = s.webIndex(dir, depth)
	}
	if manifest != "" || index != "" {
		own := site == "" || s.marker(dir, wpMarkers) != "" || manifest != "" && (index != "" || s.appEntry(dir)) || w.servesBelow(dir)
		if own {
			w.seen[dir] = true
			w.out = append(w.out, Discovered{Dir: dir, By: []string{firstNonEmpty(manifest, index)}, site: manifest == ""})
		}
		if manifest != "" {
			return // lockfiles below are found by the app scan itself
		}
		if own {
			site = dir
		}
	}
	entries, err := os.ReadDir(s.path(dir))
	if err != nil {
		// A site the agent may not list is reported rather than missed:
		// directly below /var/www or /srv, or named like a shared host's
		// site. Elsewhere (/opt, home directories) directories only their
		// owner may list are common and are not sites.
		name := path.Base(dir)
		if site == "" && depth > 0 && !w.bases[dir] && errors.Is(err, fs.ErrPermission) &&
			(depth == 1 && (base == "/var/www" || base == "/srv") || unreadableSites[name]) {
			w.seen[dir] = true
			w.out = append(w.out, Discovered{Dir: dir, By: []string{"unreadable"}})
		}
		return
	}
	for _, e := range entries {
		if !e.IsDir() || skipDiscover[e.Name()] || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		s.discoverIn(w, base, path.Join(dir, e.Name()), depth+1, site)
	}
}

// appEntry reports whether a project directory runs as an application of
// its own rather than being a library: it has an entry point one level
// down (Laravel's or Symfony's public/index.php, Drupal's web/index.php),
// a framework's launcher (Laravel's artisan, Django's manage.py, Rack's
// config.ru), or a package.json naming what it runs (main, or a start
// script).
func (s *Scanner) appEntry(dir string) bool {
	for _, sub := range []string{"public", "web"} {
		if s.marker(path.Join(dir, sub), webIndexes) != "" {
			return true
		}
	}
	if s.marker(dir, []string{"artisan", "manage.py", "config.ru"}) != "" {
		return true
	}
	var p struct {
		Main    string            `json:"main"`
		Scripts map[string]string `json:"scripts"`
	}
	return readJSON(s.path(path.Join(dir, "package.json")), &p) == nil && (p.Main != "" || p.Scripts["start"] != "")
}

// servesBelow reports whether a document root of the configuration is dir
// or below it.
func (w *walk) servesBelow(dir string) bool {
	for _, d := range w.docs {
		if d == dir || strings.HasPrefix(d, dir+"/") {
			return true
		}
	}
	return false
}

// marker returns the first of names that is a regular file in dir.
func (s *Scanner) marker(dir string, names []string) string {
	for _, m := range names {
		if fi, err := os.Lstat(s.path(path.Join(dir, m))); err == nil && fi.Mode().IsRegular() {
			return m
		}
	}
	return ""
}

// webIndex returns the index file that marks dir, depth levels below a
// discovery base, as a site (see webIndexes for where none does).
func (s *Scanner) webIndex(dir string, depth int) string {
	if depth == 0 {
		return ""
	}
	parts := strings.Split(dir, "/")
	for _, part := range parts[max(len(parts)-depth, 0):] {
		if skipWebDir[part] {
			return ""
		}
	}
	for _, m := range webIndexes {
		if s.marker(dir, []string{m}) != "" && (m == "index.php" || !s.defaultPage(dir, m)) {
			return m
		}
	}
	return ""
}

var skipDiscover = map[string]bool{"node_modules": true, "vendor": true, "releases": true, "shared": true, "cache": true, "tmp": true, "logs": true,
	"lost+found": true}

// releaseDirs hold a release layout's releases: Capistrano, Deployer and
// Envoyer keep them in releases/, Ghost-CLI in versions/. Only the one
// "current" links to runs; the others are old releases kept for rollback.
var releaseDirs = []string{"releases", "versions"}

// currentRelease follows a release layout: dir has a releases/ (or
// versions/) directory and a "current" link to one release in it, as
// Capistrano, Deployer, Envoyer and Ghost-CLI (/var/www/ghost/current ->
// versions/6.52.0) deploy. Old releases stay on disk but only current runs.
func (s *Scanner) currentRelease(dir string) (string, bool) {
	target, err := os.Readlink(s.path(path.Join(dir, "current")))
	if err != nil {
		return "", false
	}
	if !path.IsAbs(target) {
		target = path.Join(dir, target)
	}
	target = path.Clean(target)
	inRelease := false
	for _, r := range releaseDirs {
		base := path.Join(dir, r)
		if fi, err := os.Stat(s.path(base)); err == nil && fi.IsDir() && strings.HasPrefix(target, base+"/") {
			inRelease = true
			break
		}
	}
	if !inRelease {
		return "", false // a release must live in the application's releases
	}
	// The release itself (releases/2) may be another link: what it finally
	// resolves to must be inside the application as well.
	realDir, err1 := filepath.EvalSymlinks(s.path(dir))
	realTarget, err2 := filepath.EvalSymlinks(s.path(target))
	if err1 != nil || err2 != nil || !strings.HasPrefix(realTarget, realDir+string(filepath.Separator)) {
		return "", false
	}
	return target, true
}

// isReleaseDir reports whether host path p is the versions/ (or
// releases/) directory of a release layout: its parent has a current link
// into it.
func (s *Scanner) isReleaseDir(p string) bool {
	cur, ok := s.currentRelease(path.Dir(p))
	return ok && strings.HasPrefix(cur, p+"/")
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
	den := &denied{dir: dir}
	fi, err := os.Stat(s.path(dir))
	if den.note(dir, err) {
		c, _ := den.coverage()
		app.Coverage, app.Unreadable = append(app.Coverage, c), true
		return app
	}
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
	unusable := 0
	add := func(obs []model.Observation) {
		for _, o := range obs {
			if len(app.Observations) >= MaxPackagesPerApp {
				app.Truncated = true
				return
			}
			// Anyone who publishes a package controls its name and version;
			// one the server would refuse must not void the whole batch.
			if !model.Usable(o) {
				unusable++
				continue
			}
			app.Observations = append(app.Observations, o)
		}
	}
	web := &webAssets{s: s, dir: dir, seen: map[string]bool{}, denied: den}
	err = filepath.WalkDir(s.path(dir), func(full string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr // the collection's time limit stops the walk
		}
		if err != nil {
			den.note(s.hostPath(full), err)
			return nil
		}
		if !d.IsDir() {
			web.consider(full, d)
			return nil
		}
		host := s.hostPath(full)
		name := d.Name()
		switch {
		case s.nestedApp(dir, host):
			return fs.SkipDir
		case name == "node_modules":
			project := path.Dir(host)
			obs, cov := s.scanNodeModules(project, host)
			add(obs)
			app.Coverage = append(app.Coverage, cov)
			den.noteTree(host, cov)
			if len(obs) > 0 {
				note(project, "npm")
			}
			return fs.SkipDir
		case name == "site-packages" || name == "dist-packages":
			project := pythonProject(host)
			obs, cov := s.scanSitePackages(host)
			add(obs)
			app.Coverage = append(app.Coverage, cov)
			den.noteTree(host, cov)
			if len(obs) > 0 {
				note(project, "pypi")
			}
			return fs.SkipDir
		case name == "vendor":
			if _, err := os.Stat(path.Join(full, "composer", "installed.json")); den.note(host, err) {
				// Composer's or a site's own: nothing says which.
			} else if err == nil {
				project := path.Dir(host)
				obs, cov := s.scanComposerInstalled(host)
				add(obs)
				app.Coverage = append(app.Coverage, cov)
				den.noteTree(host, cov)
				if len(obs) > 0 {
					note(project, "composer")
				}
			} else if !composerVendor(full) {
				web.walk(ctx, host) // a site's own copies (assets/vendor/jquery/...)
			}
			return fs.SkipDir
		case name == ".git" || name == "releases" && host != dir:
			return fs.SkipDir
		case name == "versions" && host != dir && s.isReleaseDir(host):
			return fs.SkipDir // Ghost-CLI's old releases, next to current
		}
		return nil
	})
	if err != nil {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: clipScope("app:" + dir), Status: "failed", Reason: clipScope(err.Error())})
	}

	// Lockfiles fill in ecosystems that have nothing installed (for example
	// a Go or Rust service, or a PHP app deployed without vendor/).
	locks, lcov, err := lockfile.ScanWith(ctx, os.DirFS(s.path(dir)), s.Packs)
	if err != nil {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: clipScope("lockfiles:" + dir), Status: "failed", Reason: clipScope(err.Error())})
	}
	var kept []model.Observation
	for _, o := range locks {
		lockDir := path.Join(dir, path.Dir(o.Location))
		if installed[lockDir][purlType(o.Purl)] || s.nestedApp(dir, lockDir) {
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
	// Libraries loaded from a CDN or copied into the application, unless a
	// manifest already reported the same package and version.
	add(unlisted(web.obs, app.Observations))
	if web.files > 0 || web.limit != "" {
		c := model.CoverageItem{Scope: clipScope(webAssetsScopeID + dir), Status: "checked"}
		if web.limit != "" {
			c.Status, c.Reason = "partial", web.limit
		}
		app.Coverage = append(app.Coverage, c)
	}
	for _, c := range lcov {
		if i := strings.Index(c.Scope, ":"); i > 0 {
			c.Scope = c.Scope[:i+1] + path.Join(dir, c.Scope[i+1:])
			if s.nestedApp(dir, c.Scope[i+1:]) {
				continue
			}
			// A directory or lockfile the agent may not read is counted
			// with the others below, not listed one by one.
			if kind := c.Scope[:i]; (kind == "path" || kind == "lockfile") && c.Status == "failed" && permissionText(c.Reason) {
				if kind == "lockfile" {
					den.noteManifest(c.Scope[i+1:])
				} else {
					den.note(c.Scope[i+1:], fs.ErrPermission)
				}
				continue
			}
		}
		app.Coverage = append(app.Coverage, c)
	}
	if c, ok := den.coverage(); ok {
		app.Coverage = append(app.Coverage, c)
	}
	app.Unreadable = den.root
	if len(app.Coverage) == 0 {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: "app:" + dir, Status: "skipped", Reason: "no installed libraries or supported lockfiles found"})
	}
	if app.Truncated {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: "app:" + dir, Status: "partial",
			Reason: fmt.Sprintf("stopped after %d packages", MaxPackagesPerApp)})
	}
	for i := range app.Observations {
		app.Observations[i].Evidence["app_dir"] = clip(dir)
	}
	if unusable > 0 {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: clip("app:" + dir), Status: "partial",
			Reason: fmt.Sprintf("%d package(s) with an invalid or over-long name or version were skipped", unusable)})
	}
	app.Name = clip(app.Name)
	app.GitURL = clip(app.GitURL)
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

// clip keeps text taken from the application (names, URLs, paths) within
// the batch's field limit.
func clip(s string) string {
	if len(s) <= 1000 {
		return s
	}
	return s[:1000]
}

// clipScope keeps a coverage field within the batch limit.
func clipScope(s string) string {
	if len(s) > 1000 {
		return s[:1000]
	}
	return s
}
