package apps

// Files the agent's user may not read. A site owned by its own user
// (vwoods:www-data, 750/640) is invisible to an unprivileged agent; an
// application whose files were skipped for that reason must say so rather
// than look clean.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/stackurity/stackurity/internal/model"
)

// PermissionScope is the coverage scope (followed by the application's
// directory) of the files an application scan could not read. It is
// unsupported, so the asset is not shown as clean and the instance's
// coverage gaps count it, when what was skipped holds the inventory: the
// application's directory, a manifest or lockfile, or an installed tree
// (node_modules, vendor, site-packages). Otherwise (a js/ directory, one
// template) it is partial.
const PermissionScope = "app-permissions:"

// maxDeniedPaths bounds the paths kept per application; more are counted.
const maxDeniedPaths = 10_000

// packageTrees hold what package managers installed.
var packageTrees = map[string]bool{"node_modules": true, "vendor": true, "site-packages": true, "dist-packages": true, "venv": true, ".venv": true}

// unneededDirs hold nothing the scan reads (uploads, caches, logs, a
// library's documentation and tests): one the agent may not read is not
// a gap.
var unneededDirs = map[string]bool{"cache": true, "tmp": true, "logs": true, "uploads": true, "__pycache__": true,
	"examples": true, "example": true, "demo": true, "demos": true, "docs": true, "doc": true,
	"test": true, "tests": true, "spec": true, "samples": true, "lost+found": true}

// secretFiles hold a CMS's database credentials (WordPress, Drupal's
// sites/*/settings.php, Joomla), which hardening keeps from other users
// and which nothing the scan looks for is in.
var secretFiles = map[string]bool{"wp-config.php": true, "settings.php": true, "settings.local.php": true, "configuration.php": true}

// denied collects the paths one application scan skipped because the
// agent's user may not read them.
type denied struct {
	dir     string // the application's host path
	paths   map[string]bool
	more    int
	serious bool // the inventory itself is incomplete
	root    bool // the application's directory could not be read
}

// note records host path p when err is a permission error (EACCES or
// EPERM) and reports whether it was one. A path nothing needs (see
// unneededDirs, secretFiles, .env files) is not recorded.
func (d *denied) note(p string, err error) bool {
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return false
	}
	if d == nil {
		return true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(p, d.dir), "/")
	parts := strings.Split(rel, "/")
	inTree := false
	for i, part := range parts {
		if i < len(parts)-1 && unneededDirs[part] {
			return true
		}
		inTree = inTree || packageTrees[part]
	}
	name := parts[len(parts)-1]
	if secretFiles[name] || strings.HasPrefix(name, ".env") || unneededDirs[name] {
		return true
	}
	switch {
	case p == d.dir:
		d.root, d.serious = true, true
	case inTree:
		d.serious = true
	}
	if d.paths == nil {
		d.paths = map[string]bool{}
	}
	if !d.paths[p] {
		if len(d.paths) >= maxDeniedPaths {
			d.more++
		} else {
			d.paths[p] = true
		}
	}
	return true
}

// noteManifest records a manifest or lockfile that could not be read.
func (d *denied) noteManifest(p string) {
	if d.note(p, fs.ErrPermission) && d != nil && (d.paths[p] || d.more > 0) {
		d.serious = true
	}
}

// noteTree records an installed tree (node_modules, site-packages,
// vendor) whose scan cov could not read all of it for lack of permission.
// The scan's own item stays: it names what was read.
func (d *denied) noteTree(tree string, cov model.CoverageItem) {
	if cov.Status != "checked" && permissionText(cov.Reason) {
		d.note(tree, fs.ErrPermission)
	}
}

// permissionText reports whether an error message from another scanner
// (the lockfile walk keeps only the text) is a permission error.
func permissionText(reason string) bool {
	return strings.Contains(reason, "permission denied") || strings.Contains(reason, "operation not permitted")
}

// coverage is one item for every skipped path of the application: the
// shallowest path, and how many more there were.
func (d *denied) coverage() (model.CoverageItem, bool) {
	n := len(d.paths) + d.more
	if n == 0 {
		return model.CoverageItem{}, false
	}
	first := ""
	for p := range d.paths {
		if first == "" || strings.Count(p, "/") < strings.Count(first, "/") || strings.Count(p, "/") == strings.Count(first, "/") && p < first {
			first = p
		}
	}
	reason := fmt.Sprintf("cannot read %s: permission denied (agent runs as %s)", first, agentUser())
	if n > 1 {
		reason += fmt.Sprintf("; %d more paths were skipped for the same reason", n-1)
	}
	status := "partial"
	if d.serious {
		status = "unsupported"
	}
	return model.CoverageItem{Scope: clipScope(PermissionScope + d.dir), Status: status, Reason: clipScope(reason)}, true
}

// agentUser names the user the agent runs as, for the reason text.
var agentUser = sync.OnceValue(func() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "uid " + strconv.Itoa(os.Getuid())
})
