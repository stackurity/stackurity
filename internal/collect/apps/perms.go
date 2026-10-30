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
// reported as unsupported, so the asset is not shown as clean and the
// instance's coverage gaps count it.
const PermissionScope = "app-permissions:"

// maxDeniedPaths bounds the paths kept per application; more are counted.
const maxDeniedPaths = 10_000

// denied collects the paths one application scan skipped because the
// agent's user may not read them.
type denied struct {
	paths map[string]bool
	more  int
}

// note records host path p when err is a permission error (EACCES or
// EPERM) and reports whether it was one.
func (d *denied) note(p string, err error) bool {
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return false
	}
	if d == nil {
		return true
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

// permissionText reports whether an error message from another scanner
// (the lockfile walk keeps only the text) is a permission error.
func permissionText(reason string) bool {
	return strings.HasSuffix(reason, "permission denied") || strings.HasSuffix(reason, "operation not permitted")
}

// coverage is one item for every skipped path of the application in dir:
// the shallowest path, and how many more there were.
func (d *denied) coverage(dir string) (model.CoverageItem, bool) {
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
	return model.CoverageItem{Scope: clipScope(PermissionScope + dir), Status: "unsupported", Reason: clipScope(reason)}, true
}

// Unreadable reports whether the scan skipped files of the application
// because the agent's user may not read them.
func (a App) Unreadable() bool {
	for _, c := range a.Coverage {
		if strings.HasPrefix(c.Scope, PermissionScope) {
			return true
		}
	}
	return false
}

// agentUser names the user the agent runs as, for the reason text.
var agentUser = sync.OnceValue(func() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "uid " + strconv.Itoa(os.Getuid())
})
