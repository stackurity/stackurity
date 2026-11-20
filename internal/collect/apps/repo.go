package apps

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

// repoWebTimeout bounds the walk within a repository scan's own limit, so
// the leak and configuration checks after it still have time.
const repoWebTimeout = 3 * time.Minute

// RepoWebAssets finds the front-end libraries a repository checkout at dir
// keeps outside a package manager: a CDN address in a template, a copied
// file named by its banner (js/jquery-3.6.0.min.js), or a library compiled
// into a committed bundle. It is the same detection a deployed application
// gets (webassets.go, bundles.go), so a PHP or static site's repository
// reports the jQuery or Bootstrap copy it ships, not zero components.
// Source maps and WebAssembly are not read: the server's sparse clone
// leaves them out (gitrepo.sparsePatterns), and a CI scan must read the
// same files or its findings would differ from the server's.
//
// manifest is what the lockfile scan already found in dir: a package and
// version it lists is not reported again. ignored holds the slash paths
// git ignores (lockfile.GitIgnored; nil for a fresh clone): a build's
// output in a local checkout is not what the repository holds. Locations
// are relative to dir, as the lockfile scan's are.
//
// web is the "web-assets:." item, always returned: "checked" tells the
// server this scan looked everywhere, so a library it no longer finds is
// gone; anything else (a read limit, an unreadable path, the time limit)
// keeps the libraries found before (store/removal.go), and never makes the
// rest of the batch incomplete. more are the notes on compiled code.
func RepoWebAssets(ctx context.Context, dir string, manifest []model.Observation, ignored map[string]bool) (obs []model.Observation, web model.CoverageItem, more []model.CoverageItem) {
	ctx, cancel := context.WithTimeout(ctx, repoWebTimeout)
	defer cancel()
	if real, err := filepath.EvalSymlinks(dir); err == nil {
		dir = real // a CI workspace reached through a link
	}
	s := &Scanner{Root: dir}
	den := &denied{}
	otherErr := 0
	// dir "" makes paths under the checkout "/js/x.js" (host paths of a
	// root at dir) and paths relative to the application "js/x.js".
	w := &webAssets{s: s, dir: "", seen: map[string]bool{}, denied: den, repo: true}
	walkErr := filepath.WalkDir(dir, func(full string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			if !den.note(s.hostPath(full), err) {
				otherErr++ // a file gone mid-walk, a name too long: not read either
			}
			return nil
		}
		if rel, rerr := filepath.Rel(dir, full); rerr == nil && ignored[filepath.ToSlash(rel)] {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			w.consider(full, d)
			return nil
		}
		if full == dir {
			return nil
		}
		name := d.Name()
		switch {
		case strings.HasPrefix(name, ".") || skipWebDir[name]:
			return fs.SkipDir // .git, node_modules, docs, tests (see skipWebDir)
		case name == "vendor" && composerVendor(full):
			return fs.SkipDir // Composer's, which composer.lock reports
		}
		return nil
	})

	bundleObs, bundleCov := w.bundleResults()
	for _, o := range append(unlisted(w.obs, manifest), bundleObs...) {
		if len(obs) >= MaxPackagesPerApp {
			break
		}
		if !model.Usable(o) {
			continue
		}
		o.Location = strings.TrimPrefix(o.Location, "/")
		obs = append(obs, o)
	}

	web = model.CoverageItem{Scope: webAssetsScopeID + ".", Status: "checked"}
	unread := len(den.paths) + den.more + otherErr
	switch {
	case walkErr != nil:
		web.Status, web.Reason = "partial", clipScope("stopped: "+walkErr.Error())
	case w.limit != "":
		web.Status, web.Reason = "partial", w.limit
	case unread > 0:
		web.Status, web.Reason = "partial", fmt.Sprintf("%d path(s) could not be read", unread)
	}
	for _, c := range bundleCov {
		scope, rest, _ := strings.Cut(c.Scope, ":")
		rest = strings.TrimPrefix(rest, "/")
		if rest == "" {
			rest = "."
		}
		c.Scope = clipScope(scope + ":" + rest)
		if scope+":" == "bundle-limits:" && web.Status == "checked" {
			// A bundle past the limit may hold a library found before.
			web.Status, web.Reason = "partial", "compiled bundles read in part (see bundle-limits)"
		}
		more = append(more, c)
	}
	return obs, web, more
}
