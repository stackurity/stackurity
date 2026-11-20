package apps

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// RepoWebAssets finds the front-end libraries a repository checkout at dir
// keeps outside a package manager: a CDN address in a template, a copied
// file named by its banner (js/jquery-3.6.0.min.js), or a library compiled
// into a committed bundle. It is the same detection a deployed application
// gets (webassets.go, bundles.go), so a PHP or static site's repository
// reports the jQuery or Bootstrap copy it ships, not zero components.
//
// manifest is what the lockfile scan already found in dir: a package and
// version it lists is not reported again. ignored holds the slash paths
// git ignores (lockfile.GitIgnored; nil for a fresh clone): a build's
// output in a local checkout is not what the repository holds. Locations
// are relative to dir, as the lockfile scan's are. The "web-assets:."
// coverage item is always returned: it tells the server this scan looked
// for these libraries, so one it no longer finds is gone (an older CLI's
// scan of the same repository does not look and proves nothing about
// them; store/removal.go). complete is false when a read limit stopped
// the walk, so a library past the limit is never taken for removed; the
// notes on compiled code that cannot be identified do not make the scan
// incomplete, since that code was never inventoried before either.
func RepoWebAssets(ctx context.Context, dir string, manifest []model.Observation, ignored map[string]bool) (obs []model.Observation, cov []model.CoverageItem, complete bool) {
	s := &Scanner{Root: dir}
	// dir "" makes paths under the checkout "/js/x.js" (host paths of a
	// root at dir) and paths relative to the application "js/x.js".
	web := &webAssets{s: s, dir: "", seen: map[string]bool{}}
	walkErr := filepath.WalkDir(dir, func(full string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if err != nil {
			return nil
		}
		if rel, rerr := filepath.Rel(dir, full); rerr == nil && ignored[filepath.ToSlash(rel)] {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() {
			web.consider(full, d)
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

	bundleObs, bundleCov := web.bundleResults()
	for _, o := range append(unlisted(web.obs, manifest), bundleObs...) {
		if len(obs) >= MaxPackagesPerApp {
			break
		}
		if !model.Usable(o) {
			continue
		}
		o.Location = strings.TrimPrefix(o.Location, "/")
		obs = append(obs, o)
	}

	complete = true
	c := model.CoverageItem{Scope: webAssetsScopeID + ".", Status: "checked"}
	switch {
	case walkErr != nil:
		c.Status, c.Reason = "failed", clipScope(walkErr.Error())
		complete = false
	case web.limit != "":
		c.Status, c.Reason = "partial", web.limit
		complete = false
	}
	cov = append(cov, c)
	for _, c := range bundleCov {
		scope, rest, _ := strings.Cut(c.Scope, ":")
		rest = strings.TrimPrefix(rest, "/")
		if rest == "" {
			rest = "."
		}
		c.Scope = clipScope(scope + ":" + rest)
		if scope+":" == "bundle-limits:" {
			complete = false // a bundle past the limit may hold a reported library
		}
		cov = append(cov, c)
	}
	return obs, cov, complete
}
