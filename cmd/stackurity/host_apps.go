//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
)

// scanAppDirs scans the configured and discovered application directories
// and returns one batch per application, linked to the host of osBatch. It
// sets osBatch's application list when that list is complete.
func scanAppDirs(ctx context.Context, o *hostOptions, osBatch *model.ObservationBatch, scanner *apps.Scanner,
	collectorID string) []*model.ObservationBatch {
	var batches []*model.ObservationBatch
	// Every application is known before any is scanned, so one inside
	// another is reported once, by itself.
	dirs := append([]string{}, o.appDirs...)
	full := true // the list names every application on the host
	foundBy := map[string]string{}
	if o.discoverApps {
		found, all := scanner.DiscoverSites()
		for _, d := range found {
			dirs = append(dirs, d.Dir)
			foundBy[d.Dir] = strings.Join(d.By, ", ")
		}
		full = all
	}
	scanner.Apps = dirs
	seen := map[string]bool{}
	reported := []string{}
	for i, dir := range dirs {
		explicit := i < len(o.appDirs)
		// A configured directory that no longer exists (an application
		// that was deleted) is not reported: the host's app list leaves
		// it out, and the server resolves its issues as removed.
		if explicit && missingDir(o.root, dir) {
			fmt.Fprintf(os.Stderr, "application directory %s does not exist; it is reported as removed\n", dir)
			continue
		}
		app := scanner.ScanApp(ctx, dir)
		if seen[app.Dir] {
			continue
		}
		seen[app.Dir] = true
		if !reportable(app, explicit, foundBy[dir]) {
			continue
		}
		b := appBatch(app, osBatch.Asset, collectorID)
		if o.leaks && !app.Unreadable {
			b.Leaks = scanner.Leaks(ctx, app.Dir)
		}
		if by := foundBy[dir]; by != "" && !explicit {
			b.Asset.Attributes["discovered_by"] = clipAttr(by) // a manifest, an index file, a web server's configuration
		}
		batches = append(batches, b)
		reported = append(reported, app.Dir)
	}
	if full && len(reported) <= model.MaxAppDirs {
		osBatch.Apps = &model.AppList{Dirs: reported}
	}
	return batches
}

// reportable reports whether an application is sent. A discovered
// directory with nothing installed and no lockfile is a tool or an empty
// checkout, not an application to track, unless the agent may not read the
// directory at all (a site owned by its own user): that one is sent with
// its coverage gap, so that it does not look clean or go missing. One
// with only some files unreadable (a vendor tool under /opt with a
// root-only directory) is not.
func reportable(app apps.App, explicit bool, foundBy string) bool {
	return explicit || len(app.Observations) > 0 || app.Unreadable || foundBy == "unreadable"
}

// clipAttr keeps an attribute value within the batch's field limit.
func clipAttr(v string) string {
	if len(v) > 1000 {
		return v[:1000]
	}
	return v
}

// missingDir reports whether a configured application directory is gone
// (not merely unreadable).
func missingDir(root, dir string) bool {
	_, err := os.Stat(filepath.Join(root, dir))
	return errors.Is(err, fs.ErrNotExist)
}

// appBatch describes one deployed application as its own asset, linked to
// the host it runs on and, when its Git origin is known, to its repository.
func appBatch(app apps.App, host model.AssetRef, collectorID string) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: collectorID, Version: version, Method: "agent"}, model.AssetRef{
		Kind:        model.AssetApplication,
		Name:        fmt.Sprintf("%s on %s", app.Name, host.Name),
		Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: app.Dir}},
		Attributes:  map[string]string{"app_dir": app.Dir, "host": host.Name},
	})
	b.Observations = app.Observations
	if b.Observations == nil {
		b.Observations = []model.Observation{}
	}
	b.Coverage = app.Coverage
	b.Relations = []model.RelationRef{{Kind: "runs_on", To: host.Identifiers}}
	if app.Version != "" {
		b.Asset.Attributes["app_version"] = clipAttr(app.Version)
	}
	if names := lockfile.JoinPackageNames(app.PackageNames); names != "" {
		b.Asset.Attributes[lockfile.PackageNamesAttr] = names
	}
	// A deployed Git checkout names its repository: the server links the
	// two (built_from) once a scan or an integration has reported it.
	if app.GitURL != "" {
		b.Asset.Attributes["git_url"] = app.GitURL
		b.Relations = append(b.Relations, model.RelationRef{Kind: "built_from",
			To: []model.Identifier{{Scheme: "git-url", Value: gitrepo.NormalizeURL(app.GitURL)}}})
	}
	b.Complete = true
	for _, c := range b.Coverage {
		if c.Status != "checked" {
			b.Complete = false
		}
	}
	return b
}
