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
	"github.com/stackurity/stackurity/internal/collect/linux"
	"github.com/stackurity/stackurity/internal/model"
)

// AppsCollectorID reports applications deployed on a host.
const AppsCollectorID = "linux-apps"

// hostCollector returns the inventory collector for this platform. The first
// batch is always the host's OS packages; the host must exist on the server
// before its applications can be linked to it.
func hostCollector(o *hostOptions) (func(context.Context) ([]*model.ObservationBatch, error), error) {
	col := linux.New(version)
	col.Root = o.root
	col.Runtimes = o.runtimes
	if o.root != "/" {
		// A mounted image or container filesystem is not this host's code:
		// report its runtimes from paths, never by running them.
		col.RunVersion = nil
	}
	return func(ctx context.Context) ([]*model.ObservationBatch, error) {
		ctx, cancel := context.WithTimeout(ctx, hostCollectTimeout)
		defer cancel()
		host, _ := os.Hostname()
		osBatch, err := col.Collect(ctx, host, col.MachineID())
		if err != nil {
			return nil, err
		}
		scanner := &apps.Scanner{Root: o.root, Owned: col.OwnedFunc()}
		// Stack packs read application files the core cannot, such as
		// deployed JARs; each is fetched only if such a file is found.
		if o.packs != nil && (len(o.appDirs) > 0 || o.discoverApps) {
			exts, done := o.packs(ctx)
			defer done()
			scanner.Packs = exts
		}
		batches := []*model.ObservationBatch{osBatch, col.CollectSoftware(ctx, osBatch, scanner.ScanGlobal)}

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
			// A discovered directory with nothing installed and no lockfile
			// is a tool or an empty checkout, not an application to track.
			// One the agent may not read is reported, so that it does not
			// look clean.
			if !explicit && len(app.Observations) == 0 && !app.Unreadable() {
				continue
			}
			b := appBatch(app, osBatch.Asset)
			if by := foundBy[dir]; by != "" && !explicit {
				b.Asset.Attributes["discovered_by"] = clipAttr(by) // a manifest, an index file, a web server's configuration
			}
			batches = append(batches, b)
			reported = append(reported, app.Dir)
		}
		if full && len(reported) <= model.MaxAppDirs {
			osBatch.Apps = &model.AppList{Dirs: reported}
		}
		return batches, nil
	}, nil
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
func appBatch(app apps.App, host model.AssetRef) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: AppsCollectorID, Version: version, Method: "agent"}, model.AssetRef{
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
