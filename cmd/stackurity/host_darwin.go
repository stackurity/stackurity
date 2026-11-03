//go:build darwin

package main

import (
	"context"
	"os"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/darwin"
	"github.com/stackurity/stackurity/internal/model"
)

// MacAppsCollectorID reports applications deployed on a Mac (--app-dir,
// --discover-apps), such as a project on a build server.
const MacAppsCollectorID = "macos-apps"

// hostCollector returns the macOS collector: the system-wide batch (OS,
// /Applications, Homebrew) first, then runtimes, host-wide libraries and
// per-user applications, then any application directories. With --root
// the agent reads a Linux filesystem mounted there (an image), as it did
// before it could read macOS.
func hostCollector(o *hostOptions) (func(context.Context) ([]*model.ObservationBatch, error), error) {
	if o.root != "/" && o.root != "" {
		return linuxHostCollector(o)
	}
	col := darwin.New(version)
	col.Runtimes = o.runtimes
	return func(ctx context.Context) ([]*model.ObservationBatch, error) {
		ctx, cancel := context.WithTimeout(ctx, hostCollectTimeout)
		defer cancel()
		host, _ := os.Hostname()
		sys, err := col.Collect(ctx, host)
		if err != nil {
			return nil, err
		}
		scanner := &apps.Scanner{Root: "/"}
		if o.packs != nil && (len(o.appDirs) > 0 || o.discoverApps) {
			exts, done := o.packs(ctx)
			defer done()
			scanner.Packs = exts
		}
		col.Global = scanner.ScanGlobalDirs
		batches := []*model.ObservationBatch{sys, col.CollectSoftware(ctx, sys)}
		return append(batches, scanAppDirs(ctx, o, sys, scanner, MacAppsCollectorID)...), nil
	}, nil
}
