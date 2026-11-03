//go:build !windows

package main

import (
	"context"
	"os"
	"time"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/linux"
	"github.com/stackurity/stackurity/internal/model"
)

// AppsCollectorID reports applications deployed on a Linux host.
const AppsCollectorID = "linux-apps"

// linuxHostCollector returns the Linux inventory collector: for this host
// on Linux, and on any system for a Linux filesystem under --root (a
// mounted image). The first batch is always the host's OS packages; the
// host must exist on the server before its applications can be linked to
// it.
func linuxHostCollector(o *hostOptions) (func(context.Context) ([]*model.ObservationBatch, error), error) {
	col := linux.New(version)
	col.Root = o.root
	col.Runtimes = o.runtimes
	if o.root != "/" {
		// A mounted image or container filesystem is not this host's code:
		// report its runtimes from paths, never by running them.
		col.RunVersion = nil
	}
	return func(parent context.Context) ([]*model.ObservationBatch, error) {
		ctx, cancel := context.WithTimeout(parent, hostCollectTimeout)
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
		batches = append(batches, scanAppDirs(ctx, o, osBatch, scanner, AppsCollectorID)...)
		if o.docker != nil {
			// Its own time limit: reading a new image can take minutes, and
			// each image has a limit of its own.
			dctx, dcancel := context.WithTimeout(parent, dockerCollectTimeout)
			defer dcancel()
			batches = append(batches, o.docker.Collect(dctx, osBatch.Asset)...)
		}
		return batches, nil
	}, nil
}

// dockerCollectTimeout bounds one collection's reading of container images.
const dockerCollectTimeout = 2 * time.Hour
