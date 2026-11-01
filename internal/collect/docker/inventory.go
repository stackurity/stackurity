package docker

import (
	"context"
	"os"
	"path"
	"path/filepath"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/linux"
	"github.com/stackurity/stackurity/internal/model"
)

// ReadRoot inventories an unpacked image with the host collectors: the OS
// package database (dpkg, apk; rpm when the host has an rpm binary),
// runtimes found by path (never run), host-wide libraries, and the
// applications discovery finds plus the image's working directory.
func ReadRoot(ctx context.Context, root string, im *Image, version string) Reading {
	var r Reading
	col := linux.New(version)
	col.Root = root
	col.RunVersion = nil // the image's binaries are never run
	osBatch, err := col.Collect(ctx, "image", "")
	if err != nil {
		// No os-release: a scratch or distroless image with no package
		// database. Its applications are still read below.
		osBatch = model.NewBatch(model.Collector{ID: linux.CollectorID}, model.AssetRef{})
		osBatch.Cover("os-packages", "unsupported", "no /etc/os-release in the image: no OS package database to read")
	} else {
		r.Attributes = map[string]string{}
		for _, k := range []string{"os", "os_version", "os_name", "os_codename"} {
			if v := osBatch.Asset.Attributes[k]; v != "" {
				r.Attributes[k] = v
			}
		}
	}
	r.Observations = append(r.Observations, osBatch.Observations...)
	r.Coverage = append(r.Coverage, osBatch.Coverage...)

	scanner := &apps.Scanner{Root: root, Owned: col.OwnedFunc()}
	sw := col.CollectSoftware(ctx, osBatch, scanner.ScanGlobal)
	r.Observations = append(r.Observations, sw.Observations...)
	r.Coverage = append(r.Coverage, sw.Coverage...)

	found, full := scanner.DiscoverSites()
	var dirs []string
	explicit := map[string]bool{}
	if wd := path.Clean("/" + im.WorkingDir()); wd != "/" {
		if fi, err := os.Stat(filepath.Join(root, wd)); err == nil && fi.IsDir() {
			dirs = append(dirs, wd)
			explicit[wd] = true
		}
	}
	for _, d := range found {
		dirs = append(dirs, d.Dir)
	}
	scanner.Apps = dirs
	seen := map[string]bool{}
	for _, dir := range dirs {
		app := scanner.ScanApp(ctx, dir)
		if seen[app.Dir] {
			continue
		}
		seen[app.Dir] = true
		if len(app.Observations) == 0 && !app.Unreadable && !explicit[dir] {
			continue // a tool or an empty directory, as on a host
		}
		r.Observations = append(r.Observations, app.Observations...)
		r.Coverage = append(r.Coverage, app.Coverage...)
	}
	if !full {
		r.Coverage = append(r.Coverage, model.CoverageItem{Scope: "apps", Status: "partial",
			Reason: "application discovery stopped at its limits; some applications in the image may not have been read"})
	}
	return r
}
