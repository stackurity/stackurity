// Package lockfile discovers application dependencies by parsing lockfiles
// as data. It never runs package managers, install scripts or builds.
package lockfile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/pkg/pack"
)

const CollectorID = "lockfile-scanner"

// MaxLockfileSize guards against hostile or accidental giant files.
const MaxLockfileSize = 64 << 20

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".hg": true, ".svn": true,
	"bower_components": true, ".venv": true, "venv": true, "__pycache__": true, "target": true, ".yarn": true,
}

// Ecosystem lockfiles we recognise but cannot parse yet; reported as
// unsupported coverage rather than silently ignored.
var unsupported = map[string]string{
	"bun.lockb":        "npm:bun.lockb",
	"pom.xml":          "maven:pom.xml",
	"gradle.lockfile":  "maven:gradle.lockfile",
	"build.gradle":     "maven:build.gradle",
	"build.gradle.kts": "maven:build.gradle.kts",
	"mix.lock":         "hex:mix.lock",
	// Read by the Cargo stack pack (packs/cargo).
	"Cargo.lock": "cargo:Cargo.lock",
}

type parser func(fsys fs.FS, dir, file string) ([]model.Observation, error)

var parsers = map[string]parser{
	"package-lock.json":   parseNpm,
	"npm-shrinkwrap.json": parseNpm,
	"yarn.lock":           parseYarn,
	"pnpm-lock.yaml":      parsePnpm,
	"composer.lock":       parseComposer,
	"poetry.lock":         parsePoetry,
	"Pipfile.lock":        parsePipfileLock,
	"requirements.txt":    parseRequirements,
	"go.mod":              parseGoMod,
	"Gemfile.lock":        parseGemfileLock,
	"packages.lock.json":  parseNuGetLock,
	"pubspec.lock":        parsePubspecLock,
}

// packBatchBytes bounds how much one pack run is handed. A deployed Java
// application can hold hundreds of megabytes of libraries; they are read in
// batches rather than refused.
const packBatchBytes = 48 << 20

// batches splits files into groups of at most limit bytes, smallest first, so
// small related files (a pom and its parent) stay in the same run.
func batches(files []pack.File, limit int) [][]pack.File {
	if len(files) == 0 {
		return nil
	}
	sorted := append([]pack.File{}, files...)
	sort.SliceStable(sorted, func(i, j int) bool { return len(sorted[i].Content) < len(sorted[j].Content) })
	var out [][]pack.File
	var cur []pack.File
	size := 0
	for _, f := range sorted {
		if len(cur) > 0 && size+len(f.Content) > limit {
			out = append(out, cur)
			cur, size = nil, 0
		}
		cur = append(cur, f)
		size += len(f.Content)
	}
	return append(out, cur)
}

// Extension reads files the core has no parser for: an installed stack
// pack (internal/packs). Each extension runs once per scan with all the files
// it matched, so it can relate files to each other (a pom and its parent).
type Extension interface {
	ID() string
	Matches(name string) bool
	Scan(ctx context.Context, files []pack.File) ([]model.Observation, []model.CoverageItem, error)
}

// Scan walks fsys and returns observations and coverage for every lockfile.
// Paths in results are slash-separated and relative to the scan root.
func Scan(fsys fs.FS) ([]model.Observation, []model.CoverageItem, error) {
	return ScanWith(context.Background(), fsys, nil)
}

// ScanWith is Scan with extensions for files the core cannot read itself.
func ScanWith(ctx context.Context, fsys fs.FS, exts []Extension) ([]model.Observation, []model.CoverageItem, error) {
	var obs []model.Observation
	var cov []model.CoverageItem
	extFiles := map[int][]pack.File{}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			cov = append(cov, model.CoverageItem{Scope: "path:" + p, Status: "failed", Reason: err.Error()})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p != "." && skipDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow links out of the scan root
		}
		name := d.Name()
		if _, builtin := parsers[name]; !builtin {
			matched := false
			for i, e := range exts {
				if !e.Matches(name) {
					continue
				}
				matched = true
				if info, err := d.Info(); err == nil && info.Size() > MaxLockfileSize {
					cov = append(cov, model.CoverageItem{Scope: "pack:" + e.ID() + ":" + p, Status: "skipped",
						Reason: fmt.Sprintf("larger than %d MiB", MaxLockfileSize>>20)})
					continue
				}
				data, err := readLimited(fsys, p)
				if err != nil {
					cov = append(cov, model.CoverageItem{Scope: "pack:" + e.ID() + ":" + p, Status: "failed", Reason: err.Error()})
					continue
				}
				extFiles[i] = append(extFiles[i], pack.File{Path: p, Content: data})
			}
			if matched {
				return nil
			}
		}
		if scope, ok := unsupported[name]; ok {
			cov = append(cov, model.CoverageItem{Scope: scope + ":" + p, Status: "unsupported", Reason: "parser not implemented yet"})
			return nil
		}
		parse, ok := parsers[name]
		if !ok {
			return nil
		}
		scope := "lockfile:" + p
		if info, err := d.Info(); err == nil && info.Size() > MaxLockfileSize {
			cov = append(cov, model.CoverageItem{Scope: scope, Status: "skipped", Reason: fmt.Sprintf("larger than %d MiB", MaxLockfileSize>>20)})
			return nil
		}
		found, err := parse(fsys, path.Dir(p), p)
		var partial *partialError
		switch {
		case errors.As(err, &partial):
			obs = append(obs, found...)
			cov = append(cov, model.CoverageItem{Scope: scope, Status: "partial", Reason: partial.msg})
		case err != nil:
			cov = append(cov, model.CoverageItem{Scope: scope, Status: "failed", Reason: err.Error()})
		default:
			obs = append(obs, found...)
			cov = append(cov, model.CoverageItem{Scope: scope, Status: "checked"})
		}
		return nil
	})
	for i, e := range exts {
		for _, files := range batches(extFiles[i], packBatchBytes) {
			found, c, err := e.Scan(ctx, files)
			if err != nil {
				for _, f := range files {
					cov = append(cov, model.CoverageItem{Scope: "pack:" + e.ID() + ":" + f.Path, Status: "failed", Reason: err.Error()})
				}
				continue
			}
			obs = append(obs, found...)
			cov = append(cov, c...)
		}
	}
	sort.SliceStable(obs, func(i, j int) bool {
		if obs[i].Location != obs[j].Location {
			return obs[i].Location < obs[j].Location
		}
		return obs[i].Purl < obs[j].Purl
	})
	return obs, cov, err
}

// ScanDir scans a local directory and wraps the result in a batch.
func ScanDir(dir string, asset model.AssetRef, version string) (*model.ObservationBatch, error) {
	return ScanDirWith(context.Background(), dir, asset, version, nil)
}

// ScanDirWith is ScanDir with extensions (installed stack packs).
func ScanDirWith(ctx context.Context, dir string, asset model.AssetRef, version string, exts []Extension) (*model.ObservationBatch, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("not a directory: " + dir)
	}
	obs, cov, err := ScanWith(ctx, os.DirFS(dir), exts)
	if err != nil {
		return nil, err
	}
	b := model.NewBatch(model.Collector{ID: CollectorID, Version: version, Method: "lockfile"}, asset)
	b.Observations = obs
	b.Coverage = cov
	if len(cov) == 0 {
		b.Cover("lockfiles", "skipped", "no supported lockfiles found")
	}
	b.Complete = true
	for _, c := range cov {
		if c.Status == "failed" || c.Status == "skipped" || c.Status == "partial" {
			b.Complete = false
		}
	}
	return b, nil
}

func readLimited(fsys fs.FS, p string) ([]byte, error) {
	f, err := fsys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxLockfileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxLockfileSize {
		return nil, errors.New("file too large")
	}
	return data, nil
}

func boolp(b bool) *bool { return &b }

// cleanRel turns an fs path into a display path; "." becomes "".
func cleanRel(p string) string {
	if p == "." {
		return ""
	}
	return filepath.ToSlash(strings.TrimPrefix(p, "./"))
}
