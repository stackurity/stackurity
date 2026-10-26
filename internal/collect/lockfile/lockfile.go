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
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/pkg/pack"
)

const CollectorID = "lockfile-scanner"

// MaxLockfileSize guards against hostile or accidental giant files.
const MaxLockfileSize = 64 << 20

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".hg": true, ".svn": true,
	"bower_components": true, ".venv": true, "venv": true, "__pycache__": true, "target": true, ".yarn": true,
	// Coding agents (Claude Code) keep worktrees of the repository here.
	".claude": true,
}

// Coverage scopes for parts of the tree a scan leaves out on purpose. They
// do not make the batch incomplete: nothing that belongs to this checkout
// was missed.
const (
	nestedScope  = "nested-checkout:"
	ignoredScope = "gitignored"
)

// nestedCheckout reports whether directory p (below the scan root) is a
// checkout of its own: a repository or clone (.git directory) or a git
// worktree (.git file pointing into another repository's worktrees). Their
// lockfiles belong to that checkout; scanning them counted the same
// dependencies once per worktree (a repository with coding-agent worktrees
// in .claude/worktrees reported 1658 observations instead of 340).
// Submodules (.git file pointing into the parent's .git/modules) are part of
// the checkout and are scanned.
func nestedCheckout(fsys fs.FS, p string) bool {
	gp := path.Join(p, ".git")
	info, err := fs.Stat(fsys, gp)
	if err != nil {
		return false
	}
	if info.IsDir() {
		return true
	}
	data, err := readLimited(fsys, gp)
	if err != nil {
		return true // unreadable: treat as a separate checkout, and say so
	}
	gitdir := filepath.ToSlash(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(data)), "gitdir:")))
	return !strings.Contains(gitdir, "/modules/") && !strings.HasPrefix(gitdir, "modules/")
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
	return scanWith(ctx, fsys, exts, nil)
}

// scanWith walks fsys. ignored holds slash paths git ignores (directories
// without a trailing slash); nil when unknown.
func scanWith(ctx context.Context, fsys fs.FS, exts []Extension, ignored map[string]bool) ([]model.Observation, []model.CoverageItem, error) {
	var obs []model.Observation
	var cov []model.CoverageItem
	extFiles := map[int][]pack.File{}
	skippedIgnored := 0
	nested := func(p string) {
		cov = append(cov, model.CoverageItem{Scope: clip(nestedScope + p), Status: "skipped",
			Reason: "nested checkout: a separate repository or worktree, not part of this one; scan it on its own"})
	}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			cov = append(cov, model.CoverageItem{Scope: "path:" + p, Status: "failed", Reason: err.Error()})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			if d.Name() == ".claude" {
				// Say which worktrees are left out with it.
				if entries, err := fs.ReadDir(fsys, path.Join(p, "worktrees")); err == nil {
					for _, e := range entries {
						if wt := path.Join(p, "worktrees", e.Name()); e.IsDir() && nestedCheckout(fsys, wt) {
							nested(wt)
						}
					}
				}
			}
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			if ignored[p] {
				skippedIgnored++
				return fs.SkipDir
			}
			if nestedCheckout(fsys, p) {
				nested(p)
				return fs.SkipDir
			}
			return nil
		}
		if ignored[p] {
			skippedIgnored++
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
		// One hostile entry (an over-long or malformed name) must not make
		// the whole batch invalid and so hide every other package.
		kept := found[:0]
		for _, o := range found {
			if model.Usable(o) {
				kept = append(kept, o)
			}
		}
		if dropped := len(found) - len(kept); dropped > 0 {
			msg := fmt.Sprintf("%d entr%s with an invalid or over-long name or version were skipped", dropped, map[bool]string{true: "y", false: "ies"}[dropped == 1])
			var partial *partialError
			if errors.As(err, &partial) {
				msg = partial.msg + "; " + msg
			}
			if err == nil || errors.As(err, &partial) {
				err = &partialError{msg}
			}
		}
		found = kept
		var partial *partialError
		switch {
		case errors.As(err, &partial):
			obs = append(obs, found...)
			cov = append(cov, model.CoverageItem{Scope: clip(scope), Status: "partial", Reason: clip(partial.msg)})
		case err != nil:
			cov = append(cov, model.CoverageItem{Scope: clip(scope), Status: "failed", Reason: clip(err.Error())})
		default:
			obs = append(obs, found...)
			cov = append(cov, model.CoverageItem{Scope: clip(scope), Status: "checked"})
		}
		return nil
	})
	if skippedIgnored > 0 {
		cov = append(cov, model.CoverageItem{Scope: ignoredScope, Status: "skipped",
			Reason: fmt.Sprintf("%d paths ignored by git (.gitignore) were not scanned", skippedIgnored)})
	}
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
	obs, cov, err := scanWith(ctx, os.DirFS(dir), exts, gitIgnored(ctx, dir))
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
		if strings.HasPrefix(c.Scope, nestedScope) || c.Scope == ignoredScope {
			continue // left out on purpose
		}
		if c.Status == "failed" || c.Status == "skipped" || c.Status == "partial" {
			b.Complete = false
		}
	}
	return b, nil
}

// gitIgnored returns the paths below dir that git ignores, relative to dir
// (directories without their trailing slash), or nil when git is not
// installed or dir is not in a work tree. It asks git itself, so nested
// .gitignore files, .git/info/exclude and the global excludes file apply,
// and tracked files never count as ignored. The repository's own
// configuration could otherwise run commands (core.fsmonitor), so that is
// switched off.
func gitIgnored(ctx context.Context, dir string) map[string]bool {
	git, err := exec.LookPath("git")
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	run := func(args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, git, append([]string{"-C", dir, "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
		return cmd.Output()
	}
	if out, err := run("rev-parse", "--is-inside-work-tree"); err != nil || strings.TrimSpace(string(out)) != "true" {
		return nil
	}
	out, err := run("ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory")
	if err != nil {
		return nil
	}
	ignored := map[string]bool{}
	for _, p := range strings.Split(string(out), "\x00") {
		if p = strings.TrimSuffix(p, "/"); p != "" {
			ignored[p] = true
		}
	}
	return ignored
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

// clip keeps coverage text (paths, parser errors that quote the file) within
// the batch's field limit.
func clip(s string) string {
	if len(s) <= 1000 {
		return s
	}
	return s[:1000] + "…"
}

// cleanRel turns an fs path into a display path; "." becomes "".
func cleanRel(p string) string {
	if p == "." {
		return ""
	}
	return filepath.ToSlash(strings.TrimPrefix(p, "./"))
}
