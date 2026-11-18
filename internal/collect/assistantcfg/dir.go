package assistantcfg

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/model"
)

// Limits on one directory's scan. Only the few configuration files are
// read, but the walk visits every directory to find them; what is past a
// limit is reported as not checked, never as clean.
const (
	MaxFileSize = 1 << 20 // a larger file is not an assistant's settings
	MaxEntries  = 500_000 // directory entries visited per scan
)

// skipDirs hold other people's code and tooling: an assistant opened on
// the project does not read a dependency's settings.
var skipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true, "bower_components": true,
	"vendor": true, "site-packages": true, "dist-packages": true, "venv": true, ".venv": true, "__pycache__": true,
	".tox": true, ".terraform": true, ".next": true, ".nuxt": true, ".cache": true, "third_party": true, "third-party": true}

// Result is one directory's scan.
type Result struct {
	Found []Finding
	// Complete is false when a limit, an unreadable file or a file that
	// is not valid JSON left part of the directory unchecked; Reason says
	// which.
	Complete bool
	Reason   string
	Files    int // configuration files read
}

// Scan is the result as a batch carries it.
func (r Result) Scan() *model.AssistantScan {
	found := r.Found
	if found == nil {
		found = []Finding{}
	}
	if len(found) > model.MaxAssistantFindings {
		found, r.Complete, r.Reason = found[:model.MaxAssistantFindings], false, "more findings than one scan reports"
	}
	return &model.AssistantScan{Found: found, Complete: r.Complete, Reason: r.Reason, Files: r.Files}
}

func (r *Result) incomplete(reason string) {
	if r.Complete {
		r.Complete, r.Reason = false, reason
	}
}

// read scans one file at p, reported as rel.
func (r *Result) read(p, rel string) {
	info, err := os.Lstat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return
	}
	if info.Size() > MaxFileSize {
		r.incomplete(rel + " is larger than " + "1 MiB and was not read")
		return
	}
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			r.incomplete("some files could not be read: " + err.Error())
		}
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileSize))
	f.Close()
	if err != nil {
		r.incomplete("some files could not be read: " + err.Error())
		return
	}
	r.Files++
	found, err := Scan(rel, data)
	if err != nil {
		r.incomplete(err.Error())
		return
	}
	r.Found = append(r.Found, found...)
}

// Dir scans the assistant configuration files under root. skip, when set,
// leaves out a directory (rel, forward slashes) and everything below it.
// Symbolic links are not followed, so a scan stays inside root.
func Dir(ctx context.Context, root string, skip func(rel string) bool) Result {
	res := Result{Complete: true}
	entries := 0
	stop := errors.New("limit")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				res.incomplete("some directories could not be read: " + err.Error())
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entries++; entries > MaxEntries {
			res.incomplete("the directory is larger than the scan's limits")
			return stop
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if p == root {
				return nil
			}
			if skipDirs[d.Name()] || (skip != nil && skip(rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := Known(rel); ok && d.Type().IsRegular() {
			res.read(p, rel)
		}
		return nil
	})
	if err != nil && err != stop {
		res.incomplete(err.Error())
	}
	return res
}

// Files scans the listed files under root (relative paths, a Git
// checkout's tracked files), reading those the package knows.
func Files(ctx context.Context, root string, rels []string) Result {
	res := Result{Complete: true}
	for _, rel := range rels {
		if ctx.Err() != nil {
			res.incomplete(ctx.Err().Error())
			break
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		if rel == "." || strings.HasPrefix(rel, "../") || path.IsAbs(rel) || inSkipped(rel) {
			continue
		}
		if _, ok := Known(rel); ok {
			res.read(filepath.Join(root, filepath.FromSlash(rel)), rel)
		}
	}
	return res
}

func inSkipped(rel string) bool {
	parts := strings.Split(rel, "/")
	for _, d := range parts[:len(parts)-1] {
		if skipDirs[d] {
			return true
		}
	}
	return false
}

// Repo scans a project directory. In a Git checkout only the files Git
// tracks are read: a developer's own .claude/settings.local.json, ignored
// by Git, is theirs, not the repository's. Elsewhere every file is.
func Repo(ctx context.Context, dir string) Result {
	if tracked, ok := leaks.TrackedFiles(ctx, dir); ok {
		return Files(ctx, dir, tracked)
	}
	return Dir(ctx, dir, nil)
}
