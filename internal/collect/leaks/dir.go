package leaks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits on one directory's scan. A WordPress site with its plugins has
// tens of thousands of files; what is past a limit is reported as not
// checked, never as clean.
const (
	MaxFileSize = 2 << 20   // larger files are data, not configuration or code
	MaxFiles    = 100_000   // files read per directory
	MaxBytes    = 512 << 20 // bytes read per directory
	MaxLeaks    = 1_000     // leaks reported per directory
)

// skipDirs hold other people's code or tooling, not the project's: a
// library's test keys are not the project's leak. testdata and fixtures
// are skipped for the same reason: their keys are made up far more often
// than real.
var skipDirs = map[string]bool{".git": true, ".hg": true, ".svn": true, "node_modules": true, "bower_components": true,
	"vendor": true, "site-packages": true, "dist-packages": true, "venv": true, ".venv": true, "__pycache__": true,
	".tox": true, ".terraform": true, "testdata": true, "fixtures": true, "__fixtures__": true, "__snapshots__": true,
	".next": true, ".nuxt": true, ".cache": true, "cache": true, "logs": true, "third_party": true, "third-party": true}

// testFile reports whether name is a test, whose keys are made up far
// more often than real.
func testFile(name string) bool {
	stem := strings.TrimSuffix(name, path.Ext(name))
	return strings.HasSuffix(stem, "_test") || strings.HasSuffix(stem, ".test") || strings.HasSuffix(stem, ".spec") ||
		strings.HasPrefix(name, "test_") || strings.HasSuffix(stem, "Test")
}

// skipFiles are lockfiles and checksums: long lists of hashes that no rule
// matches and that are slow to read.
var skipFiles = map[string]bool{"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "composer.lock": true,
	"go.sum": true, "Cargo.lock": true, "poetry.lock": true, "Gemfile.lock": true, "pubspec.lock": true}

// skipExt are binary formats, read for nothing.
var skipExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true,
	".svg": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".otf": true, ".pdf": true, ".zip": true,
	".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".7z": true, ".rar": true, ".jar": true, ".war": true,
	".mp3": true, ".mp4": true, ".mov": true, ".webm": true, ".wasm": true, ".so": true, ".dll": true, ".exe": true,
	".dylib": true, ".o": true, ".a": true, ".class": true, ".pyc": true, ".map": true, ".min.css": true, ".css": true}

// Result is one directory's scan.
type Result struct {
	Leaks []Leak
	// Complete is false when a limit or an unreadable file left part of
	// the directory unchecked; Reason says which.
	Complete bool
	Reason   string
	Files    int // files read
}

// Dir scans the files under root. Paths in the result are relative to
// root. Symbolic links are not followed, so a scan stays inside root.
func Dir(ctx context.Context, root string) Result {
	res := Result{Complete: true}
	var bytesRead int64
	stop := errors.New("limit")
	incomplete := func(reason string) {
		if res.Complete {
			res.Complete, res.Reason = false, reason
		}
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				incomplete("some files could not be read: " + err.Error())
				return nil
			}
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		name := d.Name()
		if d.IsDir() {
			if p != root && skipDirs[name] {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || skipFiles[name] || testFile(name) || skipExt[strings.ToLower(path.Ext(name))] || strings.HasSuffix(name, ".min.css") {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() == 0 || info.Size() > MaxFileSize {
			return nil
		}
		if res.Files >= MaxFiles || bytesRead+info.Size() > MaxBytes {
			incomplete("the directory is larger than the scan's limits")
			return stop
		}
		data, err := readFile(p)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				incomplete("some files could not be read: " + err.Error())
			}
			return nil
		}
		res.Files++
		bytesRead += int64(len(data))
		if binary(data) {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		for _, l := range Scan(filepath.ToSlash(rel), data) {
			if len(res.Leaks) >= MaxLeaks {
				incomplete("more leaks were found than one scan reports")
				return stop
			}
			res.Leaks = append(res.Leaks, l)
		}
		return nil
	})
	if err != nil && err != stop {
		incomplete(err.Error())
	}
	return res
}

func readFile(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxFileSize))
}

// binary reports whether data looks like a binary file: a NUL byte near
// the start.
func binary(data []byte) bool {
	return bytes.IndexByte(data[:min(len(data), 8<<10)], 0) >= 0
}
