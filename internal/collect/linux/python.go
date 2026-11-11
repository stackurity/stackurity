package linux

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Python's version without running the interpreter, for container images
// (whose binaries are never run) and for a host where python3 --version
// could not be run or was not recognised.
//
// The sources, most reliable first:
//
//  1. <prefix>/include/pythonX.Y/patchlevel.h, whose PY_VERSION is the
//     exact release. make install writes it with the interpreter, so it
//     describes the build next to it (the official images keep it).
//  2. PYTHON_VERSION in the image's configuration, which the official
//     python images set to the release they build into /usr/local. It is
//     metadata a later layer can leave stale, so it is used only for an
//     interpreter in /usr/local/bin whose release line it matches.
//  3. The standard library's directory <prefix>/lib/pythonX.Y (or the
//     binary's name, pythonX.Y): the release line only. No patch release
//     is invented; the version reported is X.Y, which endoflife.date's
//     release cycles match exactly, and the evidence says the patch
//     release is not known.
//
// Not used: _sysconfigdata_*.py and the Makefile in lib/pythonX.Y/config-*
// hold X.Y, not the patch release; libpythonX.Y.so's name holds X.Y too,
// which the binary's name and the library directory already give.
//
// A distribution's own Python is never read here: its binary belongs to a
// package (dpkg, apk, rpm), which is skipped as a runtime because the
// package database already reports it with its version.

// pythonFileVersion is a version read from files, and how.
type pythonFileVersion struct {
	version    string
	confidence model.Confidence
	how        string            // evidence detected_by
	evidence   map[string]string // more evidence
}

var (
	pythonBinName  = regexp.MustCompile(`^python(\d+\.\d+)$`) // also the standard library's directory
	pyVersionDef   = regexp.MustCompile(`(?m)^#define\s+PY_VERSION\s+"(\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?)"\s*$`)
	pythonEnvValue = regexp.MustCompile(`^\d+\.\d+\.\d+(?:(?:a|b|rc)\d+)?$`)
)

// pythonVersionFromFiles reads the version of the interpreter at bin (a
// host path with symlinks resolved), or ok false when no file gives even
// its release line.
func (c *Collector) pythonVersionFromFiles(bin string) (pythonFileVersion, bool) {
	prefix := path.Dir(path.Dir(bin)) // /usr/local/bin/python3.12 -> /usr/local
	release := ""
	if m := pythonBinName.FindStringSubmatch(path.Base(bin)); m != nil {
		release = m[1]
	}
	stdlib := ""
	if release != "" {
		if c.isFile(path.Join(prefix, "lib", "python"+release, "os.py")) {
			stdlib = path.Join(prefix, "lib", "python"+release)
		}
	} else {
		// python3 itself is the binary: the release line is the one
		// standard library next to it, when there is exactly one.
		libs, _ := filepath.Glob(c.path(path.Join(prefix, "lib", "python3.*", "os.py")))
		var found []string
		for _, l := range libs {
			dir := path.Join(prefix, "lib", filepath.Base(filepath.Dir(l)))
			if m := pythonBinName.FindStringSubmatch(path.Base(dir)); m != nil && c.isFile(path.Join(dir, "os.py")) {
				found = append(found, dir)
				release = m[1]
			}
		}
		if len(found) != 1 {
			return pythonFileVersion{}, false
		}
		stdlib = found[0]
	}

	header := path.Join(prefix, "include", "python"+release, "patchlevel.h")
	if data, err := c.readSmall(header); err == nil {
		if m := pyVersionDef.FindSubmatch(data); m != nil && strings.HasPrefix(string(m[1]), release+".") {
			return pythonFileVersion{string(m[1]), model.ConfidenceConfirmed, "header",
				map[string]string{"version_file": header}}, true
		}
	}
	if v := c.ImageEnv["PYTHON_VERSION"]; pythonEnvValue.MatchString(v) && strings.HasPrefix(v, release+".") &&
		strings.HasPrefix(bin, "/usr/local/bin/") {
		return pythonFileVersion{v, model.ConfidenceInferred, "image-env",
			map[string]string{"version_env": "PYTHON_VERSION=" + v}}, true
	}
	const precision = "release line only: no file names the patch release"
	if stdlib != "" {
		return pythonFileVersion{release, model.ConfidenceInferred, "stdlib-dir",
			map[string]string{"version_file": stdlib, "version_precision": precision}}, true
	}
	return pythonFileVersion{release, model.ConfidenceInferred, "binary-name",
		map[string]string{"version_precision": precision}}, true
}

// isFile reports whether the host path is a regular file under Root.
func (c *Collector) isFile(hostPath string) bool {
	fi, err := os.Stat(c.path(hostPath))
	return err == nil && fi.Mode().IsRegular()
}

// readSmall reads at most 64 KiB of a regular file under Root.
func (c *Collector) readSmall(hostPath string) ([]byte, error) {
	f, err := os.Open(c.path(hostPath))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, os.ErrInvalid
	}
	return io.ReadAll(io.LimitReader(f, 64<<10))
}
