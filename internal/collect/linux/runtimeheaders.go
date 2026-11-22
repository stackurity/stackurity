package linux

import (
	"path"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// PHP's and Node.js's version without running the binary, for container
// images (whose binaries are never run) and for a host where --version
// could not be run or was not recognised.
//
// The official php and node images build the runtime from source into
// /usr/local, so no package owns it and, in an image, nothing ran it:
// before this the runtime was reported with no version, and end of life
// could not be evaluated. Both keep the C headers make install wrote next
// to the binary (extensions and native addons are built against them):
//
//  1. <prefix>/include/php/main/php_version.h (PHP_VERSION "8.3.14") and
//     <prefix>/include/node/node_version.h (NODE_MAJOR_VERSION,
//     NODE_MINOR_VERSION, NODE_PATCH_VERSION): the exact release.
//  2. PHP_VERSION or NODE_VERSION in the image's configuration, which the
//     official images set to the release they build. It is metadata a later
//     layer can leave stale, so it is used only for a binary in
//     /usr/local/bin, as for PYTHON_VERSION (python.go).
//
// A distribution's PHP or Node.js is never read here: its binary belongs to
// a package, which is skipped as a runtime.

var (
	phpVersionDef = regexp.MustCompile(`(?m)^#define\s+PHP_VERSION\s+"(\d+\.\d+\.\d+)(?:[-.+~][0-9A-Za-z.~+-]*)?"\s*$`)
	nodeVerDef    = regexp.MustCompile(`(?m)^#define\s+NODE_(MAJOR|MINOR|PATCH)_VERSION\s+(\d+)\s*$`)
	envVersion    = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)$`)
)

// headerVersionFromFiles reads the version of the PHP or Node.js binary at
// bin (a host path with symlinks resolved), or ok false when no file gives
// it.
func (c *Collector) headerVersionFromFiles(product, bin string) (pythonFileVersion, bool) {
	prefix := path.Dir(path.Dir(bin)) // /usr/local/bin/php -> /usr/local
	var header, envName, v string
	switch product {
	case "php":
		header, envName = path.Join(prefix, "include", "php", "main", "php_version.h"), "PHP_VERSION"
		if data, err := c.readSmall(header); err == nil {
			if m := phpVersionDef.FindSubmatch(data); m != nil {
				v = string(m[1])
			}
		}
	case "nodejs":
		header, envName = path.Join(prefix, "include", "node", "node_version.h"), "NODE_VERSION"
		if data, err := c.readSmall(header); err == nil {
			parts := map[string]string{}
			for _, m := range nodeVerDef.FindAllSubmatch(data, -1) {
				if parts[string(m[1])] == "" {
					parts[string(m[1])] = string(m[2])
				}
			}
			if parts["MAJOR"] != "" && parts["MINOR"] != "" && parts["PATCH"] != "" {
				v = parts["MAJOR"] + "." + parts["MINOR"] + "." + parts["PATCH"]
			}
		}
	default:
		return pythonFileVersion{}, false
	}
	if v != "" {
		return pythonFileVersion{v, model.ConfidenceConfirmed, "header",
			map[string]string{"version_file": header}}, true
	}
	if raw := c.ImageEnv[envName]; strings.HasPrefix(bin, "/usr/local/bin/") {
		if m := envVersion.FindStringSubmatch(raw); m != nil {
			return pythonFileVersion{m[1], model.ConfidenceInferred, "image-env",
				map[string]string{"version_env": envName + "=" + raw}}, true
		}
	}
	return pythonFileVersion{}, false
}
