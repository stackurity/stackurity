package apps

// WordPress core. WordPress is not installed by a package manager: its
// release is the $wp_version line of wp-includes/version.php. It is reported
// as pkg:generic/wordpress, as runtimes outside a package manager are
// (pkg:generic/<endoflife.date product>), so endoflife.date's wordpress
// release lines apply. No vulnerability source covered by Stackurity lists
// WordPress core (OSV has no WordPress ecosystem), so its rows are lifecycle
// only.

import (
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

const (
	wpVersionFile = "wp-includes/version.php"
	wpVersionSize = 8 << 10 // read from the top of version.php; the line is in the first 1 KB
	// KindCMS is the evidence kind of a content management system's core
	// (WordPress), read from its own files.
	KindCMS = "cms"
)

// wpVersionLine is an assignment of the variable WordPress's own code
// reads. A comment naming it ("@global string $wp_version") does not match.
var wpVersionLine = regexp.MustCompile(`(?m)^[ \t]*\$wp_version[ \t]*=[ \t]*['"]([^'"\r\n]{1,64})['"][ \t]*;`)

// wpRelease is a WordPress release: 6.4.2, 6.5, and pre-releases and
// development builds (6.5-RC1, 6.6-beta2, 6.7-alpha-58576-src).
var wpRelease = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$`)

// parseWPVersion returns the release in the head of version.php: the last
// assignment, as PHP runs it, once comments are removed, so an old
// "$wp_version = '3.0';" left in a /* */ block or after // is not read.
func parseWPVersion(data []byte) (string, bool) {
	all := wpVersionLine.FindAllSubmatch(stripComments("version.php", data), -1)
	if len(all) == 0 {
		return "", false
	}
	v := all[len(all)-1][1]
	if !wpRelease.Match(v) {
		return "", false
	}
	return string(v), true
}

// wordpressCore reports the WordPress core of the application in dir (host
// path): its own wp-includes/version.php, or, when dir holds wp-config.php
// one level above the install (as WordPress allows), that of each directory
// directly below it. A copy an OS package installed is reported by the
// package database instead.
func (s *Scanner) wordpressCore(dir string, den *denied) []model.Observation {
	roots := []string{dir}
	if !s.hasWPCore(dir) && s.marker(dir, []string{"wp-config.php"}) != "" {
		roots = nil
		entries, err := os.ReadDir(s.path(dir))
		den.note(dir, err)
		for _, e := range entries {
			sub := path.Join(dir, e.Name())
			if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && !s.nestedApp(dir, sub) {
				if s.hasWPCore(sub) {
					roots = append(roots, sub)
				}
			}
		}
	}
	var out []model.Observation
	for _, root := range roots {
		if !s.hasWPCore(root) {
			continue
		}
		if o, ok := s.wordpressVersion(root, den); ok {
			out = append(out, o)
		}
		// Its plugins and themes (wpextensions.go).
		out = append(out, s.wordpressExtensions(root, den)...)
	}
	return out
}

// wordpressVersion reads the core release of the install at root.
func (s *Scanner) wordpressVersion(root string, den *denied) (model.Observation, bool) {
	host := path.Join(root, wpVersionFile)
	if s.Owned != nil && s.Owned(host) {
		return model.Observation{}, false
	}
	f, err := openRegular(s.path(host))
	if err != nil {
		den.note(host, err)
		return model.Observation{}, false
	}
	data, _ := io.ReadAll(io.LimitReader(f, wpVersionSize))
	f.Close()
	v, ok := parseWPVersion(data)
	if !ok {
		return model.Observation{}, false
	}
	return model.Observation{
		Purl: packageurl.NewPackageURL("generic", "", "wordpress", v, nil, "").ToString(), Version: v,
		Location: clip(host), Direct: boolp(true), Scope: "runtime", Confidence: model.ConfidenceConfirmed,
		Evidence: map[string]string{"kind": KindCMS, "product": "WordPress core", "source": "version-file"},
	}, true
}

// hasWPCore reports whether host path dir has WordPress core files: a
// wp-includes directory, not a link, with version.php.
func (s *Scanner) hasWPCore(dir string) bool {
	fi, err := os.Lstat(s.path(path.Join(dir, "wp-includes")))
	if err != nil || !fi.IsDir() {
		return false
	}
	_, err = os.Lstat(s.path(path.Join(dir, wpVersionFile)))
	return err == nil
}
