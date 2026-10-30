package apps

// WordPress plugins and themes. WordPress reads their name and version from
// a header comment: a plugin's in the top-level .php file of its folder
// under wp-content/plugins (or a single .php file there, or one in
// wp-content/mu-plugins), a theme's in style.css of its folder under
// wp-content/themes. Like WordPress (get_file_data), only the first 8 KB of
// a file is read.
//
// Each is reported as pkg:generic/wordpress-plugin/<slug> or
// pkg:generic/wordpress-theme/<slug>, the folder (or file) name being the
// wordpress.org slug for those installed from wordpress.org. The server
// reads their latest release from wordpress.org (intel/wporg.go); one that
// says it is updated from elsewhere (Update URI), a must-use plugin, or one
// whose folder name cannot be a wordpress.org slug is marked
// wordpress_org "no" and never looked up there. No vulnerability source
// covers them yet.

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

const (
	wpHeaderSize = 8 << 10 // WordPress reads 8 KB of a plugin or theme file
	// The purl namespaces (pkg:generic/<namespace>/<slug>) and evidence
	// kinds of WordPress plugins and themes.
	WPPlugin = "wordpress-plugin"
	WPTheme  = "wordpress-theme"

	maxWPPluginPHP = 100 // top-level .php files opened per plugin folder
	wpExtScope     = "wordpress-extensions:"
)

// Plugins, must-use plugins and themes read per install, each with its own
// budget so a site with thousands of plugins still reports its themes; past
// one, the install has partial coverage (wpExtScope). Tests lower them.
var maxWPPlugins, maxWPMustUse, maxWPThemes = 2000, 200, 500

// wpHeader reads one header field as WordPress does (get_file_data and
// _cleanup_header_comment): a line, possibly after "<?php" and comment
// characters, starting with the field name and a colon; the value ends at
// "*/" or "?>".
func wpHeader(data []byte, field string) string {
	m := wpHeaderRes[field].FindSubmatch([]byte(strings.ReplaceAll(string(data), "\r", "\n")))
	if m == nil {
		return ""
	}
	v := string(m[1])
	if i := strings.Index(v, "*/"); i >= 0 {
		v = v[:i]
	}
	if i := strings.Index(v, "?>"); i >= 0 {
		v = v[:i]
	}
	return clipText(strings.TrimSpace(v), 200)
}

// wpHeaderRes are the header fields read, as wpHeader matches them.
var wpHeaderRes = func() map[string]*regexp.Regexp {
	m := map[string]*regexp.Regexp{}
	for _, f := range []string{"Plugin Name", "Theme Name", "Version", "Update URI", "Template"} {
		m[f] = regexp.MustCompile(`(?mi)^(?:[ \t]*<\?php)?[ \t/*#@]*` + regexp.QuoteMeta(f) + `:(.*)$`)
	}
	return m
}()

// clipText keeps printable text within n bytes.
func clipText(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "")
	}
	return s
}

// wpExtVersion is a version as plugin and theme authors write them (1.2.3,
// 2.0-beta, 3.1.2.1, 10.0.0-rc.1): at least one digit, no spaces.
var wpExtVersion = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$`)

// wpSlug is a wordpress.org slug: lower-case letters, digits and hyphens.
var wpSlug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// updateURIElsewhere names the host a plugin or theme says it is updated
// from (Update URI header) when that is not wordpress.org, as WordPress
// decides (wp_update_plugins): any value naming another host, including
// "false", turns off updates from wordpress.org.
func updateURIElsewhere(uri string) string {
	if uri == "" {
		return ""
	}
	raw := uri
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return uri
	}
	switch h := strings.ToLower(u.Hostname()); h {
	case "wordpress.org", "w.org", "www.wordpress.org":
		return ""
	default:
		return h
	}
}

// wpExtension is one plugin or theme found.
type wpExtension struct {
	kind, slug, file string // file: host path of the file with the header
	name, version    string
	updateURI        string
	template         string // a child theme's parent
	mustUse          bool
}

func (e wpExtension) observation() (model.Observation, bool) {
	if e.version == "" || !wpExtVersion.MatchString(e.version) || !strings.ContainsAny(e.version, "0123456789") {
		return model.Observation{}, false
	}
	ev := map[string]string{"kind": e.kind, "name": e.name}
	reason := ""
	switch {
	case e.mustUse:
		reason = "a must-use plugin, which WordPress does not update from wordpress.org"
	case strings.EqualFold(strings.TrimSpace(e.updateURI), "false"):
		reason = "its Update URI header is false: updates from wordpress.org are turned off"
	case updateURIElsewhere(e.updateURI) != "":
		reason = "its Update URI header says it is updated from " + clipText(updateURIElsewhere(e.updateURI), 200)
	case !wpSlug.MatchString(e.slug):
		reason = "its folder name is not a wordpress.org slug"
	}
	if reason != "" {
		ev["wordpress_org"], ev["wordpress_org_reason"] = "no", reason
	}
	if e.mustUse {
		ev["must_use"] = "true"
	}
	if e.template != "" {
		ev["template"] = e.template
	}
	return model.Observation{
		Purl:    packageurl.NewPackageURL("generic", e.kind, e.slug, e.version, nil, "").ToString(),
		Version: e.version, Location: clip(e.file), Direct: boolp(true), Scope: "runtime",
		Confidence: model.ConfidenceConfirmed, Evidence: ev,
	}, true
}

// wordpressExtensions reports the plugins, must-use plugins and themes of
// the WordPress install at root (host path), in wp-content. Links are not
// followed; files an OS package installed are left to the package database.
// A partial coverage item says when a budget stopped the reading.
func (s *Scanner) wordpressExtensions(root string, den *denied) ([]model.Observation, []model.CoverageItem) {
	content := path.Join(root, "wp-content")
	var found []wpExtension
	var cov []model.CoverageItem
	// Each kind has its own budget; what is left out is counted.
	budgeted := func(what string, max int, read func(add func(wpExtension))) {
		n, more := 0, 0
		read(func(e wpExtension) {
			if n >= max {
				more++
				return
			}
			n++
			found = append(found, e)
		})
		if more > 0 {
			cov = append(cov, model.CoverageItem{Scope: clipScope(wpExtScope + root), Status: "partial",
				Reason: fmt.Sprintf("stopped after %d %s; %d more were not read", max, what, more)})
		}
	}
	// Plugins: a folder's top-level .php files with a Plugin Name header
	// (wpPluginDir), or a single .php file in plugins/. Hello Dolly ships
	// as hello.php; its wordpress.org slug is hello-dolly.
	budgeted("plugins", maxWPPlugins, func(add func(wpExtension)) {
		for _, e := range s.wpEntries(path.Join(content, "plugins"), den) {
			full := path.Join(content, "plugins", e.Name())
			switch {
			case e.IsDir():
				for _, x := range s.wpPluginDir(full, e.Name(), den) {
					add(x)
				}
			case e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".php"):
				slug := strings.TrimSuffix(e.Name(), ".php")
				if e.Name() == "hello.php" {
					slug = "hello-dolly"
				}
				if x, ok := s.wpHeaderFile(WPPlugin, slug, full, "Plugin Name", den); ok {
					add(x)
				}
			}
		}
	})
	// Must-use plugins: WordPress loads only the top-level .php files.
	budgeted("must-use plugins", maxWPMustUse, func(add func(wpExtension)) {
		for _, e := range s.wpEntries(path.Join(content, "mu-plugins"), den) {
			if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".php") {
				if x, ok := s.wpHeaderFile(WPPlugin, strings.TrimSuffix(e.Name(), ".php"), path.Join(content, "mu-plugins", e.Name()), "Plugin Name", den); ok {
					x.mustUse = true
					add(x)
				}
			}
		}
	})
	// Themes: style.css of each folder.
	budgeted("themes", maxWPThemes, func(add func(wpExtension)) {
		for _, e := range s.wpEntries(path.Join(content, "themes"), den) {
			if e.IsDir() {
				if x, ok := s.wpHeaderFile(WPTheme, e.Name(), path.Join(content, "themes", e.Name(), "style.css"), "Theme Name", den); ok {
					add(x)
				}
			}
		}
	})
	var out []model.Observation
	for _, e := range found {
		if o, ok := e.observation(); ok {
			out = append(out, o)
		}
	}
	return out, cov
}

// wpEntries lists a directory (host path) without following links, hidden
// entries left out, sorted by name. A missing directory is no entry.
func (s *Scanner) wpEntries(dir string, den *denied) []os.DirEntry {
	if fi, err := os.Lstat(s.path(dir)); err != nil || !fi.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(s.path(dir))
	den.note(dir, err)
	out := entries[:0]
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), ".") && (e.IsDir() || e.Type().IsRegular()) {
			out = append(out, e)
		}
	}
	return out
}

// wpPluginDir finds the plugins in a folder of plugins/: <slug>.php when
// it has a Plugin Name header, the folder's own plugin; otherwise every
// top-level .php file with one, as WordPress lists each of them.
func (s *Scanner) wpPluginDir(dir, slug string, den *denied) []wpExtension {
	var files []string
	for _, e := range s.wpEntries(dir, den) {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".php") {
			files = append(files, e.Name())
		}
	}
	for _, f := range files {
		if f == slug+".php" {
			if e, ok := s.wpHeaderFile(WPPlugin, slug, path.Join(dir, f), "Plugin Name", den); ok {
				return []wpExtension{e}
			}
		}
	}
	if len(files) > maxWPPluginPHP {
		files = files[:maxWPPluginPHP]
	}
	var out []wpExtension
	for _, f := range files {
		if e, ok := s.wpHeaderFile(WPPlugin, slug, path.Join(dir, f), "Plugin Name", den); ok {
			out = append(out, e)
		}
	}
	return out
}

// wpHeaderFile reads a plugin or theme header from host path file; ok when
// the file has the header naming it (nameField).
func (s *Scanner) wpHeaderFile(kind, slug, file, nameField string, den *denied) (wpExtension, bool) {
	if s.Owned != nil && s.Owned(file) {
		return wpExtension{}, false
	}
	f, err := openRegular(s.path(file))
	if err != nil {
		den.note(file, err)
		return wpExtension{}, false
	}
	data, _ := io.ReadAll(io.LimitReader(f, wpHeaderSize))
	f.Close()
	name := wpHeader(data, nameField)
	if name == "" {
		return wpExtension{}, false
	}
	e := wpExtension{kind: kind, slug: slug, file: file, name: name, version: wpHeader(data, "Version"),
		updateURI: wpHeader(data, "Update URI")}
	if kind == WPTheme {
		e.template = wpHeader(data, "Template")
	}
	return e, true
}
