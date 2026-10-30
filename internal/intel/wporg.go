package intel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// FeedWordPressOrg holds the latest releases of the WordPress plugins and
// themes installed somewhere (pkg:generic/wordpress-plugin/<slug>,
// pkg:generic/wordpress-theme/<slug>), read from wordpress.org's plugin and
// theme info APIs, which need no key. Only installed slugs that are in
// wordpress.org's public plugin or theme list are looked up
// (syncWordPressOrg), so an in-house plugin's or theme's name never leaves
// the server, and never one the collector marked as not from wordpress.org
// (an Update URI naming another host, a must-use plugin, a folder name that
// is no slug). It is release data only: no vulnerability source covers
// plugins and themes yet.
const FeedWordPressOrg = "releases:wordpress.org"

const wporgMax = 8 << 20 // one answer; WooCommerce's, with 650 versions, is about 100 KB

// wpPre marks a version wordpress.org lists that is not a stable release.
var wpPre = regexp.MustCompile(`(?i)(alpha|beta|rc|dev|pre|trunk|nightly|test)`)

// wporgInfo is the part of an info API answer read. A closed plugin, and
// a slug wordpress.org does not know, come back as HTTP 404 with "error".
type wporgInfo struct {
	Error       string          `json:"error"`
	Name        string          `json:"name"`
	Slug        string          `json:"slug"`
	Version     string          `json:"version"`
	LastUpdated string          `json:"last_updated"`      // plugins: "2026-08-18 11:42pm GMT"
	LastTime    string          `json:"last_updated_time"` // themes: "2026-10-29 13:22:58"
	Versions    json.RawMessage `json:"versions"`          // {version: download URL}, or [] when none
	Closed      bool            `json:"closed"`
	ClosedDate  string          `json:"closed_date"`
	ReasonText  string          `json:"reason_text"`
}

// The public slug lists are the root listings of wordpress.org's plugin and
// theme Subversion repositories: one <li><a href="<slug>/"> line per
// plugin or theme ever published there, closed ones included. Measured on
// 2026-10-31: plugins 131,496 slugs, 9.1 MB (1.4 MB with gzip, which the
// fetcher asks for), about 2.5 s; themes 31,821 slugs, 1.7 MB (0.24 MB
// gzip), about 1.7 s. They are read in full on each sync that has slugs to
// look up (about once a day): the listing names the repository revision,
// which changes many times a day, so a stored copy would rarely be current
// and is not kept; the slug count is (the cursor), to refuse a shrunken
// list.
const wporgListMax = 64 << 20 // uncompressed; the plugin list is about 9 MB

// wporgCursor is the feed's cursor: the size of the last good lists.
type wporgCursor struct {
	Plugins int `json:"plugins,omitempty"`
	Themes  int `json:"themes,omitempty"`
}

var wporgListItem = regexp.MustCompile(`<li><a href="([^"/]+)/">`)

// syncWordPressOrg refreshes the latest releases of installed plugins and
// themes. Only slugs in wordpress.org's public lists are looked up there, so
// the name of an in-house plugin or theme is never sent: the others are
// recorded as not on wordpress.org without a request. A list that cannot be
// read, is truncated or has shrunk to less than half its last size is
// refused: its slugs are not looked up and keep what was stored, and the
// feed warns.
func (s *Syncer) syncWordPressOrg(ctx context.Context, cursor string) (*SyncResult, string, error) {
	reg := registries[FeedWordPressOrg]
	cands, err := s.Store.ReleaseCandidatesIn(ctx, reg.purlType, reg.namespaces, releaseRefresh, 2000)
	if err != nil {
		return nil, cursor, err
	}
	if len(cands) == 0 {
		return &SyncResult{}, cursor, nil
	}
	var cur wporgCursor
	_ = json.Unmarshal([]byte(cursor), &cur)
	byNS := map[string][]store.ReleaseCandidate{}
	for _, c := range cands {
		byNS[c.Namespace] = append(byNS[c.Namespace], c)
	}
	var lookup []store.ReleaseCandidate
	var warnings []string
	lists, refused, local := 0, 0, 0
	for _, l := range []struct {
		ns, kind, url string
		count         *int
	}{
		{"wordpress-plugin", "plugin", s.f.cfg.WordPressPluginsListURL, &cur.Plugins},
		{"wordpress-theme", "theme", s.f.cfg.WordPressThemesListURL, &cur.Themes},
	} {
		cs := byNS[l.ns]
		if len(cs) == 0 {
			continue
		}
		lists++
		wanted := map[string]bool{}
		for _, c := range cs {
			wanted[c.Name] = true
		}
		found, n, err := s.wporgSlugList(ctx, l.url, wanted)
		if err == nil && n < *l.count/2 {
			err = fmt.Errorf("the public %s list has %d slugs, fewer than half of the %d last read: refused", l.kind, n, *l.count)
		}
		if err != nil {
			refused++
			warnings = append(warnings, err.Error())
			s.Log.Warn("wordpress.org slug list refused", "kind", l.kind, "err", err)
			continue
		}
		*l.count = n
		for _, c := range cs {
			if found[c.Name] {
				lookup = append(lookup, c)
				continue
			}
			local++
			r := store.Release{ComponentID: c.ComponentID, CheckedAt: time.Now(), Source: FeedWordPressOrg,
				LastError: fmt.Sprintf("not on wordpress.org: %q is not in wordpress.org's public %s list", c.Name, l.kind)}
			if err := s.Store.UpsertRelease(ctx, r); err != nil {
				return nil, cursor, err
			}
		}
	}
	next, _ := json.Marshal(cur)
	if lists > 0 && refused == lists {
		return nil, cursor, fmt.Errorf("wordpress.org's public lists could not be used: %s", strings.Join(warnings, "; "))
	}
	failed := s.lookupReleases(ctx, reg, lookup)
	if err := ctx.Err(); err != nil {
		return nil, string(next), err
	}
	if len(lookup) > 0 && failed == len(lookup) {
		return nil, string(next), fmt.Errorf("all %d wordpress.org lookups failed", failed)
	}
	return &SyncResult{Changed: local + len(lookup) - failed, Warning: strings.Join(warnings, "; ")}, string(next), nil
}

// wporgSlugList reads one public slug list, streaming, and returns which of
// wanted it has and how many slugs it lists. A listing without its heading
// and closing tag is truncated.
func (s *Syncer) wporgSlugList(ctx context.Context, u string, wanted map[string]bool) (map[string]bool, int, error) {
	resp, err := s.f.get(ctx, u, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body := &countingReader{r: io.LimitReader(resp.Body, wporgListMax+1)}
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	found := map[string]bool{}
	n := 0
	head, end := false, false
	for sc.Scan() {
		line := sc.Bytes()
		switch {
		case bytes.Contains(line, []byte("Revision ")) && !head:
			head = true
		case bytes.Contains(line, []byte("</ul>")):
			end = true
		default:
			if m := wporgListItem.FindSubmatch(line); m != nil {
				n++
				if slug, err := url.PathUnescape(string(m[1])); err == nil && wanted[slug] {
					found[slug] = true
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", u, err)
	}
	if body.n > wporgListMax {
		return nil, 0, fmt.Errorf("%s is larger than %d MB: refused", u, wporgListMax>>20)
	}
	if !head || !end || n == 0 {
		return nil, 0, fmt.Errorf("%s is truncated or not a slug listing (%d slugs read)", u, n)
	}
	return found, n, nil
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (s *Syncer) wordpressRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	kind, api := "plugin", "plugins"
	if c.Namespace == "wordpress-theme" {
		kind, api = "theme", "themes"
	}
	r := store.Release{Source: FeedWordPressOrg, SourceURL: "https://wordpress.org/" + api + "/" + url.PathEscape(c.Name) + "/"}
	if !wpOrgSlug.MatchString(c.Name) {
		r.LastError = fmt.Sprintf("not on wordpress.org: %q is not a wordpress.org slug", c.Name)
		return r, nil
	}
	q := url.Values{}
	q.Set("action", kind+"_information")
	q.Set("request[slug]", c.Name)
	q.Set("request[fields][versions]", "1")
	for _, f := range []string{"sections", "description", "reviews", "screenshots", "banners", "icons", "contributors", "tags", "ratings", "compatibility"} {
		q.Set("request[fields]["+f+"]", "0")
	}
	u := strings.TrimSuffix(s.f.cfg.WordPressOrgURL, "/") + "/" + api + "/info/1.2/?" + q.Encode()
	status, b, err := s.f.downloadAllowing(ctx, u, wporgMax, 404)
	if err != nil {
		s.Log.Warn("wordpress.org lookup failed", kind, c.Name, "err", err)
		return r, err
	}
	var info wporgInfo
	if err := json.Unmarshal(b, &info); err != nil {
		err = fmt.Errorf("wordpress.org %s %s: unreadable or truncated answer: %w", kind, c.Name, err)
		s.Log.Warn("wordpress.org lookup failed", kind, c.Name, "err", err)
		return r, err
	}
	if status == 404 {
		if info.Closed || info.Error == "closed" {
			// Not available any more: no latest release, and why. Shown
			// whatever its name: wordpress.org renames a closed plugin
			// (wp-gdpr-compliance), and a security closure is never hidden.
			r.Deprecated = "closed on wordpress.org"
			if info.ClosedDate != "" {
				r.Deprecated += " since " + info.ClosedDate
			}
			if info.ReasonText != "" {
				r.Deprecated += ": " + info.ReasonText
			}
			return r, nil
		}
		// In the public list but unknown to the API (removed since).
		r.LastError = fmt.Sprintf("not on wordpress.org: no %s %q there", kind, c.Name)
		return r, nil
	}
	// The installed copy must be wordpress.org's, by name: a premium or
	// in-house one can share a slug. Older releases may carry a shorter
	// name ("Akismet Anti-Spam" before "Akismet Anti-spam: Spam
	// Protection"), so one name starting with the other counts.
	if info.Name != "" && len(c.Names) > 0 && !anyNameMatches(info.Name, c.Names) {
		r.LastError = fmt.Sprintf("not the wordpress.org %s: wordpress.org's %q is %q, the installed one %q", kind, c.Name, plainName(info.Name), c.Names[0])
		return r, nil
	}
	if info.Slug != c.Name || info.Version == "" || info.Error != "" {
		err := fmt.Errorf("wordpress.org %s %s: incomplete answer (slug %q, version %q, error %q)", kind, c.Name, info.Slug, info.Version, info.Error)
		s.Log.Warn("wordpress.org lookup failed", kind, c.Name, "err", err)
		return r, err
	}
	var versions map[string]any
	if v := bytes.TrimSpace(info.Versions); len(v) > 0 && v[0] == '{' {
		if err := json.Unmarshal(v, &versions); err != nil {
			return r, fmt.Errorf("wordpress.org %s %s: versions: %w", kind, c.Name, err)
		}
	}
	var stable []string
	for v := range versions {
		if !wpPre.MatchString(v) {
			stable = append(stable, v)
		}
	}
	if !wpPre.MatchString(info.Version) {
		stable = append(stable, info.Version)
	}
	// An answer listing far fewer versions than before is a broken one, not
	// a plugin that lost its history: the stored data is kept.
	if prev, err := s.Store.ReleasesFor(ctx, []int64{c.ComponentID}); err == nil {
		if p := prev[c.ComponentID]; p != nil && len(p.StableVersions) >= 10 && len(stable) < len(p.StableVersions)/2 {
			err := fmt.Errorf("wordpress.org %s %s lists %d versions, fewer than half of the %d stored: refused", kind, c.Name, len(stable), len(p.StableVersions))
			s.Log.Warn("wordpress.org lookup refused", kind, c.Name, "err", err)
			return r, err
		}
	}
	r.Latest, r.LatestStable = info.Version, info.Version
	r.StableVersions = sortedVersions(version.CompareGeneric, stable)
	for _, layout := range []struct{ v, layout string }{{info.LastUpdated, "2006-01-02 3:04pm MST"}, {info.LastTime, "2006-01-02 15:04:05"}} {
		if t, err := time.Parse(layout.layout, layout.v); err == nil {
			r.LatestPublished = &t
			break
		}
	}
	return r, nil
}

// wpOrgSlug is a wordpress.org slug.
var wpOrgSlug = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

var wpTags = regexp.MustCompile(`<[^>]*>`)
var wpNonWord = regexp.MustCompile(`[^\p{L}\p{N}]+`)

// plainName is a name as text: wordpress.org's carry HTML entities.
func plainName(s string) string {
	return strings.TrimSpace(html.UnescapeString(wpTags.ReplaceAllString(s, "")))
}

// nameKey compares names by their words, ignoring case and punctuation.
func nameKey(s string) string {
	return strings.Trim(wpNonWord.ReplaceAllString(strings.ToLower(plainName(s)), " "), " ")
}

// anyNameMatches reports whether one installed name is wordpress.org's, or
// one starts with the other at a word boundary.
func anyNameMatches(org string, installed []string) bool {
	o := nameKey(org)
	for _, n := range installed {
		k := nameKey(n)
		if k == "" || o == "" {
			continue
		}
		if k == o || strings.HasPrefix(o, k+" ") || strings.HasPrefix(k, o+" ") {
			return true
		}
	}
	return false
}

// downloadAllowing is download that also returns the body of a response
// with status allow (a 404 that says why), with its status.
func (f *fetcher) downloadAllowing(ctx context.Context, url string, max int64, allow int) (int, []byte, error) {
	resp, err := f.getAllowing(ctx, url, nil, allow)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return 0, nil, err
	}
	if int64(len(b)) > max {
		return 0, nil, errors.New("GET " + url + ": response larger than the limit")
	}
	return resp.StatusCode, b, nil
}
