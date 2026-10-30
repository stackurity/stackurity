package intel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// Release feed names, one per registry. npm and Packagist are in feeds.go.
const (
	FeedPyPI     = "releases:pypi"
	FeedGo       = "releases:go"
	FeedCrates   = "releases:crates"
	FeedRubyGems = "releases:rubygems"
	FeedNuGet    = "releases:nuget"
	FeedMaven    = "releases:maven"
	FeedPub      = "releases:pub"
	FeedHex      = "releases:hex"
)

// registry describes how one release feed looks packages up.
type registry struct {
	purlType string
	workers  int           // concurrent lookups
	gap      time.Duration // minimum spacing between lookups, for registries with a rate limit
	lookup   func(*Syncer, context.Context, store.ReleaseCandidate) (store.Release, error)
	// namespaces limit the registry to components of purlType in these
	// namespaces (wordpress.org: pkg:generic/wordpress-plugin/...). Its
	// feed is then created for them only (EnsureFeeds), not for the type.
	namespaces []string
}

var registries = map[string]registry{
	FeedNpm:       {purlType: "npm", workers: 6, lookup: (*Syncer).npmRelease},
	FeedPackagist: {purlType: "composer", workers: 6, lookup: (*Syncer).packagistRelease},
	FeedPyPI:      {purlType: "pypi", workers: 6, lookup: (*Syncer).pypiRelease},
	FeedGo:        {purlType: "golang", workers: 4, lookup: (*Syncer).goRelease},
	// The sparse index is a CDN, not the crates.io API (which asks crawlers
	// for at most one request per second), so it needs no spacing.
	FeedCrates: {purlType: "cargo", workers: 4, lookup: (*Syncer).cratesRelease},
	// rubygems.org allows 10 API requests per second per IP.
	FeedRubyGems: {purlType: "gem", workers: 2, gap: 200 * time.Millisecond, lookup: (*Syncer).rubygemsRelease},
	FeedNuGet:    {purlType: "nuget", workers: 4, lookup: (*Syncer).nugetRelease},
	FeedMaven:    {purlType: "maven", workers: 4, lookup: (*Syncer).mavenRelease},
	FeedPub:      {purlType: "pub", workers: 4, lookup: (*Syncer).pubRelease},
	// hex.pm allows 100 API requests a minute per IP address.
	FeedHex: {purlType: "hex", workers: 1, gap: 650 * time.Millisecond, lookup: (*Syncer).hexRelease},
	// wordpress.org publishes no rate limit for its info API: a few
	// requests a second, as WordPress sites themselves make.
	FeedWordPressOrg: {purlType: "generic", namespaces: store.WordPressNamespaces, workers: 2, gap: 250 * time.Millisecond,
		lookup: (*Syncer).wordpressRelease},
}

func isReleaseFeed(name string) bool {
	_, ok := registries[name]
	return ok
}

// releaseFeedFor returns the release feed for a purl type, or "".
func releaseFeedFor(purlType string) string {
	for name, r := range registries {
		if r.purlType == purlType && r.namespaces == nil {
			return name
		}
	}
	return ""
}

// releaseRefresh is how old release data may get before it is refreshed.
const releaseRefresh = 24 * time.Hour

func (s *Syncer) syncReleases(ctx context.Context, feed string) (*SyncResult, error) {
	reg := registries[feed]
	var cands []store.ReleaseCandidate
	var err error
	if reg.namespaces != nil {
		cands, err = s.Store.ReleaseCandidatesIn(ctx, reg.purlType, reg.namespaces, releaseRefresh, 2000)
	} else {
		cands, err = s.Store.ReleaseCandidates(ctx, []string{reg.purlType}, releaseRefresh, 2000)
	}
	if err != nil {
		return nil, err
	}
	var tick <-chan time.Time
	if reg.gap > 0 {
		t := time.NewTicker(reg.gap)
		defer t.Stop()
		tick = t.C
	}
	sem := make(chan struct{}, reg.workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed := 0
	for _, c := range cands {
		wg.Add(1)
		go func(c store.ReleaseCandidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if tick != nil {
				select {
				case <-tick:
				case <-ctx.Done():
					return
				}
			}
			r, err := reg.lookup(s, ctx, c)
			r.ComponentID, r.CheckedAt = c.ComponentID, time.Now()
			if err != nil {
				r.LastError = err.Error()
				mu.Lock()
				failed++
				mu.Unlock()
			}
			if err := s.Store.UpsertRelease(ctx, r); err != nil {
				s.Log.Error("store release", "component", c.ComponentID, "err", err)
			}
		}(c)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(cands) > 0 && failed == len(cands) {
		return nil, fmt.Errorf("all %d registry lookups failed", failed)
	}
	return &SyncResult{Changed: len(cands) - failed}, nil
}

// regVersion is one published version as a registry reports it.
type regVersion struct {
	version   string
	published string // RFC 3339; "" when the registry gives no date
	pre       bool
	withdrawn bool // yanked, retracted or unlisted
	reason    string
}

// fill sets Latest, LatestStable, dates and withdrawn versions from vs.
// Withdrawn versions are never offered as the latest.
func fill(r *store.Release, eco version.Ecosystem, vs []regVersion) {
	cmp := version.For(eco)
	var all, stable []string
	r.VersionDates = map[string]string{}
	for _, v := range vs {
		if v.published != "" && !before(r.VersionDates[v.version], v.published) {
			r.VersionDates[v.version] = v.published // a version listed twice keeps its first date
		}
		if v.withdrawn {
			if r.Yanked == nil {
				r.Yanked = map[string]string{}
			}
			r.Yanked[v.version] = v.reason
			continue
		}
		all = append(all, v.version)
		if !v.pre {
			stable = append(stable, v.version)
		}
	}
	r.Latest, r.LatestStable = newest(cmp, all), newest(cmp, stable)
	r.StableVersions = sortedVersions(cmp, stable)
	if t, err := time.Parse(time.RFC3339, r.VersionDates[r.LatestStable]); err == nil {
		r.LatestPublished = &t
	}
}

// sortedVersions returns the distinct versions in vs that cmp can parse,
// oldest first.
func sortedVersions(cmp version.Comparator, vs []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range vs {
		if _, err := cmp(v, v); err != nil || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		c, _ := cmp(out[i], out[j])
		return c < 0
	})
	return out
}

// before reports whether RFC 3339 time a is earlier than b.
func before(a, b string) bool {
	ta, err1 := time.Parse(time.RFC3339, a)
	tb, err2 := time.Parse(time.RFC3339, b)
	return err1 == nil && err2 == nil && ta.Before(tb)
}

// newest returns the highest version in vs, skipping any cmp cannot parse.
func newest(cmp version.Comparator, vs []string) string {
	best := ""
	for _, v := range vs {
		if _, err := cmp(v, v); err != nil {
			continue
		}
		if best == "" {
			best = v
		} else if c, err := cmp(v, best); err == nil && c > 0 {
			best = v
		}
	}
	return best
}

func registryURL(base string, parts ...string) string {
	u := strings.TrimSuffix(base, "/")
	for _, p := range parts {
		u += "/" + url.PathEscape(p)
	}
	return u
}

// --- PyPI

var pep503 = regexp.MustCompile(`[-_.]+`)

func (s *Syncer) pypiRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	name := strings.ToLower(pep503.ReplaceAllString(c.Name, "-"))
	r := store.Release{Source: FeedPyPI, SourceURL: "https://pypi.org/project/" + name + "/"}
	b, err := s.f.download(ctx, registryURL(s.f.cfg.PyPIURL, "pypi", name, "json"), 64<<20)
	if err != nil {
		return r, err
	}
	var doc struct {
		Releases map[string][]struct {
			Uploaded     string  `json:"upload_time_iso_8601"`
			Yanked       bool    `json:"yanked"`
			YankedReason *string `json:"yanked_reason"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return r, err
	}
	var vs []regVersion
	for v, files := range doc.Releases {
		pre, ok := version.PEP440Prerelease(v)
		if !ok || len(files) == 0 { // a release without files cannot be installed
			continue
		}
		// A release is yanked when all of its files are; it is dated by
		// its first upload.
		rv := regVersion{version: v, pre: pre, withdrawn: true}
		for _, f := range files {
			if !f.Yanked {
				rv.withdrawn = false
			} else if f.YankedReason != nil && rv.reason == "" {
				rv.reason = *f.YankedReason
			}
			if rv.published == "" || f.Uploaded < rv.published {
				rv.published = f.Uploaded
			}
		}
		if !rv.withdrawn {
			rv.reason = ""
		}
		vs = append(vs, rv)
	}
	fill(&r, version.PEP440, vs)
	return r, nil
}

// --- Go module proxy

// goModulePath returns the module path with its original letter case: purl
// parsing lower-cases golang namespaces, but the proxy is case-sensitive.
func goModulePath(c store.ReleaseCandidate) string {
	lower := c.Name
	if c.Namespace != "" {
		lower = c.Namespace + "/" + c.Name
	}
	raw, ok := strings.CutPrefix(c.Purl, "pkg:golang/")
	if !ok {
		return lower
	}
	raw, _, _ = strings.Cut(raw, "#")
	raw, _, _ = strings.Cut(raw, "?")
	if i := strings.LastIndexByte(raw, '@'); i >= 0 {
		raw = raw[:i]
	}
	if p, err := url.PathUnescape(raw); err == nil && strings.EqualFold(p, lower) {
		return p
	}
	return lower
}

func (s *Syncer) goRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	mod := goModulePath(c)
	r := store.Release{Source: FeedGo, SourceURL: "https://pkg.go.dev/" + mod}
	first, _, _ := strings.Cut(mod, "/")
	if !strings.Contains(first, ".") {
		return r, nil // the standard library or toolchain: lifecycle data covers Go itself
	}
	esc, err := module.EscapePath(mod)
	if err != nil {
		return r, err
	}
	base := strings.TrimSuffix(s.f.cfg.GoProxyURL, "/") + "/" + esc
	b, err := s.f.download(ctx, base+"/@v/list", 4<<20)
	if err != nil {
		return r, err
	}
	var tags []string
	for _, v := range strings.Fields(string(b)) {
		if semver.IsValid(v) {
			tags = append(tags, v)
		}
	}
	// @latest is resolved by the go command on the proxy, which applies its
	// rules for retractions and +incompatible versions; it also names the
	// newest pseudo-version of a module with no tags.
	var latest struct{ Version, Time string }
	if b, err = s.f.download(ctx, base+"/@latest", 1<<20); err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &latest); err != nil {
		return r, err
	}
	if !semver.IsValid(latest.Version) {
		return r, fmt.Errorf("proxy returned invalid version %q", latest.Version)
	}
	// +incompatible versions (v2+ of a repository without go.mod) count only
	// when the go command picked one as latest.
	incompatible := semver.Build(latest.Version) == "+incompatible"
	kept := tags[:0]
	for _, v := range tags {
		if incompatible || semver.Build(v) != "+incompatible" {
			kept = append(kept, v)
		}
	}
	if tags = kept; len(tags) == 0 {
		tags = []string{latest.Version}
	}
	semver.Sort(tags)
	// Retractions and the deprecation notice are read from the go.mod of the
	// newest version, as the go command does.
	var retract []*modfile.Retract
	if ev, err := module.EscapeVersion(tags[len(tags)-1]); err == nil {
		mb, err := s.f.download(ctx, base+"/@v/"+ev+".mod", 4<<20)
		if err != nil {
			return r, err
		}
		if f, err := modfile.ParseLax("go.mod", mb, nil); err == nil {
			if f.Module != nil {
				r.Deprecated = f.Module.Deprecated
			}
			retract = f.Retract
		}
	}
	var vs []regVersion
	for _, v := range tags {
		rv := regVersion{version: v, pre: semver.Prerelease(v) != ""}
		if v == latest.Version {
			rv.published = latest.Time
		}
		for _, rt := range retract {
			if semver.Compare(rt.Low, v) <= 0 && semver.Compare(v, rt.High) <= 0 {
				rv.withdrawn, rv.reason = true, rt.Rationale
				break
			}
		}
		vs = append(vs, rv)
	}
	fill(&r, version.SemVer, vs)
	if r.LatestStable != "" && r.LatestPublished == nil {
		ev, _ := module.EscapeVersion(r.LatestStable)
		var info struct{ Time string }
		if b, err := s.f.download(ctx, base+"/@v/"+ev+".info", 1<<20); err == nil && json.Unmarshal(b, &info) == nil {
			if t, err := time.Parse(time.RFC3339, info.Time); err == nil {
				r.VersionDates[r.LatestStable], r.LatestPublished = info.Time, &t
			}
		}
	}
	return r, nil
}

// --- crates.io (sparse index)

// cratesIndexPath is the sparse index layout: 1/a, 2/ab, 3/a/abc, ab/cd/abcd...
func cratesIndexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 1:
		return "1/" + n
	case 2:
		return "2/" + n
	case 3:
		return "3/" + n[:1] + "/" + n
	}
	return n[:2] + "/" + n[2:4] + "/" + n
}

var crateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func (s *Syncer) cratesRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	r := store.Release{Source: FeedCrates, SourceURL: "https://crates.io/crates/" + c.Name}
	if !crateName.MatchString(c.Name) {
		return r, fmt.Errorf("invalid crate name %q", c.Name)
	}
	b, err := s.f.download(ctx, strings.TrimSuffix(s.f.cfg.CratesIndexURL, "/")+"/"+cratesIndexPath(c.Name), 32<<20)
	if err != nil {
		return r, err
	}
	// One JSON object per line. pubtime is absent from very old entries.
	var vs []regVersion
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var e struct {
			Vers    string `json:"vers"`
			Yanked  bool   `json:"yanked"`
			Pubtime string `json:"pubtime"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Vers == "" {
			continue
		}
		vs = append(vs, regVersion{version: e.Vers, published: e.Pubtime, pre: version.SemverPrerelease(e.Vers), withdrawn: e.Yanked})
	}
	if err := sc.Err(); err != nil {
		return r, err
	}
	fill(&r, version.SemVer, vs)
	return r, nil
}

// --- RubyGems

func (s *Syncer) rubygemsRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	r := store.Release{Source: FeedRubyGems, SourceURL: "https://rubygems.org/gems/" + c.Name}
	b, err := s.f.download(ctx, registryURL(s.f.cfg.RubyGemsURL, "api", "v1", "versions", c.Name+".json"), 64<<20)
	if err != nil {
		return r, err
	}
	// Yanked versions are not listed. Platform builds repeat a version.
	var doc []struct {
		Number     string `json:"number"`
		Prerelease bool   `json:"prerelease"`
		CreatedAt  string `json:"created_at"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return r, err
	}
	var vs []regVersion
	for _, v := range doc {
		vs = append(vs, regVersion{version: v.Number, published: v.CreatedAt, pre: v.Prerelease})
	}
	fill(&r, version.RubyGems, vs)
	return r, nil
}

// --- NuGet (registration resources)

type nugetLeaf struct {
	CatalogEntry struct {
		Version     string `json:"version"`
		Listed      *bool  `json:"listed"`
		Published   string `json:"published"`
		Deprecation *struct {
			Reasons          []string `json:"reasons"`
			Message          string   `json:"message"`
			AlternatePackage *struct {
				ID string `json:"id"`
			} `json:"alternatePackage"`
		} `json:"deprecation"`
	} `json:"catalogEntry"`
}

type nugetPage struct {
	ID    string      `json:"@id"`
	Items []nugetLeaf `json:"items"`
}

// nugetMaxPages bounds the pages read per package; pages hold 64 versions
// and are read newest first until a listed stable version is found.
const nugetMaxPages = 8

func (s *Syncer) nugetRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	r := store.Release{Source: FeedNuGet, SourceURL: "https://www.nuget.org/packages/" + c.Name}
	base := strings.TrimSuffix(s.f.cfg.NuGetURL, "/")
	b, err := s.f.download(ctx, registryURL(base, strings.ToLower(c.Name), "index.json"), 16<<20)
	if err != nil {
		return r, err
	}
	var idx struct {
		Items []nugetPage `json:"items"`
	}
	if err := json.Unmarshal(b, &idx); err != nil {
		return r, err
	}
	var leaves []nugetLeaf
	found := false
	for i, read := len(idx.Items)-1, 0; i >= 0; i-- {
		page := idx.Items[i]
		if page.Items == nil { // large packages link their pages instead of inlining them
			if read++; found || read > nugetMaxPages {
				continue
			}
			if !sameOrigin(page.ID, base) {
				return r, fmt.Errorf("registration page %q is not on %s", page.ID, base)
			}
			pb, err := s.f.download(ctx, page.ID, 16<<20)
			if err != nil {
				return r, err
			}
			if err := json.Unmarshal(pb, &page); err != nil {
				return r, err
			}
		}
		for _, l := range page.Items {
			e := l.CatalogEntry
			if (e.Listed == nil || *e.Listed) && !version.NuGetPrerelease(e.Version) {
				found = true
			}
		}
		leaves = append(leaves, page.Items...)
	}
	var vs []regVersion
	deprecation := map[string]string{}
	for _, l := range leaves {
		e := l.CatalogEntry
		v, _, _ := strings.Cut(e.Version, "+")
		rv := regVersion{version: v, pre: version.NuGetPrerelease(v)}
		// Unlisted packages carry a 1900-01-01 publish date.
		if t, err := time.Parse(time.RFC3339, e.Published); err == nil && t.Year() > 1900 {
			rv.published = t.UTC().Format(time.RFC3339)
		}
		if e.Listed != nil && !*e.Listed {
			rv.withdrawn, rv.reason = true, "unlisted"
		}
		if d := e.Deprecation; d != nil {
			msg := d.Message
			if msg == "" {
				msg = "deprecated (" + strings.Join(d.Reasons, ", ") + ")"
			}
			if d.AlternatePackage != nil && d.AlternatePackage.ID != "" && !strings.Contains(msg, d.AlternatePackage.ID) {
				msg += " Alternative: " + d.AlternatePackage.ID + "."
			}
			deprecation[v] = msg
			// A version deprecated for critical bugs is as good as withdrawn.
			for _, reason := range d.Reasons {
				if reason == "CriticalBugs" && !rv.withdrawn {
					rv.withdrawn, rv.reason = true, msg
				}
			}
		}
		vs = append(vs, rv)
	}
	fill(&r, version.NuGet, vs)
	// The package counts as deprecated when its newest version is.
	newestVersion := r.LatestStable
	if newestVersion == "" {
		newestVersion = r.Latest
	}
	r.Deprecated = deprecation[newestVersion]
	return r, nil
}

// sameOrigin reports whether u has the scheme and host of base, so a
// registry document cannot send the fetcher elsewhere.
func sameOrigin(u, base string) bool {
	a, err1 := url.Parse(u)
	b, err2 := url.Parse(base)
	return err1 == nil && err2 == nil && a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

// --- Maven Central

func (s *Syncer) mavenRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	g, a := c.Namespace, c.Name
	r := store.Release{Source: FeedMaven, SourceURL: "https://central.sonatype.com/artifact/" + g + "/" + a}
	if g == "" || a == "" || strings.Contains(g, "/") || strings.Contains(a, "/") || strings.Contains(g, "..") {
		return r, fmt.Errorf("invalid Maven coordinates %q:%q", g, a)
	}
	parts := append(strings.Split(g, "."), a, "maven-metadata.xml")
	b, err := s.f.download(ctx, registryURL(s.f.cfg.MavenURL, parts...), 8<<20)
	if err != nil {
		return r, err
	}
	var doc struct {
		Versions []string `xml:"versioning>versions>version"`
	}
	if err := xml.Unmarshal(b, &doc); err != nil {
		return r, err
	}
	if len(doc.Versions) == 0 {
		return r, errors.New("maven-metadata.xml lists no versions")
	}
	// The metadata has no per-version dates, and <release> may be a
	// milestone or release candidate, so both are worked out here.
	var vs []regVersion
	for _, v := range doc.Versions {
		v = strings.TrimSpace(v)
		if v != "" {
			vs = append(vs, regVersion{version: v, pre: version.MavenPrerelease(v)})
		}
	}
	fill(&r, version.Maven, vs)
	r.VersionDates = nil
	return r, nil
}

// --- pub.dev

func (s *Syncer) pubRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	r := store.Release{Source: FeedPub, SourceURL: "https://pub.dev/packages/" + c.Name}
	b, err := s.f.download(ctx, registryURL(s.f.cfg.PubURL, "api", "packages", c.Name), 32<<20)
	if err != nil {
		return r, err
	}
	var doc struct {
		IsDiscontinued bool   `json:"isDiscontinued"`
		ReplacedBy     string `json:"replacedBy"`
		Versions       []struct {
			Version   string `json:"version"`
			Published string `json:"published"`
			Retracted bool   `json:"retracted"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return r, err
	}
	var vs []regVersion
	for _, v := range doc.Versions {
		rv := regVersion{version: v.Version, published: v.Published, pre: version.SemverPrerelease(v.Version), withdrawn: v.Retracted}
		if v.Retracted {
			rv.reason = "retracted"
		}
		vs = append(vs, rv)
	}
	fill(&r, version.SemVer, vs)
	if doc.IsDiscontinued {
		r.Deprecated = "Discontinued by its publisher."
		if doc.ReplacedBy != "" {
			r.Deprecated += " Replaced by " + doc.ReplacedBy + "."
		}
	}
	return r, nil
}

// --- Hex

var hexName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// hexRelease reads hex.pm's package API. A retired release is still
// installable but its publisher asks people to move off it, so, like a
// yanked one, it is never offered as the latest.
func (s *Syncer) hexRelease(ctx context.Context, c store.ReleaseCandidate) (store.Release, error) {
	r := store.Release{Source: FeedHex, SourceURL: "https://hex.pm/packages/" + c.Name}
	if c.Namespace != "" {
		return r, fmt.Errorf("%s/%s is from a private Hex organisation or repository, not looked up on hex.pm", c.Namespace, c.Name)
	}
	if !hexName.MatchString(c.Name) {
		return r, fmt.Errorf("invalid Hex package name %q", c.Name)
	}
	b, err := s.f.download(ctx, registryURL(s.f.cfg.HexURL, "api", "packages", c.Name), 16<<20)
	if err != nil {
		return r, err
	}
	var doc struct {
		Releases []struct {
			Version    string `json:"version"`
			InsertedAt string `json:"inserted_at"`
		} `json:"releases"`
		Retirements map[string]struct {
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"retirements"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return r, err
	}
	var vs []regVersion
	for _, v := range doc.Releases {
		rv := regVersion{version: v.Version, published: v.InsertedAt, pre: version.SemverPrerelease(v.Version)}
		if ret, ok := doc.Retirements[v.Version]; ok {
			rv.withdrawn, rv.reason = true, "retired"
			if ret.Reason != "" {
				rv.reason += " (" + ret.Reason + ")"
			}
			if ret.Message != "" {
				rv.reason += ": " + ret.Message
			}
		}
		vs = append(vs, rv)
	}
	fill(&r, version.SemVer, vs)
	return r, nil
}
