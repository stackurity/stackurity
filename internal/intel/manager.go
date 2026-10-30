package intel

import (
	"context"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// purl types handled by language-ecosystem OSV feeds.
var langFeeds = map[string]string{
	"npm": "npm", "composer": "Packagist", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io",
	"gem": "RubyGems", "maven": "Maven", "nuget": "NuGet", "pub": "Pub",
	// Read by the Swift and Hex stack packs.
	"swift": "SwiftURL", "hex": "Hex",
}

// distroFeeds maps the distro qualifier prefix to the OSV ecosystem.
var distroFeeds = map[string]string{
	"deb:debian": "Debian", "deb:ubuntu": "Ubuntu", "apk:alpine": "Alpine",
	"rpm:rocky": "Rocky Linux", "rpm:almalinux": "AlmaLinux", "rpm:rhel": "Red Hat",
	"rpm:sles": "SUSE", "rpm:sles_sap": "SUSE", "rpm:sled": "SUSE", "rpm:opensuse-leap": "openSUSE",
	"rpm:amzn": "Amazon Linux", "rpm:ol": "Oracle Linux",
}

// purlTypesFor lists the purl types whose components an OSV ecosystem covers.
func purlTypesFor(base string) []string {
	for t, eco := range langFeeds {
		if eco == base {
			return []string{t}
		}
	}
	for k, eco := range distroFeeds {
		if eco == base {
			t, _, _ := strings.Cut(k, ":")
			return []string{t}
		}
	}
	return nil
}

// EnsureFeeds creates feeds for the ecosystems present in inventory. Feeds
// an operator has disabled stay disabled.
func EnsureFeeds(ctx context.Context, s *store.Store) error {
	p, err := s.InventoryProfile(ctx)
	if err != nil {
		return err
	}
	ensure := func(name, kind string, refresh, stale time.Duration) error {
		return s.EnsureFeed(ctx, name, kind, refresh, stale)
	}
	// CISA adds to KEV a few times a week, at any hour; an unchanged
	// catalogue costs one conditional GET (syncKEV). Before 0.13.9 it was
	// checked daily: a feed still on those settings moves to these.
	if err := s.RetuneFeed(ctx, FeedKEV, 24*time.Hour, 72*time.Hour, time.Hour, 12*time.Hour); err != nil {
		return err
	}
	if err := ensure(FeedKEV, "vulnerability", time.Hour, 12*time.Hour); err != nil {
		return err
	}
	if err := ensure(FeedEndOfLife, "lifecycle", 24*time.Hour, 7*24*time.Hour); err != nil {
		return err
	}
	if err := ensure(FeedEPSS, "prediction", 24*time.Hour, 72*time.Hour); err != nil {
		return err
	}
	for t := range p.Types {
		if eco, ok := langFeeds[t]; ok {
			if err := ensure(OSVFeed(eco), "vulnerability", time.Hour, 6*time.Hour); err != nil {
				return err
			}
		}
		if feed := releaseFeedFor(t); feed != "" {
			if err := ensure(feed, "release", 6*time.Hour, 72*time.Hour); err != nil {
				return err
			}
		}
	}
	if p.Types["generic"] > 0 {
		// WordPress plugins and themes: their latest releases on wordpress.org.
		if wp, err := s.HasComponentsIn(ctx, "generic", store.WordPressNamespaces); err != nil {
			return err
		} else if wp {
			if err := ensure(FeedWordPressOrg, "release", 6*time.Hour, 72*time.Hour); err != nil {
				return err
			}
		}
		win, err := s.ComponentsWithPurlKey(ctx, windowsPurlKey)
		if err != nil {
			return err
		}
		if len(win) > 0 {
			// The index is about 50 KB and says which monthly documents
			// changed, so checking every 6 hours reads a Patch Tuesday
			// release (about 17:00 UTC) the same evening.
			if err := ensure(FeedMSRC, "vulnerability", 6*time.Hour, 72*time.Hour); err != nil {
				return err
			}
			// Installed programs of the curated catalogue, read from NVD
			// (only those installed somewhere).
			if err := ensure(FeedWindowsPrograms, "vulnerability", 6*time.Hour, 72*time.Hour); err != nil {
				return err
			}
		}
	}
	for d := range p.Distros {
		for prefix, eco := range distroFeeds {
			if !strings.HasPrefix(d, prefix+"-") {
				continue
			}
			refresh, stale := time.Hour, 6*time.Hour
			switch eco {
			case "Amazon Linux":
				// A full read of every repository; Amazon publishes a few times a week.
				refresh, stale = 6*time.Hour, 48*time.Hour
			case "Oracle Linux":
				// A full read of each release's file (4 to 6 MB); Oracle
				// publishes several times a day.
				refresh, stale = 6*time.Hour, 48*time.Hour
			}
			if err := ensure(VulnFeed(eco), "vulnerability", refresh, stale); err != nil {
				return err
			}
		}
	}
	return nil
}

// ComponentsToEvaluate maps a sync result to the components that need
// re-evaluation. nil means none.
func ComponentsToEvaluate(ctx context.Context, s *store.Store, feed string, res *SyncResult) ([]int64, error) {
	if res == nil || (res.Changed == 0 && len(res.Packages) == 0 && !res.All) {
		return nil, nil
	}
	switch {
	case feed == FeedKEV || feed == FeedEndOfLife:
		return s.ComponentsOfTypes(ctx, allTypes())
	case feed == FeedMSRC:
		ids, err := s.ComponentsWithPurlKey(ctx, windowsPurlKey)
		if err != nil {
			return nil, err
		}
		// The same documents list fixes for catalogued programs (Edge, the
		// .NET runtimes): their rows are evaluated again with the hosts'.
		pkgs := map[store.PackageRef]bool{}
		for _, p := range winprograms.Default().Programs() {
			if p.Source != nil && p.Source.Type == winprograms.SourceMSRC {
				pkgs[store.PackageRef{BaseEcosystem: winprograms.Ecosystem, Name: p.ID}] = true
			}
		}
		progs, err := programComponents(ctx, s, &SyncResult{Packages: pkgs})
		return append(ids, progs...), err
	case feed == FeedWindowsPrograms:
		return programComponents(ctx, s, res)
	case strings.HasPrefix(feed, "osv:") || feed == FeedAmazonLinux || feed == FeedOracleLinux:
		base, _ := feedEcosystem(feed)
		types := purlTypesFor(base)
		if len(types) == 0 {
			return nil, nil
		}
		ids, err := s.ComponentsOfTypes(ctx, types)
		if err != nil || res.All || len(ids) == 0 {
			return ids, err
		}
		rows, err := s.EvalRows(ctx, ids, 0)
		if err != nil {
			return nil, err
		}
		seen := map[int64]bool{}
		var out []int64
		for _, r := range rows {
			t, ok := osv.TargetFor(r.Purl, r.Version, r.Evidence)
			if !ok || seen[r.ComponentID] {
				continue
			}
			if res.Packages[store.PackageRef{BaseEcosystem: osv.BaseEcosystem(t.Ecosystem), Name: t.Name}] {
				seen[r.ComponentID] = true
				out = append(out, r.ComponentID)
			}
		}
		return out, nil
	}
	// Release data does not change findings, and EPSS changes only
	// priorities, which the next prioritisation reads directly.
	return nil, nil
}

func allTypes() []string {
	return []string{"npm", "composer", "pypi", "golang", "cargo", "gem", "maven", "nuget", "pub", "swift", "hex",
		"cocoapods", "conan", "deb", "rpm", "apk", "generic"}
}
