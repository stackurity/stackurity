package intel

import (
	"context"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
)

// purl types handled by language-ecosystem OSV feeds.
var langFeeds = map[string]string{
	"npm": "npm", "composer": "Packagist", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io",
	"gem": "RubyGems", "maven": "Maven", "nuget": "NuGet", "pub": "Pub",
}

// distroFeeds maps the distro qualifier prefix to the OSV ecosystem.
var distroFeeds = map[string]string{
	"deb:debian": "Debian", "deb:ubuntu": "Ubuntu", "apk:alpine": "Alpine",
	"rpm:rocky": "Rocky Linux", "rpm:almalinux": "AlmaLinux",
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
	if err := ensure(FeedKEV, "vulnerability", 24*time.Hour, 72*time.Hour); err != nil {
		return err
	}
	if err := ensure(FeedEndOfLife, "lifecycle", 24*time.Hour, 7*24*time.Hour); err != nil {
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
	for d := range p.Distros {
		for prefix, eco := range distroFeeds {
			if strings.HasPrefix(d, prefix+"-") {
				if err := ensure(OSVFeed(eco), "vulnerability", time.Hour, 6*time.Hour); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ComponentsToEvaluate maps a sync result to the components that need
// re-evaluation. nil means none.
func ComponentsToEvaluate(ctx context.Context, s *store.Store, feed string, res *SyncResult) ([]int64, error) {
	if res == nil || res.Changed == 0 {
		return nil, nil
	}
	switch {
	case feed == FeedKEV || feed == FeedEndOfLife:
		return s.ComponentsOfTypes(ctx, allTypes())
	case strings.HasPrefix(feed, "osv:"):
		base := strings.TrimPrefix(feed, "osv:")
		types := purlTypesFor(base)
		if len(types) == 0 {
			return nil, nil
		}
		ids, err := s.ComponentsOfTypes(ctx, types)
		if err != nil || res.Full || len(ids) == 0 {
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
	return nil, nil // release data does not change findings
}

func allTypes() []string {
	return []string{"npm", "composer", "pypi", "golang", "cargo", "gem", "maven", "nuget", "deb", "rpm", "apk", "generic"}
}
