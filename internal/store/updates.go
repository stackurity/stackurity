package store

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/version"
)

// Updates available: installed versions older than their package's latest
// stable release, whether or not a vulnerability is involved. They are
// shown and summarised, never turned into findings, priorities or
// incidents: a newer release with no advisory is not a security issue.

// UpdateTypes are the values of update_type, smallest change first.
var UpdateTypes = []string{"patch", "minor", "major"}

// registryTypes are the purl types whose latest stable release comes from
// a package registry (internal/intel/releases.go) and that updateType
// classifies. Of the generic components, only WordPress plugins and themes
// (WordPressNamespaces, from wordpress.org) have one; other generic and
// distribution packages have no update type.
var registryTypes = []string{"npm", "composer", "pypi", "golang", "cargo", "gem", "nuget", "maven", "pub", "hex"}

// behindSQL keeps inventory rows i (with components c and package_releases
// pr joined) whose installed version may be older than the latest stable
// release; updateType decides. A row the collector marked as not from the
// registry (evidence wordpress_org "no": a plugin whose Update URI names
// another host, a must-use plugin) is updated from elsewhere, so the
// registry's latest release says nothing about it.
const behindSQL = `(c.type = ANY(?) OR c.type = 'generic' AND c.namespace = ANY(?))
	AND pr.latest_stable <> '' AND pr.latest_stable <> i.version
	AND COALESCE(i.evidence->>'wordpress_org', '') <> 'no'`

// addBehind adds behindSQL with its arguments.
func (w *where) addBehind() {
	w.args = append(w.args, registryTypes, WordPressNamespaces)
	n := len(w.args)
	w.conds = append(w.conds, strings.Replace(strings.Replace(behindSQL, "?", fmt.Sprintf("$%d", n-1), 1), "?", fmt.Sprintf("$%d", n), 1))
}

// validUpdateFilter reports whether f is a value of InventoryFilter.UpdateType.
func validUpdateFilter(f string) bool {
	return f == "any" || containsString(UpdateTypes, f)
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// matchesUpdate reports whether an update of type t passes filter f
// ("any" or one of UpdateTypes). "ahead" (installed newer than the latest
// stable release) is never an update.
func matchesUpdate(f, t string) bool {
	return containsString(UpdateTypes, t) && (f == "any" || f == t)
}

// behindIDs returns, in the listing's order, the ids of the rows that
// from (whose conditions include behindSQL) selects and whose update type
// passes filter f.
func (s *Store) behindIDs(ctx context.Context, from string, args []any, f string) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT i.id, c.type, c.namespace, i.version, pr.latest_stable`+from+
		` ORDER BY c.type, c.namespace, c.name, i.version, i.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []int64{}
	for rows.Next() {
		var id int64
		var typ, ns, installed, latest string
		if err := rows.Scan(&id, &typ, &ns, &installed, &latest); err != nil {
			return nil, err
		}
		if matchesUpdate(f, updateType(typ, ns, installed, latest)) {
			ids = append(ids, id)
		}
	}
	return ids, rows.Err()
}

// BehindInstall is one inventory row older than its package's latest
// stable release, with what route scopes need to know about its asset.
type BehindInstall struct {
	InventoryID  int64
	AssetID      int64
	Environment  string
	OwnerTeamID  *int64
	ComponentID  int64
	Type         string
	Namespace    string
	Name         string
	Version      string
	LatestStable string
	UpdateType   string
}

// BehindInstalls returns every current inventory row with an update
// available, optionally for one asset. It reads the caller's workspace
// (and project) only, as inventory listings do.
func (s *Store) BehindInstalls(ctx context.Context, assetID int64) ([]BehindInstall, error) {
	w := &where{conds: []string{"i.removed_at IS NULL", "a.merged_into IS NULL"}}
	w.addBehind()
	if assetID > 0 {
		w.add("i.asset_id = ?", assetID)
	}
	rows, err := s.Pool.Query(ctx, `SELECT i.id, i.asset_id, a.environment, a.owner_team_id, c.id, c.type, c.namespace, c.name,
		i.version, pr.latest_stable
		FROM inventory i JOIN components c ON c.id = i.component_id JOIN assets a ON a.id = i.asset_id
		JOIN package_releases pr ON pr.component_id = c.id`+w.sql(), w.args...)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (BehindInstall, error) {
		var b BehindInstall
		err := r.Scan(&b.InventoryID, &b.AssetID, &b.Environment, &b.OwnerTeamID, &b.ComponentID, &b.Type, &b.Namespace, &b.Name,
			&b.Version, &b.LatestStable)
		return b, err
	})
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, b := range all {
		if b.UpdateType = updateType(b.Type, b.Namespace, b.Version, b.LatestStable); matchesUpdate("any", b.UpdateType) {
			out = append(out, b)
		}
	}
	return out, nil
}

// ComponentUpdate is one package with installs behind its latest stable
// release. UpdateType is the largest change among them.
type ComponentUpdate struct {
	ComponentID       int64    `json:"component_id"`
	Type              string   `json:"type"`
	Namespace         string   `json:"namespace"`
	Name              string   `json:"name"`
	InstalledVersions []string `json:"installed_versions"`
	LatestStable      string   `json:"latest_stable"`
	UpdateType        string   `json:"update_type"`
	Installs          int      `json:"installs"`
	Assets            int      `json:"assets"`
}

// UpdatesSummary counts installs with an update available by update type
// and lists the packages with the most installs behind.
type UpdatesSummary struct {
	// Counts are installs (inventory rows) by update type: patch, minor,
	// major, and their total.
	Counts map[string]int `json:"counts"`
	// Components is how many packages have at least one install behind
	// (matching the filter); Top lists the first of them.
	Components int               `json:"components"`
	Top        []ComponentUpdate `json:"top"`
}

// SummarizeUpdates builds a summary of installs: counts over every
// install, Top over those of update type filter ("" or "any" for all), at
// most limit, most installs behind first.
func SummarizeUpdates(installs []BehindInstall, filter string, limit int) UpdatesSummary {
	sum := UpdatesSummary{Counts: map[string]int{"total": 0}, Top: []ComponentUpdate{}}
	for _, t := range UpdateTypes {
		sum.Counts[t] = 0
	}
	type acc struct {
		ComponentUpdate
		versions map[string]bool
		assets   map[int64]bool
	}
	by := map[int64]*acc{}
	for _, b := range installs {
		sum.Counts[b.UpdateType]++
		sum.Counts["total"]++
		if filter != "" && !matchesUpdate(filter, b.UpdateType) {
			continue
		}
		a := by[b.ComponentID]
		if a == nil {
			a = &acc{ComponentUpdate: ComponentUpdate{ComponentID: b.ComponentID, Type: b.Type, Namespace: b.Namespace, Name: b.Name,
				LatestStable: b.LatestStable}, versions: map[string]bool{}, assets: map[int64]bool{}}
			by[b.ComponentID] = a
		}
		a.Installs++
		a.versions[b.Version] = true
		a.assets[b.AssetID] = true
		if updateRank(b.UpdateType) > updateRank(a.UpdateType) {
			a.UpdateType = b.UpdateType
		}
	}
	list := make([]ComponentUpdate, 0, len(by))
	for _, a := range by {
		cmp := version.For(version.ForPurlType(a.Type))
		for v := range a.versions {
			a.InstalledVersions = append(a.InstalledVersions, v)
		}
		sort.Slice(a.InstalledVersions, func(i, j int) bool {
			if c, err := cmp(a.InstalledVersions[i], a.InstalledVersions[j]); err == nil && c != 0 {
				return c < 0
			}
			return a.InstalledVersions[i] < a.InstalledVersions[j]
		})
		a.Assets = len(a.assets)
		list = append(list, a.ComponentUpdate)
	}
	sort.Slice(list, func(i, j int) bool {
		x, y := list[i], list[j]
		if x.Installs != y.Installs {
			return x.Installs > y.Installs
		}
		if x.Assets != y.Assets {
			return x.Assets > y.Assets
		}
		if r := updateRank(x.UpdateType) - updateRank(y.UpdateType); r != 0 {
			return r > 0
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		return x.ComponentID < y.ComponentID
	})
	sum.Components = len(list)
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	sum.Top = list
	return sum
}

func updateRank(t string) int {
	for i, u := range UpdateTypes {
		if u == t {
			return i + 1
		}
	}
	return 0
}

// UpdatesFilter limits an updates summary.
type UpdatesFilter struct {
	AssetID int64
	// UpdateType limits Top to one update type ("" or "any": all).
	UpdateType string
	// Limit is the number of packages listed (default 20, at most 100).
	Limit int
}

// SummarizeWorkspaceUpdates summarises the updates available in the
// caller's workspace.
func (s *Store) SummarizeWorkspaceUpdates(ctx context.Context, f UpdatesFilter) (UpdatesSummary, error) {
	if f.UpdateType != "" && !validUpdateFilter(f.UpdateType) {
		return UpdatesSummary{}, fmt.Errorf("update_type must be patch, minor, major or any: %w", ErrInvalid)
	}
	if f.Limit <= 0 {
		f.Limit = 20
	}
	f.Limit = min(f.Limit, 100)
	installs, err := s.BehindInstalls(ctx, f.AssetID)
	if err != nil {
		return UpdatesSummary{}, err
	}
	return SummarizeUpdates(installs, f.UpdateType, f.Limit), nil
}
