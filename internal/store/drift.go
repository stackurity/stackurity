package store

import (
	"context"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/version"
)

// DriftItem is one component whose installed versions differ between an
// asset and the asset it is compared with (typically its primary, through a
// replica_of relation).
type DriftItem struct {
	ComponentID int64    `json:"component_id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Versions    []string `json:"versions"`  // on the asset
	Reference   []string `json:"reference"` // on the compared asset
	Status      string   `json:"status"`    // behind, ahead, differs, only_here, only_there
}

type Drift struct {
	AssetID     int64          `json:"asset_id"`
	ReferenceID int64          `json:"reference_id"`
	Items       []DriftItem    `json:"items"`
	Counts      map[string]int `json:"counts"`
	Truncated   bool           `json:"truncated"`
}

// maxDriftItems bounds the response; counts always cover everything.
const maxDriftItems = 2000

// CompareAssets lists components whose current versions differ between an
// asset and a reference asset.
func (s *Store) CompareAssets(ctx context.Context, assetID, referenceID int64) (*Drift, error) {
	rows, err := s.Pool.Query(ctx, `
		WITH here AS (SELECT component_id, array_agg(DISTINCT version ORDER BY version) v
		              FROM inventory WHERE asset_id = $1 AND removed_at IS NULL GROUP BY component_id),
		     there AS (SELECT component_id, array_agg(DISTINCT version ORDER BY version) v
		              FROM inventory WHERE asset_id = $2 AND removed_at IS NULL GROUP BY component_id)
		SELECT c.id, CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END, c.type,
		       COALESCE(here.v, '{}'), COALESCE(there.v, '{}')
		FROM here FULL JOIN there USING (component_id) JOIN components c ON c.id = component_id
		WHERE here.v IS DISTINCT FROM there.v
		ORDER BY c.type, c.namespace, c.name`, assetID, referenceID)
	if err != nil {
		return nil, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (DriftItem, error) {
		var d DriftItem
		err := row.Scan(&d.ComponentID, &d.Name, &d.Type, &d.Versions, &d.Reference)
		return d, err
	})
	if err != nil {
		return nil, err
	}
	out := &Drift{AssetID: assetID, ReferenceID: referenceID, Items: []DriftItem{}, Counts: map[string]int{}}
	for i := range items {
		items[i].Status = driftStatus(items[i])
		out.Counts[items[i].Status]++
	}
	// Show what needs attention first: behind, then only on the reference.
	order := map[string]int{"behind": 0, "only_there": 1, "differs": 2, "ahead": 3, "only_here": 4}
	sort.SliceStable(items, func(i, j int) bool { return order[items[i].Status] < order[items[j].Status] })
	if len(items) > maxDriftItems {
		items, out.Truncated = items[:maxDriftItems], true
	}
	out.Items = append(out.Items, items...)
	return out, nil
}

// driftStatus compares the newest version on each side with the
// component's own ecosystem rules.
func driftStatus(d DriftItem) string {
	switch {
	case len(d.Reference) == 0:
		return "only_here"
	case len(d.Versions) == 0:
		return "only_there"
	}
	cmp := version.For(version.ForPurlType(d.Type))
	newest := func(vs []string) (string, bool) {
		best := vs[0]
		for _, v := range vs[1:] {
			c, err := cmp(v, best)
			if err != nil {
				return "", false
			}
			if c > 0 {
				best = v
			}
		}
		return best, true
	}
	here, ok1 := newest(d.Versions)
	there, ok2 := newest(d.Reference)
	if !ok1 || !ok2 {
		return "differs"
	}
	c, err := cmp(here, there)
	switch {
	case err != nil || c == 0:
		return "differs" // same newest version, different extra versions
	case c < 0:
		return "behind"
	default:
		return "ahead"
	}
}

// ReplicaPairs returns (replica, primary) asset pairs from replica_of
// relations between current assets.
func (s *Store) ReplicaPairs(ctx context.Context) ([][2]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.from_asset, r.to_asset FROM asset_relations r
		JOIN assets f ON f.id = r.from_asset AND f.merged_into IS NULL
		JOIN assets t ON t.id = r.to_asset AND t.merged_into IS NULL
		WHERE r.kind = 'replica_of' ORDER BY r.from_asset, r.to_asset`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) ([2]int64, error) {
		var p [2]int64
		err := row.Scan(&p[0], &p[1])
		return p, err
	})
}
