package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// FindingAssetGroup is one asset in the findings list grouped by asset: how
// many findings match the filters, and the first of them in priority order.
type FindingAssetGroup struct {
	AssetID   int64     `json:"asset_id"`
	AssetName string    `json:"asset_name"`
	AssetKind string    `json:"asset_kind"`
	Total     int64     `json:"total"`
	Findings  []Finding `json:"findings"`
}

// MaxFindingsPerAsset caps the findings shown under each asset.
const MaxFindingsPerAsset = 50

// ListFindingsByAsset pages the findings matching f by asset, by asset name:
// each group carries its count and its first perAsset findings in the
// order of ListFindings. It returns the groups, the number of assets and
// the number of findings that match. f.Page pages the assets.
func (s *Store) ListFindingsByAsset(ctx context.Context, f FindingFilter, perAsset int) ([]FindingAssetGroup, int64, int64, error) {
	if perAsset <= 0 || perAsset > MaxFindingsPerAsset {
		perAsset = 5
	}
	fq, err := s.findingConditions(ctx, f)
	if err != nil {
		return nil, 0, 0, err
	}
	var assets, findings int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(DISTINCT f.asset_id), count(*)`+fq.countFrom+fq.countWhere, fq.args...).Scan(&assets, &findings); err != nil {
		return nil, 0, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT f.asset_id, a.name, a.kind, count(*)`+fq.countFrom+fq.countWhere+fmt.Sprintf(`
		GROUP BY f.asset_id, a.name, a.kind ORDER BY a.name, f.asset_id LIMIT %d OFFSET %d`, p.Limit, p.Offset), fq.args...)
	if err != nil {
		return nil, 0, 0, err
	}
	groups, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (FindingAssetGroup, error) {
		var g FindingAssetGroup
		err := r.Scan(&g.AssetID, &g.AssetName, &g.AssetKind, &g.Total)
		return g, err
	})
	if err != nil || len(groups) == 0 {
		return groups, assets, findings, err
	}
	ids := make([]int64, len(groups))
	at := make(map[int64]int, len(groups))
	for i, g := range groups {
		ids[i] = g.AssetID
		at[g.AssetID] = i
	}
	args := append(append([]any{}, fq.args...), ids)
	// The first perAsset of each asset's findings, in the list's order: a
	// top-N per asset, reading only what the conditions read (the count's
	// FROM and WHERE), not the display joins of every finding of an asset
	// with thousands.
	top := `SELECT f.id` + fq.countFrom + andWhere(fq.countWhere, "f.asset_id = g.asset_id") +
		fmt.Sprintf(` ORDER BY `+findingOrder+` LIMIT %d`, perAsset)
	rows, err = s.Pool.Query(ctx, fmt.Sprintf(`SELECT x.id FROM unnest($%d::bigint[]) AS g(asset_id) CROSS JOIN LATERAL (`+top+`) x`, len(args)), args...)
	if err != nil {
		return nil, 0, 0, err
	}
	shown, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, 0, 0, err
	}
	// Then those findings by id: with the ids in a subquery the planner
	// joined the display tables for every finding first (10 s on 3,000).
	rows, err = s.Pool.Query(ctx, `SELECT `+findingCols+findingFrom+` WHERE f.id = ANY($1)
		ORDER BY f.asset_id, `+findingOrder, shown)
	if err != nil {
		return nil, 0, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Finding])
	if err != nil {
		return nil, 0, 0, err
	}
	ptrs := make([]*Finding, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	if err := s.fillFindingVEX(ctx, ptrs); err != nil {
		return nil, 0, 0, err
	}
	for _, x := range out {
		g := &groups[at[x.AssetID]]
		g.Findings = append(g.Findings, x)
	}
	for i := range groups {
		if groups[i].Findings == nil {
			groups[i].Findings = []Finding{}
		}
	}
	return groups, assets, findings, nil
}
