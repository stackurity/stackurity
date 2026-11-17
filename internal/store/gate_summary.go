package store

import (
	"context"
	"sort"
)

// GateAssetViolations counts the open violations of one policy on one
// asset, with what a notification route filters assets by (environment
// and owner team). The weekly summary's "Policy gates" section is built
// from these (notify, gate_summary.go).
type GateAssetViolations struct {
	PolicyID    int64
	PolicyName  string
	Mode        string
	AssetID     int64
	AssetName   string
	Environment string
	OwnerTeamID *int64
	Count       int
}

// GateViolationsByAsset groups the current violations (GateViolations)
// by policy and asset, ordered by policy name and asset name.
func (s *Store) GateViolationsByAsset(ctx context.Context) ([]GateAssetViolations, error) {
	vs, err := s.GateViolations(ctx, GateViolationFilter{})
	if err != nil || len(vs) == 0 {
		return []GateAssetViolations{}, err
	}
	type key struct{ policy, asset int64 }
	at := map[key]int{}
	var out []GateAssetViolations
	var ids []int64
	seen := map[int64]bool{}
	for _, v := range vs {
		k := key{v.PolicyID, v.AssetID}
		if i, ok := at[k]; ok {
			out[i].Count++
			continue
		}
		at[k] = len(out)
		out = append(out, GateAssetViolations{PolicyID: v.PolicyID, PolicyName: v.PolicyName, Mode: v.Mode,
			AssetID: v.AssetID, AssetName: v.AssetName, Count: 1})
		if !seen[v.AssetID] {
			seen[v.AssetID] = true
			ids = append(ids, v.AssetID)
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT id, COALESCE(environment, ''), owner_team_id FROM assets WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type where struct {
		env  string
		team *int64
	}
	info := map[int64]where{}
	for rows.Next() {
		var (
			id int64
			w  where
		)
		if err := rows.Scan(&id, &w.env, &w.team); err != nil {
			return nil, err
		}
		info[id] = w
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		w := info[out[i].AssetID]
		out[i].Environment, out[i].OwnerTeamID = w.env, w.team
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PolicyName != out[j].PolicyName {
			return out[i].PolicyName < out[j].PolicyName
		}
		if out[i].PolicyID != out[j].PolicyID {
			return out[i].PolicyID < out[j].PolicyID
		}
		return out[i].AssetName < out[j].AssetName
	})
	return out, nil
}
