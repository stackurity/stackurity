package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// VerifyReport answers "what changed since T": findings resolved since then,
// findings that existed then and are still open, and when each asset last
// reported, so "fixed" can be told apart from "not scanned again yet".
type VerifyReport struct {
	Since     time.Time     `json:"since"`
	Resolved  VerifyList    `json:"resolved"`
	StillOpen VerifyList    `json:"still_open"`
	NewSince  int64         `json:"opened_since"` // findings first seen after T
	Assets    []VerifyAsset `json:"assets"`
}

type VerifyList struct {
	Total int64           `json:"total"`
	Items []VerifyFinding `json:"items"`
}

type VerifyFinding struct {
	FindingID    int64      `json:"finding_id"`
	Kind         string     `json:"kind"`
	Key          string     `json:"key"`
	Priority     string     `json:"priority"`
	Severity     string     `json:"severity"`
	AssetID      int64      `json:"asset_id"`
	AssetName    string     `json:"asset_name"`
	Component    string     `json:"component"`
	Version      string     `json:"version"`
	FixedVersion string     `json:"fixed_version"`
	FirstSeen    time.Time  `json:"first_seen"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	Resolution   string     `json:"resolution,omitempty"`
	Cause        string     `json:"cause,omitempty"` // upgraded, remediation, removed, reevaluated, other
	// Rescanned: the asset sent a complete inventory after T, so an open
	// finding was checked against fresh evidence.
	Rescanned bool `json:"asset_rescanned_since"`
}

type VerifyAsset struct {
	AssetID          int64      `json:"asset_id"`
	Name             string     `json:"name"`
	CollectionStatus string     `json:"collection_status"`
	LastCollection   *time.Time `json:"last_collection_at"`
	LastComplete     *time.Time `json:"last_complete_collection_at"`
	Rescanned        bool       `json:"rescanned_since"`
}

// resolutionCause classifies a resolution written by the matcher.
func resolutionCause(col string) string {
	return `CASE WHEN ` + col + ` LIKE 'fixed by remediation plan%' THEN 'remediation'
		WHEN ` + col + ` LIKE 'upgraded to %' THEN 'upgraded'
		WHEN ` + col + ` = 'component no longer installed' THEN 'removed'
		WHEN ` + col + ` LIKE 'no longer affected%' THEN 'reevaluated' ELSE 'other' END`
}

// VerifySince builds the report for findings of one asset (or all, assetID
// 0), with at most limit items per list.
func (s *Store) VerifySince(ctx context.Context, since time.Time, assetID int64, limit int) (*VerifyReport, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	r := &VerifyReport{Since: since, Assets: []VerifyAsset{}}
	scope := ""
	args := []any{since}
	if assetID > 0 {
		scope = " AND f.asset_id = $2"
		args = append(args, assetID)
	}
	const from = ` FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		JOIN components c ON c.id = f.component_id JOIN inventory i ON i.id = f.inventory_id`
	const cols = `f.id, f.kind, f.key, f.priority, f.severity, f.asset_id, a.name,
		CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END, i.version, f.fixed_version, f.first_seen,
		f.resolved_at, f.resolution, `
	rescanned := `EXISTS (SELECT 1 FROM collections co WHERE co.asset_id = f.asset_id AND co.complete AND co.observed_at >= $1)`
	resolved := ` WHERE f.status = 'resolved' AND f.resolved_at >= $1` + scope
	open := ` WHERE f.status = 'open' AND f.first_seen < $1` + scope
	if err := s.Pool.QueryRow(ctx, `SELECT (SELECT count(*)`+from+resolved+`), (SELECT count(*)`+from+open+`),
		(SELECT count(*)`+from+` WHERE f.status = 'open' AND f.first_seen >= $1`+scope+`)`, args...).
		Scan(&r.Resolved.Total, &r.StillOpen.Total, &r.NewSince); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+cols+resolutionCause("f.resolution")+`, `+rescanned+from+resolved+
		fmt.Sprintf(` ORDER BY f.resolved_at DESC, f.id LIMIT %d`, limit), args...)
	if err != nil {
		return nil, err
	}
	if r.Resolved.Items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[VerifyFinding]); err != nil {
		return nil, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT `+cols+`'', `+rescanned+from+open+
		fmt.Sprintf(` ORDER BY f.priority, f.first_seen, f.id LIMIT %d`, limit), args...)
	if err != nil {
		return nil, err
	}
	if r.StillOpen.Items, err = pgx.CollectRows(rows, pgx.RowToStructByPos[VerifyFinding]); err != nil {
		return nil, err
	}
	if r.Resolved.Items == nil {
		r.Resolved.Items = []VerifyFinding{}
	}
	if r.StillOpen.Items == nil {
		r.StillOpen.Items = []VerifyFinding{}
	}

	// Collection times for the assets in the lists (or the one asked for).
	ids := map[int64]bool{}
	var list []int64
	if assetID > 0 {
		ids[assetID] = true
		list = append(list, assetID)
	}
	for _, l := range [][]VerifyFinding{r.Resolved.Items, r.StillOpen.Items} {
		for _, f := range l {
			if !ids[f.AssetID] {
				ids[f.AssetID] = true
				list = append(list, f.AssetID)
			}
		}
	}
	if len(list) == 0 {
		return r, nil
	}
	rows, err = s.Pool.Query(ctx, `SELECT a.id, a.name, a.collection_status,
		(SELECT max(observed_at) FROM collections co WHERE co.asset_id = a.id),
		(SELECT max(observed_at) FROM collections co WHERE co.asset_id = a.id AND co.complete), false
		FROM assets a WHERE a.id = ANY($1) AND a.merged_into IS NULL ORDER BY a.name, a.id`, list)
	if err != nil {
		return nil, err
	}
	if r.Assets, err = pgx.CollectRows(rows, pgx.RowToStructByPos[VerifyAsset]); err != nil {
		return nil, err
	}
	for i := range r.Assets {
		a := &r.Assets[i]
		a.Rescanned = a.LastComplete != nil && !a.LastComplete.Before(since)
	}
	return r, nil
}

// AssetCollectionTimes returns when an asset last reported, and last sent a
// complete inventory.
func (s *Store) AssetCollectionTimes(ctx context.Context, assetID int64) (last, complete *time.Time, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT max(observed_at), max(observed_at) FILTER (WHERE complete) FROM collections WHERE asset_id = $1`,
		assetID).Scan(&last, &complete)
	return last, complete, err
}
