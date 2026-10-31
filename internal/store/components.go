package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type Component struct {
	ID         int64     `json:"id"`
	PurlKey    string    `json:"purl_key"`
	Type       string    `json:"type"`
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	AssetCount int64     `json:"asset_count"`
	Versions   []string  `json:"versions"`
	CreatedAt  time.Time `json:"created_at"`
}

type ComponentFilter struct {
	Type   string
	Search string
	Page
}

const componentCols = `c.id, c.purl_key, c.type, c.namespace, c.name,
	(SELECT count(DISTINCT i.asset_id) FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL),
	COALESCE((SELECT array_agg(DISTINCT i.version ORDER BY i.version) FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL), '{}'),
	c.created_at`

// ListComponents lists components currently present on at least one asset.
func (s *Store) ListComponents(ctx context.Context, f ComponentFilter) ([]Component, int64, error) {
	w := &where{}
	w.conds = append(w.conds, `EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL)`)
	if f.Type != "" {
		w.add("c.type = ?", f.Type)
	}
	if f.Search != "" {
		w.add("(c.name ILIKE ? OR c.namespace ILIKE ?)", likeEscape(f.Search))
	}
	from := ` FROM components c` + w.sql()
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+from, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+componentCols+from+
		fmt.Sprintf(` ORDER BY c.type, c.namespace, c.name LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Component])
	return out, total, err
}

func (s *Store) GetComponent(ctx context.Context, id int64) (*Component, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+componentCols+` FROM components c WHERE c.id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Component])
	return c, notFound(err)
}

type Overview struct {
	Assets         map[string]int64 `json:"assets"`       // by kind
	AssetStatus    map[string]int64 `json:"asset_status"` // ok, partial, stale
	Components     int64            `json:"components"`
	InventoryRows  int64            `json:"inventory_rows"`
	Ecosystems     map[string]int64 `json:"ecosystems"`      // components by purl type
	CoverageStatus map[string]int64 `json:"coverage_status"` // checked, failed, ...
	Conflicts      int64            `json:"identity_conflicts"`
	LastCollection *time.Time       `json:"last_collection"`
	Confidence     map[string]int64 `json:"confidence"`      // inventory rows by confidence
	RebootRequired int64            `json:"reboot_required"` // hosts running older code than installed
	// AssetCoverage counts assets by coverage state (healthy, stale_intelligence,
	// failed_collection, unsupported, partially_evaluated, awaiting_verification).
	AssetCoverage map[string]int64 `json:"asset_coverage"`
	// ComponentCoverage counts components by row coverage (evaluated,
	// stale_intelligence, not_evaluated, unsupported, awaiting); a component
	// with rows in several states counts in each.
	ComponentCoverage map[string]int64 `json:"component_coverage"`
	// OneOff counts the assets scanned once, per kind, with the dates their
	// results are from (Home: "5 repositories scanned once (as of 26 Oct)").
	OneOff []OneOffGroup `json:"one_off"`
	// NotReporting counts stale assets per kind (Home: "2 servers not
	// reporting").
	NotReporting map[string]int64 `json:"not_reporting"`
}

func (s *Store) Overview(ctx context.Context) (*Overview, error) {
	o := &Overview{}
	var err error
	group := func(sql string) map[string]int64 {
		if err != nil {
			return nil
		}
		m := map[string]int64{}
		var rows pgx.Rows
		rows, err = s.Pool.Query(ctx, sql)
		if err != nil {
			return nil
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int64
			if err = rows.Scan(&k, &v); err != nil {
				return nil
			}
			m[k] = v
		}
		err = rows.Err()
		return m
	}
	o.Assets = group(`SELECT kind, count(*) FROM assets WHERE merged_into IS NULL GROUP BY kind`)
	o.AssetStatus = group(`SELECT collection_status, count(*) FROM assets WHERE merged_into IS NULL GROUP BY collection_status`)
	o.NotReporting = group(`SELECT kind, count(*) FROM assets WHERE merged_into IS NULL AND collection_status = 'stale' GROUP BY kind`)
	o.Ecosystems = group(`SELECT c.type, count(DISTINCT c.id) FROM components c JOIN inventory i ON i.component_id = c.id
		WHERE i.removed_at IS NULL GROUP BY c.type`)
	o.CoverageStatus = group(`SELECT status, count(*) FROM coverage GROUP BY status`)
	o.Confidence = group(`SELECT confidence, count(*) FROM inventory WHERE removed_at IS NULL GROUP BY confidence`)
	o.ComponentCoverage = group(`SELECT cov, count(DISTINCT component_id) FROM (SELECT i.component_id, ` + rowCoverageSQL + ` AS cov
		FROM inventory i JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL WHERE i.removed_at IS NULL) x GROUP BY cov`)
	if err != nil {
		return nil, err
	}
	if o.AssetCoverage, err = s.AssetCoverageCounts(ctx); err != nil {
		return nil, err
	}
	if o.OneOff, err = s.OneOffAssets(ctx); err != nil {
		return nil, err
	}
	if o.OneOff == nil {
		o.OneOff = []OneOffGroup{}
	}
	err = s.Pool.QueryRow(ctx, `SELECT
		(SELECT count(DISTINCT component_id) FROM inventory WHERE removed_at IS NULL),
		(SELECT count(*) FROM inventory WHERE removed_at IS NULL),
		(SELECT count(*) FROM identity_conflicts WHERE resolved_at IS NULL),
		(SELECT max(received_at) FROM collections),
		(SELECT count(*) FROM assets WHERE merged_into IS NULL AND attributes->>'reboot_required' = 'true')`).Scan(
		&o.Components, &o.InventoryRows, &o.Conflicts, &o.LastCollection, &o.RebootRequired)
	return o, err
}
