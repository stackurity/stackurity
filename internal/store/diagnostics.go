package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// The queries below are for `stackurity doctor` and `stackurity
// support-bundle` (internal/diag). They run in system scope and return
// counts across every workspace, never names.

// ReportingCount summarises the assets one source reports (agent, scan,
// integration, manual, or "" for assets from before migration 0064 that
// never reported again).
type ReportingCount struct {
	Source string `json:"source"`
	Assets int64  `json:"assets"`
	// Stale counts those that stopped reporting (collection status stale).
	Stale int64 `json:"stale"`
	// Newest is the latest report from any of them.
	Newest *time.Time `json:"newest"`
}

// ReportingCounts counts current assets by how they report. Selftest
// assets are left out.
func (s *Store) ReportingCounts(ctx context.Context) ([]ReportingCount, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT a.report_source, count(*), count(*) FILTER (WHERE a.collection_status = 'stale'),
		max(a.last_seen) FROM assets a WHERE a.merged_into IS NULL AND NOT `+selftestAsset+` GROUP BY 1 ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ReportingCount])
}

// Count is a number of rows sharing one value.
type Count struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

// AssetKindCounts counts current assets by kind, in every workspace.
func (s *Store) AssetKindCounts(ctx context.Context) ([]Count, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT kind, count(*) FROM assets WHERE merged_into IS NULL GROUP BY 1 ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Count])
}

// FindingStatusCounts counts findings by status, in every workspace.
func (s *Store) FindingStatusCounts(ctx context.Context) ([]Count, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT status, count(*) FROM findings GROUP BY 1 ORDER BY 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Count])
}

// InstanceCounts are the sizes of an installation.
type InstanceCounts struct {
	Workspaces int64 `json:"workspaces"`
	Users      int64 `json:"users"`
	Components int64 `json:"components"`
	Advisories int64 `json:"advisories"`
}

func (s *Store) InstanceCounts(ctx context.Context) (InstanceCounts, error) {
	var c InstanceCounts
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT (SELECT count(*) FROM workspaces), (SELECT count(*) FROM users),
		(SELECT count(*) FROM components), (SELECT count(*) FROM advisories)`).Scan(&c.Workspaces, &c.Users, &c.Components, &c.Advisories)
	return c, err
}

// Setting is one stored setting of a workspace.
type Setting struct {
	WorkspaceID int64           `json:"workspace_id"`
	Key         string          `json:"key"`
	Value       json.RawMessage `json:"value"`
}

// AllSettings returns every workspace's settings.
func (s *Store) AllSettings(ctx context.Context) ([]Setting, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT workspace_id, key, value FROM settings ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Setting])
}
