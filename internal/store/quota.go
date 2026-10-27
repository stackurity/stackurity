package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Monitored-asset limits (docs/asset-limits.md).
//
// A monitored asset is an asset of the organisation that has not been
// merged into another and whose kind is anything but a Kubernetes
// workload: host, application, repository, image, cluster, managed service
// or a standalone SBOM. Workloads are described by their cluster and the
// images they run, so they are not counted; with a limit set, a new
// workload is added only when its cluster is already monitored. Stale
// assets count until they are deleted.
//
// At the limit a new asset is refused wherever it would be created (every
// path goes through Ingest), enrollment codes cannot be redeemed, and new
// enrollment codes and integrations cannot be made. Assets that exist keep
// being collected, evaluated and alerted on: a limit never stops
// monitoring.

// CountsAsMonitored reports whether assets of kind count towards the limit.
func CountsAsMonitored(k model.AssetKind) bool { return k != model.AssetWorkload }

// monitoredWhere selects the monitored assets of workspace $1.
const monitoredWhere = `workspace_id = $1 AND merged_into IS NULL AND kind <> 'workload'`

// ErrAssetLimit matches an *AssetLimitError with errors.Is.
var ErrAssetLimit = errors.New("monitored-asset limit reached")

// AssetLimitError means a new asset was refused because the organisation
// monitors as many assets as its limit allows.
type AssetLimitError struct {
	Limit     int64
	Monitored int64
	// Kind and Name describe the refused asset; empty for an enrollment or
	// an integration refused before it could create one.
	Kind, Name string
	// NoCluster: a workload whose cluster is not monitored.
	NoCluster bool
}

func (e *AssetLimitError) Error() string {
	what := "a new asset"
	if e.Kind != "" {
		what = fmt.Sprintf("the new %s %q", e.Kind, e.Name)
	}
	if e.NoCluster {
		return fmt.Sprintf("%s was not added: a workload is added with its cluster, and its cluster is not monitored "+
			"(this organisation monitors %d of %d assets allowed)", what, e.Monitored, e.Limit)
	}
	return fmt.Sprintf("this organisation monitors %d of %d assets allowed, so %s was not added. "+
		"Assets already monitored keep being checked. Delete assets you no longer run, or ask an admin to raise the limit",
		e.Monitored, e.Limit, what)
}

func (e *AssetLimitError) Is(target error) bool { return target == ErrAssetLimit }

// assetLimitLock serialises the check-and-create of new assets within one
// workspace (pg_advisory_xact_lock(key, workspace)), so two collectors
// racing cannot both take the last place.
const assetLimitLock = 726_354_139

// assetLimit reads a workspace's limit; nil means none.
func assetLimit(ctx context.Context, db q, ws int64) (*int64, error) {
	var limit *int64
	err := db.QueryRow(ctx, `SELECT asset_limit FROM workspaces WHERE id = $1`, ws).Scan(&limit)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return limit, err
}

// checkNewAsset is called in Ingest's transaction before an asset is
// created. It returns an *AssetLimitError when the workspace may not have
// another monitored asset; the lock it takes is held until the transaction
// ends, so the count stays true until the asset is inserted.
func checkNewAsset(ctx context.Context, tx pgx.Tx, b *model.ObservationBatch) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil // system work (demo data) has no limit
	}
	limit, err := assetLimit(ctx, tx, ws)
	if err != nil || limit == nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, $2::int)`, assetLimitLock, ws); err != nil {
		return err
	}
	// Counted in system scope with an explicit workspace, so a caller
	// narrowed to some projects still counts every asset.
	var n int64
	err = asSystem(ctx, tx, func() error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM assets WHERE `+monitoredWhere, ws).Scan(&n)
	})
	if err != nil {
		return err
	}
	le := &AssetLimitError{Limit: *limit, Monitored: n, Kind: string(b.Asset.Kind), Name: b.Asset.Name}
	if !CountsAsMonitored(b.Asset.Kind) {
		for _, rel := range b.Relations {
			if rel.Kind != "runs_on" {
				continue
			}
			for _, id := range rel.To {
				var found bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id
					WHERE i.scheme = $1 AND i.value = $2 AND a.kind = 'cluster')`, id.Scheme, id.Value).Scan(&found); err != nil {
					return err
				}
				if found {
					return nil
				}
			}
		}
		le.NoCluster = true
		return le
	}
	if n >= *limit {
		return le
	}
	return nil
}

// recordRefused remembers a refused asset for the Usage page. It keeps the
// most recent 200 per workspace.
func (s *Store) recordRefused(ctx context.Context, b *model.ObservationBatch) error {
	name := b.Asset.Name
	if len(name) > 500 {
		name = name[:500]
	}
	src := b.Collector.ID
	if len(src) > 200 {
		src = src[:200]
	}
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO refused_assets AS r (kind, name, source) VALUES ($1, $2, $3)
			ON CONFLICT (workspace_id, kind, name) DO UPDATE SET attempts = r.attempts + 1, last_refused_at = now(), source = EXCLUDED.source`,
			string(b.Asset.Kind), name, src); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM refused_assets WHERE id IN (
			SELECT id FROM refused_assets ORDER BY last_refused_at DESC OFFSET 200)`)
		return err
	})
}

// AssetLimitReached returns an *AssetLimitError when the current workspace
// is at its limit, else nil.
func (s *Store) AssetLimitReached(ctx context.Context) error {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil
	}
	return s.workspaceAtLimit(ctx, s.Pool, ws)
}

func (s *Store) workspaceAtLimit(ctx context.Context, db q, ws int64) error {
	sys := tenant.System(ctx)
	limit, err := assetLimit(sys, db, ws)
	if err != nil || limit == nil {
		return err
	}
	var n int64
	if err := db.QueryRow(sys, `SELECT count(*) FROM assets WHERE `+monitoredWhere, ws).Scan(&n); err != nil {
		return err
	}
	if n >= *limit {
		return &AssetLimitError{Limit: *limit, Monitored: n}
	}
	return nil
}

// RefusedAsset is a new asset refused at the limit.
type RefusedAsset struct {
	Kind           string    `json:"kind"`
	Name           string    `json:"name"`
	Source         string    `json:"source"`
	Attempts       int       `json:"attempts"`
	FirstRefusedAt time.Time `json:"first_refused_at"`
	LastRefusedAt  time.Time `json:"last_refused_at"`
}

// AssetUsage is a workspace's monitored assets against its limit.
type AssetUsage struct {
	Monitored int64 `json:"monitored"`
	// Limit is nil when the organisation has no limit.
	Limit   *int64 `json:"limit"`
	AtLimit bool   `json:"at_limit"`
	// ByKind counts monitored assets per kind.
	ByKind map[string]int64 `json:"by_kind"`
	// Stale monitored assets have not reported recently; they count until
	// deleted.
	Stale int64 `json:"stale"`
	// Workloads are Kubernetes workloads, which are not counted.
	Workloads int64 `json:"workloads"`
	// Refused lists the most recent new assets refused at the limit.
	Refused []RefusedAsset `json:"refused"`
	// RefusedRecently counts refused assets last tried in the past 7 days.
	RefusedRecently int64 `json:"refused_recently"`
}

// AssetUsage reports the current workspace's monitored assets and limit.
func (s *Store) AssetUsage(ctx context.Context) (*AssetUsage, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return nil, ErrNotFound
	}
	return s.WorkspaceAssetUsage(ctx, ws)
}

// WorkspaceAssetUsage reports workspace ws's usage. The counts are read in
// system scope filtered to ws, so a caller narrowed to some projects still
// sees the organisation's total.
func (s *Store) WorkspaceAssetUsage(ctx context.Context, ws int64) (*AssetUsage, error) {
	sys := tenant.System(ctx)
	u := &AssetUsage{ByKind: map[string]int64{}, Refused: []RefusedAsset{}}
	var err error
	if u.Limit, err = assetLimit(sys, s.Pool, ws); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(sys, `SELECT kind, count(*), count(*) FILTER (WHERE collection_status = 'stale')
		FROM assets WHERE workspace_id = $1 AND merged_into IS NULL GROUP BY kind`, ws)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var kind string
		var n, stale int64
		if err := rows.Scan(&kind, &n, &stale); err != nil {
			rows.Close()
			return nil, err
		}
		if !CountsAsMonitored(model.AssetKind(kind)) {
			u.Workloads += n
			continue
		}
		u.ByKind[kind] = n
		u.Monitored += n
		u.Stale += stale
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	u.AtLimit = u.Limit != nil && u.Monitored >= *u.Limit
	rows, err = s.Pool.Query(sys, `SELECT kind, name, source, attempts, first_refused_at, last_refused_at
		FROM refused_assets WHERE workspace_id = $1 ORDER BY last_refused_at DESC LIMIT 50`, ws)
	if err != nil {
		return nil, err
	}
	refused, err := pgx.CollectRows(rows, pgx.RowToStructByPos[RefusedAsset])
	if err != nil {
		return nil, err
	}
	if refused != nil {
		u.Refused = refused
	}
	err = s.Pool.QueryRow(sys, `SELECT count(*) FROM refused_assets WHERE workspace_id = $1 AND last_refused_at > now() - interval '7 days'`,
		ws).Scan(&u.RefusedRecently)
	return u, err
}

// SetAssetLimit sets workspace ws's monitored-asset limit; nil removes it.
// For instance administration and a hosted edition's billing.
func (s *Store) SetAssetLimit(ctx context.Context, ws int64, limit *int64) error {
	if limit != nil && (*limit < 0 || *limit > 1_000_000_000) {
		return fmt.Errorf("asset limit must be between 0 and 1000000000: %w", ErrInvalid)
	}
	tag, err := s.Pool.Exec(tenant.System(ctx), `UPDATE workspaces SET asset_limit = $2 WHERE id = $1`, ws, limit)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// IngestAll ingests a plugin's batches in order. A batch refused at the
// monitored-asset limit is skipped and named in refused; the others,
// including updates to assets already monitored, are stored. results has
// one entry per batch, nil where it was refused. Any other error stops.
func (s *Store) IngestAll(ctx context.Context, batches []*model.ObservationBatch, tokenID int64) (results []*IngestResult, refused []string, err error) {
	results = make([]*IngestResult, len(batches))
	for i, b := range batches {
		r, err := s.Ingest(ctx, b, tokenID)
		if errors.Is(err, ErrAssetLimit) {
			refused = append(refused, b.Asset.Name)
			continue
		}
		if err != nil {
			return results, refused, err
		}
		results[i] = r
	}
	return results, refused, nil
}
