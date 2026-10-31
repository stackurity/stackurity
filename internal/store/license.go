package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// LicenseKey returns the stored licence key, or "" when none was uploaded.
func (s *Store) LicenseKey(ctx context.Context) (string, error) {
	var k string
	err := s.Pool.QueryRow(ctx, `SELECT key FROM license_key WHERE id = 1`).Scan(&k)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return k, err
}

func (s *Store) SaveLicenseKey(ctx context.Context, key string, by int64) error {
	var who *int64
	if by > 0 {
		who = &by
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO license_key (id, key, uploaded_by) VALUES (1, $1, $2)
		ON CONFLICT (id) DO UPDATE SET key = EXCLUDED.key, uploaded_by = EXCLUDED.uploaded_by, uploaded_at = now()`, key, who)
	return err
}

func (s *Store) DeleteLicenseKey(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM license_key`)
	return err
}

// WorkspacePlan is the plan of the workspace ctx is scoped to: "inherit",
// "community", "pro" or "enterprise". System scope inherits.
func (s *Store) WorkspacePlan(ctx context.Context) (string, error) {
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		return "inherit", nil
	}
	var p string
	err := s.Pool.QueryRow(ctx, `SELECT plan FROM workspaces WHERE id = $1`, ws).Scan(&p)
	return p, notFound(err)
}

// CountActiveAssets counts current assets across all workspaces, for the
// licence's asset limit.
func (s *Store) CountActiveAssets(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(tenant.System(ctx), `SELECT count(*) FROM assets WHERE merged_into IS NULL
		AND last_seen > now() - interval '30 days'`).Scan(&n)
	return n, err
}

// LicenseRequirement is from when this installation needs a key, whether
// it got the grace period of an upgrade, and how long servers have been
// seen running since (migration 0072). Without the row, a key is needed now.
func (s *Store) LicenseRequirement(ctx context.Context) (from time.Time, upgraded bool, observed time.Duration, err error) {
	var secs int64
	err = s.Pool.QueryRow(tenant.System(ctx), `SELECT required_from, upgraded, observed_seconds FROM license_requirement WHERE id = 1`).
		Scan(&from, &upgraded, &secs)
	if err == pgx.ErrNoRows {
		return time.Time{}, false, 0, nil
	}
	return from, upgraded, time.Duration(secs) * time.Second, err
}

// TickLicenseRequirement adds the running time since the last tick (by the
// database's clock, at most maxStep, never negative) and returns the total.
func (s *Store) TickLicenseRequirement(ctx context.Context, maxStep time.Duration) (time.Duration, error) {
	var secs int64
	err := s.Pool.QueryRow(tenant.System(ctx), `UPDATE license_requirement
		SET observed_seconds = observed_seconds + LEAST(GREATEST(extract(epoch FROM now() - last_tick), 0), $1)::bigint,
		    last_tick = now()
		WHERE id = 1 RETURNING observed_seconds`, int64(maxStep/time.Second)).Scan(&secs)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	return time.Duration(secs) * time.Second, err
}
