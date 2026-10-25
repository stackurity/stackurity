package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// JobCount is the number of jobs of one kind in one state: queued (due and
// waiting for a worker), scheduled (waiting for its time, e.g. a retry
// backoff), running, or failed (gave up within the last 24 hours).
type JobCount struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
	Count int64  `json:"count"`
}

// JobStats summarises the queue across workspaces (system scope), with the
// age in seconds of the oldest job that is due but not running.
func (s *Store) JobStats(ctx context.Context) ([]JobCount, float64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT kind,
		  CASE WHEN failed_at IS NOT NULL THEN 'failed'
		       WHEN locked_at IS NOT NULL AND locked_at >= now() - make_interval(secs => $1) THEN 'running'
		       WHEN run_at <= now() THEN 'queued'
		       ELSE 'scheduled' END AS state,
		  count(*)
		FROM jobs
		WHERE done_at IS NULL AND (failed_at IS NULL OR failed_at >= now() - interval '24 hours')
		GROUP BY 1, 2 ORDER BY 1, 2`, lockTimeout.Seconds())
	if err != nil {
		return nil, 0, err
	}
	counts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[JobCount])
	if err != nil {
		return nil, 0, err
	}
	var oldest float64
	err = s.Pool.QueryRow(ctx, `SELECT COALESCE(extract(epoch FROM now() - min(run_at)), 0)::float8 FROM jobs
		WHERE done_at IS NULL AND failed_at IS NULL AND run_at <= now()
		  AND (locked_at IS NULL OR locked_at < now() - make_interval(secs => $1))`, lockTimeout.Seconds()).Scan(&oldest)
	return counts, oldest, err
}

// CountStaleAssets counts assets that stopped reporting, across workspaces
// in system scope.
func (s *Store) CountStaleAssets(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM assets WHERE merged_into IS NULL AND collection_status = 'stale'`).Scan(&n)
	return n, err
}
