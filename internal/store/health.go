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
		GROUP BY 1, 2 ORDER BY 1, 2`, s.lockTimeout().Seconds())
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
		  AND (locked_at IS NULL OR locked_at < now() - make_interval(secs => $1))`, s.lockTimeout().Seconds()).Scan(&oldest)
	return counts, oldest, err
}

// CountStaleAssets counts assets that stopped reporting, across workspaces
// in system scope.
func (s *Store) CountStaleAssets(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM assets WHERE merged_into IS NULL AND collection_status = 'stale'`).Scan(&n)
	return n, err
}

// DeliveryCount is the number of notification deliveries to one kind of
// channel in one state: pending (waiting for its first attempt, its time or
// quiet hours to end), retrying (a send failed and another attempt is
// scheduled), held (kept for the next digest by a rate limit) or failed (ran
// out of attempts within the last 24 hours). Deliveries to disabled
// channels are left out unless they failed.
type DeliveryCount struct {
	Kind  string `json:"kind"`
	State string `json:"state"`
	Count int64  `json:"count"`
}

// ChannelCount is the number of enabled channels of one kind.
type ChannelCount struct {
	Kind  string `json:"kind"`
	Count int64  `json:"count"`
}

// DeliveryStats summarises notification deliveries across workspaces
// (system scope), with the age in seconds of the oldest delivery that is due
// but has not been claimed for sending, and the enabled channels whose last
// send failed.
func (s *Store) DeliveryStats(ctx context.Context) ([]DeliveryCount, float64, []ChannelCount, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.kind,
		  CASE WHEN d.status = 'failed' THEN 'failed'
		       WHEN d.status = 'held' THEN 'held'
		       WHEN d.attempts > 0 AND d.last_error <> '' THEN 'retrying'
		       ELSE 'pending' END AS state,
		  count(*)
		FROM deliveries d JOIN channels c ON c.id = d.channel_id
		WHERE (d.status IN ('pending', 'held') AND c.enabled)
		   OR (d.status = 'failed' AND d.failed_at >= now() - interval '24 hours')
		GROUP BY 1, 2 ORDER BY 1, 2`)
	if err != nil {
		return nil, 0, nil, err
	}
	counts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[DeliveryCount])
	if err != nil {
		return nil, 0, nil, err
	}
	var oldest float64
	if err := s.Pool.QueryRow(ctx, `SELECT COALESCE(extract(epoch FROM now() - min(d.next_attempt)), 0)::float8
		FROM deliveries d JOIN channels c ON c.id = d.channel_id
		WHERE d.status = 'pending' AND c.enabled AND d.next_attempt <= now()`).Scan(&oldest); err != nil {
		return nil, 0, nil, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT kind, count(*) FROM channels WHERE enabled AND last_error <> '' GROUP BY 1 ORDER BY 1`)
	if err != nil {
		return nil, 0, nil, err
	}
	failing, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ChannelCount])
	return counts, oldest, failing, err
}
