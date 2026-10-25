package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// PeriodicTask is a periodic task's schedule, lease and last outcome
// (migration 0014). Every method here needs system scope.
type PeriodicTask struct {
	Name                string         `json:"name"`
	Every               time.Duration  `json:"-"`
	EverySeconds        float64        `json:"every_seconds"`
	SeenAt              time.Time      `json:"seen_at"`
	LastStartedAt       *time.Time     `json:"last_started_at"`
	LastFinishedAt      *time.Time     `json:"last_finished_at"`
	LastSuccessAt       *time.Time     `json:"last_success_at"`
	LastError           string         `json:"last_error"`
	LastDuration        *time.Duration `json:"-"`
	ConsecutiveFailures int            `json:"consecutive_failures"`
	LockedBy            *string        `json:"locked_by"`
	LockedUntil         *time.Time     `json:"locked_until"`
	CreatedAt           time.Time      `json:"created_at"`
	// Running is true while a replica holds an unexpired lease.
	Running bool `json:"running"`
}

const periodicCols = `name, every, extract(epoch FROM every)::float8, seen_at, last_started_at, last_finished_at, last_success_at,
	last_error, last_duration, consecutive_failures, locked_by, locked_until, created_at, COALESCE(locked_until > now(), false)`

// RegisterPeriodic records that a running server has the task, creating its
// row on first use and keeping its interval current.
func (s *Store) RegisterPeriodic(ctx context.Context, name string, every time.Duration) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO periodic_tasks (name, every) VALUES ($1, $2)
		ON CONFLICT (name) DO UPDATE SET every = EXCLUDED.every, seen_at = now()`, name, every)
	return err
}

// ClaimPeriodic takes the task for owner until the lease ends, if it is due
// and no other replica holds it. A task is due once its interval has passed
// since it last started, or at once when its last run never finished (the
// replica died or shut down while running it).
func (s *Store) ClaimPeriodic(ctx context.Context, name, owner string, every, lease time.Duration) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE periodic_tasks
		SET locked_by = $2, locked_until = now() + $4::interval, last_started_at = now(), every = $3
		WHERE name = $1
		  AND (locked_until IS NULL OR locked_until <= now())
		  AND (last_started_at IS NULL OR last_started_at <= now() - $3::interval
		       OR last_finished_at IS NULL OR last_finished_at < last_started_at)`, name, owner, every, lease)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// RenewPeriodic extends owner's lease. False means the lease was lost: it
// expired and another replica claimed the task.
func (s *Store) RenewPeriodic(ctx context.Context, name, owner string, lease time.Duration) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE periodic_tasks SET locked_until = now() + $3::interval
		WHERE name = $1 AND locked_by = $2`, name, owner, lease)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// FinishPeriodic records the outcome of owner's run and releases the lease.
// It does nothing if owner no longer holds the task.
func (s *Store) FinishPeriodic(ctx context.Context, name, owner string, runErr error) error {
	msg := ""
	if runErr != nil {
		msg = truncateText(runErr.Error(), 4000)
		if msg == "" {
			msg = "failed"
		}
	}
	_, err := s.Pool.Exec(ctx, `UPDATE periodic_tasks SET
		locked_by = NULL, locked_until = NULL, last_finished_at = now(), last_duration = now() - last_started_at,
		last_success_at = CASE WHEN $3 = '' THEN now() ELSE last_success_at END,
		consecutive_failures = CASE WHEN $3 = '' THEN 0 ELSE consecutive_failures + 1 END,
		last_error = $3
		WHERE name = $1 AND locked_by = $2`, name, owner, msg)
	return err
}

// ReleasePeriodic gives up owner's lease without recording an outcome, so
// another replica runs the task again soon (used on shutdown).
func (s *Store) ReleasePeriodic(ctx context.Context, name, owner string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE periodic_tasks SET locked_by = NULL, locked_until = NULL
		WHERE name = $1 AND locked_by = $2`, name, owner)
	return err
}

// ListPeriodicTasks returns every task a server has registered.
func (s *Store) ListPeriodicTasks(ctx context.Context) ([]PeriodicTask, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+periodicCols+` FROM periodic_tasks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[PeriodicTask])
}

// SharedSetupToken returns the setup token every replica must accept: the
// first replica to start stores its candidate, the others adopt it.
func (s *Store) SharedSetupToken(ctx context.Context, candidate string) (string, error) {
	var tok string
	err := s.Pool.QueryRow(ctx, `INSERT INTO instance_state (key, value) VALUES ('setup_token', $1)
		ON CONFLICT (key) DO UPDATE SET key = EXCLUDED.key RETURNING value`, candidate).Scan(&tok)
	return tok, err
}

// ClearSetupToken forgets the setup token once the first admin exists.
func (s *Store) ClearSetupToken(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM instance_state WHERE key = 'setup_token'`)
	return err
}
