package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

type Job struct {
	ID          int64           `json:"id"`
	Kind        string          `json:"kind"`
	Payload     json.RawMessage `json:"payload"`
	Attempts    int             `json:"attempts"`
	MaxAttempts int             `json:"max_attempts"`
	RunAt       time.Time       `json:"run_at"`
	LastError   string          `json:"last_error"`
	DoneAt      *time.Time      `json:"done_at"`
	FailedAt    *time.Time      `json:"failed_at"`
	CreatedAt   time.Time       `json:"created_at"`
	// WorkspaceID is the workspace the job runs in; nil for platform jobs.
	WorkspaceID *int64 `json:"workspace_id"`
}

const jobCols = `id, kind, payload, attempts, max_attempts, run_at, last_error, done_at, failed_at, created_at, workspace_id`

// Enqueue adds a job that runs in the context's workspace, or as a platform
// job in system scope. With a dedupe key, an identical pending job in the
// same workspace makes this a no-op (returns 0).
func (s *Store) Enqueue(ctx context.Context, kind string, payload any, dedupe string, runAt time.Time) (int64, error) {
	p, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	var key *string
	if dedupe != "" {
		key = &dedupe
	}
	if runAt.IsZero() {
		runAt = time.Now()
	}
	var id int64
	err = s.Pool.QueryRow(ctx, `INSERT INTO jobs (kind, payload, dedupe_key, run_at) VALUES ($1,$2,$3,$4)
		ON CONFLICT (COALESCE(workspace_id, 0), dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL DO NOTHING
		RETURNING id`, kind, p, key, runAt).Scan(&id)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// DefaultJobLockTimeout bounds how long a crashed worker can hold a job.
// Running jobs renew their lock well within it (see worker.JobRenew).
const DefaultJobLockTimeout = 30 * time.Minute

func (s *Store) lockTimeout() time.Duration {
	if s.JobLockTimeout > 0 {
		return s.JobLockTimeout
	}
	return DefaultJobLockTimeout
}

// TouchJob renews worker's lock on a running job, so a job that runs longer
// than the lock timeout is not claimed a second time. False means worker no
// longer holds it.
func (s *Store) TouchJob(ctx context.Context, id int64, worker string) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE jobs SET locked_at = now()
		WHERE id = $1 AND locked_by = $2 AND done_at IS NULL AND failed_at IS NULL`, id, worker)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// Claim locks the next runnable job for worker, or returns nil.
func (s *Store) Claim(ctx context.Context, worker string) (*Job, error) {
	rows, err := s.Pool.Query(ctx, `UPDATE jobs SET locked_by = $1, locked_at = now(), attempts = attempts + 1
		WHERE id = (
		  SELECT id FROM jobs
		  WHERE done_at IS NULL AND failed_at IS NULL AND run_at <= now()
		    AND (locked_at IS NULL OR locked_at < now() - make_interval(secs => $2))
		  ORDER BY run_at, id
		  FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING `+jobCols,
		worker, s.lockTimeout().Seconds())
	if err != nil {
		return nil, err
	}
	j, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Job])
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return j, err
}

// CompleteJob marks a job done, or schedules it again at once when a request
// arrived while it was running (see requeue in migration 0006).
func (s *Store) CompleteJob(ctx context.Context, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE jobs SET
		done_at = CASE WHEN requeue THEN NULL ELSE now() END,
		run_at = CASE WHEN requeue THEN now() ELSE run_at END,
		attempts = CASE WHEN requeue THEN 0 ELSE attempts END,
		requeue = false, locked_by = NULL, locked_at = NULL
		WHERE id = $1`, id)
	return err
}

// FailJob records an error and retries with exponential backoff until
// max_attempts, after which the job is marked failed.
func (s *Store) FailJob(ctx context.Context, j *Job, jobErr error) error {
	msg := jobErr.Error()
	if len(msg) > 4000 {
		msg = msg[:4000]
	}
	if j.Attempts >= j.MaxAttempts {
		// A requeued job has new work waiting, so it gets a fresh set of attempts.
		_, err := s.Pool.Exec(ctx, `UPDATE jobs SET
			failed_at = CASE WHEN requeue THEN NULL ELSE now() END,
			attempts = CASE WHEN requeue THEN 0 ELSE attempts END,
			run_at = CASE WHEN requeue THEN now() + interval '30 seconds' ELSE run_at END,
			requeue = false, last_error = $2, locked_by = NULL, locked_at = NULL
			WHERE id = $1`, j.ID, msg)
		return err
	}
	backoff := time.Duration(1<<min(j.Attempts, 10)) * 30 * time.Second
	_, err := s.Pool.Exec(ctx, `UPDATE jobs SET run_at = now() + make_interval(secs => $3), last_error = $2,
		locked_by = NULL, locked_at = NULL WHERE id = $1`, j.ID, msg, backoff.Seconds())
	return err
}

func (s *Store) ListJobs(ctx context.Context, state string, limit int) ([]Job, error) {
	cond := ""
	switch state {
	case "pending":
		cond = "WHERE done_at IS NULL AND failed_at IS NULL"
	case "failed":
		cond = "WHERE failed_at IS NOT NULL"
	case "done":
		cond = "WHERE done_at IS NOT NULL"
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+jobCols+` FROM jobs `+cond+` ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Job])
}

func (s *Store) GetJob(ctx context.Context, id int64) (*Job, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+jobCols+` FROM jobs WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	j, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Job])
	return j, notFound(err)
}

// PurgeJobs deletes finished jobs older than age.
func (s *Store) PurgeJobs(ctx context.Context, age time.Duration) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM jobs WHERE (done_at IS NOT NULL OR failed_at IS NOT NULL)
		AND created_at < now() - make_interval(secs => $1)`, age.Seconds())
	return err
}

type Integration struct {
	ID          int64           `json:"id"`
	Kind        string          `json:"kind"`
	Name        string          `json:"name"`
	Config      json.RawMessage `json:"config"`
	SecretRef   string          `json:"secret_ref"`
	ScheduleMin int64           `json:"schedule_minutes"`
	Enabled     bool            `json:"enabled"`
	AssetID     *int64          `json:"asset_id"`
	LastAttempt *time.Time      `json:"last_attempt"`
	LastSuccess *time.Time      `json:"last_success"`
	LastError   string          `json:"last_error"`
	CreatedAt   time.Time       `json:"created_at"`
}

const integrationCols = `id, kind, name, config, secret_ref, (extract(epoch FROM schedule) / 60)::bigint, enabled, asset_id, last_attempt, last_success, last_error, created_at`

func (s *Store) ListIntegrations(ctx context.Context) ([]Integration, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+integrationCols+` FROM integrations ORDER BY kind, name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Integration])
}

func (s *Store) GetIntegration(ctx context.Context, id int64) (*Integration, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+integrationCols+` FROM integrations WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	i, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Integration])
	return i, notFound(err)
}

func (s *Store) CreateIntegration(ctx context.Context, kind, name string, config any, secretRef string, schedule time.Duration) (*Integration, error) {
	c, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `INSERT INTO integrations (kind, name, config, secret_ref, schedule) VALUES ($1,$2,$3,$4,$5)
		RETURNING `+integrationCols, kind, name, c, secretRef, schedule)
	if err != nil {
		return nil, err
	}
	i, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Integration])
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return i, err
}

type IntegrationUpdate struct {
	Name      *string         `json:"name"`
	Config    json.RawMessage `json:"config"`
	SecretRef *string         `json:"secret_ref"`
	Schedule  *time.Duration  `json:"-"`
	Enabled   *bool           `json:"enabled"`
}

func (s *Store) UpdateIntegration(ctx context.Context, id int64, u IntegrationUpdate) error {
	var cfg []byte
	if len(u.Config) > 0 {
		cfg = u.Config
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE integrations SET name = COALESCE($2, name), config = COALESCE($3, config),
		secret_ref = COALESCE($4, secret_ref), schedule = COALESCE($5, schedule), enabled = COALESCE($6, enabled) WHERE id = $1`,
		id, u.Name, cfg, u.SecretRef, u.Schedule, u.Enabled)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteIntegration(ctx context.Context, id int64) error {
	tag, err := s.Pool.Exec(ctx, `DELETE FROM integrations WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// IntegrationResult records the outcome of a run.
func (s *Store) IntegrationResult(ctx context.Context, id int64, assetID int64, runErr error) error {
	if runErr != nil {
		msg := runErr.Error()
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		_, err := s.Pool.Exec(ctx, `UPDATE integrations SET last_attempt = now(), last_error = $2 WHERE id = $1`, id, msg)
		return err
	}
	var a *int64
	if assetID > 0 {
		a = &assetID
	}
	_, err := s.Pool.Exec(ctx, `UPDATE integrations SET last_attempt = now(), last_success = now(), last_error = '',
		asset_id = COALESCE($2, asset_id) WHERE id = $1`, id, a)
	return err
}

// DueIntegrations returns enabled integrations whose schedule has elapsed.
func (s *Store) DueIntegrations(ctx context.Context) ([]Integration, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+integrationCols+` FROM integrations
		WHERE enabled AND (last_attempt IS NULL OR last_attempt + schedule <= now())`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Integration])
}
