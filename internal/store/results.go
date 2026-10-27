package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/stackurity/stackurity/internal/tenant"
)

// DBNow returns the database clock, which collection and job times use.
func (s *Store) DBNow(ctx context.Context) (time.Time, error) {
	var t time.Time
	err := s.Pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&t)
	return t, err
}

// MarkEvaluated records that an evaluation which started at start has
// finished, for one asset or (assetID 0) for every asset.
func (s *Store) MarkEvaluated(ctx context.Context, assetID int64, start time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE assets SET evaluated_at = GREATEST(COALESCE(evaluated_at, $2), $2)
		WHERE ($1 = 0 AND merged_into IS NULL) OR id = $1`, assetID, start)
	return err
}

// CollectionResult is what a CI gate reads after submitting a batch.
type CollectionResult struct {
	CollectionID int64  `json:"collection_id"`
	AssetID      int64  `json:"asset_id"`
	Status       string `json:"status"` // pending, scoring, evaluated, failed
	Error        string `json:"error,omitempty"`
	// Findings holds the asset's open findings once evaluated.
	Findings []Finding `json:"findings"`
	// Gaps counts the asset's components that could not be evaluated.
	Gaps int64 `json:"evaluation_gaps"`
}

// CollectionSubmitter returns the token that submitted a collection (nil for
// a browser session) so callers can limit who may read its result.
func (s *Store) CollectionSubmitter(ctx context.Context, id int64) (*int64, error) {
	var tok *int64
	err := s.Pool.QueryRow(ctx, `SELECT submitted_by FROM collections WHERE id = $1`, id).Scan(&tok)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	return tok, err
}

// maxResultFindings bounds the response for very large repositories.
const maxResultFindings = 5000

// GetCollectionResult reports whether a collection's asset has been evaluated
// since the collection arrived, and if so its open findings. A collection
// counts as evaluated only when a run started after it arrived and no run
// for the asset is still queued, so a run that began before the batch was
// committed is never mistaken for one that saw it.
func (s *Store) GetCollectionResult(ctx context.Context, id int64) (*CollectionResult, error) {
	res := &CollectionResult{CollectionID: id, Findings: []Finding{}}
	var receivedAt time.Time
	var evaluatedAt *time.Time
	var pending bool
	var failedErr *string
	err := s.Pool.QueryRow(ctx, `SELECT a.id, c.received_at, a.evaluated_at,
		  EXISTS (SELECT 1 FROM jobs j WHERE j.dedupe_key = 'evaluate:asset:' || a.id
		          AND j.done_at IS NULL AND j.failed_at IS NULL),
		  (SELECT j.last_error FROM jobs j WHERE j.dedupe_key = 'evaluate:asset:' || a.id
		          AND j.failed_at >= c.received_at ORDER BY j.failed_at DESC LIMIT 1)
		FROM collections c JOIN assets x ON x.id = c.asset_id
		JOIN assets a ON a.id = COALESCE(x.merged_into, x.id)
		WHERE c.id = $1`, id).Scan(&res.AssetID, &receivedAt, &evaluatedAt, &pending, &failedErr)
	if err == pgx.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	switch {
	case pending:
		res.Status = "pending"
		return res, nil
	case evaluatedAt != nil && !evaluatedAt.Before(receivedAt):
		res.Status = "evaluated"
	case failedErr != nil:
		res.Status, res.Error = "failed", *failedErr
		return res, nil
	default:
		res.Status = "pending"
		return res, nil
	}
	// Matched but not yet prioritised: the findings still carry the
	// default priority (P4, score 0), which a priority gate must not read.
	var unscored bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM findings WHERE asset_id = $1 AND status = 'open' AND priority_policy = '')`,
		res.AssetID).Scan(&unscored); err != nil {
		return nil, err
	}
	if unscored {
		res.Status = "scoring"
		return res, nil
	}
	for off := 0; off < maxResultFindings; off += 500 {
		page, _, err := s.ListFindings(ctx, FindingFilter{AssetID: res.AssetID, Page: Page{Limit: 500, Offset: off}})
		if err != nil {
			return nil, err
		}
		res.Findings = append(res.Findings, page...)
		if len(page) < 500 {
			break
		}
	}
	err = s.Pool.QueryRow(ctx, `SELECT count(DISTINCT component_id) FROM inventory
		WHERE asset_id = $1 AND removed_at IS NULL AND coverage IN ('unsupported', 'not_evaluated')`, res.AssetID).Scan(&res.Gaps)
	return res, err
}

// ErrEvaluationBusy: another evaluation of the workspace is running.
var ErrEvaluationBusy = errors.New("another evaluation of this workspace is running")

// LockEvaluations makes sure no other evaluation of the context's workspace
// runs, and holds that until release is called; when one does, it returns
// ErrEvaluationBusy at once rather than wait (the caller defers its job,
// so a waiting evaluation does not occupy a worker slot). Evaluations read
// the inventory, the feeds and the findings, then write coverage and
// findings; two of them overlapping could let one that read older feed
// state write after a newer one, resolving findings the newer one had just
// opened. Serialised, each evaluation reads what the previous one wrote.
// The lock is held by a transaction, so it ends with the connection if the
// process dies.
func (s *Store) LockEvaluations(ctx context.Context) (release func(), err error) {
	return s.lockEvaluations(ctx, 0)
}

// LockEvaluationsWait is LockEvaluations waiting up to wait for a running
// evaluation to finish. Postgres queues the waiter ahead of evaluations
// that try the lock later, so it gets the lock as soon as the current one
// ends. The periodic upkeep of findings (the dispatcher's tick) uses it:
// it writes the same findings an evaluation writes, and the two could
// otherwise lock them in opposite orders and deadlock.
func (s *Store) LockEvaluationsWait(ctx context.Context, wait time.Duration) (release func(), err error) {
	return s.lockEvaluations(ctx, wait)
}

// evaluationKey is the advisory lock key of the context's workspace.
// Advisory locks are per database; the key names the schema too, so
// installations (or tests) sharing a database do not wait for each other.
const evaluationKey = `hashtextextended('stackurity.evaluate:' || current_schema() || ':' || $1::bigint, 0)`

func (s *Store) lockEvaluations(ctx context.Context, wait time.Duration) (release func(), err error) {
	ws, _ := tenant.Workspace(ctx) // 0 (no workspace): evaluations in system scope
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (func(), error) {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		return nil, err
	}
	if wait <= 0 {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(`+evaluationKey+`)`, ws).Scan(&got); err != nil {
			return fail(err)
		}
		if !got {
			return fail(ErrEvaluationBusy)
		}
	} else {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL lock_timeout = '%dms'`, wait.Milliseconds())); err != nil {
			return fail(err)
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(`+evaluationKey+`)`, ws); err != nil {
			var pe *pgconn.PgError
			if errors.As(err, &pe) && pe.Code == "55P03" { // lock_not_available
				return fail(ErrEvaluationBusy)
			}
			return fail(err)
		}
	}
	return func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }, nil
}
