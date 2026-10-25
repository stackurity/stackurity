package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
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
	Status       string `json:"status"` // pending, evaluated, failed
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
	err = s.Pool.QueryRow(ctx, `SELECT count(DISTINCT g.component_id) FROM evaluation_gaps g
		JOIN inventory i ON i.component_id = g.component_id AND i.removed_at IS NULL
		WHERE i.asset_id = $1`, res.AssetID).Scan(&res.Gaps)
	return res, err
}
