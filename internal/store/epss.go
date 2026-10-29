package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// EPSSScore is FIRST's EPSS for one CVE: the probability (0 to 1) that it is
// exploited in the wild in the next 30 days, and its percentile among all
// scored CVEs, from the model and day that produced it.
type EPSSScore struct {
	CVE          string    `json:"cve"`
	Score        float32   `json:"score"`
	Percentile   float32   `json:"percentile"`
	ModelVersion string    `json:"model_version"`
	Date         time.Time `json:"date"`
}

// EPSSRow is one parsed line of an EPSS file.
type EPSSRow struct {
	CVE               string
	Score, Percentile float32
}

// EPSSFile says which model and day the stored scores come from; zero when
// none are stored.
func (s *Store) EPSSFile(ctx context.Context) (model string, date time.Time, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT model_version, score_date FROM epss_scores LIMIT 1`).Scan(&model, &date)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", time.Time{}, nil
	}
	return model, date, err
}

// ReplaceEPSS swaps in a whole EPSS file in one transaction, reading its
// rows from next (nil, nil at the end) without holding them in memory. A
// file that yields no rows, or fails part way, leaves the stored scores as
// they were. Duplicate CVEs keep their first row. It returns the number of
// scores stored.
func (s *Store) ReplaceEPSS(ctx context.Context, model string, date time.Time, next func() (*EPSSRow, error)) (int64, error) {
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE epss_load (ord bigint, cve text, score real, percentile real) ON COMMIT DROP`); err != nil {
			return err
		}
		var ord int64
		read, err := tx.CopyFrom(ctx, pgx.Identifier{"epss_load"}, []string{"ord", "cve", "score", "percentile"},
			pgx.CopyFromFunc(func() ([]any, error) {
				r, err := next()
				if r == nil || err != nil {
					return nil, err
				}
				ord++
				return []any{ord, r.CVE, r.Score, r.Percentile}, nil
			}))
		if err != nil {
			return err
		}
		if read == 0 {
			return errors.New("EPSS file has no scores; refusing to clear existing data")
		}
		// Rows are deleted and inserted rather than truncated, so readers
		// (prioritisation, the findings list) are never blocked meanwhile.
		if _, err := tx.Exec(ctx, `DELETE FROM epss_scores`); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO epss_scores (cve, score, percentile, model_version, score_date)
			SELECT DISTINCT ON (cve) cve, score, percentile, $1, $2 FROM epss_load ORDER BY cve, ord`, model, date)
		if err != nil {
			return fmt.Errorf("store EPSS scores: %w", err)
		}
		n = tag.RowsAffected()
		return nil
	})
	return n, err
}

// EPSSFor returns the stored EPSS of a CVE, nil when it has none.
func (s *Store) EPSSFor(ctx context.Context, cve string) (*EPSSScore, error) {
	var e EPSSScore
	err := s.Pool.QueryRow(ctx, `SELECT cve, score, percentile, model_version, score_date FROM epss_scores WHERE cve = $1`, cve).
		Scan(&e.CVE, &e.Score, &e.Percentile, &e.ModelVersion, &e.Date)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}
