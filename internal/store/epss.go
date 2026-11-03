package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/risk"
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

// findingCVEs lists a vulnerability finding's CVEs as rows of fc(cve), for
// the finding (or distinct key and sources) under alias x: its key (the
// lowest CVE of its advisories, osv.GroupKey) and every id its advisories
// (sources) give as an alias or upstream id. A distribution advisory fixing
// several CVEs (a DSA, an RHSA) lists all but the lowest only there, and a
// GHSA or GO record can have several CVE aliases. Ids that are not CVEs
// never match an EPSS score.
func findingCVEs(x string) string {
	return `(SELECT ` + x + `.key AS cve UNION
	  SELECT unnest(ad.aliases || ad.upstream) FROM advisories ad WHERE ad.id = ANY(` + x + `.sources) AND ad.withdrawn IS NULL) fc`
}

// findingEPSSCVE is the CVE whose EPSS finding f uses: the one prioritisation
// chose among its CVEs (findings.epss_cve, see chooseEPSS), else its key.
// Reading its score is one primary-key lookup in epss_scores.
const findingEPSSCVE = `COALESCE(f.epss_cve, f.key)`

// EPSSSwitch and EPSSSwitchPoints say how much higher another of a
// finding's CVEs must score before the finding's EPSS moves to it from the
// CVE it uses now: by more than a tenth and by more than one percentage
// point (its current CVE is kept while it scores at least 90% of the
// highest, or within 0.01 of it), and it always moves when the two are on
// different sides of the risk policy's threshold. Two CVEs whose scores
// cross each other from day to day, most of them near zero, then do not
// rewrite the finding each day.
const (
	EPSSSwitch       = 0.9
	EPSSSwitchPoints = 0.01
)

// chooseEPSS picks the CVE whose EPSS finding r uses and sets r.in.EPSS to
// its score: the highest-scored of its CVEs, unless the CVE it uses now is
// close to it (EPSSSwitch, EPSSSwitchPoints) and on the same side of policy
// p's threshold. It
// returns the CVE to store, nil when it is the finding's key or there is no
// score.
func chooseEPSS(p risk.Policy, r *riskRow) *string {
	r.in.EPSS = nil
	if len(r.epssCVEs) == 0 {
		return nil
	}
	i := 0           // the highest: scores come highest first
	current := r.key // a finding with no stored CVE uses its key
	if r.epssStored != nil {
		current = *r.epssStored
	}
	for j, c := range r.epssCVEs {
		if c != current {
			continue
		}
		best, cur := r.epssScores[0], r.epssScores[j]
		if (cur >= best*EPSSSwitch || best-cur <= EPSSSwitchPoints) && p.EPSSCounts(cur, r.in.EPSSCounted) == p.EPSSCounts(best, r.in.EPSSCounted) {
			i = j
		}
		break
	}
	score := r.epssScores[i]
	r.in.EPSS = &score
	if r.epssCVEs[i] == r.key {
		return nil
	}
	c := r.epssCVEs[i]
	return &c
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
		// CVEs new to Stackurity are recorded with the time they arrived
		// (cve_first_seen, the public log of new vulnerabilities).
		if _, err := tx.Exec(ctx, `INSERT INTO cve_first_seen (cve, first_seen, source)
			SELECT DISTINCT cve, now(), 'epss' FROM epss_load ON CONFLICT (cve) DO NOTHING`); err != nil {
			return fmt.Errorf("record new CVEs: %w", err)
		}
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
