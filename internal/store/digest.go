package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Public intelligence for digests, such as a weekly vulnerability news
// email: what the KEV and endoflife.date feeds say about a period, with no
// workspace's data. Both read catalogue tables every workspace shares.

// KEVAddition is an entry added to CISA's Known Exploited Vulnerabilities
// catalogue, with FIRST's EPSS for the CVE when the epss:first feed has one.
type KEVAddition struct {
	CVE              string    `json:"cve"`
	Vendor           string    `json:"vendor"`
	Product          string    `json:"product"`
	Name             string    `json:"name"`
	ShortDescription string    `json:"short_description"`
	Added            time.Time `json:"added"`
	// DueDate is the date CISA requires US federal agencies to act by
	// (BOD 22-01); nil when the catalogue gives none.
	DueDate    *time.Time `json:"due_date,omitempty"`
	Ransomware bool       `json:"known_ransomware_use"`
	// EPSS is nil when the CVE has no score (or EPSS is not synced).
	EPSS *EPSSScore `json:"epss,omitempty"`
}

// KEVAddedBetween returns the KEV entries added on the days from first to
// last (both included, calendar dates as the catalogue gives them), oldest
// first and then by CVE.
func (s *Store) KEVAddedBetween(ctx context.Context, first, last time.Time) ([]KEVAddition, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT k.cve, k.vendor, k.product, k.name, k.short_description, k.added, k.due_date, k.ransomware,
			e.score, e.percentile, e.model_version, e.score_date
		FROM known_exploited k LEFT JOIN epss_scores e ON e.cve = k.cve
		WHERE k.added BETWEEN $1::date AND $2::date
		ORDER BY k.added, k.cve`, first.Format(time.DateOnly), last.Format(time.DateOnly))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (KEVAddition, error) {
		var a KEVAddition
		var score, pct *float32
		var model *string
		var date *time.Time
		if err := r.Scan(&a.CVE, &a.Vendor, &a.Product, &a.Name, &a.ShortDescription, &a.Added, &a.DueDate, &a.Ransomware,
			&score, &pct, &model, &date); err != nil {
			return a, err
		}
		if score != nil {
			a.EPSS = &EPSSScore{CVE: a.CVE, Score: *score, Percentile: *pct, ModelVersion: *model, Date: *date}
		}
		return a, nil
	})
}

// LifecycleEnding is a release cycle whose security support ends soon,
// from endoflife.date.
type LifecycleEnding struct {
	Product      string    `json:"product"`
	ProductLabel string    `json:"product_label"`
	Cycle        string    `json:"cycle"`
	Label        string    `json:"label"`
	EOL          time.Time `json:"eol"`
	LTS          bool      `json:"lts"`
	Link         string    `json:"link"`
}

// LifecycleEndingBetween returns the cycles whose end of security support
// falls on the days from first to last (both included), soonest first, at
// most limit. withPackages keeps only products that name package
// identifiers (purls), the ones Stackurity matches inventory against.
func (s *Store) LifecycleEndingBetween(ctx context.Context, first, last time.Time, withPackages bool, limit int) ([]LifecycleEnding, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), `SELECT c.product, p.label, c.cycle, c.label, c.eol_until, c.lts, p.link
		FROM lifecycle_cycles c JOIN lifecycle_products p ON p.product = c.product
		WHERE c.eol_until BETWEEN $1::date AND $2::date AND (NOT $3 OR cardinality(p.purls) > 0)
		ORDER BY c.eol_until, p.label, c.cycle LIMIT $4`, first.Format(time.DateOnly), last.Format(time.DateOnly), withPackages, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[LifecycleEnding])
}
