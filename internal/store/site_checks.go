package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// SiteCheck is one website check an organisation asked for (migration
// 0126, internal/sitecheck). Report is the full report as the API returns
// it; lists leave it out.
type SiteCheck struct {
	ID             int64           `json:"id"`
	URL            string          `json:"url"`
	FinalURL       string          `json:"final_url"`
	Host           string          `json:"host"`
	Issues         int             `json:"issues"`
	KnownExploited int             `json:"known_exploited"`
	EndOfLife      int             `json:"end_of_life"`
	CreatedByName  string          `json:"created_by_name"`
	ViaAPI         bool            `json:"via_api"`
	CreatedAt      time.Time       `json:"created_at"`
	Report         json.RawMessage `json:"report,omitempty"`
}

const siteCheckCols = `id, url, final_url, host, issues, known_exploited, end_of_life, created_by_name, token_id IS NOT NULL, created_at`

// AddSiteCheck stores a finished check in the current workspace.
func (s *Store) AddSiteCheck(ctx context.Context, c SiteCheck, userID, tokenID int64) (*SiteCheck, error) {
	var uid, tid *int64
	if userID > 0 {
		uid = &userID
	}
	if tokenID > 0 {
		tid = &tokenID
	}
	row := s.Pool.QueryRow(ctx, `INSERT INTO site_checks (url, final_url, host, report, issues, known_exploited, end_of_life,
			created_by, created_by_name, token_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING `+siteCheckCols,
		clip(c.URL, 2048), clip(c.FinalURL, 2048), clip(c.Host, 253), c.Report, c.Issues, c.KnownExploited, c.EndOfLife,
		uid, clip(c.CreatedByName, 500), tid)
	out, err := scanSiteCheck(row)
	if err != nil {
		return nil, err
	}
	out.Report = c.Report
	return out, nil
}

// SiteChecks lists the current workspace's checks, newest first, without
// their reports.
func (s *Store) SiteChecks(ctx context.Context, p Page) ([]SiteCheck, int64, error) {
	if p.Limit <= 0 || p.Limit > 500 {
		p.Limit = 100
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+siteCheckCols+`, count(*) OVER () FROM site_checks
		ORDER BY created_at DESC, id DESC LIMIT $1 OFFSET $2`, p.Limit, p.Offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []SiteCheck
	var total int64
	for rows.Next() {
		var c SiteCheck
		if err := rows.Scan(&c.ID, &c.URL, &c.FinalURL, &c.Host, &c.Issues, &c.KnownExploited, &c.EndOfLife, &c.CreatedByName,
			&c.ViaAPI, &c.CreatedAt, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// SiteCheckByID returns one of the current workspace's checks with its
// report, or ErrNotFound.
func (s *Store) SiteCheckByID(ctx context.Context, id int64) (*SiteCheck, error) {
	var report json.RawMessage
	row := s.Pool.QueryRow(ctx, `SELECT `+siteCheckCols+`, report FROM site_checks WHERE id = $1`, id)
	var c SiteCheck
	err := row.Scan(&c.ID, &c.URL, &c.FinalURL, &c.Host, &c.Issues, &c.KnownExploited, &c.EndOfLife, &c.CreatedByName,
		&c.ViaAPI, &c.CreatedAt, &report)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	c.Report = report
	return &c, nil
}

func scanSiteCheck(row pgx.Row) (*SiteCheck, error) {
	var c SiteCheck
	if err := row.Scan(&c.ID, &c.URL, &c.FinalURL, &c.Host, &c.Issues, &c.KnownExploited, &c.EndOfLife, &c.CreatedByName,
		&c.ViaAPI, &c.CreatedAt); err != nil {
		return nil, err
	}
	return &c, nil
}
