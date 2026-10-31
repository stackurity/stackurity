package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// CVEFirstSeen is when a CVE first reached Stackurity, from the EPSS file or
// the KEV catalogue (migration 0068). Exact is false for CVEs stored before
// that was recorded: they arrived on or before At.
type CVEFirstSeen struct {
	CVE    string    `json:"cve"`
	At     time.Time `json:"added"`
	Source string    `json:"source"`
	Exact  bool      `json:"exact"`
}

// RecentCVEs returns the CVEs that most recently reached Stackurity, newest
// first, up to limit, added before before (zero: now). Only exact times
// are listed.
func (s *Store) RecentCVEs(ctx context.Context, before time.Time, limit int) ([]CVEFirstSeen, error) {
	if before.IsZero() {
		before = time.Now().Add(time.Second)
	}
	rows, err := s.Pool.Query(ctx, `SELECT cve, first_seen, source, NOT backfilled FROM cve_first_seen
		WHERE NOT backfilled AND first_seen < $1 ORDER BY first_seen DESC, cve DESC LIMIT $2`, before, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[CVEFirstSeen])
}

// CVEsFirstSeen returns what is recorded for the given CVEs; unknown ones are
// left out.
func (s *Store) CVEsFirstSeen(ctx context.Context, cves []string) ([]CVEFirstSeen, error) {
	rows, err := s.Pool.Query(ctx, `SELECT cve, first_seen, source, NOT backfilled FROM cve_first_seen
		WHERE cve = ANY($1) ORDER BY cve`, cves)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[CVEFirstSeen])
}

// CVETrackingSince is when exact times began: the earliest backfilled time,
// or zero when nothing was backfilled.
func (s *Store) CVETrackingSince(ctx context.Context) (time.Time, error) {
	var t *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT min(first_seen) FROM cve_first_seen WHERE backfilled`).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}
