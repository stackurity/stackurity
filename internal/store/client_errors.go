package store

// Error reports (migration 0094; docs/install.md#error-reports): errors
// people hit in the dashboard and 5xx answers from the API, counted per
// fingerprint, day and workspace. A workspace's reports are written in its
// own scope, so row-level security checks them; reports from pages before
// sign-in and server errors outside a workspace are written in system scope
// with no workspace. client_error_fingerprints and the instance-wide
// listing are system scope only.

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/clienterrors"
	"github.com/stackurity/stackurity/internal/tenant"
)

// ClientErrorRetention is how long error reports are kept.
const ClientErrorRetention = 90 * 24 * time.Hour

// ClientErrorNewAfter is how long a fingerprint must have been absent to
// count as new again.
const ClientErrorNewAfter = 7 * 24 * time.Hour

// RecordClientErrors adds reports to the counts of workspace ws (0: none).
// Reports with the same fingerprint in one call are counted together; the
// last one is kept as the sample.
func (s *Store) RecordClientErrors(ctx context.Context, ws int64, reports []clienterrors.Clean) error {
	type agg struct {
		c clienterrors.Clean
		n int
	}
	var order []string
	byFP := map[string]*agg{}
	for _, c := range reports {
		fp := c.Fingerprint()
		if a, ok := byFP[fp]; ok {
			a.c, a.n = c, a.n+1
			continue
		}
		byFP[fp] = &agg{c, 1}
		order = append(order, fp)
	}
	if len(order) == 0 {
		return nil
	}
	wctx := tenant.System(ctx)
	var wsArg *int64
	if ws > 0 {
		wctx, wsArg = tenant.WithWorkspace(ctx, ws), &ws
	}
	err := pgx.BeginFunc(wctx, s.Pool, func(tx pgx.Tx) error {
		for _, fp := range order {
			a := byFP[fp]
			sample, err := json.Marshal(a.c)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(wctx, `INSERT INTO client_errors AS e (workspace_id, day, fingerprint, kind, route, method, api_route,
				  status, code, name, top_frame, count, sample, versions, browsers)
				VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
				  CASE WHEN $13 = '' THEN '{}'::text[] ELSE ARRAY[$13] END, CASE WHEN $14 = '' THEN '{}'::text[] ELSE ARRAY[$14] END)
				ON CONFLICT ((COALESCE(workspace_id, 0)), fingerprint, day) DO UPDATE SET
				  last_seen = now(), count = e.count + EXCLUDED.count, sample = EXCLUDED.sample,
				  versions = CASE WHEN $13 = '' OR $13 = ANY(e.versions) OR cardinality(e.versions) >= 10 THEN e.versions ELSE e.versions || $13 END,
				  browsers = CASE WHEN $14 = '' OR $14 = ANY(e.browsers) OR cardinality(e.browsers) >= 10 THEN e.browsers ELSE e.browsers || $14 END`,
				wsArg, fp, a.c.Kind, a.c.Route, a.c.Method, a.c.APIRoute, a.c.Status, a.c.Code, a.c.Name, a.c.TopFrame(), a.n, sample,
				a.c.Version, a.c.Browser); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	sys := tenant.System(ctx)
	_, err = s.Pool.Exec(sys, `INSERT INTO client_error_fingerprints AS f (fingerprint)
		SELECT unnest($1::text[])
		ON CONFLICT (fingerprint) DO UPDATE SET last_seen = now(),
		  new_since = CASE WHEN f.last_seen < now() - make_interval(secs => $2) THEN now() ELSE f.new_since END`,
		order, ClientErrorNewAfter.Seconds())
	return err
}

// ClientErrorGroup is one fingerprint, added up over days and workspaces.
type ClientErrorGroup struct {
	Fingerprint string    `json:"fingerprint"`
	Kind        string    `json:"kind"`
	Route       string    `json:"route"`
	Method      string    `json:"method"`
	APIRoute    string    `json:"api_route"`
	Status      int       `json:"status"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	TopFrame    string    `json:"top_frame"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	// NewSince is when the fingerprint last became new: first seen, or
	// seen again after ClientErrorNewAfter without it.
	NewSince time.Time `json:"new_since"`
	// Count and Workspaces cover the listing's period; workspaces are
	// counted, never named (reports before sign-in count as one).
	Count      int64           `json:"count"`
	Workspaces int64           `json:"workspaces"`
	Versions   []string        `json:"versions"`
	Browsers   []string        `json:"browsers"`
	Sample     json.RawMessage `json:"sample"`
}

// ClientErrorSummary is what instance administrators see on Platform health.
type ClientErrorSummary struct {
	// New: fingerprints that became new in the last 24 hours.
	New []ClientErrorGroup `json:"new"`
	// Top: the most frequent fingerprints over the last 7 days.
	Top []ClientErrorGroup `json:"top"`
}

const clientErrorGroupSQL = `SELECT e.fingerprint, min(e.kind), min(e.route), min(e.method), min(e.api_route), min(e.status), min(e.code),
	  min(e.name), min(e.top_frame), min(e.first_seen), max(e.last_seen), f.new_since, sum(e.count)::bigint,
	  count(DISTINCT COALESCE(e.workspace_id, 0)),
	  COALESCE((SELECT array_agg(DISTINCT v) FROM client_errors x, unnest(x.versions) v WHERE x.fingerprint = e.fingerprint AND x.day >= $1::date), '{}'),
	  COALESCE((SELECT array_agg(DISTINCT b) FROM client_errors x, unnest(x.browsers) b WHERE x.fingerprint = e.fingerprint AND x.day >= $1::date), '{}'),
	  (SELECT x.sample FROM client_errors x WHERE x.fingerprint = e.fingerprint ORDER BY x.last_seen DESC LIMIT 1)
	FROM client_errors e JOIN client_error_fingerprints f ON f.fingerprint = e.fingerprint
	WHERE e.day >= $1::date `

func (s *Store) clientErrorGroups(ctx context.Context, where string, args ...any) ([]ClientErrorGroup, error) {
	rows, err := s.Pool.Query(tenant.System(ctx), clientErrorGroupSQL+where, args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ClientErrorGroup, error) {
		var g ClientErrorGroup
		err := row.Scan(&g.Fingerprint, &g.Kind, &g.Route, &g.Method, &g.APIRoute, &g.Status, &g.Code, &g.Name, &g.TopFrame,
			&g.FirstSeen, &g.LastSeen, &g.NewSince, &g.Count, &g.Workspaces, &g.Versions, &g.Browsers, &g.Sample)
		if len(g.Versions) > 10 {
			g.Versions = g.Versions[:10]
		}
		if len(g.Browsers) > 10 {
			g.Browsers = g.Browsers[:10]
		}
		return g, err
	})
	if out == nil {
		out = []ClientErrorGroup{}
	}
	return out, err
}

// NewClientErrors lists fingerprints that became new since since, with
// their counts from that day on. It runs in system scope.
func (s *Store) NewClientErrors(ctx context.Context, since time.Time) ([]ClientErrorGroup, error) {
	return s.clientErrorGroups(ctx, `AND f.new_since >= $2
		GROUP BY e.fingerprint, f.new_since ORDER BY f.new_since DESC LIMIT 50`, since.UTC().Format(time.DateOnly), since)
}

// ClientErrorsSummary lists the fingerprints new in the last 24 hours and
// the 20 most frequent over the last 7 days. It runs in system scope.
func (s *Store) ClientErrorsSummary(ctx context.Context) (*ClientErrorSummary, error) {
	now, err := s.DBNow(tenant.System(ctx))
	if err != nil {
		return nil, err
	}
	fresh, err := s.NewClientErrors(ctx, now.Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	top, err := s.clientErrorGroups(ctx, `GROUP BY e.fingerprint, f.new_since ORDER BY sum(e.count) DESC, max(e.last_seen) DESC LIMIT 20`,
		now.UTC().Add(-6*24*time.Hour).Format(time.DateOnly))
	if err != nil {
		return nil, err
	}
	return &ClientErrorSummary{New: fresh, Top: top}, nil
}

// PurgeClientErrors deletes error reports older than ClientErrorRetention.
func (s *Store) PurgeClientErrors(ctx context.Context) (int64, error) {
	sys := tenant.System(ctx)
	tag, err := s.Pool.Exec(sys, `DELETE FROM client_errors WHERE day < (now() AT TIME ZONE 'UTC')::date - $1::int`,
		int(ClientErrorRetention/(24*time.Hour)))
	if err != nil {
		return 0, err
	}
	if _, err := s.Pool.Exec(sys, `DELETE FROM client_error_fingerprints WHERE last_seen < now() - make_interval(secs => $1)`,
		ClientErrorRetention.Seconds()); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
