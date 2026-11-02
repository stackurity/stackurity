package store

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// ExposedSecret is a secret a scan found in one place (docs/design/
// exposed-secrets.md). Its value is never stored.
type ExposedSecret struct {
	ID           int64      `json:"id"`
	AssetID      int64      `json:"asset_id"`
	AssetName    string     `json:"asset_name"`
	AssetKind    string     `json:"asset_kind"`
	Rule         string     `json:"rule"`
	Title        string     `json:"title"`
	Location     string     `json:"location"`
	Line         int        `json:"line"`
	Fingerprint  string     `json:"fingerprint"`
	Preview      string     `json:"preview"`
	Severity     string     `json:"severity"`
	Exposure     string     `json:"exposure"`
	Note         string     `json:"note"`
	Status       string     `json:"status"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     time.Time  `json:"last_seen"`
	ResolvedAt   *time.Time `json:"resolved_at,omitempty"`
	IgnoredBy    string     `json:"ignored_by,omitempty"`
	IgnoredAt    *time.Time `json:"ignored_at,omitempty"`
	IgnoreReason string     `json:"ignore_reason,omitempty"`
	// Places: rows of the same secret (fingerprint) with this status that
	// the viewer can see, this one included.
	Places int `json:"places"`
}

// ExposedSecretFilter narrows ListExposedSecrets.
type ExposedSecretFilter struct {
	Status   string // open (default), resolved, ignored, all
	AssetID  int64
	Severity string
	Limit    int
	Offset   int
}

// ExposedSecretSummary counts open exposed secrets.
type ExposedSecretSummary struct {
	Open       int64            `json:"open"`
	Secrets    int64            `json:"secrets"` // distinct fingerprints among them
	Assets     int64            `json:"assets"`
	BySeverity map[string]int64 `json:"by_severity"`
}

const secretSeverityOrder = `CASE e.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`

// syncSecrets records what a batch's secret scan found on the asset. A
// complete scan resolves the open rows of the same collector it did not
// list; a person's "ignored" stays.
func syncSecrets(ctx context.Context, tx pgx.Tx, assetID, collectionID int64, b *model.ObservationBatch) error {
	for _, f := range b.Secrets.Findings {
		if _, err := tx.Exec(ctx, `INSERT INTO exposed_secrets AS e (asset_id, collector_id, rule, title, location, line, fingerprint,
			  preview, severity, exposure, note, first_seen, last_seen, last_collection_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12,$13)
			ON CONFLICT (asset_id, collector_id, fingerprint, location) DO UPDATE SET
			  rule = EXCLUDED.rule, title = EXCLUDED.title, line = EXCLUDED.line, preview = EXCLUDED.preview,
			  severity = EXCLUDED.severity, exposure = EXCLUDED.exposure, note = EXCLUDED.note,
			  last_seen = GREATEST(e.last_seen, EXCLUDED.last_seen), last_collection_id = EXCLUDED.last_collection_id,
			  status = CASE WHEN e.status = 'resolved' THEN 'open' ELSE e.status END,
			  resolved_at = CASE WHEN e.status = 'resolved' THEN NULL ELSE e.resolved_at END`,
			assetID, b.Collector.ID, f.Rule, f.Title, f.Location, f.Line, f.Fingerprint, f.Preview, f.Severity, f.Exposure, f.Note,
			b.ObservedAt, collectionID); err != nil {
			return err
		}
	}
	if !b.Secrets.Complete {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE exposed_secrets SET status = 'resolved', resolved_at = $3
		WHERE asset_id = $1 AND collector_id = $2 AND status = 'open' AND last_collection_id IS DISTINCT FROM $4`,
		assetID, b.Collector.ID, b.ObservedAt, collectionID)
	return err
}

// ListExposedSecrets lists exposed secrets, most severe first, and the
// total that match.
func (s *Store) ListExposedSecrets(ctx context.Context, f ExposedSecretFilter) ([]ExposedSecret, int64, error) {
	where, args := `TRUE`, []any{}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	switch f.Status {
	case "", "open":
		where += ` AND e.status = 'open'`
	case "all":
	default:
		where += ` AND e.status = ` + arg(f.Status)
	}
	if f.AssetID > 0 {
		where += ` AND e.asset_id = ` + arg(f.AssetID)
	}
	if f.Severity != "" {
		where += ` AND e.severity = ` + arg(f.Severity)
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM exposed_secrets e WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `SELECT e.id, e.asset_id, a.name, a.kind, e.rule, e.title, e.location, e.line, e.fingerprint,
		  e.preview, e.severity, e.exposure, e.note, e.status, e.first_seen, e.last_seen, e.resolved_at,
		  COALESCE(u.email, ''), e.ignored_at, e.ignore_reason,
		  (SELECT count(*) FROM exposed_secrets o WHERE o.fingerprint = e.fingerprint AND o.status = e.status)::int
		FROM exposed_secrets e JOIN assets a ON a.id = e.asset_id LEFT JOIN users u ON u.id = e.ignored_by
		WHERE `+where+` ORDER BY `+secretSeverityOrder+`, e.exposure = 'public' DESC, e.first_seen DESC, e.id
		LIMIT `+arg(limit)+` OFFSET `+arg(max(f.Offset, 0)), args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[ExposedSecret])
	return out, total, err
}

// SummarizeExposedSecrets counts the open exposed secrets the viewer can see.
func (s *Store) SummarizeExposedSecrets(ctx context.Context) (*ExposedSecretSummary, error) {
	out := &ExposedSecretSummary{BySeverity: map[string]int64{}}
	if err := s.Pool.QueryRow(ctx, `SELECT count(*), count(DISTINCT fingerprint), count(DISTINCT asset_id)
		FROM exposed_secrets WHERE status = 'open'`).Scan(&out.Open, &out.Secrets, &out.Assets); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT severity, count(*) FROM exposed_secrets WHERE status = 'open' GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int64
		if err := rows.Scan(&sev, &n); err != nil {
			return nil, err
		}
		out.BySeverity[sev] = n
	}
	return out, rows.Err()
}

// IgnoreExposedSecret marks a secret ignored everywhere the viewer can see
// it (every open row with its fingerprint), with the person and reason,
// and returns how many rows changed. Scans keep finding it but it stays
// ignored until reopened.
func (s *Store) IgnoreExposedSecret(ctx context.Context, id, by int64, reason string) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE exposed_secrets SET status = 'ignored', ignored_by = $2, ignored_at = now(), ignore_reason = $3
		WHERE status = 'open' AND fingerprint = (SELECT fingerprint FROM exposed_secrets WHERE id = $1)`, id, by, reason)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, s.exposedSecretExists(ctx, id)
	}
	return tag.RowsAffected(), nil
}

// ReopenExposedSecret undoes IgnoreExposedSecret for every ignored row of
// the same secret.
func (s *Store) ReopenExposedSecret(ctx context.Context, id int64) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE exposed_secrets SET status = 'open', ignored_by = NULL, ignored_at = NULL, ignore_reason = ''
		WHERE status = 'ignored' AND fingerprint = (SELECT fingerprint FROM exposed_secrets WHERE id = $1)`, id)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, s.exposedSecretExists(ctx, id)
	}
	return tag.RowsAffected(), nil
}

// exposedSecretExists is ErrNotFound for a row the viewer cannot see, and
// ErrConflict when it is there but not in the state the change needs.
func (s *Store) exposedSecretExists(ctx context.Context, id int64) error {
	var ok bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM exposed_secrets WHERE id = $1)`, id).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	return fmt.Errorf("%w: the secret is not in a state this changes", ErrConflict)
}

// ExposedSecretAssets returns the assets that hold the secret of row id in
// the given status (the rows IgnoreExposedSecret or ReopenExposedSecret
// would change), so the caller's role can be checked on each.
func (s *Store) ExposedSecretAssets(ctx context.Context, id int64, status string) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT asset_id FROM exposed_secrets
		WHERE status = $2 AND fingerprint = (SELECT fingerprint FROM exposed_secrets WHERE id = $1) ORDER BY 1`, id, status)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}
