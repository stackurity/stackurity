package store

// Leaked keys: keys, tokens and passwords collectors found written in an
// asset's files (migration 0083). The value never reaches the server; a
// leak holds where it is, a fingerprint and a masked preview.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/model"
)

// Leak is one leaked key as stored.
type Leak struct {
	ID             int64      `json:"id"`
	AssetID        int64      `json:"asset_id"`
	AssetName      string     `json:"asset_name"`
	AssetKind      string     `json:"asset_kind"`
	CollectorID    string     `json:"collector_id"`
	Fingerprint    string     `json:"fingerprint"`
	Path           string     `json:"path"`
	Line           int        `json:"line"`
	Rule           string     `json:"rule"`
	Title          string     `json:"title"`
	Name           string     `json:"name"`
	Preview        string     `json:"preview"`
	Severity       string     `json:"severity"`
	Exposure       string     `json:"exposure"`
	Status         string     `json:"status"`
	Resolution     string     `json:"resolution"`
	ResolutionNote string     `json:"resolution_note"`
	ResolvedBy     *int64     `json:"resolved_by"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	// Why says in one line why the leak has its severity and what to do,
	// from where the file is (LeakWhy).
	Why string `json:"why" db:"-"`
}

// Reasons a leak is graded as it is. Every place a leak is shown (the
// dashboard, alerts, the API and MCP) takes its line from LeakWhy, so they
// say the same thing.
const (
	whyServed = "The web server may send this file to anyone who asks for it (e.g. /.env). " +
		"Rotate the key and move the file out of the document root."
	whyRepository = "Committed to the repository: everyone with access to it, and every clone, has the key. " +
		"Rotate it; deleting the file does not remove it from history."
	whyImage = "Built into the container image: anyone who can pull the image has the key. " +
		"Rotate it and pass it to the container when it starts instead."
	whyWorldReadable = "In a configuration file every account on this server can read. " +
		"Restrict it to the application's user (chmod 640)."
	whyConfig = "Kept in the application's configuration file, where keys belong. " +
		"Listed so you know where this key lives when you rotate it."
	whyCode = "Written into the application's code, so it is in its repository too. Move it to configuration and rotate it."
)

// LeakWhy is the one-line reason for a leak's severity: what its exposure,
// the kind of asset and the file mean, and what to do.
func LeakWhy(assetKind, exposure, severity string) string {
	switch {
	case exposure == model.ExposureServed:
		return whyServed
	case assetKind == string(model.AssetRepository):
		return whyRepository
	case assetKind == string(model.AssetImage) || assetKind == string(model.AssetWorkload):
		return whyImage
	case exposure == model.ExposureWorldReadable:
		return whyWorldReadable
	case severity == "low":
		return whyConfig
	}
	return whyCode
}

func withWhy(ls []Leak) {
	for i := range ls {
		ls[i].Why = LeakWhy(ls[i].AssetKind, ls[i].Exposure, ls[i].Severity)
	}
}

const leakCols = `l.id, l.asset_id, a.name, a.kind, l.collector_id, l.fingerprint, l.path, l.line, l.rule, l.title, l.name,
	l.preview, l.severity, l.exposure, l.status, l.resolution, l.resolution_note, l.resolved_by, l.first_seen, l.last_seen, l.resolved_at`

// writeLeaks stores a batch's key scan: found leaks are added or seen
// again, and when the scan was complete the collector's open leaks on the
// asset it no longer saw are resolved as gone. A dismissed leak stays
// dismissed. found is the number of leaks in the batch; gone the number
// resolved.
func writeLeaks(ctx context.Context, tx pgx.Tx, assetID, collectionID int64, b *model.ObservationBatch) (found int, gone int64, err error) {
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE leaks_in (fingerprint text, path text, line int, rule text, title text,
		name text, preview text, severity text, exposure text) ON COMMIT DROP`); err != nil {
		return 0, 0, err
	}
	rows := make([][]any, 0, len(b.Leaks.Found))
	for _, l := range b.Leaks.Found {
		rows = append(rows, []any{l.Fingerprint, l.Path, l.Line, l.Rule, l.Title, l.Name, l.Preview, l.Severity, l.Exposure})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"leaks_in"},
		[]string{"fingerprint", "path", "line", "rule", "title", "name", "preview", "severity", "exposure"}, pgx.CopyFromRows(rows)); err != nil {
		return 0, 0, err
	}
	// The same value twice in one file is one leak: the first line wins,
	// and the most severe rule.
	if _, err := tx.Exec(ctx, `INSERT INTO leaks AS l (asset_id, collector_id, fingerprint, path, line, rule, title, name, preview,
			severity, exposure, first_seen, last_seen, last_collection_id)
		SELECT DISTINCT ON (fingerprint, path) $1, $2, fingerprint, path, line, rule, title, name, preview, severity, exposure, $3, $3, $4
		FROM leaks_in
		ORDER BY fingerprint, path, array_position(ARRAY['critical','high','medium','low'], severity), line
		ON CONFLICT (asset_id, collector_id, fingerprint, path) DO UPDATE SET
		  line = EXCLUDED.line, rule = EXCLUDED.rule, title = EXCLUDED.title, name = EXCLUDED.name, preview = EXCLUDED.preview,
		  severity = EXCLUDED.severity, exposure = EXCLUDED.exposure,
		  last_seen = GREATEST(l.last_seen, EXCLUDED.last_seen), last_collection_id = EXCLUDED.last_collection_id,
		  status = CASE WHEN l.resolution = 'dismissed' THEN l.status ELSE 'open' END,
		  resolution = CASE WHEN l.resolution = 'dismissed' THEN l.resolution ELSE '' END,
		  resolution_note = CASE WHEN l.resolution = 'dismissed' THEN l.resolution_note ELSE '' END,
		  resolved_by = CASE WHEN l.resolution = 'dismissed' THEN l.resolved_by END,
		  resolved_at = CASE WHEN l.resolution = 'dismissed' THEN l.resolved_at END`,
		assetID, b.Collector.ID, b.ObservedAt, collectionID); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO leak_scans (asset_id, collector_id, complete, reason, found, scanned_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (asset_id, collector_id) DO UPDATE SET complete = EXCLUDED.complete, reason = EXCLUDED.reason,
		  found = EXCLUDED.found, scanned_at = EXCLUDED.scanned_at`,
		assetID, b.Collector.ID, b.Leaks.Complete, b.Leaks.Reason, len(b.Leaks.Found), b.ObservedAt); err != nil {
		return 0, 0, err
	}
	if b.Leaks.Complete {
		tag, err := tx.Exec(ctx, `UPDATE leaks SET status = 'resolved', resolution = 'gone', resolved_at = $3
			WHERE asset_id = $1 AND collector_id = $2 AND status = 'open' AND last_collection_id IS DISTINCT FROM $4`,
			assetID, b.Collector.ID, b.ObservedAt, collectionID)
		if err != nil {
			return 0, 0, err
		}
		gone = tag.RowsAffected()
	}
	return len(b.Leaks.Found), gone, nil
}

// LeakFilter selects leaks. Status is open (the default), resolved or all;
// Severity is one severity or several, comma-separated.
type LeakFilter struct {
	AssetID  int64
	Status   string
	Severity string
	Page
}

// ListLeaks lists leaks, most severe first.
func (s *Store) ListLeaks(ctx context.Context, f LeakFilter) ([]Leak, int64, error) {
	w := &where{}
	switch f.Status {
	case "", "open":
		w.add("l.status = ?", "open")
	case "resolved":
		w.add("l.status = ?", "resolved")
	case "all":
	default:
		return nil, 0, fmt.Errorf("status must be open, resolved or all: %w", ErrInvalid)
	}
	if f.Severity != "" {
		w.add("l.severity = ANY(?)", strings.Split(f.Severity, ","))
	}
	if f.AssetID > 0 {
		w.add("l.asset_id = ?", f.AssetID)
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+leakCols+`, count(*) OVER () FROM leaks l JOIN assets a ON a.id = l.asset_id`+w.sql()+
		fmt.Sprintf(` ORDER BY l.status DESC, array_position(ARRAY['critical','high','medium','low'], l.severity), l.first_seen DESC, l.id
		LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	type counted struct {
		Leak
		Total int64
	}
	page, err := pgx.CollectRows(rows, pgx.RowToStructByPos[counted])
	if err != nil {
		return nil, 0, err
	}
	out := make([]Leak, len(page))
	var total int64
	for i, c := range page {
		out[i], total = c.Leak, c.Total
	}
	withWhy(out)
	return out, total, nil
}

// GetLeak returns one leak.
func (s *Store) GetLeak(ctx context.Context, id int64) (*Leak, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+leakCols+` FROM leaks l JOIN assets a ON a.id = l.asset_id WHERE l.id = $1`, id)
	if err != nil {
		return nil, err
	}
	l, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Leak])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	l.Why = LeakWhy(l.AssetKind, l.Exposure, l.Severity)
	return &l, err
}

// DismissLeak marks a leak dismissed (a test key kept on purpose, or one
// already rotated): it stays dismissed whatever later scans see.
func (s *Store) DismissLeak(ctx context.Context, id int64, userID *int64, note string) (*Leak, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE leaks SET status = 'resolved', resolution = 'dismissed', resolution_note = $2,
		resolved_by = $3, resolved_at = now() WHERE id = $1`, id, note, userID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetLeak(ctx, id)
}

// UndismissLeak opens a dismissed leak again. One resolved as gone stays
// resolved: only a scan can say it is back.
func (s *Store) UndismissLeak(ctx context.Context, id int64) (*Leak, error) {
	l, err := s.GetLeak(ctx, id)
	if err != nil {
		return nil, err
	}
	if l.Resolution != "dismissed" {
		return nil, fmt.Errorf("only a dismissed leak can be opened again: %w", ErrConflict)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE leaks SET status = 'open', resolution = '', resolution_note = '', resolved_by = NULL,
		resolved_at = NULL WHERE id = $1 AND resolution = 'dismissed'`, id); err != nil {
		return nil, err
	}
	return s.GetLeak(ctx, id)
}

// LeakAssets returns the assets of the given leaks, for role checks on
// project grants.
func (s *Store) LeakAssets(ctx context.Context, ids ...int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT asset_id FROM leaks WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// maxLeakDetail bounds the titles and files an incident's detail lists.
const maxLeakDetail = 10

// leakProblems is one incident per asset with open critical or high
// leaks. Medium and low leaks are listed, never alerted on.
func (s *Store) leakProblems(ctx context.Context) ([]SystemIncident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.kind, a.owner_team_id, a.environment,
		  count(*), count(*) FILTER (WHERE l.severity = 'critical'), count(*) FILTER (WHERE l.exposure = 'served'),
		  array_agg(DISTINCT l.title), (array_agg(l.path || ':' || l.line ORDER BY
		    array_position(ARRAY['critical','high'], l.severity), l.path, l.line))[1:$1],
		  (array_agg(l.exposure ORDER BY l.exposure = 'served' DESC, array_position(ARRAY['critical','high'], l.severity)))[1],
		  (array_agg(l.severity ORDER BY l.exposure = 'served' DESC, array_position(ARRAY['critical','high'], l.severity)))[1]
		FROM leaks l JOIN assets a ON a.id = l.asset_id
		WHERE l.status = 'open' AND l.severity IN ('critical', 'high') AND a.merged_into IS NULL
		GROUP BY a.id ORDER BY a.id`, maxLeakDetail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SystemIncident
	for rows.Next() {
		var id int64
		var name, kind, env string
		var team *int64
		var n, critical, served int
		var titles, files []string
		var exposure, severity string
		if err := rows.Scan(&id, &name, &kind, &team, &env, &n, &critical, &served, &titles, &files, &exposure, &severity); err != nil {
			return nil, err
		}
		sort.Strings(titles)
		if len(titles) > maxLeakDetail {
			titles = titles[:maxLeakDetail]
		}
		title := fmt.Sprintf("%d leaked keys on %s", n, name)
		if n == 1 {
			title = titles[0] + " leaked on " + name
		}
		pri := "P2"
		if critical > 0 {
			pri = "P1"
		}
		det := map[string]any{"asset_id": id, "asset_name": name, "asset_kind": kind, "count": n, "critical": critical,
			"served": served, "titles": titles, "files": files, "why": LeakWhy(kind, exposure, severity)}
		if env != "" {
			det["environments"] = []string{env}
		}
		out = append(out, SystemIncident{Kind: "leak", Key: fmt.Sprintf("asset:%d", id), OwnerTeamID: team, Title: title,
			Priority: pri, Detail: det})
	}
	return out, rows.Err()
}

// LeakScan is the last key scan one collector made of an asset.
type LeakScan struct {
	CollectorID string    `json:"collector_id"`
	Complete    bool      `json:"complete"`
	Reason      string    `json:"reason"`
	Found       int       `json:"found"`
	ScannedAt   time.Time `json:"scanned_at"`
}

// LeakScans returns the last key scan of an asset by each collector. None
// means the asset's files were never scanned for keys, which is not the
// same as no leaks.
func (s *Store) LeakScans(ctx context.Context, assetID int64) ([]LeakScan, error) {
	rows, err := s.Pool.Query(ctx, `SELECT collector_id, complete, reason, found, scanned_at FROM leak_scans
		WHERE asset_id = $1 ORDER BY collector_id`, assetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[LeakScan])
}
