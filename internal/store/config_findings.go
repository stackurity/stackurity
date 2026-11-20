package store

// Config findings: risky settings collectors found in an asset's files
// (migration 0114, internal/collect/confcheck): AI coding-agent hooks that
// download and run code, SSH access that gives root an unrestricted shell,
// GitHub Actions workflows that run third-party actions by a movable tag.
// Each carries the collector's one-line why and fix; the server adds the
// page that explains the rule (ConfigRuleDoc).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/collect/confcheck"
	"github.com/stackurity/stackurity/internal/model"
)

// ConfigFinding is one config finding as stored.
type ConfigFinding struct {
	ID             int64      `json:"id"`
	AssetID        int64      `json:"asset_id"`
	AssetName      string     `json:"asset_name"`
	AssetKind      string     `json:"asset_kind"`
	CollectorID    string     `json:"collector_id"`
	Fingerprint    string     `json:"fingerprint"`
	Rule           string     `json:"rule"`
	Category       string     `json:"category"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	Path           string     `json:"path"`
	Line           int        `json:"line"`
	Subject        string     `json:"subject"`
	Why            string     `json:"why"`
	Fix            string     `json:"fix"`
	Status         string     `json:"status"`
	Resolution     string     `json:"resolution"`
	ResolutionNote string     `json:"resolution_note"`
	ResolvedBy     *int64     `json:"resolved_by"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	// DocURL is a page that explains the rule and its fix, when there is
	// one (ConfigRuleDoc).
	DocURL string `json:"doc_url" db:"-"`
}

// ConfigRuleDoc is the page that explains a config rule, or "": the rule
// engine's own list (internal/collect/confcheck).
func ConfigRuleDoc(rule string) string { return confcheck.RuleDoc(rule) }

const configCols = `c.id, c.asset_id, a.name, a.kind, c.collector_id, c.fingerprint, c.rule, c.category, c.title, c.severity,
	c.path, c.line, c.subject, c.why, c.fix, c.status, c.resolution, c.resolution_note, c.resolved_by, c.first_seen, c.last_seen,
	c.resolved_at`

const configFrom = ` FROM config_findings c JOIN assets a ON a.id = c.asset_id`

var configSeverities = []string{"high", "medium", "low", "info"}

// writeConfigFindings stores a batch's config checks: found ones are added
// or seen again, and when the checks were complete the collector's open
// findings on the asset that were not seen are resolved as gone. A
// dismissed finding stays dismissed.
func writeConfigFindings(ctx context.Context, tx pgx.Tx, assetID, collectionID int64, b *model.ObservationBatch) (found int, gone int64, err error) {
	s := b.ConfigFindings
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE config_in (fingerprint text, rule text, category text, title text, severity text,
		path text, line int, subject text, why text, fix text) ON COMMIT DROP`); err != nil {
		return 0, 0, err
	}
	rows := make([][]any, 0, len(s.Found))
	for _, f := range s.Found {
		rows = append(rows, []any{f.Fingerprint, f.Rule, f.Category, f.Title, f.Severity, f.Path, f.Line, f.Subject, f.Why, f.Fix})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"config_in"},
		[]string{"fingerprint", "rule", "category", "title", "severity", "path", "line", "subject", "why", "fix"}, pgx.CopyFromRows(rows)); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO config_findings AS c (asset_id, collector_id, fingerprint, rule, category, title, severity,
			path, line, subject, why, fix, first_seen, last_seen, last_collection_id)
		SELECT DISTINCT ON (fingerprint) $1, $2, fingerprint, rule, category, title, severity, path, line, subject, why, fix, $3, $3, $4
		FROM config_in ORDER BY fingerprint, array_position(ARRAY['high','medium','low','info'], severity)
		ON CONFLICT (asset_id, collector_id, fingerprint) DO UPDATE SET
		  rule = EXCLUDED.rule, category = EXCLUDED.category, title = EXCLUDED.title, severity = EXCLUDED.severity,
		  path = EXCLUDED.path, line = EXCLUDED.line, subject = EXCLUDED.subject, why = EXCLUDED.why, fix = EXCLUDED.fix,
		  last_seen = GREATEST(c.last_seen, EXCLUDED.last_seen), last_collection_id = EXCLUDED.last_collection_id,
		  status = CASE WHEN c.resolution = 'dismissed' THEN c.status ELSE 'open' END,
		  resolution = CASE WHEN c.resolution = 'dismissed' THEN c.resolution ELSE '' END,
		  resolution_note = CASE WHEN c.resolution = 'dismissed' THEN c.resolution_note ELSE '' END,
		  resolved_by = CASE WHEN c.resolution = 'dismissed' THEN c.resolved_by END,
		  resolved_at = CASE WHEN c.resolution = 'dismissed' THEN c.resolved_at END`,
		assetID, b.Collector.ID, b.ObservedAt, collectionID); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO config_scans (asset_id, collector_id, complete, reason, found, scanned_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (asset_id, collector_id) DO UPDATE SET complete = EXCLUDED.complete, reason = EXCLUDED.reason,
		  found = EXCLUDED.found, scanned_at = EXCLUDED.scanned_at`,
		assetID, b.Collector.ID, s.Complete, s.Reason, len(s.Found), b.ObservedAt); err != nil {
		return 0, 0, err
	}
	if s.Complete {
		tag, err := tx.Exec(ctx, `UPDATE config_findings SET status = 'resolved', resolution = 'gone', resolved_at = $3
			WHERE asset_id = $1 AND collector_id = $2 AND status = 'open' AND last_collection_id IS DISTINCT FROM $4`,
			assetID, b.Collector.ID, b.ObservedAt, collectionID)
		if err != nil {
			return 0, 0, err
		}
		gone = tag.RowsAffected()
	}
	return len(s.Found), gone, nil
}

// ConfigFindingFilter selects config findings. Status is open (the
// default), resolved or all; Severity and Category are one value or
// several, comma-separated.
type ConfigFindingFilter struct {
	AssetID  int64
	Status   string
	Severity string
	Category string
	Page
}

func (f ConfigFindingFilter) where() (*where, error) {
	w := &where{}
	switch f.Status {
	case "", "open":
		w.add("c.status = ?", "open")
	case "resolved":
		w.add("c.status = ?", "resolved")
	case "all":
	default:
		return nil, fmt.Errorf("status must be open, resolved or all: %w", ErrInvalid)
	}
	if f.Severity != "" {
		for _, s := range strings.Split(f.Severity, ",") {
			if !model.ValidConfigSeverity(s) {
				return nil, fmt.Errorf("severity must be high, medium, low or info, or several comma-separated: %w", ErrInvalid)
			}
		}
		w.add("c.severity = ANY(?)", strings.Split(f.Severity, ","))
	}
	if f.Category != "" {
		for _, c := range strings.Split(f.Category, ",") {
			switch c {
			case model.ConfigAgentHook, model.ConfigSSH, model.ConfigCI, model.ConfigAttackTool:
			default:
				return nil, fmt.Errorf("category must be agent_hook, ssh, ci or attack_tool, or several comma-separated: %w", ErrInvalid)
			}
		}
		w.add("c.category = ANY(?)", strings.Split(f.Category, ","))
	}
	if f.AssetID > 0 {
		w.add("c.asset_id = ?", f.AssetID)
	}
	return w, nil
}

func withDoc(fs []ConfigFinding) {
	for i := range fs {
		fs[i].DocURL = ConfigRuleDoc(fs[i].Rule)
	}
}

// ListConfigFindings lists config findings, most severe first.
func (s *Store) ListConfigFindings(ctx context.Context, f ConfigFindingFilter) ([]ConfigFinding, int64, error) {
	w, err := f.where()
	if err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+configCols+`, count(*) OVER ()`+configFrom+w.sql()+andMerged(w)+
		fmt.Sprintf(` ORDER BY c.status DESC, array_position(ARRAY['high','medium','low','info'], c.severity), c.first_seen DESC, c.id
		LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	type counted struct {
		ConfigFinding
		Total int64
	}
	page, err := pgx.CollectRows(rows, pgx.RowToStructByPos[counted])
	if err != nil {
		return nil, 0, err
	}
	out := make([]ConfigFinding, len(page))
	var total int64
	for i, c := range page {
		out[i], total = c.ConfigFinding, c.Total
	}
	withDoc(out)
	return out, total, nil
}

// GetConfigFinding returns one config finding.
func (s *Store) GetConfigFinding(ctx context.Context, id int64) (*ConfigFinding, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+configCols+configFrom+` WHERE c.id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[ConfigFinding])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	c.DocURL = ConfigRuleDoc(c.Rule)
	return &c, err
}

// ConfigSummary counts open config findings by severity and category,
// for the page's summary strip.
type ConfigSummary struct {
	BySeverity    map[string]int64 `json:"by_severity"`
	ByCategory    map[string]int64 `json:"by_category"`
	ScannedAssets int64            `json:"scanned_assets"`
}

// SummariseConfigFindings counts the open findings of one asset, or all.
func (s *Store) SummariseConfigFindings(ctx context.Context, assetID int64) (ConfigSummary, error) {
	out := ConfigSummary{BySeverity: map[string]int64{}, ByCategory: map[string]int64{}}
	for _, sev := range configSeverities {
		out.BySeverity[sev] = 0
	}
	for _, c := range []string{model.ConfigAgentHook, model.ConfigSSH, model.ConfigCI, model.ConfigAttackTool} {
		out.ByCategory[c] = 0
	}
	w, err := ConfigFindingFilter{AssetID: assetID}.where()
	if err != nil {
		return out, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT c.severity, c.category, count(*)`+configFrom+w.sql()+andMerged(w)+
		` GROUP BY c.severity, c.category`, w.args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev, cat string
		var n int64
		if err := rows.Scan(&sev, &cat, &n); err != nil {
			return out, err
		}
		out.BySeverity[sev] += n
		out.ByCategory[cat] += n
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	q := `SELECT count(DISTINCT cs.asset_id) FROM config_scans cs JOIN assets a ON a.id = cs.asset_id WHERE a.merged_into IS NULL`
	args := []any{}
	if assetID > 0 {
		q += ` AND cs.asset_id = $1`
		args = append(args, assetID)
	}
	err = s.Pool.QueryRow(ctx, q, args...).Scan(&out.ScannedAssets)
	return out, err
}

// DismissConfigFinding marks a finding dismissed (a key that is meant to
// be there): it stays dismissed whatever later scans see.
func (s *Store) DismissConfigFinding(ctx context.Context, id int64, userID *int64, note string) (*ConfigFinding, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE config_findings SET status = 'resolved', resolution = 'dismissed', resolution_note = $2,
		resolved_by = $3, resolved_at = now() WHERE id = $1`, id, note, userID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetConfigFinding(ctx, id)
}

// UndismissConfigFinding opens a dismissed finding again. One resolved as
// gone stays resolved: only a scan can say it is back.
func (s *Store) UndismissConfigFinding(ctx context.Context, id int64) (*ConfigFinding, error) {
	c, err := s.GetConfigFinding(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.Resolution != "dismissed" {
		return nil, fmt.Errorf("only a dismissed finding can be opened again: %w", ErrConflict)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE config_findings SET status = 'open', resolution = '', resolution_note = '', resolved_by = NULL,
		resolved_at = NULL WHERE id = $1 AND resolution = 'dismissed'`, id); err != nil {
		return nil, err
	}
	return s.GetConfigFinding(ctx, id)
}

// ConfigFindingAssets returns the assets of the given findings, for role
// checks on project grants.
func (s *Store) ConfigFindingAssets(ctx context.Context, ids ...int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT asset_id FROM config_findings WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// ConfigScan is the last config check one collector made of an asset.
type ConfigScan struct {
	CollectorID string    `json:"collector_id"`
	Complete    bool      `json:"complete"`
	Reason      string    `json:"reason"`
	Found       int       `json:"found"`
	ScannedAt   time.Time `json:"scanned_at"`
	// CollectorVersion is the version that collector recorded on the
	// asset's latest complete collection ("" when none).
	CollectorVersion string `json:"collector_version"`
}

// ConfigScans returns the last config check of an asset by each collector.
// None means it was never checked, which is not the same as clean.
func (s *Store) ConfigScans(ctx context.Context, assetID int64) ([]ConfigScan, error) {
	rows, err := s.Pool.Query(ctx, `SELECT s.collector_id, s.complete, s.reason, s.found, s.scanned_at,
		  COALESCE((SELECT c.collector_version FROM collections c WHERE c.asset_id = s.asset_id AND c.collector_id = s.collector_id
		    AND c.complete ORDER BY c.received_at DESC, c.id DESC LIMIT 1), '')
		FROM config_scans s WHERE s.asset_id = $1 ORDER BY s.collector_id`, assetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ConfigScan])
}

// maxConfigDetail bounds the titles and files an incident's detail lists.
const maxConfigDetail = 10

// configProblems is one incident per asset with open high config
// findings. Medium, low and info ones are listed, never alerted on.
func (s *Store) configProblems(ctx context.Context) ([]SystemIncident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.kind, a.owner_team_id, a.environment, count(*),
		  array_agg(DISTINCT c.title), (array_agg(c.path || ':' || c.line ORDER BY c.path, c.line))[1:$1],
		  (array_agg(c.why ORDER BY c.first_seen, c.id))[1]
		FROM config_findings c JOIN assets a ON a.id = c.asset_id
		WHERE c.status = 'open' AND c.severity = 'high' AND a.merged_into IS NULL
		GROUP BY a.id ORDER BY a.id`, maxConfigDetail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SystemIncident
	for rows.Next() {
		var id int64
		var name, kind, env, why string
		var team *int64
		var n int
		var titles, files []string
		if err := rows.Scan(&id, &name, &kind, &team, &env, &n, &titles, &files, &why); err != nil {
			return nil, err
		}
		sort.Strings(titles)
		if len(titles) > maxConfigDetail {
			titles = titles[:maxConfigDetail]
		}
		title := fmt.Sprintf("%d risky settings on %s", n, name)
		if n == 1 {
			title = titles[0] + " on " + name
		}
		det := map[string]any{"asset_id": id, "asset_name": name, "asset_kind": kind, "count": n, "titles": titles, "files": files, "why": why}
		if env != "" {
			det["environments"] = []string{env}
		}
		out = append(out, SystemIncident{Kind: "config", Key: fmt.Sprintf("asset:%d", id), OwnerTeamID: team, Title: title,
			Priority: "P2", Detail: det})
	}
	return out, rows.Err()
}
