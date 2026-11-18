package store

// AI assistant configuration: risky settings collectors found in the files
// AI coding assistants read from a project (migration 0114,
// internal/collect/assistantcfg).

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

// AssistantFinding is one risky assistant setting as stored.
type AssistantFinding struct {
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
	Tool           string     `json:"tool"`
	Setting        string     `json:"setting"`
	Command        string     `json:"command"`
	Severity       string     `json:"severity"`
	Status         string     `json:"status"`
	Resolution     string     `json:"resolution"`
	ResolutionNote string     `json:"resolution_note"`
	ResolvedBy     *int64     `json:"resolved_by"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AssetOwnerTeam string     `json:"asset_owner_team"`
	// Why says in one line what the setting does and what to do
	// (AssistantWhy), the same wherever it is shown.
	Why string `json:"why" db:"-"`
}

// AssistantWhy is the one-line reason a finding matters and what to do,
// by its rule.
func AssistantWhy(rule string) string {
	switch rule {
	case "remote-code":
		return "Runs on its own on every developer's machine that opens this project with the assistant, and runs code " +
			"downloaded from the internet with their access. Unless your team added it on purpose, treat the repository as " +
			"tampered with: remove the setting, find who changed the file, and check machines that ran it."
	case "network":
		return "Runs on its own and contacts a server, which can send out code or data from the developer's machine. " +
			"Check that the destination is yours and the command is what the team intended."
	case "mcp-from-url":
		return "The assistant installs and runs this MCP server from a Git repository or URL each time it starts, so whoever " +
			"controls that source controls code on developers' machines. Use a reviewed package pinned to a version."
	case "api-redirect":
		return "Sends the assistant's requests, with the code in them and its API key, to another host. Check that the host is " +
			"your own gateway; otherwise remove the setting and rotate the key."
	case "mcp-unpinned":
		return "Starts the newest version of the package each time, so a compromised release runs without review. Pin a version."
	case "auto-approve":
		return "Lets the assistant start the project's MCP servers or run tools without asking, so a change to the project " +
			"decides what runs. Prefer approving them one by one."
	case "auto-task":
		return "Runs as soon as the folder is opened in the editor, before anyone reads it. Check that it is what the team intended."
	}
	return "Check that this setting is what the team intended."
}

func withAssistantWhy(fs []AssistantFinding) {
	for i := range fs {
		fs[i].Why = AssistantWhy(fs[i].Rule)
	}
}

const assistantFindingCols = `f.id, f.asset_id, a.name, a.kind, f.collector_id, f.fingerprint, f.path, f.line, f.rule, f.title, f.tool,
	f.setting, f.command, f.severity, f.status, f.resolution, f.resolution_note, f.resolved_by, f.first_seen, f.last_seen,
	f.resolved_at, COALESCE(ot.name, '')`

const assistantFindingFrom = ` FROM assistant_findings f JOIN assets a ON a.id = f.asset_id LEFT JOIN teams ot ON ot.id = a.owner_team_id`

// writeAssistant stores a batch's assistant configuration scan: found
// settings are added or seen again, and when the scan was complete the
// collector's open findings on the asset it no longer saw are resolved as
// gone. A dismissed finding stays dismissed.
func writeAssistant(ctx context.Context, tx pgx.Tx, assetID, collectionID int64, b *model.ObservationBatch) (found int, gone int64, err error) {
	sc := b.AssistantConfig
	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE assistant_in (fingerprint text, path text, line int, rule text, title text,
		tool text, setting text, command text, severity text) ON COMMIT DROP`); err != nil {
		return 0, 0, err
	}
	rows := make([][]any, 0, len(sc.Found))
	for _, f := range sc.Found {
		rows = append(rows, []any{f.Fingerprint, f.Path, f.Line, f.Rule, f.Title, f.Tool, f.Setting, f.Command, f.Severity})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"assistant_in"},
		[]string{"fingerprint", "path", "line", "rule", "title", "tool", "setting", "command", "severity"}, pgx.CopyFromRows(rows)); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO assistant_findings AS f (asset_id, collector_id, fingerprint, path, line, rule, title, tool,
			setting, command, severity, first_seen, last_seen, last_collection_id)
		SELECT DISTINCT ON (fingerprint, path) $1, $2, fingerprint, path, line, rule, title, tool, setting, command, severity, $3, $3, $4
		FROM assistant_in
		ORDER BY fingerprint, path, array_position(ARRAY['critical','high','medium','low'], severity), line
		ON CONFLICT (asset_id, collector_id, fingerprint, path) DO UPDATE SET
		  line = EXCLUDED.line, title = EXCLUDED.title, tool = EXCLUDED.tool, severity = EXCLUDED.severity,
		  last_seen = GREATEST(f.last_seen, EXCLUDED.last_seen), last_collection_id = EXCLUDED.last_collection_id,
		  status = CASE WHEN f.resolution = 'dismissed' THEN f.status ELSE 'open' END,
		  resolution = CASE WHEN f.resolution = 'dismissed' THEN f.resolution ELSE '' END,
		  resolution_note = CASE WHEN f.resolution = 'dismissed' THEN f.resolution_note ELSE '' END,
		  resolved_by = CASE WHEN f.resolution = 'dismissed' THEN f.resolved_by END,
		  resolved_at = CASE WHEN f.resolution = 'dismissed' THEN f.resolved_at END`,
		assetID, b.Collector.ID, b.ObservedAt, collectionID); err != nil {
		return 0, 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO assistant_scans (asset_id, collector_id, complete, reason, files, found, scanned_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (asset_id, collector_id) DO UPDATE SET complete = EXCLUDED.complete, reason = EXCLUDED.reason,
		  files = EXCLUDED.files, found = EXCLUDED.found, scanned_at = EXCLUDED.scanned_at`,
		assetID, b.Collector.ID, sc.Complete, sc.Reason, sc.Files, len(sc.Found), b.ObservedAt); err != nil {
		return 0, 0, err
	}
	if sc.Complete {
		tag, err := tx.Exec(ctx, `UPDATE assistant_findings SET status = 'resolved', resolution = 'gone', resolved_at = $3
			WHERE asset_id = $1 AND collector_id = $2 AND status = 'open' AND last_collection_id IS DISTINCT FROM $4`,
			assetID, b.Collector.ID, b.ObservedAt, collectionID)
		if err != nil {
			return 0, 0, err
		}
		gone = tag.RowsAffected()
	}
	return len(sc.Found), gone, nil
}

// AssistantFilter selects assistant findings. Status is open (the
// default), resolved or all; Severity is one severity or several,
// comma-separated.
type AssistantFilter struct {
	AssetID  int64
	Status   string
	Severity string
	Page
}

func (f AssistantFilter) where() (*where, error) {
	w := &where{}
	switch f.Status {
	case "", "open":
		w.add("f.status = ?", "open")
	case "resolved":
		w.add("f.status = ?", "resolved")
	case "all":
	default:
		return nil, fmt.Errorf("status must be open, resolved or all: %w", ErrInvalid)
	}
	if f.Severity != "" {
		sevs := strings.Split(f.Severity, ",")
		for _, s := range sevs {
			switch s {
			case "critical", "high", "medium", "low":
			default:
				return nil, fmt.Errorf("severity must be critical, high, medium or low: %w", ErrInvalid)
			}
		}
		w.add("f.severity = ANY(?)", sevs)
	}
	if f.AssetID > 0 {
		w.add("f.asset_id = ?", f.AssetID)
	}
	w.conds = append(w.conds, "a.merged_into IS NULL")
	return w, nil
}

// ListAssistantFindings lists assistant findings, open and most severe
// first.
func (s *Store) ListAssistantFindings(ctx context.Context, f AssistantFilter) ([]AssistantFinding, int64, error) {
	w, err := f.where()
	if err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+assistantFindingCols+`, count(*) OVER ()`+assistantFindingFrom+w.sql()+
		fmt.Sprintf(` ORDER BY f.status DESC, array_position(ARRAY['critical','high','medium','low'], f.severity), f.first_seen DESC, f.id
		LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	type counted struct {
		AssistantFinding
		Total int64
	}
	page, err := pgx.CollectRows(rows, pgx.RowToStructByPos[counted])
	if err != nil {
		return nil, 0, err
	}
	out := make([]AssistantFinding, len(page))
	var total int64
	for i, c := range page {
		out[i], total = c.AssistantFinding, c.Total
	}
	withAssistantWhy(out)
	return out, total, nil
}

// GetAssistantFinding returns one assistant finding.
func (s *Store) GetAssistantFinding(ctx context.Context, id int64) (*AssistantFinding, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+assistantFindingCols+assistantFindingFrom+` WHERE f.id = $1`, id)
	if err != nil {
		return nil, err
	}
	f, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[AssistantFinding])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f.Why = AssistantWhy(f.Rule)
	return &f, nil
}

// DismissAssistantFinding marks a finding dismissed (a setting the team
// means to keep): it stays dismissed whatever later scans see.
func (s *Store) DismissAssistantFinding(ctx context.Context, id int64, userID *int64, note string) (*AssistantFinding, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE assistant_findings SET status = 'resolved', resolution = 'dismissed', resolution_note = $2,
		resolved_by = $3, resolved_at = now() WHERE id = $1`, id, note, userID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetAssistantFinding(ctx, id)
}

// UndismissAssistantFinding opens a dismissed finding again. One resolved
// as gone stays resolved: only a scan can say it is back.
func (s *Store) UndismissAssistantFinding(ctx context.Context, id int64) (*AssistantFinding, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE assistant_findings SET status = 'open', resolution = '', resolution_note = '',
		resolved_by = NULL, resolved_at = NULL WHERE id = $1 AND resolution = 'dismissed'`, id)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		if _, err := s.GetAssistantFinding(ctx, id); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("only a dismissed finding can be opened again: %w", ErrConflict)
	}
	return s.GetAssistantFinding(ctx, id)
}

// AssistantFindingAssets returns the assets of the given findings, for
// role checks on project grants.
func (s *Store) AssistantFindingAssets(ctx context.Context, ids ...int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT asset_id FROM assistant_findings WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// AssistantScan is the last assistant configuration scan one collector
// made of an asset.
type AssistantScan struct {
	CollectorID string    `json:"collector_id"`
	Complete    bool      `json:"complete"`
	Reason      string    `json:"reason"`
	Files       int       `json:"files"`
	Found       int       `json:"found"`
	ScannedAt   time.Time `json:"scanned_at"`
}

// AssistantScans returns the last scan of an asset by each collector.
// None means the asset was never scanned, which is not the same as clean.
func (s *Store) AssistantScans(ctx context.Context, assetID int64) ([]AssistantScan, error) {
	rows, err := s.Pool.Query(ctx, `SELECT collector_id, complete, reason, files, found, scanned_at FROM assistant_scans
		WHERE asset_id = $1 ORDER BY collector_id`, assetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[AssistantScan])
}

// AssistantScannedAssets counts the assets a collector has scanned for
// assistant configuration. None means an empty list proves nothing.
func (s *Store) AssistantScannedAssets(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(DISTINCT sc.asset_id) FROM assistant_scans sc JOIN assets a ON a.id = sc.asset_id
		WHERE a.merged_into IS NULL`).Scan(&n)
	return n, err
}

// assistantProblems is one incident per asset with open critical or high
// assistant findings. Medium and low ones are listed, never alerted on.
func (s *Store) assistantProblems(ctx context.Context) ([]SystemIncident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.kind, a.owner_team_id, a.environment,
		  count(*), count(*) FILTER (WHERE f.severity = 'critical'), array_agg(DISTINCT f.title),
		  (array_agg(f.path || ':' || f.line ORDER BY array_position(ARRAY['critical','high'], f.severity), f.path, f.line))[1:$1],
		  (array_agg(f.rule ORDER BY array_position(ARRAY['critical','high'], f.severity), f.path, f.line))[1]
		FROM assistant_findings f JOIN assets a ON a.id = f.asset_id
		WHERE f.status = 'open' AND f.severity IN ('critical', 'high') AND a.merged_into IS NULL
		GROUP BY a.id ORDER BY a.id`, maxLeakDetail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SystemIncident
	for rows.Next() {
		var id int64
		var name, kind, env, rule string
		var team *int64
		var n, critical int
		var titles, files []string
		if err := rows.Scan(&id, &name, &kind, &team, &env, &n, &critical, &titles, &files, &rule); err != nil {
			return nil, err
		}
		sort.Strings(titles)
		title := fmt.Sprintf("%d risky AI assistant settings in %s", n, name)
		if n == 1 {
			title = "AI assistant setting on " + name + ": " + strings.ToLower(titles[0][:1]) + titles[0][1:]
		}
		pri := "P2"
		if critical > 0 {
			pri = "P1"
		}
		det := map[string]any{"asset_id": id, "asset_name": name, "asset_kind": kind, "count": n, "critical": critical,
			"titles": titles, "files": files, "why": AssistantWhy(rule)}
		if env != "" {
			det["environments"] = []string{env}
		}
		out = append(out, SystemIncident{Kind: "assistant", Key: fmt.Sprintf("asset:%d", id), OwnerTeamID: team, Title: title,
			Priority: pri, Detail: det})
	}
	return out, rows.Err()
}
