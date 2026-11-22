package store

// Code findings: what code-review security scanners found in a
// repository's source, imported from their reports (migration 0121,
// internal/codefindings): deepsec's JSON export and SARIF. They sit next to
// the dependency, host and image findings of the same asset. The source's
// own verdict (deepsec's revalidation, a SARIF suppression) is kept; one
// that says there is nothing to do resolves the finding and never alerts.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/codefindings"
)

// CodeFinding is one code finding as stored.
type CodeFinding struct {
	ID             int64      `json:"id"`
	AssetID        int64      `json:"asset_id"`
	AssetName      string     `json:"asset_name"`
	AssetKind      string     `json:"asset_kind"`
	Source         string     `json:"source"`
	Fingerprint    string     `json:"fingerprint"`
	Rule           string     `json:"rule"`
	Category       string     `json:"category"`
	Title          string     `json:"title"`
	Severity       string     `json:"severity"`
	Path           string     `json:"path"`
	StartLine      int        `json:"start_line"`
	EndLine        int        `json:"end_line"`
	Description    string     `json:"description"`
	Recommendation string     `json:"recommendation"`
	Confidence     string     `json:"confidence"`
	Verdict        string     `json:"verdict"`
	VerdictNote    string     `json:"verdict_note"`
	Tool           string     `json:"tool"`
	ToolVersion    string     `json:"tool_version"`
	Model          string     `json:"model"`
	RunID          string     `json:"run_id"`
	Status         string     `json:"status"`
	Resolution     string     `json:"resolution"`
	ResolutionNote string     `json:"resolution_note"`
	ResolvedBy     *int64     `json:"resolved_by"`
	FirstSeen      time.Time  `json:"first_seen"`
	LastSeen       time.Time  `json:"last_seen"`
	ResolvedAt     *time.Time `json:"resolved_at"`
}

const codeCols = `c.id, c.asset_id, a.name, a.kind, c.source, c.fingerprint, c.rule, c.category, c.title, c.severity, c.path,
	c.start_line, c.end_line, c.description, c.recommendation, c.confidence, c.verdict, c.verdict_note, c.tool, c.tool_version,
	c.model, c.run_id, c.status, c.resolution, c.resolution_note, c.resolved_by, c.first_seen, c.last_seen, c.resolved_at`

const codeFrom = ` FROM code_findings c JOIN assets a ON a.id = c.asset_id`

const codeSeverityOrder = `array_position(ARRAY['critical','high','medium','low','info'], c.severity)`

// CodeImport is what one import of a report did, per source.
type CodeImport struct {
	Source string `json:"source"`
	Tool   string `json:"tool"`
	// Found is how many findings the report held for this source (after
	// merging repeats), Open how many of them are open, Closed how many
	// its verdict resolved, Gone how many open ones it no longer has.
	Found   int   `json:"found"`
	Open    int   `json:"open"`
	Closed  int   `json:"closed"`
	New     int   `json:"new"`
	Gone    int64 `json:"gone"`
	Skipped int   `json:"skipped"`
}

// CodeImportResult is the answer to an import.
type CodeImportResult struct {
	AssetID  int64        `json:"asset_id"`
	Format   string       `json:"format"`
	Complete bool         `json:"complete"`
	Sources  []CodeImport `json:"sources"`
}

// ImportCodeFindings stores a parsed report's findings on an asset. Each
// run replaces its source's findings: found ones are added or updated
// (a dismissed one stays dismissed), and when complete, the source's open
// findings the report no longer has are resolved as gone. A finding whose
// verdict closes it is stored resolved ('verdict'); a later report that
// opens it again (say, a new revalidation) opens it again.
func (s *Store) ImportCodeFindings(ctx context.Context, assetID int64, rep *codefindings.Report, model string, complete bool) (*CodeImportResult, error) {
	out := &CodeImportResult{AssetID: assetID, Format: rep.Format, Complete: complete, Sources: []CodeImport{}}
	now := time.Now().UTC()
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		for _, run := range rep.Runs {
			// One import of a source on an asset at a time.
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('code_findings:' || $1::bigint || ':' || $2::text, 0))`,
				assetID, run.Source); err != nil {
				return err
			}
			res, err := writeCodeRun(ctx, tx, assetID, run, rep.Format, model, complete, now)
			if err != nil {
				return err
			}
			out.Sources = append(out.Sources, res)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func writeCodeRun(ctx context.Context, tx pgx.Tx, assetID int64, run codefindings.Run, format, model string, complete bool, now time.Time) (CodeImport, error) {
	res := CodeImport{Source: run.Source, Tool: run.Tool, Skipped: run.Skipped}
	// Repeats of one finding in a report (same fingerprint) are one: the
	// most severe, with every line they cover.
	byFP := map[string]codefindings.Finding{}
	rank := func(sev string) int {
		for i, v := range codefindings.Severities {
			if v == sev {
				return i
			}
		}
		return len(codefindings.Severities)
	}
	for _, f := range run.Findings {
		prev, ok := byFP[f.Fingerprint]
		if !ok {
			byFP[f.Fingerprint] = f
			continue
		}
		if rank(f.Severity) < rank(prev.Severity) {
			f.StartLine, f.EndLine = minLine(f.StartLine, prev.StartLine), max(f.EndLine, prev.EndLine)
			byFP[f.Fingerprint] = f
		} else {
			prev.StartLine, prev.EndLine = minLine(f.StartLine, prev.StartLine), max(f.EndLine, prev.EndLine)
			byFP[f.Fingerprint] = prev
		}
	}
	fps := make([]string, 0, len(byFP))
	for fp := range byFP {
		fps = append(fps, fp)
	}
	sort.Strings(fps)

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE code_in (fingerprint text, rule text, category text, title text, severity text,
		path text, start_line int, end_line int, description text, recommendation text, confidence text, verdict text,
		verdict_note text, closed boolean) ON COMMIT DROP`); err != nil {
		return res, err
	}
	rows := make([][]any, 0, len(fps))
	for _, fp := range fps {
		f := byFP[fp]
		closed := codefindings.Closed(f.Verdict)
		if closed {
			res.Closed++
		} else {
			res.Open++
		}
		rows = append(rows, []any{f.Fingerprint, f.Rule, f.Category, f.Title, f.Severity, f.Path, f.StartLine, f.EndLine,
			f.Description, f.Recommendation, f.Confidence, f.Verdict, f.VerdictNote, closed})
	}
	res.Found = len(rows)
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"code_in"}, []string{"fingerprint", "rule", "category", "title", "severity", "path",
		"start_line", "end_line", "description", "recommendation", "confidence", "verdict", "verdict_note", "closed"},
		pgx.CopyFromRows(rows)); err != nil {
		return res, err
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM code_in i WHERE NOT EXISTS (SELECT 1 FROM code_findings c
		WHERE c.asset_id = $1 AND c.source = $2 AND c.fingerprint = i.fingerprint)`, assetID, run.Source).Scan(&res.New); err != nil {
		return res, err
	}
	// status/resolution: dismissed stays dismissed; otherwise the verdict
	// decides (closed: resolved 'verdict', else open).
	if _, err := tx.Exec(ctx, `INSERT INTO code_findings AS c (asset_id, source, fingerprint, rule, category, title, severity, path,
			start_line, end_line, description, recommendation, confidence, verdict, verdict_note, tool, tool_version, model, run_id,
			status, resolution, resolved_at, first_seen, last_seen)
		SELECT $1, $2, fingerprint, rule, category, title, severity, path, start_line, end_line, description, recommendation,
			confidence, verdict, verdict_note, $3, $4, $5, $6,
			CASE WHEN closed THEN 'resolved' ELSE 'open' END, CASE WHEN closed THEN 'verdict' ELSE '' END,
			CASE WHEN closed THEN $7::timestamptz END, $7, $7
		FROM code_in
		ON CONFLICT (asset_id, source, fingerprint) DO UPDATE SET
		  rule = EXCLUDED.rule, category = EXCLUDED.category, title = EXCLUDED.title, severity = EXCLUDED.severity,
		  path = EXCLUDED.path, start_line = EXCLUDED.start_line, end_line = EXCLUDED.end_line, description = EXCLUDED.description,
		  recommendation = EXCLUDED.recommendation, confidence = EXCLUDED.confidence, verdict = EXCLUDED.verdict,
		  verdict_note = EXCLUDED.verdict_note, tool = EXCLUDED.tool, tool_version = EXCLUDED.tool_version, model = EXCLUDED.model,
		  run_id = EXCLUDED.run_id, last_seen = GREATEST(c.last_seen, EXCLUDED.last_seen),
		  status = CASE WHEN c.resolution = 'dismissed' THEN c.status ELSE EXCLUDED.status END,
		  resolution = CASE WHEN c.resolution = 'dismissed' THEN c.resolution ELSE EXCLUDED.resolution END,
		  resolution_note = CASE WHEN c.resolution = 'dismissed' THEN c.resolution_note ELSE '' END,
		  resolved_by = CASE WHEN c.resolution = 'dismissed' THEN c.resolved_by END,
		  resolved_at = CASE WHEN c.resolution = 'dismissed' THEN c.resolved_at
		                     WHEN EXCLUDED.status = 'resolved' THEN COALESCE(CASE WHEN c.resolution = 'verdict' THEN c.resolved_at END, EXCLUDED.resolved_at)
		                END`,
		assetID, run.Source, run.Tool, run.ToolVersion, model, run.RunID, now); err != nil {
		return res, err
	}
	if complete {
		tag, err := tx.Exec(ctx, `UPDATE code_findings c SET status = 'resolved', resolution = 'gone', resolved_at = $3
			WHERE c.asset_id = $1 AND c.source = $2 AND c.status = 'open'
			  AND NOT EXISTS (SELECT 1 FROM code_in i WHERE i.fingerprint = c.fingerprint)`, assetID, run.Source, now)
		if err != nil {
			return res, err
		}
		res.Gone = tag.RowsAffected()
	}
	if _, err := tx.Exec(ctx, `DROP TABLE code_in`); err != nil {
		return res, err
	}
	_, err := tx.Exec(ctx, `INSERT INTO code_imports (asset_id, source, format, tool, tool_version, model, run_id, complete, found, imported_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (asset_id, source) DO UPDATE SET format = EXCLUDED.format, tool = EXCLUDED.tool, tool_version = EXCLUDED.tool_version,
		  model = EXCLUDED.model, run_id = EXCLUDED.run_id, complete = EXCLUDED.complete, found = EXCLUDED.found,
		  imported_at = EXCLUDED.imported_at`,
		assetID, run.Source, format, run.Tool, run.ToolVersion, model, run.RunID, complete, res.Found, now)
	return res, err
}

func minLine(a, b int) int {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	return min(a, b)
}

// CodeFindingFilter selects code findings. Status is open (the default),
// resolved or all; Severity, Category and Verdict are one value or several,
// comma-separated; Source is one source.
type CodeFindingFilter struct {
	AssetID  int64
	Status   string
	Severity string
	Category string
	Source   string
	Page
}

func (f CodeFindingFilter) where() (*where, error) {
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
			if !codefindings.ValidSeverity(s) {
				return nil, fmt.Errorf("severity must be critical, high, medium, low or info, or several comma-separated: %w", ErrInvalid)
			}
		}
		w.add("c.severity = ANY(?)", strings.Split(f.Severity, ","))
	}
	if f.Category != "" {
		for _, c := range strings.Split(f.Category, ",") {
			switch c {
			case codefindings.CategorySecurity, codefindings.CategoryBug, codefindings.CategoryOther:
			default:
				return nil, fmt.Errorf("category must be security, bug or other, or several comma-separated: %w", ErrInvalid)
			}
		}
		w.add("c.category = ANY(?)", strings.Split(f.Category, ","))
	}
	if f.Source != "" {
		w.add("c.source = ?", f.Source)
	}
	if f.AssetID > 0 {
		w.add("c.asset_id = ?", f.AssetID)
	}
	return w, nil
}

// ListCodeFindings lists code findings, most severe first.
func (s *Store) ListCodeFindings(ctx context.Context, f CodeFindingFilter) ([]CodeFinding, int64, error) {
	w, err := f.where()
	if err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+codeCols+`, count(*) OVER ()`+codeFrom+w.sql()+andMerged(w)+
		fmt.Sprintf(` ORDER BY c.status DESC, CASE c.category WHEN 'security' THEN 0 ELSE 1 END, `+codeSeverityOrder+`, c.first_seen DESC, c.id
		LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	type counted struct {
		CodeFinding
		Total int64
	}
	page, err := pgx.CollectRows(rows, pgx.RowToStructByPos[counted])
	if err != nil {
		return nil, 0, err
	}
	out := make([]CodeFinding, len(page))
	var total int64
	for i, c := range page {
		out[i], total = c.CodeFinding, c.Total
	}
	return out, total, nil
}

// GetCodeFinding returns one code finding.
func (s *Store) GetCodeFinding(ctx context.Context, id int64) (*CodeFinding, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+codeCols+codeFrom+` WHERE c.id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[CodeFinding])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &c, err
}

// CodeSummary counts open code findings by severity and category, and the
// assets with an import.
type CodeSummary struct {
	BySeverity     map[string]int64 `json:"by_severity"`
	ByCategory     map[string]int64 `json:"by_category"`
	ImportedAssets int64            `json:"imported_assets"`
}

// SummariseCodeFindings counts the open findings of one asset, or all.
func (s *Store) SummariseCodeFindings(ctx context.Context, assetID int64) (CodeSummary, error) {
	out := CodeSummary{BySeverity: map[string]int64{}, ByCategory: map[string]int64{}}
	for _, sev := range codefindings.Severities {
		out.BySeverity[sev] = 0
	}
	for _, c := range []string{codefindings.CategorySecurity, codefindings.CategoryBug, codefindings.CategoryOther} {
		out.ByCategory[c] = 0
	}
	w, err := CodeFindingFilter{AssetID: assetID}.where()
	if err != nil {
		return out, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT c.severity, c.category, count(*)`+codeFrom+w.sql()+andMerged(w)+
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
	q := `SELECT count(DISTINCT ci.asset_id) FROM code_imports ci JOIN assets a ON a.id = ci.asset_id WHERE a.merged_into IS NULL`
	args := []any{}
	if assetID > 0 {
		q += ` AND ci.asset_id = $1`
		args = append(args, assetID)
	}
	err = s.Pool.QueryRow(ctx, q, args...).Scan(&out.ImportedAssets)
	return out, err
}

// CodeImportRecord is the last import of one source on an asset.
type CodeImportRecord struct {
	Source      string    `json:"source"`
	Format      string    `json:"format"`
	Tool        string    `json:"tool"`
	ToolVersion string    `json:"tool_version"`
	Model       string    `json:"model"`
	RunID       string    `json:"run_id"`
	Complete    bool      `json:"complete"`
	Found       int       `json:"found"`
	ImportedAt  time.Time `json:"imported_at"`
}

// CodeImports returns the last import of each source on an asset. None
// means no report was imported, which is not the same as clean.
func (s *Store) CodeImports(ctx context.Context, assetID int64) ([]CodeImportRecord, error) {
	rows, err := s.Pool.Query(ctx, `SELECT source, format, tool, tool_version, model, run_id, complete, found, imported_at
		FROM code_imports WHERE asset_id = $1 ORDER BY source`, assetID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[CodeImportRecord])
}

// DismissCodeFinding marks a finding dismissed: it stays dismissed
// whatever later imports say.
func (s *Store) DismissCodeFinding(ctx context.Context, id int64, userID *int64, note string) (*CodeFinding, error) {
	tag, err := s.Pool.Exec(ctx, `UPDATE code_findings SET status = 'resolved', resolution = 'dismissed', resolution_note = $2,
		resolved_by = $3, resolved_at = now() WHERE id = $1`, id, note, userID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return s.GetCodeFinding(ctx, id)
}

// UndismissCodeFinding opens a dismissed finding again, or, when its
// source's verdict closes it, puts it back as the source left it. One
// resolved as gone stays resolved: only an import can say it is back.
func (s *Store) UndismissCodeFinding(ctx context.Context, id int64) (*CodeFinding, error) {
	c, err := s.GetCodeFinding(ctx, id)
	if err != nil {
		return nil, err
	}
	if c.Resolution != "dismissed" {
		return nil, fmt.Errorf("only a dismissed finding can be opened again: %w", ErrConflict)
	}
	status, resolution := "open", ""
	if codefindings.Closed(c.Verdict) {
		status, resolution = "resolved", "verdict"
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE code_findings SET status = $2, resolution = $3, resolution_note = '', resolved_by = NULL,
		resolved_at = CASE WHEN $2 = 'resolved' THEN now() END WHERE id = $1 AND resolution = 'dismissed'`, id, status, resolution); err != nil {
		return nil, err
	}
	return s.GetCodeFinding(ctx, id)
}

// LiveAssetID is the asset id, or the asset it was merged into.
func (s *Store) LiveAssetID(ctx context.Context, id int64) (int64, error) {
	var live int64
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(merged_into, id) FROM assets WHERE id = $1`, id).Scan(&live)
	return live, notFound(err)
}

// CodeFindingAssets returns the assets of the given findings, for role
// checks on project grants.
func (s *Store) CodeFindingAssets(ctx context.Context, ids ...int64) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT DISTINCT asset_id FROM code_findings WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// maxCodeDetail bounds the titles and files an incident's detail lists.
const maxCodeDetail = 10

// codeProblems is one incident per asset with open critical or high
// security code findings: P1 when one is critical, P2 otherwise. Bugs,
// other results and lower severities are listed, never alerted on; so is
// anything the source's verdict closed.
func (s *Store) codeProblems(ctx context.Context) ([]SystemIncident, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.kind, a.owner_team_id, a.environment, count(*),
		  bool_or(c.severity = 'critical'), array_agg(DISTINCT c.title),
		  (array_agg(CASE WHEN c.start_line > 0 THEN c.path || ':' || c.start_line ELSE c.path END ORDER BY c.path, c.start_line))[1:$1],
		  array_agg(DISTINCT c.source)
		FROM code_findings c JOIN assets a ON a.id = c.asset_id
		WHERE c.status = 'open' AND c.category = 'security' AND c.severity IN ('critical', 'high') AND a.merged_into IS NULL
		GROUP BY a.id ORDER BY a.id`, maxCodeDetail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SystemIncident
	for rows.Next() {
		var id int64
		var name, kind, env string
		var team *int64
		var n int
		var critical bool
		var titles, files, sources []string
		if err := rows.Scan(&id, &name, &kind, &team, &env, &n, &critical, &titles, &files, &sources); err != nil {
			return nil, err
		}
		sort.Strings(titles)
		if len(titles) > maxCodeDetail {
			titles = titles[:maxCodeDetail]
		}
		title := fmt.Sprintf("%d code findings in %s", n, name)
		if n == 1 {
			title = titles[0] + " in " + name
		}
		prio := "P2"
		if critical {
			prio = "P1"
		}
		det := map[string]any{"asset_id": id, "asset_name": name, "asset_kind": kind, "count": n, "titles": titles, "files": files,
			"sources": sources, "critical": critical}
		if env != "" {
			det["environments"] = []string{env}
		}
		out = append(out, SystemIncident{Kind: "code", Key: fmt.Sprintf("asset:%d", id), OwnerTeamID: team, Title: title,
			Priority: prio, Detail: det})
	}
	return out, rows.Err()
}
