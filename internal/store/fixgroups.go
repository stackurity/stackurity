package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/fixplan"
)

// FixPlanRows loads every open, active finding with what the planner needs.
func (s *Store) FixPlanRows(ctx context.Context) ([]fixplan.Row, error) {
	rows, err := s.Pool.Query(ctx, `SELECT f.id, f.kind, f.key, f.asset_id, a.name, a.kind, a.environment,
		COALESCE(a.attributes->>'os', ''), COALESCE(a.attributes->>'os_version', ''), COALESCE(a.attributes->>'os_name', ''),
		c.id, c.type, CASE WHEN c.namespace = '' OR c.type IN ('deb','rpm','apk') THEN c.name ELSE c.namespace || '/' || c.name END,
		i.version, f.fixed_version, f.priority, f.severity, f.sos,
		COALESCE((f.evidence->>'known_exploited')::boolean, false),
		COALESCE((f.evidence->>'not_running_kernel')::boolean, false),
		COALESCE(f.evidence->>'requires_subscription',
		  CASE WHEN (f.evidence->>'requires_ubuntu_pro')::boolean THEN 'Ubuntu Pro' ELSE '' END),
		COALESCE(i.evidence->>'kind', '') = 'operating-system', f.title
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		JOIN components c ON c.id = f.component_id JOIN inventory i ON i.id = f.inventory_id
		WHERE f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []fixplan.Row
	for rows.Next() {
		var r fixplan.Row
		if err := rows.Scan(&r.FindingID, &r.Kind, &r.Key, &r.AssetID, &r.AssetName, &r.AssetKind, &r.Environment,
			&r.OS, &r.OSVersion, &r.OSName, &r.ComponentID, &r.PurlType, &r.Component, &r.Version, &r.FixedVersion,
			&r.Priority, &r.Severity, &r.SOS, &r.KnownExploited, &r.KernelIdle, &r.Subscription, &r.IsOS, &r.EOLTitle); err != nil {
			return nil, err
		}
		r.RequiresPro = r.Subscription != ""
		out = append(out, r)
	}
	return out, rows.Err()
}

// EndedPackages returns, per asset, the distribution packages past upstream
// end of life on a release that is itself end of life (inventory
// lifecycle_note status distribution_ended), for the release upgrade.
func (s *Store) EndedPackages(ctx context.Context) (map[int64][]fixplan.EndedPackage, error) {
	rows, err := s.Pool.Query(ctx, `SELECT i.asset_id, c.name, COALESCE(i.lifecycle_note->>'subject', '')
		FROM inventory i JOIN components c ON c.id = i.component_id JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		WHERE i.removed_at IS NULL AND i.lifecycle_note->>'status' = 'distribution_ended' ORDER BY i.asset_id, c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64][]fixplan.EndedPackage{}
	for rows.Next() {
		var id int64
		var p fixplan.EndedPackage
		if err := rows.Scan(&id, &p.Component, &p.Subject); err != nil {
			return nil, err
		}
		out[id] = append(out[id], p)
	}
	return out, rows.Err()
}

// ReplaceFixGroups stores the current plan and each finding's group.
func (s *Store) ReplaceFixGroups(ctx context.Context, groups []*fixplan.Group, assign map[int64]string) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Findings resolved since the last plan still name the group they
		// were in: keep which fix closed them, for summaries, before the
		// group is replaced.
		if _, err := tx.Exec(ctx, `UPDATE findings f SET resolved_fix_group = f.fix_group, resolved_fix_title = COALESCE(g.data->>'title', '')
			FROM fix_groups g WHERE g.id = f.fix_group AND f.status = 'resolved' AND f.fix_group <> ''
			  AND f.resolved_fix_group IS DISTINCT FROM f.fix_group`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM fix_groups`); err != nil {
			return err
		}
		rows := make([][]any, 0, len(groups))
		for i, g := range groups {
			d, _ := json.Marshal(g)
			rows = append(rows, []any{g.ID, g.AssetID, g.Kind, d, i})
		}
		// COPY cannot write to a table with row-level security, so rows are
		// staged in a temporary table first.
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE fg_in (id text, asset_id bigint, kind text, data jsonb, sort_order int) ON COMMIT DROP`); err != nil {
			return err
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"fg_in"}, []string{"id", "asset_id", "kind", "data", "sort_order"},
			pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fix_groups (id, asset_id, kind, data, sort_order) SELECT * FROM fg_in`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE fg_assign (finding_id bigint, fix_group text) ON COMMIT DROP`); err != nil {
			return err
		}
		as := make([][]any, 0, len(assign))
		for id, g := range assign {
			as = append(as, []any{id, g})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"fg_assign"}, []string{"finding_id", "fix_group"}, pgx.CopyFromRows(as)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE findings f SET fix_group = a.fix_group FROM fg_assign a
			WHERE a.finding_id = f.id AND f.fix_group IS DISTINCT FROM a.fix_group`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE findings SET fix_group = '' WHERE fix_group <> ''
			AND NOT EXISTS (SELECT 1 FROM fg_assign a WHERE a.finding_id = findings.id)`)
		return err
	})
}

type FixGroupFilter struct {
	AssetID     int64
	Kind        string
	Environment string
	Search      string
	// Bucket keeps the groups of one FixBucket (focus, no_fix, ...).
	Bucket string
	// ProductionEnvs names the production environments (from the risk
	// policy), for the non_production bucket.
	ProductionEnvs []string
	Page
}

// Fix buckets sort every fix group into what needs a person now (focus) or
// the first reason it is left out of that view. Home shows the focus groups
// and counts the others, so nothing is hidden without saying why.
const (
	BucketFocus         = "focus"          // a fix exists, SOS or P1, production or no environment
	BucketNoFix         = "no_fix"         // no free fixed version yet
	BucketOldKernels    = "old_kernels"    // kernels installed but not running
	BucketNonProduction = "non_production" // the asset's environment is not a production one
	BucketLowerPriority = "lower_priority" // P2 to P4 without SOS
)

// FixBuckets lists the buckets in the order the reasons are checked.
var FixBuckets = []string{BucketFocus, BucketNoFix, BucketOldKernels, BucketNonProduction, BucketLowerPriority}

// fixBucketSQL returns the bucket of fix group g as a SQL expression; $n is
// the text[] of production environment names (lower case).
func fixBucketSQL(n int) string {
	return fmt.Sprintf(`CASE
		WHEN g.kind = 'no_fix' THEN 'no_fix'
		WHEN g.kind = 'old_kernels' THEN 'old_kernels'
		WHEN COALESCE(g.data->>'environment', '') <> '' AND NOT (lower(g.data->>'environment') = ANY($%d::text[])) THEN 'non_production'
		WHEN COALESCE((g.data->>'sos')::boolean, false) OR g.data->>'top_priority' = 'P1' THEN 'focus'
		ELSE 'lower_priority' END`, n)
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		out = append(out, strings.ToLower(e))
	}
	return out
}

func (s *Store) ListFixGroups(ctx context.Context, f FixGroupFilter) ([]json.RawMessage, int64, error) {
	w := &where{}
	if f.AssetID > 0 {
		w.add("g.asset_id = ?", f.AssetID)
	}
	if f.Kind != "" {
		w.add("g.kind = ?", f.Kind)
	}
	if f.Environment != "" {
		w.add("g.data->>'environment' = ?", f.Environment)
	}
	if f.Search != "" {
		w.add("(g.data->>'title' ILIKE ? OR g.data->>'asset_name' ILIKE ? OR g.data->>'packages' ILIKE ?)", likeEscape(f.Search))
	}
	if f.Bucket != "" {
		w.args = append(w.args, lowerAll(f.ProductionEnvs))
		w.add(fixBucketSQL(len(w.args))+" = ?", f.Bucket)
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM fix_groups g`+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT g.data FROM fix_groups g`+w.sql()+fmt.Sprintf(` ORDER BY g.sort_order LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
	return out, total, err
}

func (s *Store) GetFixGroup(ctx context.Context, id string) (json.RawMessage, error) {
	var d json.RawMessage
	err := s.Pool.QueryRow(ctx, `SELECT data FROM fix_groups WHERE id = $1`, id).Scan(&d)
	return d, notFound(err)
}

type FixPlanSummary struct {
	Groups       int64                       `json:"groups"`
	Findings     int64                       `json:"findings"`
	ByKind       map[string]map[string]int64 `json:"by_kind"`
	SOS          int64                       `json:"sos"`
	SOSFindings  int64                       `json:"sos_findings"`
	UniqueIssues int64                       `json:"unique_issues"` // distinct keys across all groups
	// FixableFindings counts findings a routine update resolves today
	// (security updates, kernel cleanup, package upgrades), not ones
	// that wait on a release or end-of-life upgrade.
	FixableFindings int64 `json:"fixable_findings"`
}

func (s *Store) SummarizeFixPlan(ctx context.Context, assetID int64) (*FixPlanSummary, error) {
	sum := &FixPlanSummary{ByKind: map[string]map[string]int64{}}
	w := &where{}
	if assetID > 0 {
		w.add("asset_id = ?", assetID)
	}
	rows, err := s.Pool.Query(ctx, `SELECT kind, count(*), sum((data->>'finding_count')::int), count(*) FILTER (WHERE (data->>'sos')::boolean)
		FROM fix_groups`+w.sql()+` GROUP BY kind`, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var groups, findings, sos int64
		if err := rows.Scan(&k, &groups, &findings, &sos); err != nil {
			return nil, err
		}
		sum.ByKind[k] = map[string]int64{"groups": groups, "findings": findings}
		sum.Groups += groups
		sum.Findings += findings
		sum.SOS += sos
		switch k {
		case fixplan.SecurityUpdates, fixplan.OldKernels, fixplan.PackageUpgrade:
			sum.FixableFindings += findings
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	q := `SELECT count(DISTINCT key), count(*) FILTER (WHERE sos) FROM findings WHERE fix_group IS NOT NULL AND status = 'open'`
	var args []any
	if assetID > 0 {
		q += ` AND asset_id = $1`
		args = append(args, assetID)
	}
	err = s.Pool.QueryRow(ctx, q, args...).
		Scan(&sum.UniqueIssues, &sum.SOSFindings)
	return sum, err
}

// FixFocus says how many fix groups need a person now, why the others are
// left out of that view, and which assets the focus groups are on.
type FixFocus struct {
	Groups   int64 `json:"groups"`
	Findings int64 `json:"findings"`
	// Hidden counts groups and findings per bucket other than focus.
	Hidden map[string]map[string]int64 `json:"hidden"`
	Assets []FocusAsset                `json:"assets"`
}

// FocusAsset is an asset with fix groups in the focus bucket.
type FocusAsset struct {
	AssetID   int64  `json:"asset_id"`
	AssetName string `json:"asset_name"`
	Groups    int64  `json:"groups"`
	Findings  int64  `json:"findings"`
}

// SummarizeFixFocus sorts the fix groups into buckets (see FixBuckets).
func (s *Store) SummarizeFixFocus(ctx context.Context, assetID int64, productionEnvs []string) (*FixFocus, error) {
	out := &FixFocus{Hidden: map[string]map[string]int64{}, Assets: []FocusAsset{}}
	args := []any{lowerAll(productionEnvs)}
	cond := ""
	if assetID > 0 {
		args = append(args, assetID)
		cond = " WHERE g.asset_id = $2"
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+fixBucketSQL(1)+` AS bucket, count(*), COALESCE(sum((g.data->>'finding_count')::bigint), 0)
		FROM fix_groups g`+cond+` GROUP BY 1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var b string
		var groups, findings int64
		if err := rows.Scan(&b, &groups, &findings); err != nil {
			rows.Close()
			return nil, err
		}
		if b == BucketFocus {
			out.Groups, out.Findings = groups, findings
			continue
		}
		out.Hidden[b] = map[string]int64{"groups": groups, "findings": findings}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	arows, err := s.Pool.Query(ctx, `SELECT g.asset_id, min(g.data->>'asset_name'), count(*), COALESCE(sum((g.data->>'finding_count')::bigint), 0)
		FROM fix_groups g WHERE `+fixBucketSQL(1)+` = 'focus'`+strings.Replace(cond, " WHERE", " AND", 1)+`
		GROUP BY g.asset_id ORDER BY min(g.sort_order) LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	defer arows.Close()
	for arows.Next() {
		var a FocusAsset
		if err := arows.Scan(&a.AssetID, &a.AssetName, &a.Groups, &a.Findings); err != nil {
			return nil, err
		}
		out.Assets = append(out.Assets, a)
	}
	return out, arows.Err()
}
