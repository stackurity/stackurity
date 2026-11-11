package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/trustbadge"
)

// Trust badges (migration 0103, docs/trust-badge.md). Nothing here is
// public: the badge image and trust page come later, and the server writes
// nothing unless the badge is turned on for Stackurity Cloud.

// TrustBadge is one badge of a workspace.
type TrustBadge struct {
	ID              int64      `json:"id"`
	Slug            string     `json:"slug"`
	Enabled         bool       `json:"enabled"`
	ScopeKind       string     `json:"scope_kind"` // projects or assets
	ProjectIDs      []int64    `json:"project_ids"`
	AssetIDs        []int64    `json:"asset_ids"`
	TermsVersion    string     `json:"terms_version"`
	TermsAcceptedBy *int64     `json:"terms_accepted_by"`
	TermsAcceptedAt *time.Time `json:"terms_accepted_at"`
	ShowMarketing   bool       `json:"show_marketing"`
	ShowCheckedTime bool       `json:"show_checked_time"`
	ShowKinds       bool       `json:"show_kinds"`
	ShowLogo        bool       `json:"show_logo"`
	Listed          bool       `json:"listed"`
	DisplayName     string     `json:"display_name"`
	WebsiteURL      string     `json:"website_url"`
	HasLogo         bool       `json:"has_logo"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

const trustBadgeCols = `id, slug, enabled, scope_kind, project_ids, asset_ids, terms_version, terms_accepted_by, terms_accepted_at,
	show_marketing, show_checked_time, show_kinds, show_logo, listed, display_name, website_url, logo IS NOT NULL, created_at, updated_at`

func scanTrustBadge(r pgx.Row) (TrustBadge, error) {
	var b TrustBadge
	err := r.Scan(&b.ID, &b.Slug, &b.Enabled, &b.ScopeKind, &b.ProjectIDs, &b.AssetIDs, &b.TermsVersion, &b.TermsAcceptedBy,
		&b.TermsAcceptedAt, &b.ShowMarketing, &b.ShowCheckedTime, &b.ShowKinds, &b.ShowLogo, &b.Listed, &b.DisplayName, &b.WebsiteURL, &b.HasLogo, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

var trustBadgeSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$`)

// ErrTrustBadgeSlugTaken: another badge (of any workspace) has the slug.
var ErrTrustBadgeSlugTaken = errors.New("that address is taken")

// CreateTrustBadge adds a badge, turned off, to the caller's workspace. The
// scope names some projects or some assets; there is no organisation-wide
// badge.
func (s *Store) CreateTrustBadge(ctx context.Context, b TrustBadge, createdBy int64) (TrustBadge, error) {
	b.Slug = strings.ToLower(strings.TrimSpace(b.Slug))
	if !trustBadgeSlug.MatchString(b.Slug) {
		return TrustBadge{}, fmt.Errorf("the address must be 3 to 50 lower-case letters, digits or hyphens: %w", ErrInvalid)
	}
	switch {
	case b.ScopeKind == "projects" && len(b.ProjectIDs) > 0 && len(b.AssetIDs) == 0:
	case b.ScopeKind == "assets" && len(b.AssetIDs) > 0 && len(b.ProjectIDs) == 0:
	default:
		return TrustBadge{}, fmt.Errorf("a badge covers some projects or some assets: %w", ErrInvalid)
	}
	var by *int64
	if createdBy > 0 {
		by = &createdBy
	}
	if err := checkTrustBadgeText(&b); err != nil {
		return TrustBadge{}, err
	}
	row := s.Pool.QueryRow(ctx, `INSERT INTO trust_badges (slug, scope_kind, project_ids, asset_ids, show_marketing,
		  show_checked_time, show_kinds, show_logo, listed, created_by, display_name, website_url)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING `+trustBadgeCols,
		b.Slug, b.ScopeKind, nonNilIDs(b.ProjectIDs), nonNilIDs(b.AssetIDs), b.ShowMarketing, b.ShowCheckedTime, b.ShowKinds,
		b.ShowLogo, b.Listed, by, b.DisplayName, b.WebsiteURL)
	out, err := scanTrustBadge(row)
	if isUniqueViolation(err) {
		return TrustBadge{}, ErrTrustBadgeSlugTaken
	}
	return out, err
}

// TrustBadgeByID reads one of the workspace's badges.
func (s *Store) TrustBadgeByID(ctx context.Context, id int64) (TrustBadge, error) {
	b, err := scanTrustBadge(s.Pool.QueryRow(ctx, `SELECT `+trustBadgeCols+` FROM trust_badges WHERE id = $1`, id))
	return b, notFound(err)
}

// ListTrustBadges lists the workspace's badges.
func (s *Store) ListTrustBadges(ctx context.Context) ([]TrustBadge, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+trustBadgeCols+` FROM trust_badges ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrustBadge{}
	for rows.Next() {
		b, err := scanTrustBadge(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// AcceptTrustBadgeTerms records who accepted which version of the badge
// terms, and when.
func (s *Store) AcceptTrustBadgeTerms(ctx context.Context, id, userID int64, version string) error {
	if strings.TrimSpace(version) == "" || userID <= 0 {
		return fmt.Errorf("terms version and user are required: %w", ErrInvalid)
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE trust_badges SET terms_version = $2, terms_accepted_by = $3, terms_accepted_at = now(),
		updated_at = now() WHERE id = $1`, id, version, userID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// SetTrustBadgeEnabled turns a badge on or off. Turning it on needs the
// terms accepted (the table refuses it otherwise).
func (s *Store) SetTrustBadgeEnabled(ctx context.Context, id int64, on bool) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE trust_badges SET enabled = $2, updated_at = now() WHERE id = $1`, id, on)
	if err != nil {
		var pe interface{ SQLState() string }
		if errors.As(err, &pe) && pe.SQLState() == "23514" {
			return fmt.Errorf("accept the badge terms before turning the badge on: %w", ErrInvalid)
		}
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TrustBadgeInputs gathers what the badge rule reads (trustbadge.Inputs)
// for one badge. It needs the whole workspace: a caller narrowed to some
// projects would see part of the scope and could get the wrong answer.
func (s *Store) TrustBadgeInputs(ctx context.Context, b TrustBadge) (trustbadge.Inputs, error) {
	if _, ok := tenant.Workspace(ctx); !ok || tenant.Narrowed(ctx) {
		return trustbadge.Inputs{}, errors.New("trust badge inputs need the whole workspace's scope")
	}
	in := trustbadge.Inputs{BadgeID: b.ID, Enabled: b.Enabled, ScopeKind: b.ScopeKind, Assets: []trustbadge.Asset{},
		Sources: map[string]trustbadge.Source{}, Pairs: []trustbadge.Pair{}}
	in.ScopeIDs = nonNilIDs(b.ProjectIDs)
	if b.ScopeKind == "assets" {
		in.ScopeIDs = nonNilIDs(b.AssetIDs)
	}
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.kind, col.received_at, COALESCE(col.complete, false), a.evaluated_at
		FROM assets a
		LEFT JOIN LATERAL (SELECT received_at, complete FROM collections c WHERE c.asset_id = a.id
		  ORDER BY received_at DESC, id DESC LIMIT 1) col ON true
		WHERE a.merged_into IS NULL AND (
		  ($1 = 'projects' AND a.id IN (SELECT asset_id FROM project_assets WHERE project_id = ANY($2)))
		  OR ($1 = 'assets' AND a.id = ANY($2)))
		ORDER BY a.id`, in.ScopeKind, in.ScopeIDs)
	if err != nil {
		return in, err
	}
	ids := []int64{}
	for rows.Next() {
		var a trustbadge.Asset
		if err := rows.Scan(&a.ID, &a.Kind, &a.LastReport, &a.LatestComplete, &a.ProcessedAt); err != nil {
			rows.Close()
			return in, err
		}
		in.Assets = append(in.Assets, a)
		ids = append(ids, a.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}
	if len(ids) == 0 {
		return in, nil
	}
	if err := s.trustBadgeScopes(ctx, ids, in.Assets); err != nil {
		return in, err
	}
	// Rows grouped by what the rule reads: class, broad kind, source and
	// the source refresh the evaluation used. Each row of inventory is one
	// pair per source it was evaluated against (inventory_evaluations), or
	// its single coverage_feed for rows evaluated before that table.
	rows, err = s.Pool.Query(ctx, `WITH inv AS (
		  SELECT i.id, i.coverage, i.coverage_feed, i.evaluated_at, i.first_seen, c.type,
		    `+uncheckedReasonSQL("false")+` AS cls, `+unsupportedCategorySQL+` AS cat
		  FROM inventory i JOIN components c ON c.id = i.component_id
		  WHERE i.removed_at IS NULL AND i.asset_id = ANY($1)),
		x AS (
		  SELECT CASE WHEN inv.coverage = 'evaluated' THEN 'evaluated'
		      WHEN inv.coverage = 'awaiting' THEN 'awaiting'
		      WHEN inv.cls = 'unsupported' THEN 'unsupported'
		      WHEN inv.cls = 'no_advisories' THEN 'no_advisories'
		      WHEN inv.cls = 'waiting_for_data' THEN 'waiting'
		      ELSE 'failed' END AS class,
		    CASE WHEN inv.coverage <> 'evaluated' AND inv.cls = 'unsupported' THEN inv.type || '|' || inv.cat
		      WHEN inv.coverage <> 'evaluated' AND inv.cls = 'no_advisories' THEN inv.type || '|no_advisories'
		      ELSE '' END AS kind,
		    CASE WHEN inv.coverage = 'evaluated' THEN COALESCE(e.feed, inv.coverage_feed) ELSE '' END AS source,
		    e.feed_last_success AS source_last_success,
		    COALESCE(e.feed_cursor, '') AS source_cursor,
		    COALESCE(e.evaluated_at, inv.evaluated_at) AS evaluated,
		    CASE WHEN inv.coverage = 'awaiting' THEN inv.first_seen ELSE inv.evaluated_at END AS since
		  FROM inv LEFT JOIN inventory_evaluations e ON e.inventory_id = inv.id AND inv.coverage = 'evaluated')
		SELECT class, kind, source, source_last_success, source_cursor, min(evaluated), min(since), count(*)
		FROM x GROUP BY 1, 2, 3, 4, 5 ORDER BY 1, 2, 3, 4, 5`, ids)
	if err != nil {
		return in, err
	}
	sources := []string{}
	seen := map[string]bool{}
	for rows.Next() {
		var p trustbadge.Pair
		var kind string
		if err := rows.Scan(&p.Class, &kind, &p.Source, &p.SourceLastSuccess, &p.SourceCursor, &p.OldestEvaluated, &p.Since, &p.Count); err != nil {
			rows.Close()
			return in, err
		}
		p.Kind = trustBadgeKind(kind)
		in.Pairs = append(in.Pairs, p)
		if p.Source != "" && !seen[p.Source] {
			seen[p.Source] = true
			sources = append(sources, p.Source)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}
	for _, name := range sources {
		in.Sources[name] = trustbadge.Source{}
	}
	rows, err = s.Pool.Query(ctx, `SELECT name, enabled, cursor, last_success, stale_after FROM feeds WHERE name = ANY($1)`, sources)
	if err != nil {
		return in, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		src := trustbadge.Source{Exists: true}
		if err := rows.Scan(&name, &src.Enabled, &src.Cursor, &src.LastSuccess, &src.StaleAfter); err != nil {
			return in, err
		}
		in.Sources[name] = src
	}
	return in, rows.Err()
}

// trustBadgeKind names a broad kind of software for the trust page, from
// "<purl type>|<category>". Never a package, vendor or organisation name:
// vendor builds and private registries are named without whose they are.
func trustBadgeKind(key string) string {
	if key == "" {
		return ""
	}
	typ, cat, _ := strings.Cut(key, "|")
	switch {
	case cat == "no_advisories":
		return TypeLabel(typ) + " packages for releases with no published advisories"
	case strings.HasPrefix(cat, "vendor_build"):
		return "vendor builds of distribution packages"
	case cat == "private_registry":
		return "packages from private registries"
	}
	if f, ok := unsupportedLabels[cat]; ok {
		if strings.Contains(f, "%s") {
			return fmt.Sprintf(f, TypeLabel(typ))
		}
		return f
	}
	return TypeLabel(typ) + " packages"
}

// TrustBadgeStatus is one decision in a badge's history.
type TrustBadgeStatus struct {
	ID             int64               `json:"id"`
	BadgeID        int64               `json:"badge_id"`
	DecidedAt      time.Time           `json:"decided_at"`
	Result         string              `json:"result"`
	Reason         string              `json:"reason"`
	RuleVersion    string              `json:"rule_version"`
	PreviousResult *string             `json:"previous_result"`
	Evidence       trustbadge.Evidence `json:"evidence"`
}

// AppendTrustBadgeStatus writes a decision to the badge's history, with
// the previous decision's result. The history is append-only (migration
// 0103): nothing here, or anywhere, changes an entry.
func (s *Store) AppendTrustBadgeStatus(ctx context.Context, badgeID int64, decidedAt time.Time, ev trustbadge.Evidence) (TrustBadgeStatus, error) {
	body, err := json.Marshal(ev)
	if err != nil {
		return TrustBadgeStatus{}, err
	}
	out := TrustBadgeStatus{BadgeID: badgeID, DecidedAt: decidedAt, Result: ev.Decision.Result, Reason: ev.Decision.Reason,
		RuleVersion: ev.Decision.RuleVersion, Evidence: ev}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// One writer per badge at a time, so previous_result is the last
		// decision (the history may not be locked with FOR UPDATE: the
		// application has no UPDATE on it).
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('trust_badge_status'), $1::int)`, int32(badgeID)); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT result FROM trust_badge_status WHERE badge_id = $1 ORDER BY decided_at DESC, id DESC LIMIT 1`,
			badgeID).Scan(&out.PreviousResult); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO trust_badge_status (badge_id, decided_at, result, reason, rule_version, previous_result, evidence)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`, badgeID, decidedAt, out.Result, out.Reason, out.RuleVersion,
			out.PreviousResult, body).Scan(&out.ID)
	})
	return out, err
}

// LatestTrustBadgeStatus is the badge's last decision, for the evaluator
// itself (nil: none yet). Reads made for a person go through
// TrustBadgeHistory, which audits them.
func (s *Store) LatestTrustBadgeStatus(ctx context.Context, badgeID int64) (*TrustBadgeStatus, error) {
	rows, err := s.readTrustBadgeStatus(ctx, badgeID, 1)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// TrustBadgeHistory reads the badge's decisions, newest first, for actor.
// Every read is audit-logged first: no audit entry, no read.
func (s *Store) TrustBadgeHistory(ctx context.Context, actor Actor, badgeID int64, limit int) ([]TrustBadgeStatus, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	if err := s.Audit(ctx, actor, "trust_badge.history.read", "trust_badge", strconv.FormatInt(badgeID, 10),
		map[string]any{"limit": limit}); err != nil {
		return nil, fmt.Errorf("audit the history read: %w", err)
	}
	return s.readTrustBadgeStatus(ctx, badgeID, limit)
}

func (s *Store) readTrustBadgeStatus(ctx context.Context, badgeID int64, limit int) ([]TrustBadgeStatus, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, badge_id, decided_at, result, reason, rule_version, previous_result, evidence
		FROM trust_badge_status WHERE badge_id = $1 ORDER BY decided_at DESC, id DESC LIMIT $2`, badgeID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrustBadgeStatus{}
	for rows.Next() {
		var st TrustBadgeStatus
		var body []byte
		if err := rows.Scan(&st.ID, &st.BadgeID, &st.DecidedAt, &st.Result, &st.Reason, &st.RuleVersion, &st.PreviousResult, &body); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(body, &st.Evidence); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// TrustBadgeMinRetention is the shortest retention period the purge
// accepts; the database function refuses anything shorter too.
const TrustBadgeMinRetention = 30 * 24 * time.Hour

// PurgeTrustBadgeStatus deletes decisions older than olderThan from every
// workspace's history under retention policy version policy, through the
// restricted path only: the purge function, as the stackurity_purge role,
// which records each purge in trust_badge_purges. It returns how many
// entries were deleted.
func (s *Store) PurgeTrustBadgeStatus(ctx context.Context, olderThan time.Duration, policy string) (int64, error) {
	if olderThan < TrustBadgeMinRetention || strings.TrimSpace(policy) == "" {
		return 0, fmt.Errorf("a retention period of at least 30 days and a policy version are required: %w", ErrInvalid)
	}
	var n int64
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var role bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_purge')`).Scan(&role); err != nil {
			return err
		}
		if role {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE stackurity_purge`); err != nil {
				return err
			}
		}
		return tx.QueryRow(ctx, `SELECT trust_badge_status_purge($1::interval, $2)`, olderThan, policy).Scan(&n)
	})
	return n, err
}

// TrustBadgePurge is one retention purge.
type TrustBadgePurge struct {
	PurgedAt      time.Time `json:"purged_at"`
	OlderThan     string    `json:"older_than"`
	PolicyVersion string    `json:"policy_version"`
	RowsDeleted   int64     `json:"rows_deleted"`
	Scope         string    `json:"scope"`
}

// TrustBadgePurges lists the retention purges, newest first (system scope).
func (s *Store) TrustBadgePurges(ctx context.Context) ([]TrustBadgePurge, error) {
	rows, err := s.Pool.Query(ctx, `SELECT purged_at, older_than::text, policy_version, rows_deleted, scope
		FROM trust_badge_purges ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrustBadgePurge{}
	for rows.Next() {
		var p TrustBadgePurge
		if err := rows.Scan(&p.PurgedAt, &p.OlderThan, &p.PolicyVersion, &p.RowsDeleted, &p.Scope); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// trustBadgeScopes classifies each asset's collector coverage scopes that
// are not checked (trustbadge.ScopeClass): failed ones are counted in
// FailedScopes, coverage limits give LimitKinds, and an incomplete latest
// inventory is explained when every such scope is a limit or had nothing to
// read. assets is in the order of ids.
func (s *Store) trustBadgeScopes(ctx context.Context, ids []int64, assets []trustbadge.Asset) error {
	rows, err := s.Pool.Query(ctx, `SELECT asset_id, scope, status FROM coverage
		WHERE asset_id = ANY($1) AND status <> 'checked' ORDER BY asset_id, scope`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	at := make(map[int64]int, len(ids))
	for i, id := range ids {
		at[id] = i
	}
	seen := make([]bool, len(assets))
	kinds := make([]map[string]bool, len(assets))
	for rows.Next() {
		var id int64
		var scope, status string
		if err := rows.Scan(&id, &scope, &status); err != nil {
			return err
		}
		i, ok := at[id]
		if !ok {
			continue
		}
		seen[i] = true
		switch class, kind := trustbadge.ScopeClass(scope, status); class {
		case trustbadge.ScopeFailed:
			assets[i].FailedScopes++
		case trustbadge.ScopeLimit:
			if kinds[i] == nil {
				kinds[i] = map[string]bool{}
			}
			kinds[i][kind] = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range assets {
		for k := range kinds[i] {
			assets[i].LimitKinds = append(assets[i].LimitKinds, k)
		}
		sort.Strings(assets[i].LimitKinds)
		// A complete inventory needs no explaining; an incomplete one with
		// no scope saying why stays an error.
		assets[i].IncompleteExplained = !assets[i].LatestComplete && seen[i] && assets[i].FailedScopes == 0
	}
	return nil
}
