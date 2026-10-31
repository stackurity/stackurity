package store

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/version"
)

// WordPressNamespaces are the pkg:generic namespaces of WordPress plugins
// and themes (collect/apps/wpextensions.go), whose latest releases come
// from wordpress.org (releases:wordpress.org).
var WordPressNamespaces = []string{"wordpress-plugin", "wordpress-theme"}

func isWordPressExtension(purlType, namespace string) bool {
	return purlType == "generic" && (namespace == WordPressNamespaces[0] || namespace == WordPressNamespaces[1])
}

// updateType classifies the gap between installed and latest stable as
// "major", "minor" or "patch", using the ecosystem's own comparator, for
// the ecosystems that have release feeds. An installed pre-release of the
// latest release itself (2.0.0-rc.1 with 2.0.0 out) takes that release's
// type (releaseType), not "patch".
func updateType(purlType, namespace, installed, latest string) string {
	if latest == "" || installed == "" {
		return ""
	}
	// A pre-release is never the latest stable release.
	if version.Prerelease(version.ForPurlType(purlType), latest) || isWordPressExtension(purlType, namespace) && wpPreRelease.MatchString(latest) {
		return ""
	}
	if isWordPressExtension(purlType, namespace) {
		// Authors write 2.0 and 2.0.0 for one release.
		trim := func(v string) string {
			for strings.HasSuffix(v, ".0") && strings.Count(v, ".") > 1 {
				v = strings.TrimSuffix(v, ".0")
			}
			return v
		}
		if trim(installed) == trim(latest) {
			return ""
		}
		// A pre-release (2.0-beta1) is compared by its release: behind
		// when that is not newer than the latest stable release.
		if base, _, pre := strings.Cut(installed, "-"); pre && wpPreRelease.MatchString(installed) {
			if c, err := version.CompareGeneric(base, latest); err == nil && c > 0 {
				return "ahead"
			} else if trim(base) == trim(latest) {
				return releaseType(latest)
			}
			installed = base
		}
		return changeOrAhead(purlType, installed, latest, true)
	}
	switch purlType {
	case "npm", "composer", "pypi", "golang", "cargo", "gem", "nuget", "maven", "pub", "hex":
		// Ahead only for a pre-release: a newer stable version is one the
		// registry withdrew (yanked, retracted), not one to call newer.
		pre := version.Prerelease(version.ForPurlType(purlType), installed)
		if base := releaseBase.FindString(installed); pre && base != "" && base != installed {
			if c, err := version.For(version.ForPurlType(purlType))(base, latest); err == nil && c == 0 {
				return releaseType(latest)
			}
		}
		return changeOrAhead(purlType, installed, latest, pre)
	}
	return ""
}

// releaseBase is the release a pre-release leads to: 2.0.0 of 2.0.0-rc.1,
// 2.0.0rc1 or 2.0.0-RC1.
var releaseBase = regexp.MustCompile(`^v?\d+(\.\d+)*`)

// releaseType is the kind of release v is: "major" for 2.0.0 (or 2.0),
// "minor" for 2.1.0, "patch" for 2.1.3. It classifies a move from a
// pre-release to its own release.
func releaseType(v string) string {
	f := strings.Split(releaseBase.FindString(v), ".")
	if len(f) < 2 {
		return "major"
	}
	zero := func(xs []string) bool {
		for _, x := range xs {
			if strings.TrimLeft(x, "0") != "" {
				return false
			}
		}
		return true
	}
	switch {
	case zero(f[1:]):
		return "major"
	case zero(f[2:]):
		return "minor"
	}
	return "patch"
}

// wpPreRelease marks a WordPress plugin or theme pre-release or build.
var wpPreRelease = regexp.MustCompile(`(?i)(alpha|beta|rc|dev|pre|nightly)`)

// changeOrAhead is the update from installed to latest, or, when ahead may
// be said, "ahead" when the installed version is newer than the latest
// stable release (a pre-release or development build); "" when it is the
// latest or not comparable.
func changeOrAhead(purlType, installed, latest string, ahead bool) string {
	if t, err := version.ChangeType(purlType, installed, latest); err == nil {
		return t
	}
	if c, err := version.For(version.ForPurlType(purlType))(installed, latest); ahead && err == nil && c > 0 {
		return "ahead"
	}
	return ""
}

type Asset struct {
	ID              int64  `json:"id"`
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	Environment     string `json:"environment"`
	OwnerTeamID     *int64 `json:"owner_team_id"`
	OwnerTeam       string `json:"owner_team"`
	Provider        string `json:"provider"`
	Region          string `json:"region"`
	Criticality     string `json:"criticality"`
	InternetExposed *bool  `json:"internet_exposed"`
	// Exposed is the exposure risk scoring uses: internet_exposed when set,
	// else what collectors observed (see effectiveExposure).
	Exposed          *bool             `json:"exposed"`
	Tags             []string          `json:"tags"`
	Attributes       map[string]string `json:"attributes"`
	FirstSeen        time.Time         `json:"first_seen"`
	LastSeen         time.Time         `json:"last_seen"`
	CollectionStatus string            `json:"collection_status"`
	ComponentCount   int64             `json:"component_count"`
	// AgentPolledAt is when the asset's agent last asked whether to report
	// now (0.7 agents); null for older agents and assets without one.
	AgentPolledAt *time.Time `json:"agent_polled_at"`
	// Projects are the active projects the asset belongs to that the
	// caller may see.
	Projects []ProjectRef `json:"projects"`
	// Reporting is how the asset reports and what is expected of it.
	Reporting Reporting `json:"reporting"`
}

type AssetFilter struct {
	Kind        string
	Environment string
	OwnerTeamID int64
	Status      string
	Search      string
	// RebootRequired limits the list to hosts that run older code than is
	// installed (reported by the Linux agent).
	RebootRequired bool
	// Exposed limits the list by effective exposure (nil: any).
	Exposed *bool
	// Unfiled limits the list to assets in no active project.
	Unfiled bool
	Page
}

const assetCols = `a.id, a.kind, a.name, a.environment, a.owner_team_id, COALESCE(t.name, ''), a.provider, a.region,
	a.criticality, a.internet_exposed, ` + effectiveExposure + `, a.tags, a.attributes, a.first_seen, a.last_seen, a.collection_status,
	(SELECT count(*) FROM inventory i WHERE i.asset_id = a.id AND i.removed_at IS NULL), a.agent_polled_at,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('id', p.id, 'name', p.name) ORDER BY lower(p.name), p.id)
	  FROM project_assets pa JOIN projects p ON p.id = pa.project_id WHERE pa.asset_id = a.id AND p.archived_at IS NULL), '[]'),
	a.report_source, a.report_override, a.report_runs, EXTRACT(epoch FROM a.report_usual)::bigint, EXTRACT(epoch FROM a.report_due_after)::bigint`

func scanAsset(row pgx.Row) (*Asset, error) {
	var a Asset
	var attrs, projects []byte
	var source, override string
	var runs *int32
	var usual, due *int64
	err := row.Scan(&a.ID, &a.Kind, &a.Name, &a.Environment, &a.OwnerTeamID, &a.OwnerTeam, &a.Provider, &a.Region,
		&a.Criticality, &a.InternetExposed, &a.Exposed, &a.Tags, &attrs, &a.FirstSeen, &a.LastSeen, &a.CollectionStatus, &a.ComponentCount, &a.AgentPolledAt, &projects,
		&source, &override, &runs, &usual, &due)
	if err != nil {
		return nil, err
	}
	a.Reporting = reportingFrom(source, override, runs, usual, due, a.LastSeen)
	_ = json.Unmarshal(attrs, &a.Attributes)
	_ = json.Unmarshal(projects, &a.Projects)
	if a.Projects == nil {
		a.Projects = []ProjectRef{}
	}
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return &a, nil
}

// where builds a WHERE clause from optional filters.
type where struct {
	conds []string
	args  []any
}

func (w *where) add(cond string, arg any) {
	w.args = append(w.args, arg)
	w.conds = append(w.conds, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(w.args))))
}

func (w *where) sql() string {
	if len(w.conds) == 0 {
		return ""
	}
	return " WHERE " + strings.Join(w.conds, " AND ")
}

func likeEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(s) + "%"
}

func (s *Store) ListAssets(ctx context.Context, f AssetFilter) ([]Asset, int64, error) {
	w := &where{}
	w.conds = append(w.conds, "a.merged_into IS NULL")
	if f.Kind != "" {
		w.add("a.kind = ?", f.Kind)
	}
	if f.Environment != "" {
		w.add("a.environment = ?", f.Environment)
	}
	if f.OwnerTeamID > 0 {
		w.add("a.owner_team_id = ?", f.OwnerTeamID)
	}
	if f.Status != "" {
		w.add("a.collection_status = ?", f.Status)
	}
	if f.Search != "" {
		w.add("a.name ILIKE ?", likeEscape(f.Search))
	}
	if f.RebootRequired {
		w.conds = append(w.conds, "a.attributes->>'reboot_required' = 'true'")
	}
	if f.Exposed != nil {
		w.add(effectiveExposure+" = ?", *f.Exposed)
	}
	if f.Unfiled {
		w.conds = append(w.conds, `NOT EXISTS (SELECT 1 FROM project_assets pa JOIN projects p ON p.id = pa.project_id
			WHERE pa.asset_id = a.id AND p.archived_at IS NULL)`)
	}
	from := ` FROM assets a LEFT JOIN teams t ON t.id = a.owner_team_id` + w.sql()
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+from, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	rows, err := s.Pool.Query(ctx, `SELECT `+assetCols+from+
		fmt.Sprintf(` ORDER BY a.name, a.id LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

func (s *Store) GetAsset(ctx context.Context, id int64) (*Asset, error) {
	a, err := scanAsset(s.Pool.QueryRow(ctx, `SELECT `+assetCols+` FROM assets a LEFT JOIN teams t ON t.id = a.owner_team_id WHERE a.id = $1`, id))
	return a, notFound(err)
}

// Nullable distinguishes a JSON field that is absent (no change) from one
// that is explicitly null (clear the value).
type Nullable[T any] struct {
	Set   bool
	Value *T
}

func (n *Nullable[T]) UnmarshalJSON(b []byte) error {
	n.Set = true
	if string(b) == "null" {
		n.Value = nil
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	n.Value = &v
	return nil
}

func (n Nullable[T]) MarshalJSON() ([]byte, error) {
	if !n.Set {
		return []byte("null"), nil
	}
	return json.Marshal(n.Value)
}

type AssetUpdate struct {
	Name            *string         `json:"name"`
	Environment     *string         `json:"environment"`
	OwnerTeamID     Nullable[int64] `json:"owner_team_id"` // null or 0 clears
	Criticality     *string         `json:"criticality"`
	InternetExposed Nullable[bool]  `json:"internet_exposed"` // null resets to unknown
	Tags            *[]string       `json:"tags"`
	Provider        *string         `json:"provider"`
	Region          *string         `json:"region"`
	// ReportOverride is how often the asset is expected to report: auto
	// (learned from its history), daily, weekly or one_off.
	ReportOverride *string `json:"report_override"`
}

func (s *Store) UpdateAsset(ctx context.Context, id int64, u AssetUpdate) error {
	if u.ReportOverride != nil && !ValidReportOverride(*u.ReportOverride) {
		return fmt.Errorf("report_override must be auto, daily, weekly or one_off: %w", ErrInvalid)
	}
	if u.ReportOverride != nil && *u.ReportOverride == ReportOneOff {
		var source string
		if err := s.Pool.QueryRow(ctx, `SELECT report_source FROM assets WHERE id = $1`, id).Scan(&source); err != nil {
			return notFound(err)
		}
		if source == SourceAgent {
			return fmt.Errorf("report_override one_off is not allowed for an asset the agent reports: it would never say if the agent stopped; delete the server if it is gone: %w", ErrInvalid)
		}
	}
	var team *int64
	clearTeam := false
	if u.OwnerTeamID.Set {
		if u.OwnerTeamID.Value == nil || *u.OwnerTeamID.Value == 0 {
			clearTeam = true
		} else {
			team = u.OwnerTeamID.Value
		}
	}
	tag, err := s.Pool.Exec(ctx, `UPDATE assets SET
		name = COALESCE($2, name),
		name_by_person = name_by_person OR $2::text IS NOT NULL,
		environment = COALESCE($3, environment),
		owner_team_id = CASE WHEN $4 THEN NULL ELSE COALESCE($5, owner_team_id) END,
		criticality = COALESCE($6, criticality),
		internet_exposed = CASE WHEN $7 THEN $8 ELSE internet_exposed END,
		tags = COALESCE($9, tags),
		provider = COALESCE($10, provider),
		region = COALESCE($11, region)
		WHERE id = $1`, id, u.Name, u.Environment, clearTeam, team, u.Criticality,
		u.InternetExposed.Set, u.InternetExposed.Value, u.Tags, u.Provider, u.Region)
	if isForeignKey(err) {
		return fmt.Errorf("no such team: %w", ErrInvalid)
	}
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if u.ReportOverride != nil {
		return s.SetReportOverride(ctx, id, *u.ReportOverride)
	}
	return nil
}

func (s *Store) DeleteAsset(ctx context.Context, id int64) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Assets merged into this one go with it.
		if _, err := tx.Exec(ctx, `DELETE FROM assets WHERE merged_into = $1`, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM assets WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

type Identifier struct {
	Scheme    string    `json:"scheme"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"first_seen"`
}

func (s *Store) AssetIdentifiers(ctx context.Context, id int64) ([]Identifier, error) {
	rows, err := s.Pool.Query(ctx, `SELECT scheme, value, first_seen FROM asset_identifiers WHERE asset_id = $1 ORDER BY scheme, value`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Identifier])
}

type InventoryRow struct {
	ID           int64             `json:"id"`
	AssetID      int64             `json:"asset_id"`
	AssetName    string            `json:"asset_name"`
	AssetKind    string            `json:"asset_kind"`
	ComponentID  int64             `json:"component_id"`
	Type         string            `json:"type"`
	Namespace    string            `json:"namespace"`
	Name         string            `json:"name"`
	Purl         string            `json:"purl"`
	Version      string            `json:"version"`
	Location     string            `json:"location"`
	CollectorID  string            `json:"collector_id"`
	Direct       *bool             `json:"direct"`
	Scope        string            `json:"scope"`
	Confidence   string            `json:"confidence"`
	Evidence     map[string]string `json:"evidence"`
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
	CollectionID int64             `json:"collection_id"`
	RemovedAt    *time.Time        `json:"removed_at"`
	LatestStable string            `json:"latest_stable"`
	UpdateType   string            `json:"update_type"` // patch, minor, major; ahead (newer than the latest stable release); empty when current or unknown
	// ReleaseNote says why a WordPress plugin or theme has no latest
	// release: not from wordpress.org (and why), not found there, or
	// closed there.
	ReleaseNote  string `json:"release_note,omitempty"`
	OpenFindings int64  `json:"open_findings"`
	// Coverage says whether vulnerability intelligence covered this row:
	// evaluated, stale_intelligence (evaluated against a feed that is stale
	// or failing), unsupported, not_evaluated or awaiting. CoverageReason
	// explains the last three.
	Coverage       string     `json:"coverage"`
	CoverageReason string     `json:"coverage_reason"`
	CoverageFeed   string     `json:"coverage_feed"`
	EvaluatedAt    *time.Time `json:"evaluated_at"`
	// LifecycleNote says why an upstream end-of-life version raised no
	// finding (a distribution package the distribution still supports), or
	// what the distribution's support adds to a finding that stands.
	LifecycleNote map[string]any `json:"lifecycle_note,omitempty"`
	// Unchecked says why the row was not checked, by who acts (unchecked.go):
	// UncheckedReason and UncheckedActor, and for an unreadable version its
	// cause, what to do (UncheckedFix) and the docs. Empty when checked.
	UncheckedReason string `json:"unchecked_reason,omitempty"`
	UncheckedActor  string `json:"unchecked_actor,omitempty"`
	UncheckedCause  string `json:"unchecked_cause,omitempty"`
	UncheckedFix    string `json:"unchecked_fix,omitempty"`
	UncheckedDocs   string `json:"unchecked_docs,omitempty"`
}

// rowCoverageSQL is the effective coverage of inventory row i: a row matched
// against a feed that is stale, or whose last sync failed, is reported as
// stale_intelligence rather than evaluated.
const rowCoverageSQL = `CASE WHEN i.coverage = 'evaluated' AND i.coverage_feed <> '' AND EXISTS (SELECT 1 FROM feeds fd
	  WHERE fd.name = i.coverage_feed AND (NOT fd.enabled OR fd.last_error <> '' OR fd.last_success IS NULL OR fd.last_success < now() - fd.stale_after))
	THEN 'stale_intelligence' ELSE i.coverage END`

type InventoryFilter struct {
	AssetID        int64
	ComponentID    int64
	Type           string
	Search         string
	Direct         *bool
	IncludeRemoved bool
	// Coverage limits rows to one effective coverage state, or "gaps" for
	// unsupported and not_evaluated together.
	Coverage string
	// UpdateType limits rows to those with a newer stable release of this
	// update type (patch, minor or major), or of any ("any").
	UpdateType string
	// Unchecked limits rows to one unchecked reason (unchecked.go).
	Unchecked string
	Page
}

func (s *Store) ListInventory(ctx context.Context, f InventoryFilter) ([]InventoryRow, int64, error) {
	w := &where{}
	if !f.IncludeRemoved {
		w.conds = append(w.conds, "i.removed_at IS NULL")
	}
	w.conds = append(w.conds, "a.merged_into IS NULL")
	if f.AssetID > 0 {
		w.add("i.asset_id = ?", f.AssetID)
	}
	if f.ComponentID > 0 {
		w.add("i.component_id = ?", f.ComponentID)
	}
	if f.Type != "" {
		w.add("c.type = ?", f.Type)
	}
	if f.Search != "" {
		w.add("(c.name ILIKE ? OR c.namespace ILIKE ?)", likeEscape(f.Search))
	}
	if f.Direct != nil {
		w.add("i.direct = ?", *f.Direct)
	}
	switch f.Coverage {
	case "":
	case "gaps":
		w.conds = append(w.conds, "i.coverage IN ('unsupported', 'not_evaluated')")
	default:
		w.add("("+rowCoverageSQL+") = ?", f.Coverage)
	}
	if f.Unchecked != "" {
		uncheckedRowFilter(w, f.Unchecked)
	}
	const join = ` FROM inventory i JOIN components c ON c.id = i.component_id JOIN assets a ON a.id = i.asset_id
		LEFT JOIN package_releases pr ON pr.component_id = c.id`
	p := f.Page.norm()
	page := fmt.Sprintf(` LIMIT %d OFFSET %d`, p.Limit, p.Offset)
	var total int64
	if f.UpdateType != "" {
		// The update type comes from each ecosystem's version rules, so
		// the rows that may be behind are classified here, then the page
		// is read by id.
		if !validUpdateFilter(f.UpdateType) {
			return nil, 0, fmt.Errorf("update_type must be patch, minor, major or any: %w", ErrInvalid)
		}
		w.addBehind()
		ids, err := s.behindIDs(ctx, join+w.sql(), w.args, f.UpdateType)
		if err != nil {
			return nil, 0, err
		}
		total = int64(len(ids))
		ids = ids[min(p.Offset, len(ids)):min(p.Offset+p.Limit, len(ids))]
		w, page = &where{}, ""
		w.add("i.id = ANY(?)", ids)
	}
	from := join + w.sql()
	if f.UpdateType == "" {
		if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+from, w.args...).Scan(&total); err != nil {
			return nil, 0, err
		}
	}
	rows, err := s.Pool.Query(ctx, `SELECT i.id, i.asset_id, a.name, a.kind, c.id, c.type, c.namespace, c.name, i.purl, i.version,
		i.location, i.collector_id, i.direct, i.scope, i.confidence, i.evidence, i.first_seen, i.last_seen,
		i.last_collection_id, i.removed_at,
		CASE WHEN COALESCE(i.evidence->>'wordpress_org', '') = 'no' THEN '' ELSE COALESCE(pr.latest_stable, '') END,
		(SELECT count(*) FROM findings f WHERE f.inventory_id = i.id AND f.status = 'open'),
		`+rowCoverageSQL+`, i.coverage_reason, i.coverage_feed, i.evaluated_at, i.lifecycle_note,
		`+uncheckedReasonSQL(overdueFeedSQL)+`, `+uncheckedCauseSQL+`,
		CASE WHEN c.type = 'generic' AND c.namespace IN ('wordpress-plugin', 'wordpress-theme') THEN
		  CASE WHEN i.evidence->>'wordpress_org' = 'no' THEN 'not from wordpress.org: ' || COALESCE(i.evidence->>'wordpress_org_reason', '')
		    WHEN pr.deprecated <> '' THEN pr.deprecated
		    WHEN pr.last_error <> '' AND COALESCE(pr.latest_stable, '') = '' THEN pr.last_error
		    ELSE '' END
		  ELSE '' END`+from+
		` ORDER BY c.type, c.namespace, c.name, i.version, i.id`+page, w.args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []InventoryRow{}
	for rows.Next() {
		var r InventoryRow
		var ev, note []byte
		if err := rows.Scan(&r.ID, &r.AssetID, &r.AssetName, &r.AssetKind, &r.ComponentID, &r.Type, &r.Namespace, &r.Name,
			&r.Purl, &r.Version, &r.Location, &r.CollectorID, &r.Direct, &r.Scope, &r.Confidence, &ev,
			&r.FirstSeen, &r.LastSeen, &r.CollectionID, &r.RemovedAt, &r.LatestStable, &r.OpenFindings,
			&r.Coverage, &r.CoverageReason, &r.CoverageFeed, &r.EvaluatedAt, &note, &r.UncheckedReason, &r.UncheckedCause,
			&r.ReleaseNote); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(ev, &r.Evidence)
		if len(note) > 0 {
			_ = json.Unmarshal(note, &r.LifecycleNote)
		}
		r.UpdateType = updateType(r.Type, r.Namespace, r.Version, r.LatestStable)
		r.UncheckedActor = UncheckedActors[r.UncheckedReason]
		if r.UncheckedReason != UncheckedUnreadableVersion {
			r.UncheckedCause = ""
		}
		r.UncheckedFix, r.UncheckedDocs = UnreadableVersionFix(r.UncheckedCause, r.Location)
		if r.UncheckedReason == UncheckedOther {
			r.UncheckedFix = OtherFix
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

type CoverageRow struct {
	AssetID     int64      `json:"asset_id"`
	AssetName   string     `json:"asset_name"`
	CollectorID string     `json:"collector_id"`
	Scope       string     `json:"scope"`
	Status      string     `json:"status"`
	Reason      string     `json:"reason"`
	ToolVersion string     `json:"tool_version"`
	LastAttempt time.Time  `json:"last_attempt"`
	LastSuccess *time.Time `json:"last_success"`
}

// ListCoverage returns ledger rows, optionally for one asset or excluding
// healthy rows.
func (s *Store) ListCoverage(ctx context.Context, assetID int64, problemsOnly bool, p Page) ([]CoverageRow, int64, error) {
	w := &where{}
	w.conds = append(w.conds, "a.merged_into IS NULL")
	if assetID > 0 {
		w.add("cv.asset_id = ?", assetID)
	}
	if problemsOnly {
		w.conds = append(w.conds, "cv.status <> 'checked'")
	}
	from := ` FROM coverage cv JOIN assets a ON a.id = cv.asset_id` + w.sql()
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+from, w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p = p.norm()
	rows, err := s.Pool.Query(ctx, `SELECT cv.asset_id, a.name, cv.collector_id, cv.scope, cv.status, cv.reason, cv.tool_version,
		cv.last_attempt, cv.last_success`+from+
		fmt.Sprintf(` ORDER BY (cv.status = 'checked'), a.name, cv.scope LIMIT %d OFFSET %d`, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[CoverageRow])
	return out, total, err
}

type Collection struct {
	ID               int64     `json:"id"`
	AssetID          int64     `json:"asset_id"`
	CollectorID      string    `json:"collector_id"`
	CollectorVersion string    `json:"collector_version"`
	Method           string    `json:"method"`
	ObservedAt       time.Time `json:"observed_at"`
	ReceivedAt       time.Time `json:"received_at"`
	Complete         bool      `json:"complete"`
	ObservationCount int       `json:"observation_count"`
}

func (s *Store) ListCollections(ctx context.Context, assetID int64, limit int) ([]Collection, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, asset_id, collector_id, collector_version, method, observed_at, received_at,
		complete, observation_count FROM collections WHERE asset_id = $1 ORDER BY received_at DESC LIMIT $2`, assetID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Collection])
}

type Relation struct {
	FromAsset int64     `json:"from_asset"`
	FromName  string    `json:"from_name"`
	ToAsset   int64     `json:"to_asset"`
	ToName    string    `json:"to_name"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) AssetRelations(ctx context.Context, id int64) ([]Relation, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.from_asset, f.name, r.to_asset, t.name, r.kind, r.source, r.created_at
		FROM asset_relations r JOIN assets f ON f.id = r.from_asset JOIN assets t ON t.id = r.to_asset
		WHERE r.from_asset = $1 OR r.to_asset = $1 ORDER BY r.kind, f.name, t.name`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Relation])
}

func (s *Store) AddRelation(ctx context.Context, from, to int64, kind, source string) error {
	if from == to {
		return fmt.Errorf("an asset cannot relate to itself: %w", ErrConflict)
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO asset_relations (from_asset, to_asset, kind, source) VALUES ($1,$2,$3,$4)
		ON CONFLICT DO NOTHING`, from, to, kind, source)
	return err
}

func (s *Store) DeleteRelation(ctx context.Context, from, to int64, kind string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM asset_relations WHERE from_asset = $1 AND to_asset = $2 AND kind = $3`, from, to, kind)
	return err
}

type Conflict struct {
	ID          int64           `json:"id"`
	AssetIDs    []int64         `json:"asset_ids"`
	Identifiers json.RawMessage `json:"identifiers"`
	DetectedAt  time.Time       `json:"detected_at"`
	Assets      json.RawMessage `json:"assets"` // id, name, kind, last_seen of each candidate
}

func (s *Store) ListConflicts(ctx context.Context) ([]Conflict, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.id, c.asset_ids, c.identifiers, c.detected_at,
		COALESCE((SELECT json_agg(json_build_object('id', a.id, 'name', a.name, 'kind', a.kind, 'last_seen', a.last_seen,
		  'component_count', (SELECT count(*) FROM inventory i WHERE i.asset_id = a.id AND i.removed_at IS NULL)) ORDER BY a.id)
		  FROM assets a WHERE a.id = ANY(c.asset_ids)), '[]')
		FROM identity_conflicts c WHERE c.resolved_at IS NULL ORDER BY c.detected_at DESC`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Conflict])
}

// Facets lists the distinct values used by filters.
type Facets struct {
	Environments   []string `json:"environments"`
	AssetKinds     []string `json:"asset_kinds"`
	ComponentTypes []string `json:"component_types"`
}

func (s *Store) Facets(ctx context.Context) (*Facets, error) {
	f := &Facets{}
	err := s.Pool.QueryRow(ctx, `SELECT
		COALESCE((SELECT array_agg(DISTINCT environment ORDER BY environment) FROM assets WHERE merged_into IS NULL AND environment <> ''), '{}'),
		COALESCE((SELECT array_agg(DISTINCT kind ORDER BY kind) FROM assets WHERE merged_into IS NULL), '{}'),
		COALESCE((SELECT array_agg(DISTINCT c.type ORDER BY c.type) FROM components c
		  WHERE EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL)), '{}')`).
		Scan(&f.Environments, &f.AssetKinds, &f.ComponentTypes)
	return f, err
}

// ResolveConflict merges every asset in the conflict into target: their
// identifiers, inventory, coverage and relations move to target and they are
// marked merged_into so old links keep resolving.
func (s *Store) ResolveConflict(ctx context.Context, conflictID, target, userID int64) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		var ids []int64
		err := tx.QueryRow(ctx, `SELECT asset_ids FROM identity_conflicts WHERE id = $1 AND resolved_at IS NULL FOR UPDATE`, conflictID).Scan(&ids)
		if err != nil {
			return notFound(err)
		}
		found := false
		for _, id := range ids {
			if id == target {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("target asset %d is not part of conflict %d: %w", target, conflictID, ErrConflict)
		}
		// The findings of every asset merged are locked first, in id order,
		// as an evaluation locks them (see SyncFindings): merging them one
		// asset after another would lock them out of order. FOR UPDATE, as
		// dropped inventory takes its findings with it.
		if _, err := tx.Exec(ctx, `SELECT id FROM findings WHERE asset_id = ANY($1) AND asset_id <> $2 ORDER BY id FOR UPDATE`,
			ids, target); err != nil {
			return err
		}
		for _, id := range ids {
			if id == target {
				continue
			}
			if err := mergeAsset(ctx, tx, id, target); err != nil {
				return err
			}
		}
		var by *int64
		if userID > 0 {
			by = &userID
		}
		_, err = tx.Exec(ctx, `UPDATE identity_conflicts SET resolved_at = now(), resolved_by = $2 WHERE id = $1`, conflictID, by)
		return err
	})
}

func mergeAsset(ctx context.Context, tx pgx.Tx, from, into int64) error {
	// The caller has locked the merged assets' findings (see
	// ResolveConflict).
	stmts := []string{
		`UPDATE asset_identifiers SET asset_id = $2 WHERE asset_id = $1`,
		// Inventory rows that already exist on the target are dropped.
		`DELETE FROM inventory s USING inventory t WHERE s.asset_id = $1 AND t.asset_id = $2
		   AND s.component_id = t.component_id AND s.version = t.version AND s.location = t.location AND s.collector_id = t.collector_id`,
		`UPDATE inventory SET asset_id = $2 WHERE asset_id = $1`,
		`UPDATE findings SET asset_id = $2 WHERE asset_id = $1`,
		`UPDATE api_tokens SET asset_id = $2 WHERE asset_id = $1`,
		`UPDATE remediation_actions SET status = 'cancelled', error = 'asset merged into ' || $2::bigint WHERE asset_id = $1 AND status = 'pending'`,
		`UPDATE remediation_actions SET asset_id = $2 WHERE asset_id = $1 AND status NOT IN ('pending', 'dispatched', 'applied')`,
		`DELETE FROM coverage s USING coverage t WHERE s.asset_id = $1 AND t.asset_id = $2
		   AND s.collector_id = t.collector_id AND s.scope = t.scope`,
		`UPDATE coverage SET asset_id = $2 WHERE asset_id = $1`,
		`UPDATE collections SET asset_id = $2 WHERE asset_id = $1`,
		// The target joins the merged asset's projects, and grants on the
		// merged asset now apply to the target.
		`INSERT INTO project_assets (workspace_id, project_id, asset_id, added_at)
		   SELECT workspace_id, project_id, $2, added_at FROM project_assets WHERE asset_id = $1 ON CONFLICT DO NOTHING`,
		`DELETE FROM project_assets WHERE asset_id = $1 AND $2::bigint IS NOT NULL`,
		`UPDATE access_grants g SET asset_id = $2 WHERE g.asset_id = $1 AND NOT EXISTS (SELECT 1 FROM access_grants o
		   WHERE o.asset_id = $2 AND o.user_id IS NOT DISTINCT FROM g.user_id AND o.team_id IS NOT DISTINCT FROM g.team_id)`,
		`DELETE FROM access_grants WHERE asset_id = $1 AND $2::bigint IS NOT NULL`,
		`INSERT INTO asset_relations (from_asset, to_asset, kind, source, created_at)
		   SELECT CASE WHEN from_asset = $1 THEN $2 ELSE from_asset END, CASE WHEN to_asset = $1 THEN $2 ELSE to_asset END, kind, source, created_at
		   FROM asset_relations WHERE (from_asset = $1 OR to_asset = $1) AND from_asset <> to_asset
		   ON CONFLICT DO NOTHING`,
		`DELETE FROM asset_relations WHERE from_asset IN ($1, $2) AND to_asset IN ($1, $2) OR from_asset = $1 OR to_asset = $1`,
		`UPDATE assets t SET first_seen = LEAST(t.first_seen, f.first_seen), last_seen = GREATEST(t.last_seen, f.last_seen)
		   FROM assets f WHERE t.id = $2 AND f.id = $1`,
		`UPDATE assets SET merged_into = $2 WHERE id = $1 OR merged_into = $1`,
	}
	for _, q := range stmts {
		if _, err := tx.Exec(ctx, q, from, into); err != nil {
			return err
		}
	}
	return nil
}
