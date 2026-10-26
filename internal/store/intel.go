package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/osv"
)

type Feed struct {
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Enabled     bool       `json:"enabled"`
	Auto        bool       `json:"auto"`
	RefreshMin  int64      `json:"refresh_minutes"`
	StaleMin    int64      `json:"stale_after_minutes"`
	Cursor      string     `json:"cursor"`
	Records     int64      `json:"records"`
	LastAttempt *time.Time `json:"last_attempt"`
	LastSuccess *time.Time `json:"last_success"`
	LastError   string     `json:"last_error"`
	LastChanged int        `json:"last_changed"`
	Stale       bool       `json:"stale"`
	// Ecosystems lists the ecosystem strings a vulnerability feed has
	// advisories for; nil until it is known.
	Ecosystems []string `json:"ecosystems,omitempty"`
}

const feedCols = `name, kind, enabled, auto, (extract(epoch FROM refresh)/60)::bigint, (extract(epoch FROM stale_after)/60)::bigint,
	cursor, records, last_attempt, last_success, last_error, last_changed,
	(last_success IS NULL OR last_success < now() - stale_after), ecosystems`

func (s *Store) ListFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+feedCols+` FROM feeds ORDER BY kind, name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Feed])
}

func (s *Store) GetFeed(ctx context.Context, name string) (*Feed, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+feedCols+` FROM feeds WHERE name = $1`, name)
	if err != nil {
		return nil, err
	}
	f, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Feed])
	return f, notFound(err)
}

// EnsureFeed creates a feed if missing; existing settings are kept.
func (s *Store) EnsureFeed(ctx context.Context, name, kind string, refresh, staleAfter time.Duration) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO feeds (name, kind, refresh, stale_after) VALUES ($1, $2, $3, $4)
		ON CONFLICT (name) DO NOTHING`, name, kind, refresh, staleAfter)
	return err
}

func (s *Store) SetFeedEnabled(ctx context.Context, name string, enabled bool) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE feeds SET enabled = $2 WHERE name = $1`, name, enabled)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DueFeeds returns enabled feeds whose refresh interval has elapsed since
// the last attempt.
func (s *Store) DueFeeds(ctx context.Context) ([]Feed, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+feedCols+` FROM feeds
		WHERE enabled AND (last_attempt IS NULL OR last_attempt + refresh <= now())`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Feed])
}

// FeedAttempt records the start of a sync. A previous attempt that recorded
// no outcome (neither success nor error) was cut short, by a crash or kill of
// the server running it; that is recorded as the feed's error, so the feed
// shows as failing until this attempt succeeds.
func (s *Store) FeedAttempt(ctx context.Context, name string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE feeds SET last_attempt = now(),
		last_error = CASE WHEN last_attempt IS NOT NULL AND last_error = '' AND (last_success IS NULL OR last_success < last_attempt)
		  THEN 'the sync started ' || to_char(last_attempt AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') || ' UTC was interrupted before it finished'
		  ELSE last_error END
		WHERE name = $1`, name)
	return err
}

func (s *Store) FeedResult(ctx context.Context, name, cursor string, changed int, runErr error) error {
	if runErr != nil {
		msg := runErr.Error()
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		_, err := s.Pool.Exec(ctx, `UPDATE feeds SET last_error = $2 WHERE name = $1`, name, msg)
		return err
	}
	_, err := s.Pool.Exec(ctx, `UPDATE feeds SET last_success = now(), last_error = '', cursor = $2, last_changed = $3,
		records = CASE
		  WHEN name LIKE 'osv:%' THEN (SELECT count(*) FROM advisories WHERE feed = $1)
		  WHEN name LIKE 'releases:%' THEN (SELECT count(*) FROM package_releases WHERE source = $1 AND last_error = '')
		  ELSE records END
		WHERE name = $1`, name, cursor, changed)
	return err
}

// UpdateFeedEcosystems records the ecosystems a vulnerability feed covers.
// A full sync replaces the list; an incremental one adds to it, reading the
// stored advisories of the base ecosystem when nothing is known yet.
func (s *Store) UpdateFeedEcosystems(ctx context.Context, name, base string, seen []string, replace bool) error {
	if seen == nil {
		seen = []string{}
	}
	if replace {
		_, err := s.Pool.Exec(ctx, `UPDATE feeds SET ecosystems = (SELECT COALESCE(array_agg(DISTINCT e ORDER BY e), '{}') FROM unnest($2::text[]) e)
			WHERE name = $1`, name, seen)
		return err
	}
	_, err := s.Pool.Exec(ctx, `UPDATE feeds SET ecosystems = CASE
		  WHEN ecosystems IS NULL THEN (SELECT COALESCE(array_agg(DISTINCT e ORDER BY e), '{}') FROM (
		    SELECT ecosystem AS e FROM advisory_packages WHERE base_ecosystem = $3 UNION SELECT unnest($2::text[])) x)
		  ELSE (SELECT array_agg(DISTINCT e ORDER BY e) FROM unnest(ecosystems || $2::text[]) e) END
		WHERE name = $1`, name, seen, base)
	return err
}

func (s *Store) SetFeedRecords(ctx context.Context, name string, n int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE feeds SET records = $2 WHERE name = $1`, name, n)
	return err
}

// PackageRef identifies an OSV package.
type PackageRef struct {
	BaseEcosystem string
	Name          string
}

// UpsertAdvisories stores OSV records and returns the packages they touch,
// so only affected components are re-evaluated.
func (s *Store) UpsertAdvisories(ctx context.Context, feed string, vulns []*osv.Vulnerability) (map[PackageRef]bool, error) {
	touched := map[PackageRef]bool{}
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		ids := make([]string, 0, len(vulns))
		for _, v := range vulns {
			ids = append(ids, v.ID)
		}
		// Packages the old versions referenced are touched too: an advisory
		// that drops a package must clear that package's findings.
		rows, err := tx.Query(ctx, `SELECT DISTINCT base_ecosystem, name FROM advisory_packages WHERE advisory_id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var p PackageRef
			if err := rows.Scan(&p.BaseEcosystem, &p.Name); err != nil {
				rows.Close()
				return err
			}
			touched[p] = true
		}
		rows.Close()
		if _, err := tx.Exec(ctx, `DELETE FROM advisory_packages WHERE advisory_id = ANY($1)`, ids); err != nil {
			return err
		}
		batch := &pgx.Batch{}
		var pkgRows [][]any
		for _, v := range vulns {
			r := osv.Rate(v)
			var score *float32
			if r.Score > 0 || r.Source == "cvss_v3" || r.Source == "cvss_v4" {
				f := float32(r.Score)
				score = &f
			}
			refs, _ := json.Marshal(v.References)
			aliases := v.Aliases
			if aliases == nil {
				aliases = []string{}
			}
			var published *time.Time
			if !v.Published.IsZero() {
				published = &v.Published
			}
			modified := v.Modified
			if modified.IsZero() {
				modified = time.Now()
			}
			batch.Queue(`INSERT INTO advisories (id, feed, group_key, aliases, summary, severity_level, severity_score,
				severity_vector, severity_source, published, modified, withdrawn, refs, known_exploited, fetched_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
				  EXISTS (SELECT 1 FROM known_exploited k WHERE k.cve = $3 OR k.cve = ANY($4)), now())
				ON CONFLICT (id) DO UPDATE SET feed = EXCLUDED.feed, group_key = EXCLUDED.group_key, aliases = EXCLUDED.aliases,
				  summary = EXCLUDED.summary, severity_level = EXCLUDED.severity_level, severity_score = EXCLUDED.severity_score,
				  severity_vector = EXCLUDED.severity_vector, severity_source = EXCLUDED.severity_source,
				  published = EXCLUDED.published, modified = EXCLUDED.modified, withdrawn = EXCLUDED.withdrawn,
				  refs = EXCLUDED.refs, known_exploited = EXCLUDED.known_exploited, fetched_at = now()`,
				v.ID, feed, osv.GroupKey(v.ID, v.Aliases, v.Upstream...), aliases, truncateText(v.Summary, 500), r.Level, score, r.Vector, r.Source,
				published, modified, v.Withdrawn, refs)
			for _, a := range v.Affected {
				if a.Package.Name == "" || a.Package.Ecosystem == "" {
					continue
				}
				aj, _ := json.Marshal(a)
				base := osv.BaseEcosystem(a.Package.Ecosystem)
				pkgRows = append(pkgRows, []any{v.ID, base, a.Package.Ecosystem, a.Package.Name, aj})
				touched[PackageRef{base, a.Package.Name}] = true
			}
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
		_, err = tx.CopyFrom(ctx, pgx.Identifier{"advisory_packages"},
			[]string{"advisory_id", "base_ecosystem", "ecosystem", "name", "affected"}, pgx.CopyFromRows(pkgRows))
		return err
	})
	return touched, err
}

func truncateText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// AdvisoryMatch is a candidate advisory for one package.
type AdvisoryMatch struct {
	ID             string
	GroupKey       string
	Aliases        []string
	Summary        string
	SeverityLevel  string
	SeverityScore  *float32
	Withdrawn      *time.Time
	KnownExploited bool
	Feed           string
	Ecosystem      string
	Affected       osv.Affected
}

// AdvisoriesFor returns every affected entry for a package in a base
// ecosystem. Callers filter by exact ecosystem with osv.MatchEcosystem.
func (s *Store) AdvisoriesFor(ctx context.Context, base, name string) ([]AdvisoryMatch, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.group_key, a.aliases, a.summary, a.severity_level, a.severity_score,
		a.withdrawn, a.known_exploited, a.feed, p.ecosystem, p.affected
		FROM advisory_packages p JOIN advisories a ON a.id = p.advisory_id
		WHERE p.base_ecosystem = $1 AND p.name = $2`, base, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdvisoryMatch
	for rows.Next() {
		var m AdvisoryMatch
		var aff []byte
		if err := rows.Scan(&m.ID, &m.GroupKey, &m.Aliases, &m.Summary, &m.SeverityLevel, &m.SeverityScore,
			&m.Withdrawn, &m.KnownExploited, &m.Feed, &m.Ecosystem, &aff); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(aff, &m.Affected); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

type Advisory struct {
	ID             string          `json:"id"`
	Feed           string          `json:"feed"`
	GroupKey       string          `json:"group_key"`
	Aliases        []string        `json:"aliases"`
	Summary        string          `json:"summary"`
	SeverityLevel  string          `json:"severity"`
	SeverityScore  *float32        `json:"score"`
	SeverityVector string          `json:"vector"`
	SeveritySource string          `json:"severity_source"`
	Published      *time.Time      `json:"published"`
	Modified       time.Time       `json:"modified"`
	Withdrawn      *time.Time      `json:"withdrawn"`
	Refs           json.RawMessage `json:"references"`
	KnownExploited bool            `json:"known_exploited"`
	FetchedAt      time.Time       `json:"fetched_at"`
}

// AdvisoryGroup returns every advisory with the given group key or id.
func (s *Store) AdvisoryGroup(ctx context.Context, key string) ([]Advisory, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, feed, group_key, aliases, summary, severity_level, severity_score, severity_vector,
		severity_source, published, modified, withdrawn, refs, known_exploited, fetched_at
		FROM advisories WHERE group_key = $1 OR id = $1 ORDER BY id`, key)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Advisory])
}

// ReplaceKnownExploited swaps in the latest KEV catalogue and refreshes the
// advisory flags.
func (s *Store) ReplaceKnownExploited(ctx context.Context, rows [][]any) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM known_exploited`); err != nil {
			return err
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"known_exploited"},
			[]string{"cve", "vendor", "product", "name", "added", "due_date", "ransomware"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE advisories a SET known_exploited = EXISTS (
			SELECT 1 FROM known_exploited k WHERE k.cve = a.group_key OR k.cve = ANY(a.aliases))`)
		return err
	})
}

// EvalRow is an inventory row prepared for evaluation.
type EvalRow struct {
	InventoryID int64
	AssetID     int64
	ComponentID int64
	PurlKey     string
	Type        string
	Purl        string
	Version     string
	Confidence  string
	Evidence    map[string]string
	AssetStale  bool
	// RunningKernel comes from the host agent ("" when unknown).
	RunningKernel string
}

// EvalRows returns current inventory rows, optionally limited to components
// or one asset.
func (s *Store) EvalRows(ctx context.Context, componentIDs []int64, assetID int64) ([]EvalRow, error) {
	w := &where{}
	w.conds = append(w.conds, "i.removed_at IS NULL", "a.merged_into IS NULL")
	if componentIDs != nil {
		w.add("i.component_id = ANY(?)", componentIDs)
	}
	if assetID > 0 {
		w.add("i.asset_id = ?", assetID)
	}
	rows, err := s.Pool.Query(ctx, `SELECT i.id, i.asset_id, i.component_id, c.purl_key, c.type, i.purl, i.version, i.confidence,
		i.evidence, a.collection_status = 'stale', COALESCE(a.attributes->>'kernel_running', '')
		FROM inventory i JOIN components c ON c.id = i.component_id JOIN assets a ON a.id = i.asset_id`+w.sql()+` ORDER BY i.component_id`, w.args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvalRow
	for rows.Next() {
		var r EvalRow
		var ev []byte
		if err := rows.Scan(&r.InventoryID, &r.AssetID, &r.ComponentID, &r.PurlKey, &r.Type, &r.Purl, &r.Version, &r.Confidence, &ev, &r.AssetStale, &r.RunningKernel); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(ev, &r.Evidence)
		out = append(out, r)
	}
	return out, rows.Err()
}

// AssetOperatingSystems maps each asset with a current operating system row
// to "<endoflife.date product>|<version>" ("ubuntu|22.04").
func (s *Store) AssetOperatingSystems(ctx context.Context) (map[int64]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT i.asset_id, c.name, i.version FROM inventory i JOIN components c ON c.id = i.component_id
		WHERE i.removed_at IS NULL AND c.type = 'generic' AND i.evidence->>'kind' = 'operating-system' ORDER BY i.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var name, v string
		if err := rows.Scan(&id, &name, &v); err != nil {
			return nil, err
		}
		if p := OSProducts[name]; p != "" {
			out[id] = p + "|" + v
		}
	}
	return out, rows.Err()
}

// OSProducts maps os-release IDs to endoflife.date product names.
var OSProducts = map[string]string{
	"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux", "rocky": "rocky-linux",
	"almalinux": "almalinux", "rhel": "rhel", "centos": "centos", "amzn": "amazon-linux",
	"fedora": "fedora", "opensuse-leap": "opensuse", "sles": "sles", "ol": "oracle-linux",
}

// ComponentsOfTypes returns ids of components with current inventory whose
// purl type is in types.
func (s *Store) ComponentsOfTypes(ctx context.Context, types []string) ([]int64, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.id FROM components c WHERE c.type = ANY($1)
		AND EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL)`, types)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[int64])
}

// InventoryProfile summarises what is installed so feeds can be enabled for
// exactly the ecosystems in use.
type InventoryProfile struct {
	Types   map[string]int64 // purl type -> rows
	Distros map[string]int64 // "deb:debian-12" -> rows
}

func (s *Store) InventoryProfile(ctx context.Context) (*InventoryProfile, error) {
	p := &InventoryProfile{Types: map[string]int64{}, Distros: map[string]int64{}}
	rows, err := s.Pool.Query(ctx, `SELECT c.type, COALESCE(substring(i.purl from '[?&]distro=([^&#]+)'), ''), count(*)
		FROM inventory i JOIN components c ON c.id = i.component_id WHERE i.removed_at IS NULL GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t, d string
		var n int64
		if err := rows.Scan(&t, &d, &n); err != nil {
			return nil, err
		}
		p.Types[t] += n
		if d != "" {
			p.Distros[t+":"+d] += n
		}
	}
	return p, rows.Err()
}

// FindingInput is the matcher's desired state for one finding.
type FindingInput struct {
	Kind         string
	Key          string
	InventoryID  int64
	AssetID      int64
	ComponentID  int64
	Verification string
	Severity     string
	Score        *float32
	Title        string
	FixedVersion string
	Sources      []string
	Evidence     map[string]any
}

// SyncFindings makes the open findings for the evaluated inventory rows of
// the given kinds exactly match want: new ones are opened, existing ones
// refreshed (and reopened if they were resolved), and the rest resolved.
func (s *Store) SyncFindings(ctx context.Context, kinds []string, inventoryIDs []int64, want []FindingInput) (opened, resolved int64, err error) {
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE want_findings (
			kind text, key text, inventory_id bigint, asset_id bigint, component_id bigint, verification text,
			severity text, score real, title text, fixed_version text, sources text[], evidence jsonb) ON COMMIT DROP`); err != nil {
			return err
		}
		rows := make([][]any, 0, len(want))
		for _, f := range want {
			ev, _ := json.Marshal(f.Evidence)
			rows = append(rows, []any{f.Kind, f.Key, f.InventoryID, f.AssetID, f.ComponentID, f.Verification, f.Severity,
				f.Score, f.Title, f.FixedVersion, f.Sources, ev})
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"want_findings"},
			[]string{"kind", "key", "inventory_id", "asset_id", "component_id", "verification", "severity", "score", "title",
				"fixed_version", "sources", "evidence"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		// Findings detected again after being resolved are recorded before
		// the upsert reopens them, with the resolution they had.
		if _, err := tx.Exec(ctx, `INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_name, action, note, detail)
			SELECT f.workspace_id, f.id, 'system', 'matcher', 'reopened', 'detected again after it was resolved',
			  jsonb_build_object('resolved_at', f.resolved_at, 'resolution', f.resolution)
			FROM findings f JOIN want_findings w ON w.inventory_id = f.inventory_id AND w.kind = f.kind AND w.key = f.key
			WHERE f.status = 'resolved'`); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `INSERT INTO findings AS f (kind, key, inventory_id, asset_id, component_id, verification, severity,
			score, title, fixed_version, sources, evidence)
			SELECT kind, key, inventory_id, asset_id, component_id, verification, severity, score, title, fixed_version, sources, evidence
			FROM want_findings
			ON CONFLICT (inventory_id, kind, key) DO UPDATE SET
			  verification = EXCLUDED.verification, severity = EXCLUDED.severity, score = EXCLUDED.score,
			  title = EXCLUDED.title, fixed_version = EXCLUDED.fixed_version, sources = EXCLUDED.sources,
			  evidence = EXCLUDED.evidence, last_seen = now(),
			  status = 'open', resolved_at = NULL, resolution = ''
			WHERE f.status = 'resolved' OR f.verification IS DISTINCT FROM EXCLUDED.verification
			  OR f.severity IS DISTINCT FROM EXCLUDED.severity OR f.fixed_version IS DISTINCT FROM EXCLUDED.fixed_version
			  OR f.sources IS DISTINCT FROM EXCLUDED.sources OR f.evidence IS DISTINCT FROM EXCLUDED.evidence
			  OR f.last_seen < now() - interval '1 hour'`)
		if err != nil {
			return err
		}
		opened = tag.RowsAffected()
		tag, err = tx.Exec(ctx, `WITH r AS (UPDATE findings f SET status = 'resolved', resolved_at = now(),
			resolution = 'no longer affected (re-evaluated ' || to_char(now(), 'YYYY-MM-DD') || ')'
			WHERE f.status = 'open' AND f.kind = ANY($1) AND f.inventory_id = ANY($2)
			AND NOT EXISTS (SELECT 1 FROM want_findings w WHERE w.inventory_id = f.inventory_id AND w.kind = f.kind AND w.key = f.key)
			RETURNING f.workspace_id, f.id, f.resolution)
			`+resolvedEvents, kinds, inventoryIDs)
		if err != nil {
			return err
		}
		resolved = tag.RowsAffected()
		return nil
	})
	return opened, resolved, err
}

// ResolveRemovedFindings closes findings whose inventory row is gone, saying
// why: fixed by a remediation plan, upgraded to another version, or removed.
func (s *Store) ResolveRemovedFindings(ctx context.Context) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `WITH r AS (UPDATE findings f SET status = 'resolved', resolved_at = now(),
		resolution = COALESCE(
		  (SELECT 'fixed by remediation plan #' || ra.plan_id || ' (upgraded to ' || ra.to_version || ')'
		     FROM remediation_actions ra WHERE ra.inventory_id = f.inventory_id AND ra.status = 'verified'
		     ORDER BY ra.verified_at DESC LIMIT 1),
		  (SELECT 'upgraded to ' || cur.version FROM inventory cur
		     WHERE cur.asset_id = f.asset_id AND cur.component_id = f.component_id AND cur.removed_at IS NULL
		     ORDER BY cur.last_seen DESC LIMIT 1),
		  'component no longer installed')
		FROM inventory i WHERE i.id = f.inventory_id AND f.status = 'open' AND i.removed_at IS NOT NULL
		RETURNING f.workspace_id, f.id, f.resolution)
		`+resolvedEvents)
	return tag.RowsAffected(), err
}

// resolvedEvents records one 'resolved' event per row of r, the findings an
// UPDATE ... RETURNING workspace_id, id, resolution just resolved.
const resolvedEvents = `INSERT INTO finding_events (workspace_id, finding_id, actor_type, actor_name, action, note)
	SELECT workspace_id, id, 'system', 'matcher', 'resolved', resolution FROM r`

// Row coverage states (inventory.coverage). See docs/compatibility.md,
// "Coverage states".
const (
	CoverageAwaiting     = "awaiting"      // inventoried, not evaluated yet
	CoverageEvaluated    = "evaluated"     // matched against a vulnerability feed
	CoverageUnsupported  = "unsupported"   // no vulnerability source exists for it
	CoverageNotEvaluated = "not_evaluated" // a source exists but could not be used
)

// RowCoverage is the outcome of evaluating one inventory row.
type RowCoverage struct {
	InventoryID int64
	State       string // CoverageEvaluated, CoverageUnsupported or CoverageNotEvaluated
	Reason      string // why it was not evaluated, or how an evaluated row is reported
	Feed        string // the vulnerability feed it was matched against
	// Lifecycle is the upstream end-of-life note for a distribution
	// package (see intel.distroLifecycle); nil when there is none.
	Lifecycle map[string]any
}

// SetCoverage records how each evaluated inventory row was covered. It runs
// in the caller's workspace: a row's coverage is a property of that row
// (its version, its release, its workspace), never of the shared component.
func (s *Store) SetCoverage(ctx context.Context, rows []RowCoverage) error {
	const batch = 5000
	for i := 0; i < len(rows); i += batch {
		end := min(i+batch, len(rows))
		ids := make([]int64, 0, end-i)
		states := make([]string, 0, end-i)
		reasons := make([]string, 0, end-i)
		feeds := make([]string, 0, end-i)
		notes := make([]*string, 0, end-i)
		for _, r := range rows[i:end] {
			ids = append(ids, r.InventoryID)
			states = append(states, r.State)
			reasons = append(reasons, r.Reason)
			feeds = append(feeds, r.Feed)
			var note *string
			if r.Lifecycle != nil {
				b, _ := json.Marshal(r.Lifecycle)
				n := string(b)
				note = &n
			}
			notes = append(notes, note)
		}
		if _, err := s.Pool.Exec(ctx, `UPDATE inventory i SET coverage = u.state, coverage_reason = u.reason,
			coverage_feed = u.feed, lifecycle_note = u.note::jsonb, evaluated_at = now()
			FROM unnest($1::bigint[], $2::text[], $3::text[], $4::text[], $5::text[]) AS u(id, state, reason, feed, note)
			WHERE i.id = u.id`, ids, states, reasons, feeds, notes); err != nil {
			return err
		}
	}
	return nil
}

// --- releases and lifecycle

type Release struct {
	ComponentID     int64             `json:"component_id"`
	Latest          string            `json:"latest"`
	LatestStable    string            `json:"latest_stable"`
	LatestPublished *time.Time        `json:"latest_published"`
	VersionDates    map[string]string `json:"version_dates,omitempty"`
	Yanked          map[string]string `json:"yanked,omitempty"` // withdrawn version -> reason
	// StableVersions lists every stable, non-withdrawn version the registry
	// publishes (empty for data stored before it was recorded).
	StableVersions []string  `json:"stable_versions,omitempty"`
	Deprecated     string    `json:"deprecated"`
	Source         string    `json:"source"`
	SourceURL      string    `json:"source_url"`
	CheckedAt      time.Time `json:"checked_at"`
	LastError      string    `json:"last_error"`
}

func (s *Store) UpsertRelease(ctx context.Context, r Release) error {
	vd, yk := jsonMap(r.VersionDates), jsonMap(r.Yanked)
	// Release data is shared by every workspace that has the component.
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		return asSystem(ctx, tx, func() error { return upsertRelease(ctx, tx, r, vd, yk) })
	})
}

// emptyIfNil keeps NOT NULL array columns from receiving NULL.
func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func jsonMap(m map[string]string) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, _ := json.Marshal(m)
	return b
}

func upsertRelease(ctx context.Context, tx pgx.Tx, r Release, vd, yk []byte) error {
	_, err := tx.Exec(ctx, `INSERT INTO package_releases (component_id, latest, latest_stable, latest_published, version_dates,
		deprecated, source, source_url, checked_at, last_error, yanked, stable_versions) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (component_id) DO UPDATE SET
		  latest = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.latest ELSE package_releases.latest END,
		  latest_stable = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.latest_stable ELSE package_releases.latest_stable END,
		  latest_published = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.latest_published ELSE package_releases.latest_published END,
		  version_dates = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.version_dates ELSE package_releases.version_dates END,
		  deprecated = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.deprecated ELSE package_releases.deprecated END,
		  yanked = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.yanked ELSE package_releases.yanked END,
		  stable_versions = CASE WHEN EXCLUDED.last_error = '' THEN EXCLUDED.stable_versions ELSE package_releases.stable_versions END,
		  source = EXCLUDED.source, source_url = EXCLUDED.source_url, checked_at = EXCLUDED.checked_at, last_error = EXCLUDED.last_error`,
		r.ComponentID, r.Latest, r.LatestStable, r.LatestPublished, vd, r.Deprecated, r.Source, r.SourceURL, r.CheckedAt, r.LastError, yk,
		emptyIfNil(r.StableVersions))
	return err
}

func (s *Store) GetRelease(ctx context.Context, componentID int64) (*Release, error) {
	m, err := s.ReleasesFor(ctx, []int64{componentID})
	if err != nil {
		return nil, err
	}
	r, ok := m[componentID]
	if !ok {
		return nil, ErrNotFound
	}
	return r, nil
}

// ReleasesFor returns stored release data for the given components, keyed
// by component id; components without data are absent.
func (s *Store) ReleasesFor(ctx context.Context, componentIDs []int64) (map[int64]*Release, error) {
	rows, err := s.Pool.Query(ctx, `SELECT component_id, latest, latest_stable, latest_published, version_dates, deprecated, source,
		source_url, checked_at, last_error, yanked, stable_versions FROM package_releases WHERE component_id = ANY($1)`, componentIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]*Release{}
	for rows.Next() {
		var r Release
		var vd, yk []byte
		if err := rows.Scan(&r.ComponentID, &r.Latest, &r.LatestStable, &r.LatestPublished, &vd, &r.Deprecated, &r.Source,
			&r.SourceURL, &r.CheckedAt, &r.LastError, &yk, &r.StableVersions); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(vd, &r.VersionDates)
		_ = json.Unmarshal(yk, &r.Yanked)
		out[r.ComponentID] = &r
	}
	return out, rows.Err()
}

// ReleaseCandidates returns components of the given purl types whose
// release data is missing or older than maxAge.
type ReleaseCandidate struct {
	ComponentID int64
	Type        string
	Namespace   string
	Name        string
	Purl        string // one inventory purl as collected, before purl case normalisation
}

func (s *Store) ReleaseCandidates(ctx context.Context, types []string, maxAge time.Duration, limit int) ([]ReleaseCandidate, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.id, c.type, c.namespace, c.name,
		  COALESCE((SELECT i.purl FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL LIMIT 1), '')
		FROM components c
		LEFT JOIN package_releases r ON r.component_id = c.id
		WHERE c.type = ANY($1)
		  AND EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL)
		  AND (r.checked_at IS NULL OR r.checked_at < now() - make_interval(secs => $2))
		ORDER BY r.checked_at NULLS FIRST, c.id LIMIT $3`, types, maxAge.Seconds(), limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[ReleaseCandidate])
}

type LifecycleCycle struct {
	Product      string     `json:"product"`
	ProductLabel string     `json:"product_label"`
	Cycle        string     `json:"cycle"`
	Label        string     `json:"label"`
	ReleaseDate  *time.Time `json:"release_date"`
	LTS          bool       `json:"lts"`
	SupportUntil *time.Time `json:"support_until"`
	EOLUntil     *time.Time `json:"eol_until"`
	IsEOL        bool       `json:"is_eol"`
	Latest       string     `json:"latest"`
	LatestDate   *time.Time `json:"latest_date"`
	Link         string     `json:"link"`
}

// ReplaceLifecycle stores the full endoflife.date catalogue.
func (s *Store) ReplaceLifecycle(ctx context.Context, products [][]any, cycles [][]any) error {
	return pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM lifecycle_products`); err != nil {
			return err
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"lifecycle_products"}, []string{"product", "label", "purls", "link"}, pgx.CopyFromRows(products)); err != nil {
			return err
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"lifecycle_cycles"},
			[]string{"product", "cycle", "label", "release_date", "lts", "support_until", "eol_until", "is_eol", "latest", "latest_date"},
			pgx.CopyFromRows(cycles))
		return err
	})
}

// LifecycleCycles returns cycles for a product, newest first.
func (s *Store) LifecycleCycles(ctx context.Context, product string) ([]LifecycleCycle, error) {
	rows, err := s.Pool.Query(ctx, `SELECT c.product, p.label, c.cycle, c.label, c.release_date, c.lts, c.support_until, c.eol_until,
		c.is_eol, c.latest, c.latest_date, p.link
		FROM lifecycle_cycles c JOIN lifecycle_products p ON p.product = c.product WHERE c.product = $1
		ORDER BY c.release_date DESC NULLS LAST`, product)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[LifecycleCycle])
}

// LifecycleProductNames returns every known endoflife.date product id.
func (s *Store) LifecycleProductNames(ctx context.Context) (map[string]bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT product FROM lifecycle_products`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	m := map[string]bool{}
	for _, n := range names {
		m[n] = true
	}
	return m, err
}

// LifecycleProductsByPurl maps versionless purls to product names.
func (s *Store) LifecycleProductsByPurl(ctx context.Context) (map[string]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT product, unnest(purls) FROM lifecycle_products`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var prod, purl string
		if err := rows.Scan(&prod, &purl); err != nil {
			return nil, err
		}
		m[strings.ToLower(purl)] = prod
	}
	return m, rows.Err()
}

// --- findings queries

type Finding struct {
	ID             int64           `json:"id"`
	Kind           string          `json:"kind"`
	Key            string          `json:"key"`
	InventoryID    int64           `json:"inventory_id"`
	AssetID        int64           `json:"asset_id"`
	AssetName      string          `json:"asset_name"`
	AssetKind      string          `json:"asset_kind"`
	Environment    string          `json:"environment"`
	ComponentID    int64           `json:"component_id"`
	ComponentName  string          `json:"component_name"`
	ComponentType  string          `json:"component_type"`
	Version        string          `json:"version"`
	Location       string          `json:"location"`
	Direct         *bool           `json:"direct"`
	Status         string          `json:"status"`
	Verification   string          `json:"verification"`
	Severity       string          `json:"severity"`
	Score          *float32        `json:"score"`
	Title          string          `json:"title"`
	FixedVersion   string          `json:"fixed_version"`
	Sources        []string        `json:"sources"`
	Evidence       json.RawMessage `json:"evidence"`
	FirstSeen      time.Time       `json:"first_seen"`
	LastSeen       time.Time       `json:"last_seen"`
	ResolvedAt     *time.Time      `json:"resolved_at"`
	Resolution     string          `json:"resolution"`
	KnownExploited bool            `json:"known_exploited"`
	// Workflow (Stage 3)
	State           string          `json:"state"`
	Priority        string          `json:"priority"`
	PriorityScore   float32         `json:"priority_score"`
	PriorityFactors json.RawMessage `json:"priority_factors"`
	SOS             bool            `json:"sos"`
	SOSRule         string          `json:"sos_rule"`
	AssigneeUserID  *int64          `json:"assignee_user_id"`
	AssigneeEmail   string          `json:"assignee_email"`
	AssigneeTeamID  *int64          `json:"assignee_team_id"`
	AssigneeTeam    string          `json:"assignee_team"`
	AckDue          *time.Time      `json:"ack_due"`
	FixDue          *time.Time      `json:"fix_due"`
	AcknowledgedAt  *time.Time      `json:"acknowledged_at"`
	SuppressedUntil *time.Time      `json:"suppressed_until"`
	StateReason     string          `json:"state_reason"`
	Mitigation      string          `json:"mitigation"`
	EscalationLevel int             `json:"escalation_level"`
	IncidentID      *int64          `json:"incident_id"`
	Overdue         bool            `json:"overdue"`
	FixGroup        string          `json:"fix_group"`
	// PriorityPolicy is the version of the risk policy that produced
	// Priority, PriorityScore, PriorityFactors and SOS.
	PriorityPolicy string `json:"priority_policy_version"`
}

type FindingFilter struct {
	Kind         string
	Status       string // default open
	Severity     []string
	Verification string
	AssetID      int64
	AssetIDs     []int64 // any of these assets
	ComponentID  int64
	Environment  string
	Search       string
	Key          string
	Exploited    bool
	State        string // new, acknowledged, in_progress, suppressed, risk_accepted, active (= not suppressed/accepted)
	Priority     []string
	SOS          bool
	AssigneeUser int64
	AssigneeTeam int64
	Unassigned   bool
	FixGroup     string
	IncidentID   int64
	Overdue      bool
	// ResolvedWithinDays keeps findings resolved in the last N days.
	ResolvedWithinDays int
	// NewWithinDays keeps findings first seen in the last N days.
	NewWithinDays int
	// ByAsset sorts by asset name first, for a list grouped by asset.
	ByAsset bool
	Page
}

const findingCols = `f.id, f.kind, f.key, f.inventory_id, f.asset_id, a.name, a.kind, a.environment, f.component_id,
	CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END, c.type, i.version, i.location, i.direct,
	f.status, f.verification, f.severity, f.score, f.title, f.fixed_version, f.sources, f.evidence, f.first_seen, f.last_seen,
	f.resolved_at, f.resolution, COALESCE((f.evidence->>'known_exploited')::boolean, false),
	f.state, f.priority, f.priority_score, f.priority_factors, f.sos, f.sos_rule, f.assignee_user_id, COALESCE(au.email, ''),
	f.assignee_team_id, COALESCE(ateam.name, ''), f.ack_due, f.fix_due, f.acknowledged_at, f.suppressed_until, f.state_reason,
	f.mitigation, f.escalation_level, f.incident_id,
	COALESCE(f.status = 'open' AND f.state IN ('new', 'acknowledged', 'in_progress') AND f.fix_due < now(), false), f.fix_group,
	f.priority_policy`

const findingFrom = ` FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
	JOIN components c ON c.id = f.component_id JOIN inventory i ON i.id = f.inventory_id
	LEFT JOIN users au ON au.id = f.assignee_user_id LEFT JOIN teams ateam ON ateam.id = f.assignee_team_id`

func (s *Store) ListFindings(ctx context.Context, f FindingFilter) ([]Finding, int64, error) {
	w := &where{}
	status := f.Status
	if status == "" {
		status = "open"
	}
	if status != "all" {
		w.add("f.status = ?", status)
	}
	if f.Kind != "" {
		w.add("f.kind = ?", f.Kind)
	}
	if len(f.Severity) > 0 {
		w.add("f.severity = ANY(?)", f.Severity)
	}
	if f.Verification != "" {
		w.add("f.verification = ?", f.Verification)
	}
	if f.AssetID > 0 {
		w.add("f.asset_id = ?", f.AssetID)
	}
	if f.AssetIDs != nil {
		w.add("f.asset_id = ANY(?)", f.AssetIDs)
	}
	if f.ComponentID > 0 {
		w.add("f.component_id = ?", f.ComponentID)
	}
	if f.Environment != "" {
		w.add("a.environment = ?", f.Environment)
	}
	if f.Key != "" {
		w.add("f.key = ?", f.Key)
	}
	if f.Exploited {
		w.conds = append(w.conds, "(f.evidence->>'known_exploited')::boolean")
	}
	switch f.State {
	case "":
	case "active":
		w.conds = append(w.conds, "f.state IN ('new', 'acknowledged', 'in_progress')")
	default:
		w.add("f.state = ?", f.State)
	}
	if len(f.Priority) > 0 {
		w.add("f.priority = ANY(?)", f.Priority)
	}
	if f.SOS {
		w.conds = append(w.conds, "f.sos")
	}
	if f.AssigneeUser > 0 {
		w.add("f.assignee_user_id = ?", f.AssigneeUser)
	}
	if f.FixGroup != "" {
		w.add("f.fix_group = ?", f.FixGroup)
	}
	if f.Unassigned {
		w.conds = append(w.conds, "f.assignee_user_id IS NULL AND f.assignee_team_id IS NULL")
	}
	if f.AssigneeTeam > 0 {
		w.add("f.assignee_team_id = ?", f.AssigneeTeam)
	}
	if f.IncidentID > 0 {
		w.add("f.incident_id = ?", f.IncidentID)
	}
	if f.Overdue {
		w.conds = append(w.conds, "f.state IN ('new', 'acknowledged', 'in_progress') AND f.fix_due < now()")
	}
	if f.NewWithinDays > 0 {
		w.add("f.first_seen > now() - make_interval(days => ?)", f.NewWithinDays)
	}
	if f.ResolvedWithinDays > 0 {
		w.add("f.resolved_at > now() - make_interval(days => ?)", f.ResolvedWithinDays)
	}
	if f.Search != "" {
		w.add("(c.name ILIKE ? OR f.key ILIKE ? OR f.title ILIKE ? OR a.name ILIKE ?)", likeEscape(f.Search))
	}
	// The count joins only what the conditions read: a finding's inventory row
	// and component always exist in its own workspace, and the assignee joins
	// are for display. Without them the count of open findings is an
	// index-only scan of findings_open_cover.
	countFrom := ` FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL`
	if f.Search != "" {
		countFrom += ` JOIN components c ON c.id = f.component_id`
	}
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*)`+countFrom+w.sql(), w.args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	p := f.Page.norm()
	// Keep this order in step with the findings_open_order index (migration
	// 0029), which serves the first pages without sorting.
	order := ""
	switch {
	case f.ByAsset:
		order = "a.name, a.id, "
	case f.Search != "":
		// A text search usually matches few rows spread through the whole
		// order. Walking findings_open_order until 50 match read every open
		// finding (over 10 s on 130,000); sorting the matches is faster.
		// This leading key sorts like f.sos DESC but does not match the
		// index, so the planner filters first.
		order = "CASE WHEN f.sos THEN 0 ELSE 1 END, "
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+findingCols+findingFrom+w.sql()+fmt.Sprintf(`
		ORDER BY %sf.sos DESC, f.priority, COALESCE((f.evidence->>'known_exploited')::boolean, false) DESC,
		  CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END DESC,
		  f.score DESC NULLS LAST, f.first_seen DESC, f.id LIMIT %d OFFSET %d`, order, p.Limit, p.Offset), w.args...)
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Finding])
	return out, total, err
}

func (s *Store) GetFinding(ctx context.Context, id int64) (*Finding, error) {
	rows, err := s.Pool.Query(ctx, `SELECT `+findingCols+findingFrom+` WHERE f.id = $1`, id)
	if err != nil {
		return nil, err
	}
	f, err := pgx.CollectExactlyOneRow(rows, pgx.RowToAddrOfStructByPos[Finding])
	return f, notFound(err)
}

type FindingSummary struct {
	BySeverity     map[string]int64 `json:"by_severity"`
	ByKind         map[string]int64 `json:"by_kind"`
	ByVerification map[string]int64 `json:"by_verification"`
	KnownExploited int64            `json:"known_exploited"`
	FixAvailable   int64            `json:"fix_available"`
	AffectedAssets int64            `json:"affected_assets"`
	EvaluationGaps int64            `json:"evaluation_gaps"`
	StaleFeeds     int64            `json:"stale_feeds"`
	ByPriority     map[string]int64 `json:"by_priority"`
	ByState        map[string]int64 `json:"by_state"`
	SOS            int64            `json:"sos"`
	Overdue        int64            `json:"overdue"`
	Unassigned     int64            `json:"unassigned"`
	// Resolved7d counts findings resolved in the last 7 days.
	Resolved7d int64 `json:"resolved_7d"`
}

func (s *Store) SummarizeFindings(ctx context.Context) (*FindingSummary, error) {
	sum := &FindingSummary{BySeverity: map[string]int64{}, ByKind: map[string]int64{}, ByVerification: map[string]int64{},
		ByPriority: map[string]int64{}, ByState: map[string]int64{}}
	// One pass over the open findings, answered from findings_open_cover
	// without reading the wide table rows.
	rows, err := s.Pool.Query(ctx, `SELECT f.priority, f.state, f.kind, f.severity, f.verification, count(*),
		count(*) FILTER (WHERE f.sos),
		count(*) FILTER (WHERE f.fix_due < now()),
		count(*) FILTER (WHERE f.assignee_user_id IS NULL AND f.assignee_team_id IS NULL)
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.status = 'open' GROUP BY 1, 2, 3, 4, 5`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var pr, st, k, sev, ver string
		var n, sos, overdue, unassigned int64
		if err := rows.Scan(&pr, &st, &k, &sev, &ver, &n, &sos, &overdue, &unassigned); err != nil {
			rows.Close()
			return nil, err
		}
		sum.ByState[st] += n
		sum.ByKind[k] += n
		sum.BySeverity[sev] += n
		sum.ByVerification[ver] += n
		if st == "new" || st == "acknowledged" || st == "in_progress" {
			sum.ByPriority[pr] += n
			sum.SOS += sos
			sum.Overdue += overdue
			sum.Unassigned += unassigned
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	err = s.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		  WHERE f.status = 'open' AND (f.evidence->>'known_exploited')::boolean),
		(SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		  WHERE f.status = 'open' AND f.fixed_version <> ''),
		(SELECT count(*) FROM assets a WHERE a.merged_into IS NULL
		  AND EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id AND f.status = 'open')),
		(SELECT count(DISTINCT i.component_id) FROM inventory i JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		  WHERE i.removed_at IS NULL AND i.coverage IN ('unsupported', 'not_evaluated')),
		(SELECT count(*) FROM feeds WHERE enabled AND (last_success IS NULL OR last_success < now() - stale_after)),
		(SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		  WHERE f.status = 'resolved' AND f.resolved_at > now() - interval '7 days')`).
		Scan(&sum.KnownExploited, &sum.FixAvailable, &sum.AffectedAssets, &sum.EvaluationGaps, &sum.StaleFeeds, &sum.Resolved7d)
	return sum, err
}

type EvaluationGap struct {
	ComponentID int64     `json:"component_id"`
	PurlKey     string    `json:"purl_key"`
	Reason      string    `json:"reason"`
	AssetCount  int64     `json:"asset_count"`
	UpdatedAt   time.Time `json:"updated_at"`
	// Coverage is "unsupported" when no source exists, "not_evaluated" when
	// one exists but could not be used (e.g. an unparseable version).
	Coverage string `json:"coverage"`
}

// ListEvaluationGaps lists components with at least one current inventory
// row that vulnerability intelligence did not cover, one entry per component
// and reason.
func (s *Store) ListEvaluationGaps(ctx context.Context, p Page) ([]EvaluationGap, int64, error) {
	from := ` FROM inventory i JOIN components c ON c.id = i.component_id JOIN assets a ON a.id = i.asset_id
		WHERE i.removed_at IS NULL AND a.merged_into IS NULL AND i.coverage IN ('unsupported', 'not_evaluated')`
	var total int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT DISTINCT i.component_id, i.coverage_reason`+from+`) x`).Scan(&total); err != nil {
		return nil, 0, err
	}
	p = p.norm()
	rows, err := s.Pool.Query(ctx, `SELECT i.component_id, c.purl_key, i.coverage_reason, count(DISTINCT i.asset_id),
		COALESCE(max(i.evaluated_at), now()), max(i.coverage)`+from+`
		GROUP BY i.component_id, c.purl_key, i.coverage_reason`+
		fmt.Sprintf(` ORDER BY 3, 2 LIMIT %d OFFSET %d`, p.Limit, p.Offset))
	if err != nil {
		return nil, 0, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[EvaluationGap])
	return out, total, err
}
