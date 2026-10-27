package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Global search matches one query against the vulnerabilities, open finding
// titles, components, assets, teams and (when asked) members of the current
// workspace. Every query reads tenant tables, or the component catalogue
// through the workspace's own inventory, so row-level security keeps results
// (and counts) inside the workspace. Accounts are global and have no
// row-level security, so members are read through the workspace's own
// membership rows only. Advisories are public data and are shown whether or
// not anything is affected.

const (
	SearchMinLen      = 2
	SearchMaxLen      = 200
	SearchMaxLimit    = 50
	searchDefault     = 10
	searchSampleLimit = 5
	// Finding titles are matched by substring over every open finding, so
	// they need a slightly longer query.
	searchTitleMinLen = 3
)

// Match ranks: an exact id, name or identifier first, then prefixes, then
// anything containing the query.
const (
	RankExact    = 0
	RankPrefix   = 1
	RankContains = 2
)

type SearchRef struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// SearchAdvisory is the public advisory behind a vulnerability result.
type SearchAdvisory struct {
	IDs            []string   `json:"ids"`
	Aliases        []string   `json:"aliases"`
	Summary        string     `json:"summary"`
	Severity       string     `json:"severity"`
	Score          *float32   `json:"score"`
	KnownExploited bool       `json:"known_exploited"`
	Published      *time.Time `json:"published"`
	Withdrawn      *time.Time `json:"withdrawn"`
}

// SearchVuln is one vulnerability (or end-of-life) key with the workspace's
// findings for it. Kind is empty when the advisory exists but nothing in the
// workspace is affected.
type SearchVuln struct {
	Key              string          `json:"key"`
	Kind             string          `json:"kind"`
	Rank             int             `json:"rank"`
	Title            string          `json:"title"`
	Severity         string          `json:"severity"`
	Score            *float32        `json:"score"`
	KnownExploited   bool            `json:"known_exploited"`
	OpenFindings     int64           `json:"open_findings"`
	ResolvedFindings int64           `json:"resolved_findings"`
	AffectedAssets   int64           `json:"affected_assets"` // assets with an open finding
	Assets           []SearchRef     `json:"assets"`          // a sample, assets with open findings first
	Components       []string        `json:"components"`      // a sample
	Advisory         *SearchAdvisory `json:"advisory,omitempty"`
}

type SearchComponent struct {
	ID           int64       `json:"id"`
	PurlKey      string      `json:"purl_key"`
	Type         string      `json:"type"`
	Namespace    string      `json:"namespace"`
	Name         string      `json:"name"`
	Rank         int         `json:"rank"`
	AssetCount   int64       `json:"asset_count"`
	Versions     []string    `json:"versions"` // installed versions, at most 20
	OpenFindings int64       `json:"open_findings"`
	Assets       []SearchRef `json:"assets"` // a sample, at the requested version when one was given
	// Version is the version asked for (lodash@4.17.20, openssl 3.0.2, a
	// purl); VersionAssets counts the assets that have it.
	Version       string `json:"version,omitempty"`
	VersionAssets int64  `json:"version_assets"`
}

type SearchAsset struct {
	ID           int64     `json:"id"`
	Kind         string    `json:"kind"`
	Name         string    `json:"name"`
	Environment  string    `json:"environment"`
	OwnerTeam    string    `json:"owner_team"`
	Status       string    `json:"collection_status"`
	LastSeen     time.Time `json:"last_seen"`
	Rank         int       `json:"rank"`
	MatchScheme  string    `json:"match_scheme"` // the identifier or attribute that matched, empty for the name
	MatchValue   string    `json:"match_value"`
	OpenFindings int64     `json:"open_findings"`
}

type SearchTeam struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Rank         int    `json:"rank"`
	AssetCount   int64  `json:"asset_count"`
	OpenFindings int64  `json:"open_findings"`
}

// SearchFinding is one finding key whose open findings have a title matching
// the query, such as "Command injection in lodash".
type SearchFinding struct {
	Key            string      `json:"key"`
	Kind           string      `json:"kind"`
	Title          string      `json:"title"`
	Rank           int         `json:"rank"`
	Severity       string      `json:"severity"`
	Score          *float32    `json:"score"`
	OpenFindings   int64       `json:"open_findings"`
	AffectedAssets int64       `json:"affected_assets"`
	Assets         []SearchRef `json:"assets"` // a sample
}

// SearchMember is a member of the current workspace, with their role there
// and the open findings assigned to them in it.
type SearchMember struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	Disabled     bool   `json:"disabled"`
	Rank         int    `json:"rank"`
	OpenAssigned int64  `json:"open_assigned"`
}

type SearchResults struct {
	Query           string            `json:"query"`
	Vulnerabilities []SearchVuln      `json:"vulnerabilities"`
	Findings        []SearchFinding   `json:"findings"`
	Assets          []SearchAsset     `json:"assets"`
	Components      []SearchComponent `json:"components"`
	Teams           []SearchTeam      `json:"teams"`
	Members         []SearchMember    `json:"members"`
	// More names the groups that had more matches than the limit.
	More map[string]bool `json:"more"`
}

// NormalizeSearch trims a query and checks its length.
func NormalizeSearch(q string) (string, error) {
	q = strings.TrimSpace(q)
	n := utf8.RuneCountInString(q)
	if n < SearchMinLen {
		return "", fmt.Errorf("the search needs at least %d characters: %w", SearchMinLen, ErrInvalid)
	}
	if n > SearchMaxLen {
		return "", fmt.Errorf("the search is limited to %d characters: %w", SearchMaxLen, ErrInvalid)
	}
	if strings.IndexFunc(q, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("the search contains control characters: %w", ErrInvalid)
	}
	return q, nil
}

// SearchOptions tune a search. The zero value searches every group but
// members, with the default limit.
type SearchOptions struct {
	// Limit applies to each group.
	Limit int
	// Members includes workspace members (names and emails); the caller
	// decides who may see them.
	Members bool
	// ProjectOnly leaves out teams and people, as for a member with
	// project access only (an assistant connected to one project).
	ProjectOnly bool
}

// Search runs the global search in the caller's workspace, without members.
// limit applies to each group.
func (s *Store) Search(ctx context.Context, query string, limit int) (*SearchResults, error) {
	return s.SearchWith(ctx, query, SearchOptions{Limit: limit})
}

// SearchWith runs the global search in the caller's workspace.
func (s *Store) SearchWith(ctx context.Context, query string, opt SearchOptions) (*SearchResults, error) {
	limit := opt.Limit
	if _, ok := tenant.Workspace(ctx); !ok {
		// System scope would see every workspace: search is for one.
		return nil, fmt.Errorf("search needs a workspace: %w", ErrInvalid)
	}
	q, err := NormalizeSearch(query)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = searchDefault
	}
	limit = min(limit, SearchMaxLimit)
	res := &SearchResults{Query: q, Vulnerabilities: []SearchVuln{}, Findings: []SearchFinding{}, Assets: []SearchAsset{},
		Components: []SearchComponent{}, Teams: []SearchTeam{}, Members: []SearchMember{}, More: map[string]bool{}}
	err = pgx.BeginTxFunc(ctx, s.Pool, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '5s'`); err != nil {
			return err
		}
		var more bool
		if res.Vulnerabilities, more, err = searchVulns(ctx, tx, q, limit); err != nil {
			return fmt.Errorf("vulnerabilities: %w", err)
		}
		res.More["vulnerabilities"] = more
		if res.Findings, more, err = searchFindingTitles(ctx, tx, q, limit, res.Vulnerabilities); err != nil {
			return fmt.Errorf("findings: %w", err)
		}
		res.More["findings"] = more
		if res.Assets, more, err = searchAssets(ctx, tx, q, limit); err != nil {
			return fmt.Errorf("assets: %w", err)
		}
		res.More["assets"] = more
		if res.Components, more, err = searchComponents(ctx, tx, q, limit); err != nil {
			return fmt.Errorf("components: %w", err)
		}
		res.More["components"] = more
		// Teams and people belong to the organisation: a member with
		// project access only finds neither.
		narrowedToMember := tenant.Member(ctx) > 0 || opt.ProjectOnly
		if !narrowedToMember {
			if res.Teams, more, err = searchTeams(ctx, tx, q, limit); err != nil {
				return fmt.Errorf("teams: %w", err)
			}
			res.More["teams"] = more
		}
		if opt.Members && !narrowedToMember {
			if res.Members, more, err = searchMembers(ctx, tx, q, limit); err != nil {
				return fmt.Errorf("members: %w", err)
			}
			res.More["members"] = more
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// patterns returns the lower-cased query and escaped ILIKE patterns for a
// prefix and a substring match.
func patterns(q string) (lower, prefix, contains string) {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	esc := r.Replace(q)
	return strings.ToLower(q), esc + "%", "%" + esc + "%"
}

// idLike reports whether q could be (part of) an advisory id or finding key:
// one word with a digit and a separator, such as CVE-2024-3094, GHSA-...,
// DSA-5555-1, RHSA-2024:1234 or nodejs:16.
func idLike(q string) bool {
	return !strings.ContainsFunc(q, unicode.IsSpace) && strings.ContainsAny(q, "0123456789") && strings.ContainsAny(q, "-:")
}

// advisoryIDs returns the spellings an advisory id is stored under: OSV ids
// are upper case except the GHSA body, which is lower case.
func advisoryIDs(q string) []string {
	up := strings.ToUpper(q)
	out := []string{q, up}
	if strings.HasPrefix(up, "GHSA-") {
		out = append(out, "GHSA-"+strings.ToLower(q[5:]))
	}
	return out
}

var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1}
var severityName = map[int]string{5: "critical", 4: "high", 3: "medium", 2: "low"}

func sevName(n int) string {
	if s, ok := severityName[n]; ok {
		return s
	}
	return "unknown"
}

func searchVulns(ctx context.Context, tx pgx.Tx, q string, limit int) ([]SearchVuln, bool, error) {
	if !idLike(q) {
		return []SearchVuln{}, false, nil
	}
	exact := advisoryIDs(q)
	byKey := map[string]*SearchVuln{}
	var order []string

	// Public advisories whose id, alias or group is the query.
	rows, err := tx.Query(ctx, `SELECT id, group_key, aliases, summary, severity_level, severity_score, known_exploited,
		published, withdrawn FROM advisories WHERE id = ANY($1) OR group_key = ANY($1) OR aliases && $1
		ORDER BY group_key, id = group_key DESC, id LIMIT 100`, exact)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		var id, group, summary, sev string
		var aliases []string
		var score *float32
		var kev bool
		var published, withdrawn *time.Time
		if err := rows.Scan(&id, &group, &aliases, &summary, &sev, &score, &kev, &published, &withdrawn); err != nil {
			rows.Close()
			return nil, false, err
		}
		v, ok := byKey[group]
		if !ok {
			v = &SearchVuln{Key: group, Rank: RankExact, Title: summary, Severity: sev, Score: score, KnownExploited: kev,
				Assets: []SearchRef{}, Components: []string{},
				Advisory: &SearchAdvisory{Summary: summary, Severity: sev, Score: score, KnownExploited: kev,
					Published: published, Withdrawn: withdrawn, Aliases: []string{}}}
			byKey[group] = v
			order = append(order, group)
		}
		a := v.Advisory
		a.IDs = append(a.IDs, id)
		a.KnownExploited = a.KnownExploited || kev
		for _, al := range aliases {
			if al != group && !contains(a.Aliases, al) {
				a.Aliases = append(a.Aliases, al)
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	keys := append([]string{}, exact...)
	keys = append(keys, order...)

	// The workspace's findings for those keys, or keys containing the query.
	_, prefix, like := patterns(q)
	rows, err = tx.Query(ctx, `WITH m AS (
		SELECT f.key, min(f.kind) AS kind, COALESCE(max(f.title), '') AS title,
		  max(CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END) AS sev,
		  max(f.score) AS score, bool_or(COALESCE((f.evidence->>'known_exploited')::boolean, false)) AS kev,
		  count(*) FILTER (WHERE f.status = 'open') AS open, count(*) FILTER (WHERE f.status = 'resolved') AS resolved,
		  count(DISTINCT f.asset_id) FILTER (WHERE f.status = 'open') AS assets
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.key = ANY($1) OR f.key ILIKE $3
		GROUP BY f.key)
		SELECT m.key, m.kind, CASE WHEN m.key = ANY($1) THEN 0 WHEN m.key ILIKE $2 THEN 1 ELSE 2 END AS rank,
		  m.title, m.sev, m.score, m.kev, m.open, m.resolved, m.assets,
		  COALESCE((SELECT json_agg(json_build_object('id', x.id, 'name', x.name)) FROM (
		    SELECT a.id, a.name FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE f.key = m.key GROUP BY a.id, a.name ORDER BY bool_or(f.status = 'open') DESC, a.name, a.id LIMIT $5) x), '[]'),
		  COALESCE((SELECT array_agg(y.n ORDER BY y.n) FROM (
		    SELECT DISTINCT CASE WHEN c.namespace = '' THEN c.name ELSE c.namespace || '/' || c.name END AS n
		    FROM findings f JOIN components c ON c.id = f.component_id WHERE f.key = m.key ORDER BY 1 LIMIT $5) y), '{}')
		FROM m ORDER BY rank, m.open DESC, m.sev DESC, m.key LIMIT $4`, keys, prefix, like, limit+1, searchSampleLimit)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		var f SearchVuln
		var sev int
		var assets []byte
		if err := rows.Scan(&f.Key, &f.Kind, &f.Rank, &f.Title, &sev, &f.Score, &f.KnownExploited, &f.OpenFindings,
			&f.ResolvedFindings, &f.AffectedAssets, &assets, &f.Components); err != nil {
			rows.Close()
			return nil, false, err
		}
		if err := json.Unmarshal(assets, &f.Assets); err != nil {
			rows.Close()
			return nil, false, err
		}
		f.Severity = sevName(sev)
		if v, ok := byKey[f.Key]; ok {
			// Keep the advisory; the findings' own title and severity win.
			f.Advisory = v.Advisory
			f.Rank = RankExact
			f.KnownExploited = f.KnownExploited || v.KnownExploited
			if f.Title == "" {
				f.Title = v.Title
			}
		} else {
			order = append(order, f.Key)
		}
		byKey[f.Key] = &f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	out := make([]SearchVuln, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Rank != b.Rank {
			return a.Rank < b.Rank
		}
		if a.OpenFindings != b.OpenFindings {
			return a.OpenFindings > b.OpenFindings
		}
		if ra, rb := severityRank[a.Severity], severityRank[b.Severity]; ra != rb {
			return ra > rb
		}
		return a.Key < b.Key
	})
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// packageQuery is a search read as a package: a purl, name@version,
// "name version", or a bare name, optionally with a namespace (@scope/name,
// group/artifact, group:artifact).
type packageQuery struct {
	Type, Namespace, Name, Version string
	// Full is namespace/name, or the name alone.
	Full string
}

func parsePackageQuery(q string) packageQuery {
	if strings.HasPrefix(strings.ToLower(q), "pkg:") {
		if p, err := packageurl.FromString(q); err == nil && p.Name != "" {
			pq := packageQuery{Type: p.Type, Namespace: p.Namespace, Name: p.Name, Version: p.Version, Full: p.Name}
			if p.Namespace != "" {
				pq.Full = p.Namespace + "/" + p.Name
			}
			return pq
		}
	}
	name, ver := q, ""
	if f := strings.Fields(q); len(f) == 2 && startsVersion(f[1]) {
		name, ver = f[0], f[1]
	} else if i := strings.LastIndex(q, "@"); i > 0 && i < len(q)-1 && !strings.ContainsFunc(q, unicode.IsSpace) {
		name, ver = q[:i], q[i+1:]
	}
	// Maven coordinates: group:artifact.
	if !strings.Contains(name, "/") && strings.Count(name, ":") == 1 {
		name = strings.Replace(name, ":", "/", 1)
	}
	pq := packageQuery{Name: name, Version: ver, Full: name}
	if i := strings.LastIndex(name, "/"); i > 0 && i < len(name)-1 {
		pq.Namespace, pq.Name = name[:i], name[i+1:]
	}
	return pq
}

func startsVersion(s string) bool {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	return s != "" && s[0] >= '0' && s[0] <= '9'
}

func searchComponents(ctx context.Context, tx pgx.Tx, q string, limit int) ([]SearchComponent, bool, error) {
	pq := parsePackageQuery(q)
	full, fullPrefix, fullLike := patterns(pq.Full)
	_, verPrefix, _ := patterns(pq.Version)
	// $4 matches the version asked for: exactly, or as a prefix that ends at
	// a version part, so "3.0.2" finds the Debian build 3.0.2-0ubuntu1.
	const ver = `($4 = '' OR i.version = $4 OR (i.version LIKE $5 AND substr(i.version, length($4) + 1, 1) !~ '[0-9]'))`
	rows, err := tx.Query(ctx, `SELECT c.id, c.purl_key, c.type, c.namespace, c.name,
		  CASE WHEN lower(c.name) = $1 OR lower(c.namespace || '/' || c.name) = $1 THEN 0
		    WHEN c.name ILIKE $2 OR (c.namespace || '/' || c.name) ILIKE $2 THEN 1 ELSE 2 END AS rank,
		  (SELECT count(DISTINCT i.asset_id) FROM inventory i JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		    WHERE i.component_id = c.id AND i.removed_at IS NULL) AS assets,
		  COALESCE((SELECT array_agg(x.v ORDER BY x.v) FROM (SELECT DISTINCT i.version AS v FROM inventory i
		    WHERE i.component_id = c.id AND i.removed_at IS NULL ORDER BY 1 LIMIT 20) x), '{}'),
		  (SELECT count(*) FROM findings f JOIN inventory i ON i.id = f.inventory_id
		    WHERE f.component_id = c.id AND f.status = 'open' AND `+ver+`),
		  COALESCE((SELECT json_agg(json_build_object('id', y.id, 'name', y.name, 'version', y.version)) FROM (
		    SELECT a.id, a.name, min(i.version) AS version FROM inventory i JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		    WHERE i.component_id = c.id AND i.removed_at IS NULL AND `+ver+`
		    GROUP BY a.id, a.name ORDER BY a.name, a.id LIMIT $8) y), '[]'),
		  CASE WHEN $4 = '' THEN 0 ELSE (SELECT count(DISTINCT i.asset_id) FROM inventory i
		    JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		    WHERE i.component_id = c.id AND i.removed_at IS NULL AND `+ver+`) END AS version_assets
		FROM components c
		WHERE EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = c.id AND i.removed_at IS NULL)
		  AND (c.name ILIKE $3 OR (c.namespace || '/' || c.name) ILIKE $3)
		  AND ($6 = '' OR c.type = $6) AND ($7 = '' OR lower(c.namespace) = lower($7))
		ORDER BY rank, version_assets DESC, assets DESC, c.type, c.namespace, c.name LIMIT $9`,
		full, fullPrefix, fullLike, pq.Version, verPrefix, pq.Type, pq.Namespace, searchSampleLimit, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []SearchComponent{}
	for rows.Next() {
		c := SearchComponent{Version: pq.Version}
		var assets []byte
		if err := rows.Scan(&c.ID, &c.PurlKey, &c.Type, &c.Namespace, &c.Name, &c.Rank, &c.AssetCount, &c.Versions,
			&c.OpenFindings, &assets, &c.VersionAssets); err != nil {
			return nil, false, err
		}
		if err := json.Unmarshal(assets, &c.Assets); err != nil {
			return nil, false, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// textRank ranks s against the lower-cased query like the SQL does; 3 means
// no match.
func textRank(s, lowerQ string) int {
	s = strings.ToLower(s)
	switch {
	case s == lowerQ:
		return RankExact
	case strings.HasPrefix(s, lowerQ):
		return RankPrefix
	case strings.Contains(s, lowerQ):
		return RankContains
	}
	return RankContains + 1
}

// assetMatchAttributes are the asset attributes that identify an asset,
// searched alongside its identifiers.
var assetMatchAttributes = []string{"digest", "image", "arn"}

func searchAssets(ctx context.Context, tx pgx.Tx, q string, limit int) ([]SearchAsset, bool, error) {
	lower, prefix, like := patterns(q)
	rows, err := tx.Query(ctx, `SELECT a.id, a.kind, a.name, a.environment, COALESCE(t.name, ''), a.collection_status, a.last_seen,
		  CASE WHEN lower(a.name) = $1 OR lower(m.value) = $1 THEN 0 WHEN a.name ILIKE $2 OR m.value ILIKE $2 THEN 1 ELSE 2 END AS rank,
		  COALESCE(m.scheme, ''), COALESCE(m.value, ''),
		  (SELECT count(*) FROM findings f WHERE f.asset_id = a.id AND f.status = 'open')
		FROM assets a LEFT JOIN teams t ON t.id = a.owner_team_id
		LEFT JOIN LATERAL (
		  SELECT x.scheme, x.value FROM (
		    SELECT ai.scheme, ai.value FROM asset_identifiers ai WHERE ai.asset_id = a.id
		    UNION ALL
		    SELECT kv.key, kv.value FROM jsonb_each_text(a.attributes) kv WHERE kv.key = ANY($5)
		  ) x WHERE x.value ILIKE $3
		  ORDER BY lower(x.value) = $1 DESC, x.value ILIKE $2 DESC, length(x.value), x.scheme LIMIT 1) m ON true
		WHERE a.merged_into IS NULL AND (a.name ILIKE $3 OR m.value IS NOT NULL)
		ORDER BY rank, a.name, a.id LIMIT $4`, lower, prefix, like, limit+1, assetMatchAttributes)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []SearchAsset{}
	for rows.Next() {
		var a SearchAsset
		if err := rows.Scan(&a.ID, &a.Kind, &a.Name, &a.Environment, &a.OwnerTeam, &a.Status, &a.LastSeen, &a.Rank,
			&a.MatchScheme, &a.MatchValue, &a.OpenFindings); err != nil {
			return nil, false, err
		}
		// Name the identifier only when it matched better than the name did.
		if a.MatchValue != "" && textRank(a.Name, lower) <= textRank(a.MatchValue, lower) {
			a.MatchScheme, a.MatchValue = "", ""
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

func searchTeams(ctx context.Context, tx pgx.Tx, q string, limit int) ([]SearchTeam, bool, error) {
	lower, prefix, like := patterns(q)
	rows, err := tx.Query(ctx, `SELECT t.id, t.name, t.email,
		  CASE WHEN lower(t.name) = $1 OR lower(t.email) = $1 THEN 0 WHEN t.name ILIKE $2 OR t.email ILIKE $2 THEN 1 ELSE 2 END AS rank,
		  (SELECT count(*) FROM assets a WHERE a.owner_team_id = t.id AND a.merged_into IS NULL),
		  (SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE f.status = 'open' AND a.owner_team_id = t.id)
		FROM teams t WHERE t.name ILIKE $3 OR t.email ILIKE $3
		ORDER BY rank, t.name, t.id LIMIT $4`, lower, prefix, like, limit+1)
	if err != nil {
		return nil, false, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[SearchTeam])
	if err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// searchFindingTitles finds open findings whose title contains the query,
// one result per key and title. Keys the vulnerability group already shows
// are left out.
func searchFindingTitles(ctx context.Context, tx pgx.Tx, q string, limit int, shown []SearchVuln) ([]SearchFinding, bool, error) {
	if utf8.RuneCountInString(q) < searchTitleMinLen {
		return []SearchFinding{}, false, nil
	}
	skip := make([]string, 0, len(shown))
	for _, v := range shown {
		skip = append(skip, v.Key)
	}
	lower, prefix, like := patterns(q)
	rows, err := tx.Query(ctx, `WITH m AS (
		SELECT f.key, min(f.kind) AS kind, f.title,
		  max(CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 ELSE 1 END) AS sev,
		  max(f.score) AS score, count(*) AS open, count(DISTINCT f.asset_id) AS assets
		FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		WHERE f.status = 'open' AND f.title ILIKE $3 AND NOT (f.key = ANY($6))
		GROUP BY f.key, f.title)
		SELECT m.key, m.kind, m.title, CASE WHEN lower(m.title) = $1 THEN 0 WHEN m.title ILIKE $2 THEN 1 ELSE 2 END AS rank,
		  m.sev, m.score, m.open, m.assets,
		  COALESCE((SELECT json_agg(json_build_object('id', x.id, 'name', x.name)) FROM (
		    SELECT DISTINCT a.id, a.name FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE f.key = m.key AND f.title = m.title AND f.status = 'open' ORDER BY a.name, a.id LIMIT $5) x), '[]')
		FROM m ORDER BY rank, m.open DESC, m.sev DESC, m.key, m.title LIMIT $4`, lower, prefix, like, limit+1, searchSampleLimit, skip)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []SearchFinding{}
	for rows.Next() {
		var f SearchFinding
		var sev int
		var assets []byte
		if err := rows.Scan(&f.Key, &f.Kind, &f.Title, &f.Rank, &sev, &f.Score, &f.OpenFindings, &f.AffectedAssets, &assets); err != nil {
			return nil, false, err
		}
		if err := json.Unmarshal(assets, &f.Assets); err != nil {
			return nil, false, err
		}
		f.Severity = sevName(sev)
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// searchMembers finds members of the current workspace by name or email.
// Accounts are global, so the query starts from this workspace's membership
// rows: an account that is not a member here is never matched.
func searchMembers(ctx context.Context, tx pgx.Tx, q string, limit int) ([]SearchMember, bool, error) {
	lower, prefix, like := patterns(q)
	rows, err := tx.Query(ctx, `SELECT u.id, u.name, u.email, COALESCE(wm.role, ''), u.disabled,
		  CASE WHEN lower(u.email) = $1 OR lower(u.name) = $1 THEN 0 WHEN u.email ILIKE $2 OR u.name ILIKE $2 THEN 1 ELSE 2 END AS rank,
		  (SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id AND a.merged_into IS NULL
		    WHERE f.status = 'open' AND f.assignee_user_id = u.id)
		FROM workspace_members wm JOIN users u ON u.id = wm.user_id
		WHERE wm.workspace_id = stackurity_ws() AND (u.email ILIKE $3 OR u.name ILIKE $3)
		ORDER BY rank, u.disabled, u.email, u.id LIMIT $4`, lower, prefix, like, limit+1)
	if err != nil {
		return nil, false, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[SearchMember])
	if err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}
