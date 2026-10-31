package store

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The Coverage page (GET /coverage/overview and /coverage/assets): one
// answer ("93% of your components were checked"), the components split
// into five segments that add up to the total, what was found per
// ecosystem or operating system, and each asset's share checked.
//
// A component is counted once, in one segment: the first of these that
// any of its current inventory rows is in, so that the segments add up to
// the components and each segment's list (GET /components?segment=) has
// exactly its count.
//
//	needs_you      a row with no readable version or another reason the
//	               user can act on (unchecked reasons unreadable_version,
//	               other)
//	waiting        a row waiting for vulnerability data, or not evaluated
//	               yet (waiting_for_data, coverage awaiting)
//	not_supported  a row Stackurity has no vulnerability source for
//	no_advisories  a row whose release has no published advisories
//	checked        every row was checked against current data
//
// A component that is checked on one asset and has no readable version on
// another is "needs you": it was not checked everywhere it runs.
const (
	SegmentNeedsYou     = "needs_you"
	SegmentWaiting      = "waiting"
	SegmentNotSupported = "not_supported"
	SegmentNoAdvisories = "no_advisories"
	SegmentChecked      = "checked"
)

// Segments are in rank order (segmentRankSQL: 1 first).
var Segments = []string{SegmentNeedsYou, SegmentWaiting, SegmentNotSupported, SegmentNoAdvisories, SegmentChecked}

// ValidSegment reports whether s names a segment.
func ValidSegment(s string) bool {
	for _, x := range Segments {
		if x == s {
			return true
		}
	}
	return false
}

func segmentRank(s string) int {
	for i, x := range Segments {
		if x == s {
			return i + 1
		}
	}
	return 0
}

// segmentRankSQL is the segment of inventory row i, as its rank (1 to 5,
// the order of Segments). It uses only i: callers may add it to a where
// (it contains no '?').
var segmentRankSQL = `CASE (` + uncheckedReasonSQL(overdueFeedSQL) + `)
	WHEN 'unreadable_version' THEN 1 WHEN 'other' THEN 1
	WHEN 'waiting_for_data' THEN 2
	WHEN 'unsupported' THEN 3
	WHEN 'no_advisories' THEN 4
	ELSE CASE WHEN i.coverage = 'evaluated' THEN 5 ELSE 2 END END`

// currentRowsSQL are the inventory rows the page counts: current rows on
// current assets (as SummarizeUnchecked counts them).
const currentRowsSQL = ` FROM inventory i JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL AND a.collection_status <> 'removed'
	WHERE i.removed_at IS NULL`

// componentSegmentSQL lists each counted component with its segment rank.
var componentSegmentSQL = `SELECT i.component_id, min(` + segmentRankSQL + `) AS rank` + currentRowsSQL + ` GROUP BY i.component_id`

// segmentFilter limits components c to one segment (ListComponents).
func segmentFilter(w *where, segment string) {
	w.add(`c.id IN (SELECT x.component_id FROM (`+componentSegmentSQL+`) x WHERE x.rank = ?)`, segmentRank(segment))
}

// ecosystemKeySQL is the ecosystem or operating system of row i of
// component c: the package type ("npm"), the distribution release for
// distribution packages ("deb:ubuntu-24.04"), "windows" for Windows and
// its programs, "wordpress" for WordPress plugins and themes.
const ecosystemKeySQL = `CASE
	WHEN c.purl_key = 'pkg:generic/windows' OR (c.type = 'generic' AND i.evidence->>'registry_view' IS NOT NULL) THEN 'windows'
	WHEN c.type IN ('deb', 'rpm', 'apk') AND i.purl ~ '[?&]distro=' THEN c.type || ':' || lower(substring(i.purl from '[?&]distro=([^&#]+)'))
	WHEN c.type = 'generic' AND c.namespace IN ('wordpress-plugin', 'wordpress-theme') THEN 'wordpress'
	ELSE c.type END`

// CoverageOverview is the Coverage page's headline and ecosystems.
type CoverageOverview struct {
	// Total counts the components on current assets; Segments splits them
	// (every segment is present, and they add up to Total).
	Total    int64            `json:"total"`
	Segments map[string]int64 `json:"segments"`
	// Ecosystems are the ecosystems and operating systems found, most
	// components first.
	Ecosystems []EcosystemCoverage `json:"ecosystems"`
}

// EcosystemCoverage is one ecosystem or operating system found.
type EcosystemCoverage struct {
	// Key is stable for machines ("npm", "deb:ubuntu-24.04", "windows"):
	// the subject of a support request.
	Key        string `json:"key"`
	Label      string `json:"label"`
	Type       string `json:"type"` // the package type, for the component list's filter
	Components int64  `json:"components"`
	// Checked counts components checked (or with no published
	// advisories); NotSupported those Stackurity has no source for.
	Checked      int64 `json:"checked"`
	NotSupported int64 `json:"not_supported"`
	// Status: checked (every component), not_supported (none can be), or
	// partly.
	Status string `json:"status"`
	// Requested: the workspace asked for support (POST
	// /coverage/support-requests).
	Requested bool `json:"requested"`
}

// SummarizeCoverage builds the overview for the caller's workspace (row-level
// security and project scope apply).
func (s *Store) SummarizeCoverage(ctx context.Context) (*CoverageOverview, error) {
	out := &CoverageOverview{Segments: map[string]int64{}, Ecosystems: []EcosystemCoverage{}}
	for _, seg := range Segments {
		out.Segments[seg] = 0
	}
	rows, err := s.Pool.Query(ctx, `SELECT rank, count(*) FROM (`+componentSegmentSQL+`) x GROUP BY rank`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rank int
		var n int64
		if err := rows.Scan(&rank, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out.Segments[Segments[rank-1]] = n
		out.Total += n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = s.Pool.Query(ctx, `SELECT eco, min(typ), count(*), count(*) FILTER (WHERE rank >= 4), count(*) FILTER (WHERE rank = 3)
		FROM (SELECT `+ecosystemKeySQL+` AS eco, min(c.type) AS typ, i.component_id, min(`+segmentRankSQL+`) AS rank
		  FROM inventory i JOIN components c ON c.id = i.component_id
		  JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL AND a.collection_status <> 'removed'
		  WHERE i.removed_at IS NULL GROUP BY 1, 3) x
		GROUP BY eco ORDER BY 3 DESC, 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var e EcosystemCoverage
		if err := rows.Scan(&e.Key, &e.Type, &e.Components, &e.Checked, &e.NotSupported); err != nil {
			rows.Close()
			return nil, err
		}
		e.Label = EcosystemLabel(e.Key)
		switch {
		case e.Checked == e.Components:
			e.Status = "checked"
		case e.NotSupported == e.Components:
			e.Status = "not_supported"
		default:
			e.Status = "partly"
		}
		out.Ecosystems = append(out.Ecosystems, e)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	requested, err := s.supportRequested(ctx)
	if err != nil {
		return nil, err
	}
	for i := range out.Ecosystems {
		out.Ecosystems[i].Requested = requested[out.Ecosystems[i].Key]
	}
	return out, nil
}

var distroLabels = map[string]string{
	"ubuntu": "Ubuntu", "debian": "Debian", "alpine": "Alpine", "rhel": "RHEL", "redhat": "RHEL", "centos": "CentOS",
	"rocky": "Rocky Linux", "almalinux": "AlmaLinux", "alma": "AlmaLinux", "amzn": "Amazon Linux", "amazon": "Amazon Linux",
	"sles": "SLES", "opensuse-leap": "openSUSE Leap", "opensuse": "openSUSE", "fedora": "Fedora", "ol": "Oracle Linux",
	"oracle": "Oracle Linux", "wolfi": "Wolfi", "chainguard": "Chainguard", "photon": "Photon OS", "mariner": "CBL-Mariner",
	"azurelinux": "Azure Linux",
}

// EcosystemLabel names an ecosystem key for people: "npm", "PyPI",
// "Ubuntu 24.04", "Windows".
func EcosystemLabel(key string) string {
	switch key {
	case "windows":
		return "Windows"
	case "wordpress":
		return "WordPress"
	case "generic":
		return "Other software"
	}
	_, distro, ok := strings.Cut(key, ":")
	if !ok || distro == "" {
		return TypeLabel(key)
	}
	name, version := distro, ""
	if i := strings.LastIndex(distro, "-"); i > 0 && i < len(distro)-1 && distro[i+1] >= '0' && distro[i+1] <= '9' {
		name, version = distro[:i], distro[i+1:]
	}
	label, ok := distroLabels[name]
	if !ok {
		label = strings.ToUpper(name[:1]) + name[1:]
	}
	if version != "" {
		label += " " + version
	}
	return label
}

// Asset groups for the Coverage page's table and its filter chips, worst
// first.
const (
	AssetGroupFailed       = "failed_collection"
	AssetGroupNotReporting = "not_reporting"
	AssetGroupPartly       = "partly_checked"
	AssetGroupAwaiting     = "awaiting_first_check"
	AssetGroupHealthy      = "healthy"
)

// AssetGroups are in worst-first order.
var AssetGroups = []string{AssetGroupFailed, AssetGroupNotReporting, AssetGroupPartly, AssetGroupAwaiting, AssetGroupHealthy}

// ValidAssetGroup reports whether g names an asset group.
func ValidAssetGroup(g string) bool {
	for _, x := range AssetGroups {
		if x == g {
			return true
		}
	}
	return false
}

// AssetCoverageRow is one asset in the Coverage page's table.
type AssetCoverageRow struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	Kind             string    `json:"kind"`
	CollectionStatus string    `json:"collection_status"`
	Reporting        Reporting `json:"reporting"`
	Group            string    `json:"group"`
	// State is the asset's headline coverage state (CoverageSummary).
	State string `json:"state"`
	// Components counts the asset's components; Checked those checked on
	// it. NotChecked splits the rest by who acts (user, stackurity,
	// automatic, none), as the segments do.
	Components int64            `json:"components"`
	Checked    int64            `json:"checked"`
	NotChecked map[string]int64 `json:"not_checked"`
	// ProblemScopes counts collector scopes not fully checked (failed,
	// partial, unsupported or skipped); GET /coverage?asset_id=&problems=true
	// lists them.
	ProblemScopes int64      `json:"problem_scopes"`
	LastReport    *time.Time `json:"last_report"`
}

// AssetCoverageList is a page of the table with the count of every group.
type AssetCoverageList struct {
	Items  []AssetCoverageRow `json:"items"`
	Total  int64              `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
	Groups map[string]int64   `json:"groups"`
}

// segmentActors says who acts on each segment but checked.
var segmentActors = map[string]string{SegmentNeedsYou: ActorUser, SegmentNotSupported: ActorStackurity,
	SegmentWaiting: ActorAutomatic, SegmentNoAdvisories: ActorNone}

// ListAssetCoverage lists current assets worst first: by group, then the
// smallest share checked, then name. group limits it to one group ("" for
// all).
func (s *Store) ListAssetCoverage(ctx context.Context, group string, p Page) (*AssetCoverageList, error) {
	sums, err := s.coverageSummaries(ctx, 0)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	byID := map[int64]*CoverageSummary{}
	for i := range sums {
		sums[i].derive(now)
		byID[sums[i].AssetID] = &sums[i]
	}
	rows, err := s.Pool.Query(ctx, `SELECT a.id, a.name, a.kind, a.collection_status, a.last_seen,
		a.report_source, a.report_override, a.report_runs, EXTRACT(epoch FROM a.report_usual)::bigint, EXTRACT(epoch FROM a.report_due_after)::bigint,
		(SELECT max(received_at) FROM collections col WHERE col.asset_id = a.id),
		(SELECT count(*) FROM coverage cv WHERE cv.asset_id = a.id AND cv.status <> 'checked')
		FROM assets a WHERE a.merged_into IS NULL AND a.collection_status <> 'removed'`)
	if err != nil {
		return nil, err
	}
	all := []AssetCoverageRow{}
	idx := map[int64]int{}
	for rows.Next() {
		var r AssetCoverageRow
		var lastSeen time.Time
		var source, override string
		var runs *int32
		var usual, due *int64
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.CollectionStatus, &lastSeen, &source, &override, &runs, &usual, &due,
			&r.LastReport, &r.ProblemScopes); err != nil {
			rows.Close()
			return nil, err
		}
		r.Reporting = reportingFrom(source, override, runs, usual, due, lastSeen)
		r.NotChecked = map[string]int64{ActorUser: 0, ActorStackurity: 0, ActorAutomatic: 0, ActorNone: 0}
		idx[r.ID] = len(all)
		all = append(all, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = s.Pool.Query(ctx, `SELECT asset_id, rank, count(*) FROM (SELECT i.asset_id, i.component_id, min(`+segmentRankSQL+`) AS rank`+
		currentRowsSQL+` GROUP BY 1, 2) x GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, n int64
		var rank int
		if err := rows.Scan(&id, &rank, &n); err != nil {
			rows.Close()
			return nil, err
		}
		j, ok := idx[id]
		if !ok {
			continue
		}
		r := &all[j]
		r.Components += n
		if seg := Segments[rank-1]; seg == SegmentChecked {
			r.Checked += n
		} else {
			r.NotChecked[segmentActors[seg]] += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := &AssetCoverageList{Groups: map[string]int64{}}
	for _, g := range AssetGroups {
		out.Groups[g] = 0
	}
	for i := range all {
		r := &all[i]
		r.State = StateAwaitingVerification
		if sum := byID[r.ID]; sum != nil {
			r.State = sum.State
		}
		r.Group = assetGroup(r.State, r.CollectionStatus)
		out.Groups[r.Group]++
	}
	rank := map[string]int{}
	for i, g := range AssetGroups {
		rank[g] = i
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if rank[a.Group] != rank[b.Group] {
			return rank[a.Group] < rank[b.Group]
		}
		// The smallest share checked first: a/ac < b/bc without division.
		if l, r := a.Checked*max(b.Components, 1), b.Checked*max(a.Components, 1); l != r {
			return l < r
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.ID < b.ID
	})
	shown := all[:0:0]
	for _, r := range all {
		if group == "" || r.Group == group {
			shown = append(shown, r)
		}
	}
	p = p.norm()
	out.Total, out.Limit, out.Offset = int64(len(shown)), p.Limit, p.Offset
	out.Items = shown[min(p.Offset, len(shown)):min(p.Offset+p.Limit, len(shown))]
	return out, nil
}

// assetGroup puts an asset in a group of the table from its coverage state
// and reporting status: an asset that stopped reporting is "not
// reporting", not "failed collection".
func assetGroup(state, collectionStatus string) string {
	switch {
	case collectionStatus == "stale":
		return AssetGroupNotReporting
	case state == StateFailedCollection:
		return AssetGroupFailed
	case state == StateHealthy:
		return AssetGroupHealthy
	case state == StateAwaitingVerification:
		return AssetGroupAwaiting
	}
	return AssetGroupPartly
}

// Support requests: a workspace asks for an ecosystem Stackurity does not
// check yet (migration 0065). One per workspace and ecosystem; instance
// administrators see them counted on the coverage-gap report.

// ErrNotUnsupported: the ecosystem is not one the workspace has components
// Stackurity does not check.
var ErrNotUnsupported = fmt.Errorf("stackurity already checks this ecosystem, or it was not found on your assets: %w", ErrInvalid)

// RequestSupport records that the workspace wants ecosystem supported. It
// must be one the workspace has components of that Stackurity does not
// support, checked for that ecosystem alone. Asking again changes nothing
// (created reports whether this was new).
func (s *Store) RequestSupport(ctx context.Context, ecosystem string, userID *int64) (label string, created bool, err error) {
	if ecosystem == "" || len(ecosystem) > 100 {
		return "", false, ErrNotUnsupported
	}
	// The package type narrows the scan: "deb:ubuntu-24.04" is deb, and
	// Windows and WordPress are generic.
	typ, _, _ := strings.Cut(ecosystem, ":")
	if ecosystem == "windows" || ecosystem == "wordpress" {
		typ = "generic"
	}
	var found bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM inventory i JOIN components c ON c.id = i.component_id
		  JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL AND a.collection_status <> 'removed'
		  WHERE i.removed_at IS NULL AND i.coverage IN ('unsupported', 'not_evaluated') AND c.type = $2
		    AND (`+ecosystemKeySQL+`) = $1 AND (`+uncheckedReasonSQL(overdueFeedSQL)+`) = 'unsupported')`,
		ecosystem, typ).Scan(&found); err != nil {
		return "", false, err
	}
	if !found {
		return "", false, ErrNotUnsupported
	}
	label = EcosystemLabel(ecosystem)
	tag, err := s.Pool.Exec(ctx, `INSERT INTO support_requests (ecosystem, label, requested_by) VALUES ($1, $2, $3)
		ON CONFLICT (workspace_id, ecosystem) DO NOTHING`, ecosystem, label, userID)
	if err != nil {
		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "23514" {
			return "", false, ErrNotUnsupported
		}
		return "", false, err
	}
	return label, tag.RowsAffected() == 1, nil
}

func (s *Store) supportRequested(ctx context.Context) (map[string]bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT ecosystem FROM support_requests`)
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := map[string]bool{}
	for _, k := range keys {
		out[k] = true
	}
	return out, err
}

// SupportRequestTotal is one ecosystem workspaces asked for, counted.
type SupportRequestTotal struct {
	Ecosystem  string    `json:"ecosystem"`
	Label      string    `json:"label"`
	Workspaces int64     `json:"workspaces"`
	Latest     time.Time `json:"latest"`
}

// SupportRequestTotals counts the support requests of active workspaces
// per ecosystem, most asked first. Run it in system scope.
func (s *Store) SupportRequestTotals(ctx context.Context) ([]SupportRequestTotal, error) {
	rows, err := s.Pool.Query(ctx, `SELECT r.ecosystem, max(r.label), count(*), max(r.created_at)
		FROM support_requests r JOIN workspaces w ON w.id = r.workspace_id AND w.disabled_at IS NULL
		GROUP BY 1 ORDER BY 3 DESC, 4 DESC, 1`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[SupportRequestTotal])
}
