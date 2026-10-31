package store

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Components that were not checked, grouped by who can do something about
// it. "Findings are incomplete" used to be one sentence mixing four causes;
// each now says who acts:
//
//	unsupported         stackurity  no vulnerability source for the ecosystem,
//	                                distribution or kind of software yet
//	waiting_for_data    automatic   the vulnerability data is not synced yet, or
//	                                is out of date; resolves on its own unless
//	                                the source is past its staleness window
//	no_advisories       none        the source publishes no advisories for this
//	                                release: informational, not "may be vulnerable"
//	unreadable_version  user        the installed version could not be read
//	unreadable_files    user        application files the agent may not read
//	                                (counted in assets, not components)
const (
	UncheckedUnsupported       = "unsupported"
	UncheckedWaitingForData    = "waiting_for_data"
	UncheckedNoAdvisories      = "no_advisories"
	UncheckedUnreadableVersion = "unreadable_version"
	UncheckedUnreadableFiles   = "unreadable_files"
)

// Who acts on an unchecked reason.
const (
	ActorUser       = "user"
	ActorStackurity = "stackurity"
	ActorAutomatic  = "automatic"
	ActorNone       = "none"
)

// UncheckedActors maps each reason to who acts on it.
var UncheckedActors = map[string]string{
	UncheckedUnreadableVersion: ActorUser,
	UncheckedUnreadableFiles:   ActorUser,
	UncheckedUnsupported:       ActorStackurity,
	UncheckedWaitingForData:    ActorAutomatic,
	UncheckedNoAdvisories:      ActorNone,
}

// uncheckedOrder is the order of the groups: what needs the user first.
var uncheckedOrder = []string{UncheckedUnreadableVersion, UncheckedUnreadableFiles, UncheckedUnsupported,
	UncheckedWaitingForData, UncheckedNoAdvisories}

// ValidUncheckedReason reports whether r names a reason components can have
// (the inventory filter; unreadable_files is about files, not components).
func ValidUncheckedReason(r string) bool {
	switch r {
	case UncheckedUnsupported, UncheckedWaitingForData, UncheckedNoAdvisories, UncheckedUnreadableVersion:
		return true
	}
	return false
}

// uncheckedReasonSQL is why inventory row i was not checked (” when it
// was), from the reasons the matcher writes (intel.Evaluator). stale is an
// SQL condition that is true when an evaluated row was matched against
// vulnerability data that is stale or failing (rowCoverageSQL).
func uncheckedReasonSQL(stale string) string {
	return `CASE
	WHEN i.coverage = 'evaluated' THEN CASE WHEN ` + stale + ` THEN 'waiting_for_data' ELSE '' END
	WHEN i.coverage NOT IN ('unsupported', 'not_evaluated') THEN ''
	WHEN i.coverage_reason ~ 'vulnerability feed \S+ (has not been set up yet|is disabled|has not completed a sync)'
	  OR i.coverage_reason LIKE 'the advisories of % have not been read from % yet%' THEN 'waiting_for_data'
	WHEN i.coverage = 'unsupported' THEN 'unsupported'
	WHEN i.coverage_reason ~ ' has no (advisories|updates) for ' THEN 'no_advisories'
	WHEN ` + uncheckedCauseSQL + ` <> '' THEN 'unreadable_version'
	ELSE 'unsupported' END`
}

// uncheckedCauseSQL is why the installed version of row i could not be read.
const uncheckedCauseSQL = `CASE
	WHEN i.coverage_reason = 'no installed version was reported' OR i.coverage_reason LIKE 'no version was recorded for %' THEN 'no_version'
	WHEN i.coverage_reason LIKE 'installed version % could not be compared using %' THEN 'unparseable_version'
	WHEN i.coverage_reason LIKE 'the distro release is unknown%' THEN 'unknown_release'
	WHEN i.coverage_reason = 'the package URL could not be read' THEN 'unreadable_package'
	ELSE '' END`

// uncheckedSubjectSQL is what an unchecked row is about, per reason: the
// package type and category for unsupported ("cocoapods|ecosystem"), the
// vulnerability source for waiting_for_data ("osv:npm"), the release for
// no_advisories ("Debian:13") and the cause for unreadable_version.
const uncheckedSubjectSQL = `CASE r.reason
	WHEN 'unsupported' THEN c.type || '|' || ` + unsupportedCategorySQL + `
	WHEN 'waiting_for_data' THEN COALESCE(NULLIF(i.coverage_feed, ''), substring(i.coverage_reason from 'vulnerability feed (\S+) '),
	  substring(i.coverage_reason from '\(feed ([^)]+)\)'), 'unknown')
	WHEN 'no_advisories' THEN COALESCE(substring(i.coverage_reason from ' has no advisories for (\S+): '),
	  substring(i.coverage_reason from ' has no updates for (Windows \S+) '), c.type)
	WHEN 'unreadable_version' THEN ` + uncheckedCauseSQL + `
	ELSE '' END`

// UncheckedItem is one subject within a reason: an ecosystem Stackurity does
// not check, a vulnerability source being waited for, a release with no
// advisories, or a cause of unreadable versions.
type UncheckedItem struct {
	// Key is stable for machines: "cocoapods|ecosystem", "osv:npm",
	// "Debian:13", "no_version".
	Key   string `json:"key"`
	Label string `json:"label"`
	// Fix says what to do (unreadable_version and unreadable_files only).
	Fix        string `json:"fix,omitempty"`
	Docs       string `json:"docs,omitempty"`
	Components int64  `json:"components"`
	Assets     int64  `json:"assets"`
	// Overdue (waiting_for_data only): the source is past its staleness
	// window or switched off, so it will not resolve on its own.
	Overdue bool `json:"overdue,omitempty"`
}

// UncheckedGroup is one reason components were not checked, with who acts.
type UncheckedGroup struct {
	Reason     string          `json:"reason"`
	Actor      string          `json:"actor"`
	Components int64           `json:"components"`
	Assets     int64           `json:"assets"`
	Overdue    bool            `json:"overdue,omitempty"`
	Items      []UncheckedItem `json:"items"`
}

// Unchecked is what was not checked on one asset or across the workspace
// (or project), grouped by reason. The counts lead with what needs the user.
type Unchecked struct {
	// NeedYou counts what only the user can fix: components with no
	// readable version and applications with files the agent may not read.
	NeedYou int64 `json:"need_you"`
	// NotSupported counts components Stackurity does not check yet.
	NotSupported int64 `json:"not_supported"`
	// Waiting counts components waiting for vulnerability data.
	Waiting int64 `json:"waiting"`
	// NoAdvisories counts components whose release has no published
	// advisories. Informational: they are not "may be vulnerable".
	NoAdvisories int64 `json:"no_advisories"`
	// Overdue is true when vulnerability data some components wait for is
	// past its staleness window or switched off.
	Overdue bool             `json:"overdue"`
	Groups  []UncheckedGroup `json:"groups"`
}

// UncheckedFilter selects the rows a breakdown covers: one asset, or every
// current asset the caller may see (0).
type UncheckedFilter struct {
	AssetID int64
}

// SummarizeUnchecked breaks down the components that were not checked by
// reason and who acts. It reads the caller's workspace (row-level security
// and project scope apply).
func (s *Store) SummarizeUnchecked(ctx context.Context, f UncheckedFilter) (*Unchecked, error) {
	stale, overdue, err := s.staleVulnFeeds(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT r.reason, `+uncheckedSubjectSQL+` AS subject,
		  count(DISTINCT i.component_id), count(DISTINCT i.asset_id), min(c.type)
		FROM inventory i JOIN components c ON c.id = i.component_id
		JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL AND a.collection_status <> 'removed'
		CROSS JOIN LATERAL (SELECT `+uncheckedReasonSQL("i.coverage_feed = ANY($2)")+` AS reason) r
		WHERE i.removed_at IS NULL AND ($1 = 0 OR i.asset_id = $1)
		  AND (i.coverage IN ('unsupported', 'not_evaluated') OR (i.coverage = 'evaluated' AND i.coverage_feed = ANY($2)))
		GROUP BY 1, 2`, f.AssetID, stale)
	if err != nil {
		return nil, err
	}
	type key struct{ reason, subject string }
	items := map[key]*UncheckedItem{}
	typeOf := map[key]string{}
	for rows.Next() {
		var k key
		var comps, assets int64
		var typ string
		if err := rows.Scan(&k.reason, &k.subject, &comps, &assets, &typ); err != nil {
			rows.Close()
			return nil, err
		}
		if k.reason == "" {
			continue
		}
		items[k] = &UncheckedItem{Key: k.subject, Components: comps, Assets: assets}
		typeOf[k] = typ
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Distinct counts per reason, across subjects.
	totals := map[string][2]int64{}
	trows, err := s.Pool.Query(ctx, `SELECT r.reason, count(DISTINCT i.component_id), count(DISTINCT i.asset_id)
		FROM inventory i JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL AND a.collection_status <> 'removed'
		CROSS JOIN LATERAL (SELECT `+uncheckedReasonSQL("i.coverage_feed = ANY($2)")+` AS reason) r
		WHERE i.removed_at IS NULL AND ($1 = 0 OR i.asset_id = $1)
		  AND (i.coverage IN ('unsupported', 'not_evaluated') OR (i.coverage = 'evaluated' AND i.coverage_feed = ANY($2)))
		GROUP BY 1`, f.AssetID, stale)
	if err != nil {
		return nil, err
	}
	for trows.Next() {
		var reason string
		var comps, assets int64
		if err := trows.Scan(&reason, &comps, &assets); err != nil {
			trows.Close()
			return nil, err
		}
		totals[reason] = [2]int64{comps, assets}
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}

	// Applications with files the agent may not read (apps.PermissionScope).
	var denied int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(DISTINCT cv.asset_id) FROM coverage cv
		JOIN assets a ON a.id = cv.asset_id AND a.merged_into IS NULL AND a.collection_status <> 'removed'
		WHERE cv.scope LIKE 'app-permissions:%' AND cv.status IN ('unsupported', 'partial') AND ($1 = 0 OR cv.asset_id = $1)`,
		f.AssetID).Scan(&denied); err != nil {
		return nil, err
	}

	out := &Unchecked{Groups: []UncheckedGroup{}}
	byReason := map[string]*UncheckedGroup{}
	for k, it := range items {
		g := byReason[k.reason]
		if g == nil {
			t := totals[k.reason]
			g = &UncheckedGroup{Reason: k.reason, Actor: UncheckedActors[k.reason], Components: t[0], Assets: t[1]}
			byReason[k.reason] = g
		}
		it.Label = uncheckedLabel(k.reason, k.subject, typeOf[k])
		if k.reason == UncheckedUnreadableVersion {
			it.Fix, it.Docs = UnreadableVersionFix(k.subject, "")
		}
		if k.reason == UncheckedWaitingForData && overdue[k.subject] {
			it.Overdue, g.Overdue = true, true
		}
		g.Items = append(g.Items, *it)
	}
	if denied > 0 {
		fix, docs := UnreadableFilesFix()
		byReason[UncheckedUnreadableFiles] = &UncheckedGroup{Reason: UncheckedUnreadableFiles, Actor: ActorUser, Assets: denied,
			Items: []UncheckedItem{{Key: "permission_denied", Label: "files the agent's user may not read", Fix: fix, Docs: docs, Assets: denied}}}
	}
	for _, r := range uncheckedOrder {
		g := byReason[r]
		if g == nil {
			continue
		}
		sort.Slice(g.Items, func(i, j int) bool {
			if g.Items[i].Components != g.Items[j].Components {
				return g.Items[i].Components > g.Items[j].Components
			}
			return g.Items[i].Key < g.Items[j].Key
		})
		switch r {
		case UncheckedUnreadableVersion:
			out.NeedYou += g.Components
		case UncheckedUnreadableFiles:
			out.NeedYou += g.Assets
		case UncheckedUnsupported:
			out.NotSupported = g.Components
		case UncheckedWaitingForData:
			out.Waiting, out.Overdue = g.Components, g.Overdue
		case UncheckedNoAdvisories:
			out.NoAdvisories = g.Components
		}
		out.Groups = append(out.Groups, *g)
	}
	return out, nil
}

// staleVulnFeeds lists the vulnerability sources rows matched against them
// count as stale (rowCoverageSQL: switched off, failing, never synced or
// past their window), and which of those are overdue: switched off, or with
// no successful sync within their staleness window. A source failing within
// its window is stale but not overdue.
func (s *Store) staleVulnFeeds(ctx context.Context) ([]string, map[string]bool, error) {
	rows, err := s.Pool.Query(ctx, `SELECT name, NOT enabled OR COALESCE(last_success, created_at) < now() - stale_after
		FROM feeds WHERE NOT enabled OR last_error <> '' OR last_success IS NULL OR last_success < now() - stale_after`)
	if err != nil {
		return nil, nil, err
	}
	stale := []string{}
	overdue := map[string]bool{}
	for rows.Next() {
		var name string
		var od bool
		if err := rows.Scan(&name, &od); err != nil {
			rows.Close()
			return nil, nil, err
		}
		stale = append(stale, name)
		overdue[name] = od
	}
	rows.Close()
	return stale, overdue, rows.Err()
}

// typeLabels name package types the way their users do.
var typeLabels = map[string]string{
	"npm": "npm", "pypi": "PyPI", "composer": "Composer", "golang": "Go", "cargo": "Cargo", "gem": "RubyGems",
	"maven": "Maven", "nuget": "NuGet", "pub": "Dart", "swift": "Swift", "hex": "Hex", "cocoapods": "CocoaPods",
	"conan": "Conan", "deb": "deb", "rpm": "RPM", "apk": "Alpine", "generic": "other",
}

// TypeLabel is how a package type is named in the dashboard.
func TypeLabel(typ string) string {
	if l, ok := typeLabels[typ]; ok {
		return l
	}
	return typ
}

// unsupportedLabels complete "N components use <label>, which Stackurity
// doesn't check yet". %s is the package type's label.
var unsupportedLabels = map[string]string{
	"ecosystem":                 "%s packages",
	"distribution":              "%s packages from a Linux distribution with no vulnerability data",
	"runtime":                   "runtimes installed outside a package manager",
	"cms":                       "WordPress core",
	"wordpress_extension":       "WordPress plugins and themes",
	"kubernetes":                "Kubernetes components reported by the cluster",
	"managed_service":           "managed cloud services",
	"windows_hotpatch":          "Windows hotpatch builds",
	"windows_esu":               "Windows releases on paid Extended Security Updates",
	"windows_release":           "Windows releases whose missing updates are not read",
	"windows_program":           "Windows programs outside the curated catalogue",
	"windows_program_unmatched": "Windows programs the catalogue recognises but cannot match yet",
	"no_repository_url":         "Swift packages without a repository URL",
	"private_registry":          "%s packages from a private registry",
	"other":                     "%s packages",
}

// uncheckedLabel names a subject for people.
func uncheckedLabel(reason, subject, typ string) string {
	switch reason {
	case UncheckedUnsupported:
		parts := strings.SplitN(subject, "|", 3)
		cat := ""
		if len(parts) > 1 {
			cat = parts[1]
		}
		if cat == "vendor_build" && len(parts) == 3 {
			return "vendor builds from " + parts[2]
		}
		if f, ok := unsupportedLabels[cat]; ok {
			if strings.Contains(f, "%s") {
				return fmt.Sprintf(f, TypeLabel(parts[0]))
			}
			return f
		}
		return TypeLabel(parts[0]) + " packages"
	case UncheckedWaitingForData:
		// "osv:npm" -> "npm", "msrc:Windows" -> "Windows".
		if _, rest, ok := strings.Cut(subject, ":"); ok {
			return rest
		}
		return subject
	case UncheckedNoAdvisories:
		return strings.ReplaceAll(subject, ":", " ")
	case UncheckedUnreadableVersion:
		return unreadableCauses[subject].label
	}
	return subject
}

const installDocs = "https://github.com/stackurity/stackurity/blob/main/docs/install.md"

var unreadableCauses = map[string]struct{ label, fix, docs string }{
	"no_version": {"no version recorded",
		"Commit the lockfile (package-lock.json, yarn.lock, composer.lock, poetry.lock and so on) next to the manifest, or install the package with its package manager, then check again.",
		installDocs + "#repositories"},
	"unparseable_version": {"version in a form its package manager does not use",
		"Install a released version, or tag your own build with one (1.2.3), then check again.", ""},
	"unknown_release": {"operating system release not reported",
		"Let the agent read /etc/os-release (it reports the release), then check again.", installDocs + "#linux-hosts"},
	"unreadable_package": {"package identifier could not be read",
		"The package's identifier (purl) is malformed. Fix it in the SBOM or report it to the tool that wrote it.", installDocs + "#sboms"},
}

// manifests are files that declare dependencies without pinning them; a
// component found there with no version needs the matching lockfile.
var manifests = map[string]string{
	"package.json": "package-lock.json, yarn.lock or pnpm-lock.yaml", "composer.json": "composer.lock",
	"Gemfile": "Gemfile.lock", "pyproject.toml": "poetry.lock or uv.lock", "Pipfile": "Pipfile.lock",
	"requirements.txt": "exact == pins in requirements.txt", "Cargo.toml": "Cargo.lock", "pubspec.yaml": "pubspec.lock",
}

// UnreadableVersionFix says what to do about a component whose version could
// not be read, and where the docs are. location (optional) is where the
// component was found: a manifest names the lockfile to commit.
func UnreadableVersionFix(cause, location string) (fix, docs string) {
	c, ok := unreadableCauses[cause]
	if !ok {
		return "", ""
	}
	if cause == "no_version" && location != "" {
		base := location[strings.LastIndex(location, "/")+1:]
		if lock, ok := manifests[base]; ok {
			return fmt.Sprintf("Commit %s next to %s so exact versions can be read, then check again.", lock, base), c.docs
		}
	}
	return c.fix, c.docs
}

// UnreadableFilesFix says what to do about application files the agent may
// not read: an ACL, never a group that can reach PHP-FPM sockets.
func UnreadableFilesFix() (fix, docs string) {
	return "Grant the agent's user read access with an ACL (setfacl), not by adding it to the site's group, then check again.",
		installDocs + "#applications-deployed-on-the-host"
}

// uncheckedRowFilter limits inventory rows to one unchecked reason. The
// reasons other than waiting_for_data only apply to rows the partial index
// inventory_coverage_gaps covers.
func uncheckedRowFilter(w *where, reason string) {
	if reason != UncheckedWaitingForData {
		w.conds = append(w.conds, "i.coverage IN ('unsupported', 'not_evaluated')")
	}
	w.add("("+uncheckedReasonSQL("("+rowCoverageSQL+") = 'stale_intelligence'")+") = ?", reason)
}

// UncheckedGaps counts, for the coverage-gap report, the components a
// vulnerability source exists for that were still not checked (coverage
// not_evaluated, or matched against stale data), by reason, package type and
// subject (kind "reason|type|subject"). Those with no source at all are in
// VulnerabilitySourceGaps. It runs in system scope across active workspaces.
func (s *Store) UncheckedGaps(ctx context.Context) ([]GapRow, error) {
	stale, _, err := s.staleVulnFeeds(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT x.kind, count(DISTINCT x.asset_id), count(DISTINCT x.workspace_id), count(DISTINCT x.component_id)
		FROM (SELECT i.asset_id, a.workspace_id, i.component_id, r.reason || '|' || c.type || '|' || `+uncheckedSubjectSQL+` AS kind
		  FROM inventory i
		  JOIN components c ON c.id = i.component_id
		  JOIN assets a ON a.id = i.asset_id AND a.merged_into IS NULL
		  JOIN workspaces w ON w.id = a.workspace_id AND w.disabled_at IS NULL
		  CROSS JOIN LATERAL (SELECT `+uncheckedReasonSQL("i.coverage_feed = ANY($1)")+` AS reason) r
		  WHERE i.removed_at IS NULL
		    AND (i.coverage = 'not_evaluated' OR (i.coverage = 'evaluated' AND i.coverage_feed = ANY($1)))) x
		GROUP BY 1 ORDER BY 2 DESC, 1`, stale)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[GapRow])
}

// UncheckedLabel names the subject of a coverage-gap report row of
// UncheckedGaps ("reason|type|subject") for people.
func UncheckedLabel(kind string) (reason, label string) {
	parts := strings.SplitN(kind, "|", 3)
	if len(parts) < 3 {
		return "", kind
	}
	return parts[0], uncheckedLabel(parts[0], parts[2], parts[1])
}
