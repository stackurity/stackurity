package store

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

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
//	other               user        any other reason a source could not be
//	                                used; the row's reason says what to fix
//	unreadable_files    user        application files the agent may not read
//	                                (counted in assets, not components)
//
// The reason is classified from the text the matcher writes; there is no
// stored code yet (TODO: a coverage_code column would make this a lookup).
// TestUncheckedReasonsFromProducers (internal/intel) produces every reason
// from its producer and pins its class, so a wording change fails CI.
const (
	UncheckedUnsupported       = "unsupported"
	UncheckedWaitingForData    = "waiting_for_data"
	UncheckedNoAdvisories      = "no_advisories"
	UncheckedUnreadableVersion = "unreadable_version"
	UncheckedUnreadableFiles   = "unreadable_files"
	UncheckedOther             = "other"
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
	UncheckedOther:             ActorUser,
	UncheckedUnsupported:       ActorStackurity,
	UncheckedWaitingForData:    ActorAutomatic,
	UncheckedNoAdvisories:      ActorNone,
}

// uncheckedOrder is the order of the groups: what needs the user first.
var uncheckedOrder = []string{UncheckedUnreadableVersion, UncheckedOther, UncheckedUnreadableFiles, UncheckedUnsupported,
	UncheckedWaitingForData, UncheckedNoAdvisories}

// ValidUncheckedReason reports whether r names a reason components can have
// (the inventory filter; unreadable_files is about files, not components).
func ValidUncheckedReason(r string) bool {
	switch r {
	case UncheckedUnsupported, UncheckedWaitingForData, UncheckedNoAdvisories, UncheckedUnreadableVersion, UncheckedOther:
		return true
	}
	return false
}

// uncheckedReasonSQL is why inventory row i was not checked (” when it
// was), from the reasons the matcher writes (intel.Evaluator; the producers
// are in intel/reasons.go, osv.WhyNoTarget, winrelease and winprograms).
// stale is an SQL condition that is true when an evaluated row was matched
// against vulnerability data past its staleness window (overdueFeedSQL).
//
// Only coverage 'unsupported', or a not-evaluated reason known to be
// Stackurity's own gap, is "unsupported": anything else not evaluated
// falls to 'other', which the user is told to look at, never hidden as
// something Stackurity will do.
func uncheckedReasonSQL(stale string) string {
	return `CASE
	WHEN i.coverage = 'evaluated' THEN CASE WHEN ` + stale + ` THEN 'waiting_for_data' ELSE '' END
	WHEN i.coverage = 'unsupported' THEN 'unsupported'
	WHEN i.coverage <> 'not_evaluated' THEN ''
	WHEN i.coverage_reason ~ 'vulnerability feed \S+ (has not been set up yet|is disabled|has not completed a sync)'
	  OR i.coverage_reason LIKE '%the advisories of % have not been read from % yet%'
	  OR i.coverage_reason LIKE '%(the endoflife.date feed has not synced)%' THEN 'waiting_for_data'
	WHEN i.coverage_reason ~ ' has no (advisories|updates) for '
	  OR i.coverage_reason LIKE '%has no updates in Microsoft''s data since it left support%' THEN 'no_advisories'
	WHEN ` + uncheckedCauseSQL + ` <> '' THEN 'unreadable_version'
	WHEN i.coverage_reason LIKE 'the distro release % is not understood'
	  OR i.coverage_reason LIKE '%is not a known release%'
	  OR i.coverage_reason LIKE '%endoflife.date % has no release %'
	  OR i.coverage_reason LIKE '%is not a Windows Server or Windows client release%'
	  OR i.coverage_reason LIKE '%the curated catalogue reads no version for %' THEN 'unsupported'
	ELSE 'other' END`
}

// overdueFeedSQL is true when inventory row i was matched against a
// vulnerability feed that is switched off or has not synced within its
// staleness window. A failing sync within the window is not overdue: the
// data is still current, as for feed incidents.
const overdueFeedSQL = `EXISTS (SELECT 1 FROM feeds fd WHERE fd.name = i.coverage_feed
	AND (NOT fd.enabled OR fd.last_success IS NULL OR fd.last_success < now() - fd.stale_after))`

// uncheckedCauseSQL is why the installed version of row i could not be
// read, when the user can do something about it.
const uncheckedCauseSQL = `CASE
	WHEN i.coverage_reason = 'no installed version was reported' THEN 'no_version'
	WHEN i.coverage_reason LIKE 'no version was recorded for %' THEN 'program_no_version'
	WHEN i.coverage_reason LIKE 'the version % of % is not in the form the curated catalogue reads%' THEN 'program_version_form'
	WHEN i.coverage_reason LIKE 'installed version % could not be compared using %' THEN 'unparseable_version'
	WHEN i.coverage_reason LIKE 'the distro release is unknown%' THEN 'unknown_release'
	WHEN i.coverage_reason = 'the package URL could not be read' THEN 'unreadable_package'
	WHEN i.coverage_reason LIKE '%has no update revision (UBR)%' THEN 'windows_no_ubr'
	WHEN i.coverage_reason LIKE '%no Windows build number in version%' THEN 'windows_no_build'
	WHEN i.coverage_reason LIKE '%no product name, so Windows Server and client%'
	  OR i.coverage_reason LIKE '%without the product name it cannot tell which%' THEN 'windows_no_product'
	WHEN i.coverage_reason LIKE '%they disagree%' OR i.coverage_reason LIKE '%the name and build disagree%' THEN 'windows_mismatch'
	ELSE '' END`

// uncheckedSubjectSQL is what an unchecked row is about, per reason: the
// package type and category for unsupported ("cocoapods|ecosystem"), the
// vulnerability source for waiting_for_data ("osv:npm"), the release for
// no_advisories ("Debian:13") and the cause for unreadable_version.
const uncheckedSubjectSQL = `CASE r.reason
	WHEN 'unsupported' THEN c.type || '|' || ` + unsupportedCategorySQL + `
	WHEN 'waiting_for_data' THEN COALESCE(NULLIF(i.coverage_feed, ''), substring(i.coverage_reason from 'vulnerability feed (\S+) '),
	  CASE WHEN i.coverage_reason LIKE '%endoflife.date feed has not synced%' THEN 'lifecycle:endoflife' END,
	  substring(i.coverage_reason from '\(feed ([^)]+)\)'), 'unknown')
	WHEN 'no_advisories' THEN COALESCE(substring(i.coverage_reason from ' has no advisories for (\S+): '),
	  substring(i.coverage_reason from ' has no updates for (Windows \S+) '), c.type)
	WHEN 'unreadable_version' THEN ` + uncheckedCauseSQL + `
	WHEN 'other' THEN c.type
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
	// readable version or another reason to look at, and applications with
	// files the agent may not read. NeedYouComponents and
	// NeedYouApplications split it, so it can be said in the right nouns.
	NeedYou             int64 `json:"need_you"`
	NeedYouComponents   int64 `json:"need_you_components"`
	NeedYouApplications int64 `json:"need_you_applications"`
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
	feeds, stale, err := s.vulnFeedStates(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT r.reason, `+uncheckedSubjectSQL+` AS subject,
		  count(DISTINCT i.component_id), count(DISTINCT i.asset_id), min(c.type), min(i.first_seen)
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
	since := map[key]time.Time{}
	for rows.Next() {
		var k key
		var comps, assets int64
		var typ string
		var first time.Time
		if err := rows.Scan(&k.reason, &k.subject, &comps, &assets, &typ, &first); err != nil {
			rows.Close()
			return nil, err
		}
		if k.reason == "" {
			continue
		}
		items[k] = &UncheckedItem{Key: k.subject, Components: comps, Assets: assets}
		typeOf[k] = typ
		since[k] = first
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

	now := time.Now()
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
		switch k.reason {
		case UncheckedUnreadableVersion:
			it.Fix, it.Docs = UnreadableVersionFix(k.subject, "", "")
		case UncheckedOther:
			it.Fix = OtherFix
		case UncheckedWaitingForData:
			if feedOverdue(feeds[k.subject], since[k], now) {
				it.Overdue, g.Overdue = true, true
			}
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
		case UncheckedUnreadableVersion, UncheckedOther:
			out.NeedYouComponents += g.Components
		case UncheckedUnreadableFiles:
			out.NeedYouApplications = g.Assets
		case UncheckedUnsupported:
			out.NotSupported = g.Components
		case UncheckedWaitingForData:
			out.Waiting, out.Overdue = g.Components, g.Overdue
		case UncheckedNoAdvisories:
			out.NoAdvisories = g.Components
		}
		out.Groups = append(out.Groups, *g)
	}
	out.NeedYou = out.NeedYouComponents + out.NeedYouApplications
	return out, nil
}

// FeedGrace is how long a vulnerability feed may be missing or without a
// first sync before what waits for it is overdue: feeds are created and
// synced within minutes, unless feeds are switched off or the server
// cannot reach them (an air-gapped install without a mirror).
const FeedGrace = 6 * time.Hour

type feedState struct {
	enabled     bool
	lastSuccess *time.Time
	created     time.Time
	staleAfter  time.Duration
}

// vulnFeedStates reads every feed, and lists those whose matched rows wait
// for newer data (overdueFeedSQL).
func (s *Store) vulnFeedStates(ctx context.Context) (map[string]feedState, []string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT name, enabled, last_success, created_at, stale_after,
		  NOT enabled OR last_success IS NULL OR last_success < now() - stale_after FROM feeds`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	out := map[string]feedState{}
	stale := []string{}
	for rows.Next() {
		var name string
		var f feedState
		var old bool
		if err := rows.Scan(&name, &f.enabled, &f.lastSuccess, &f.created, &f.staleAfter, &old); err != nil {
			return nil, nil, err
		}
		out[name] = f
		if old {
			stale = append(stale, name)
		}
	}
	return out, stale, rows.Err()
}

// feedOverdue: what waits for this feed will not resolve on its own. A
// feed that is switched off, has not synced within its window, or has been
// missing or never synced for longer than FeedGrace since the first row
// that waits for it.
func feedOverdue(f feedState, waitingSince, now time.Time) bool {
	switch {
	case f.created.IsZero():
		return now.Sub(waitingSince) > FeedGrace
	case !f.enabled:
		return true
	case f.lastSuccess == nil:
		return now.Sub(f.created) > max(FeedGrace, f.staleAfter)
	}
	return now.Sub(*f.lastSuccess) > f.staleAfter
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
	case UncheckedOther:
		return TypeLabel(subject) + " components"
	}
	return subject
}

const installDocs = "https://github.com/stackurity/stackurity/blob/main/docs/install.md"

var unreadableCauses = map[string]struct{ label, fix, docs string }{
	// The summary's fix; each row's says what to do for where it came
	// from (UnreadableVersionFix).
	"no_version": {"no version recorded",
		"Each component's row says what to do: commit the lockfile next to a manifest, include versions in an imported SBOM, or reinstall a package whose install record has no version.",
		installDocs + "#repositories"},
	"unparseable_version": {"version in a form its package manager does not use",
		"Install a released version, or tag your own build with one (1.2.3), then check again.", ""},
	"unknown_release": {"operating system release not reported",
		"Let the agent read /etc/os-release (it reports the release), then check again.", installDocs + "#linux-hosts"},
	"unreadable_package": {"package identifier could not be read",
		"The package's identifier (purl) is malformed. Fix it in the SBOM or report it to the tool that wrote it.", installDocs + "#sboms"},
	// Windows programs (the registry's uninstall entries).
	"program_no_version": {"Windows program registered without a version",
		"The program's entry under Apps & features has no version (the registry's DisplayVersion is empty). Repair or reinstall it with the vendor's installer so it records one, then check again.",
		installDocs + "#windows-hosts"},
	"program_version_form": {"Windows program version in an unexpected form",
		"The program's registry version (DisplayVersion) is not in the form its vendor uses, often a repackaged or customised install. Install the vendor's own release, then check again.",
		installDocs + "#windows-hosts"},
	// Windows itself (the registry's CurrentVersion key).
	"windows_no_ubr": {"Windows update revision (UBR) not reported",
		"The agent reported the Windows build but not its update revision (the registry's UBR value), so the installed cumulative update is unknown. Update the Stackurity agent on the host, then check again.",
		installDocs + "#windows-hosts"},
	"windows_no_build": {"Windows build number not reported",
		"The agent did not report the Windows build number (the registry's CurrentBuild). Update the Stackurity agent on the host, then check again.",
		installDocs + "#windows-hosts"},
	"windows_no_product": {"Windows edition not reported",
		"The agent did not report the Windows product name, so Windows Server and client cannot be told apart. Update the Stackurity agent on the host, then check again.",
		installDocs + "#windows-hosts"},
	"windows_mismatch": {"Windows version and build disagree",
		"The registry's version name and build number disagree, usually after an interrupted upgrade. Finish or repair the Windows update and restart, then check again.",
		installDocs + "#windows-hosts"},
}

// OtherFix is what to do about a component not checked for a reason the
// breakdown has no rule for: the row says why; it is never assumed to be
// Stackurity's to fix.
const OtherFix = "Each component's row says why it could not be checked. Fix what it names and check again; if the reason looks wrong, tell us."

// manifests are files that declare dependencies without pinning them; a
// component found there with no version needs the matching lockfile.
var manifests = map[string]string{
	"package.json": "package-lock.json, yarn.lock or pnpm-lock.yaml", "composer.json": "composer.lock",
	"Gemfile": "Gemfile.lock", "pyproject.toml": "poetry.lock or uv.lock", "Pipfile": "Pipfile.lock",
	"requirements.txt": "exact == pins in requirements.txt", "Cargo.toml": "Cargo.lock", "pubspec.yaml": "pubspec.lock",
}

// UnreadableVersionFix says what to do about a component whose version could
// not be read, and where the docs are. For no version, it depends on where
// the component came from: collector (optional) is its collector, location
// (optional) where it was found. An imported SBOM needs versions in it; a
// manifest needs its lockfile; anything else was reported by a collector
// without one.
func UnreadableVersionFix(cause, location, collector string) (fix, docs string) {
	c, ok := unreadableCauses[cause]
	if !ok {
		return "", ""
	}
	if cause != "no_version" || (location == "" && collector == "") {
		return c.fix, c.docs
	}
	if strings.HasSuffix(collector, "-import") { // cyclonedx-import, spdx-import (internal/sbom)
		return "The imported SBOM lists this component without a version. Include versions in the SBOM (most generators do with their default settings), then import it again.",
			installDocs + "#sboms"
	}
	base := location[strings.LastIndex(location, "/")+1:]
	if lock, ok := manifests[base]; ok {
		return fmt.Sprintf("Commit %s next to %s so exact versions can be read, then check again.", lock, location), installDocs + "#repositories"
	}
	return "The collector reported this component without a version. Check again; if it stays, its install record may be damaged: reinstall it with its package manager, then check again.",
		installDocs + "#collecting-inventory"
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
	w.add("("+uncheckedReasonSQL(overdueFeedSQL)+") = ?", reason)
}

// UncheckedGaps counts, for the coverage-gap report, the components a
// vulnerability source exists for that were still not checked (coverage
// not_evaluated, or matched against stale data), by reason, package type and
// subject (kind "reason|type|subject"). Those with no source at all are in
// VulnerabilitySourceGaps. It runs in system scope across active workspaces.
func (s *Store) UncheckedGaps(ctx context.Context) ([]GapRow, error) {
	_, stale, err := s.vulnFeedStates(ctx)
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

// ClassifyUnchecked classifies one coverage state and reason the way the
// breakdown does (reason, cause and actor), for tests that produce reasons
// from their producers.
func (s *Store) ClassifyUnchecked(ctx context.Context, coverage, reason string) (class, cause, actor string, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT `+uncheckedReasonSQL("false")+`, `+uncheckedCauseSQL+`
		FROM (SELECT $1::text AS coverage, $2::text AS coverage_reason) i`, coverage, reason).Scan(&class, &cause)
	if class != UncheckedUnreadableVersion {
		cause = ""
	}
	return class, cause, UncheckedActors[class], err
}
