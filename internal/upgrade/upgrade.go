// Package upgrade recommends a version to move an installed component to,
// using only stored facts: the fixed versions advisories give for its open
// findings, the registry's release list (with withdrawn versions) and the
// endoflife.date release lines. It never invents a version: without release
// data the recommendation is the minimum fixed version, and says so.
package upgrade

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// Basis says where the recommended version comes from.
const (
	BasisDistroFixed   = "distro_fixed"   // OS package: the distribution's fixed build
	BasisLatestInLine  = "latest_in_line" // newest stable release in the major line, at or above the minimum fix
	BasisMinimumFixed  = "minimum_fixed"  // the minimum fixed version itself (no newer stable release is known)
	BasisSupportedLine = "supported_line" // the installed line is end of life: newest release of the oldest supported line
	BasisNone          = "none"           // nothing to recommend
)

// Release-data states.
const (
	ReleaseAvailable     = "available"
	ReleaseNone          = "none"           // no registry data for this component
	ReleaseFailed        = "failed"         // the last registry lookup failed and nothing is stored
	ReleaseNotApplicable = "not_applicable" // OS packages: the distribution decides the version
)

// Finding is one open finding on the installed component.
type Finding struct {
	ID           int64  `json:"finding_id"`
	Kind         string `json:"kind"` // vulnerability, end_of_life
	Key          string `json:"key"`
	FixedVersion string `json:"fixed_version,omitempty"`
	Subscription string `json:"requires_subscription,omitempty"` // the fix is only in a paid channel
}

// Input is everything a recommendation looks at.
type Input struct {
	PurlType  string
	Installed string
	Findings  []Finding
	Release   *store.Release         // nil: no release data
	Product   string                 // endoflife.date product; "" when none
	Cycles    []store.LifecycleCycle // the product's release lines, newest first
	Now       time.Time
}

// Line is the support status of one release line.
type Line struct {
	Product      string     `json:"product"`
	Cycle        string     `json:"cycle"`
	Status       string     `json:"status"` // supported, security_only, end_of_life
	SupportUntil *time.Time `json:"support_until,omitempty"`
	EOLDate      *time.Time `json:"eol_date,omitempty"`
	Latest       string     `json:"latest,omitempty"`
	Link         string     `json:"link,omitempty"`
}

type Recommendation struct {
	PurlType      string `json:"purl_type"`
	Installed     string `json:"installed_version"`
	MinimumFixed  string `json:"minimum_fixed_version,omitempty"`
	Recommended   string `json:"recommended_version,omitempty"`
	Basis         string `json:"basis"`
	ChangeType    string `json:"change_type,omitempty"` // patch, minor, major, distro
	RequiresMajor bool   `json:"requires_major"`
	// Subscription names a paid channel the fix needs (Ubuntu Pro, SUSE LTSS).
	Subscription string `json:"requires_subscription,omitempty"`

	ReleaseData      string     `json:"release_data"`
	ReleaseSource    string     `json:"release_source,omitempty"`
	ReleaseCheckedAt *time.Time `json:"release_checked_at,omitempty"`
	LatestStable     string     `json:"latest_stable,omitempty"`
	LatestInLine     string     `json:"latest_in_line,omitempty"` // newest stable release in the recommended version's major line
	// Withdrawn versions: the registry yanked, retracted or unlisted them.
	RecommendedYanked   bool   `json:"recommended_yanked"`
	MinimumFixedYanked  bool   `json:"minimum_fixed_yanked"`
	YankedReason        string `json:"yanked_reason,omitempty"`
	InstalledYanked     bool   `json:"installed_yanked"`
	Deprecated          string `json:"deprecated,omitempty"` // the maintainers' deprecation notice for the package
	MinimumFixedUnknown bool   `json:"minimum_fixed_not_in_release_data"`

	Lifecycle       *Line `json:"lifecycle,omitempty"`        // the installed version's release line
	TargetLifecycle *Line `json:"target_lifecycle,omitempty"` // the recommended version's line, when it differs
	SupportedLine   *Line `json:"supported_line,omitempty"`   // oldest supported line newer than the installed one

	Fixes     []string `json:"fixes"`     // finding keys the recommended version resolves
	Unfixed   []string `json:"unfixed"`   // keys it does not resolve (no fixed version, or a line that stays end of life)
	Rationale []string `json:"rationale"` // plain-language reasons, built from the facts above
	Findings  int      `json:"open_findings"`
}

// IsDistro reports whether the purl type is an OS package, whose fixed
// version is the distribution's build rather than an upstream release.
func IsDistro(purlType string) bool {
	return purlType == "deb" || purlType == "rpm" || purlType == "apk"
}

// Recommend applies the rules. They are, in order:
//
//  1. The minimum fixed version is the highest fixed version across the open
//     vulnerability findings (each is already the highest "first fixed"
//     across that issue's advisories), compared with the ecosystem's rules.
//  2. OS packages: recommend that version; the distribution's build is the
//     fix, so registry releases do not apply.
//  3. With release data: recommend the newest stable, non-withdrawn release
//     at or above the minimum in the installed version's major line; if the
//     minimum is in a later major line, the newest such release in that
//     line, and say a major upgrade is needed. Without a stable release at or
//     above the minimum, recommend the minimum itself.
//  4. Without release data: recommend the minimum fixed version.
//  5. When the installed line is end of life and a supported line is
//     recorded, the end-of-life finding is fixed only by moving to it: the
//     recommendation becomes the newest release of the oldest supported line
//     newer than the installed one, if that is at or above the minimum fix.
func Recommend(in Input) Recommendation {
	eco := version.ForPurlType(in.PurlType)
	cmp := version.For(eco)
	rec := Recommendation{PurlType: in.PurlType, Installed: in.Installed, Basis: BasisNone, Fixes: []string{}, Unfixed: []string{},
		Rationale: []string{}, Findings: len(in.Findings)}
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	say := func(format string, a ...any) { rec.Rationale = append(rec.Rationale, fmt.Sprintf(format, a...)) }

	// 1. minimum fixed version
	var vulnFixed, vulnOpen []Finding
	var eolKeys []string
	for _, f := range in.Findings {
		switch {
		case f.Kind == "end_of_life":
			eolKeys = appendUnique(eolKeys, f.Key)
		case f.FixedVersion == "":
			rec.Unfixed = appendUnique(rec.Unfixed, f.Key)
		default:
			vulnFixed = append(vulnFixed, f)
		}
		if f.Kind != "end_of_life" {
			vulnOpen = append(vulnOpen, f)
		}
	}
	var unparsed []string
	for _, f := range vulnFixed {
		if _, err := cmp(f.FixedVersion, f.FixedVersion); err != nil {
			unparsed = appendUnique(unparsed, f.FixedVersion)
			continue
		}
		if rec.MinimumFixed == "" {
			rec.MinimumFixed = f.FixedVersion
		} else if c, err := cmp(f.FixedVersion, rec.MinimumFixed); err == nil && c > 0 {
			rec.MinimumFixed = f.FixedVersion
		}
		if f.Subscription != "" && rec.Subscription == "" {
			rec.Subscription = f.Subscription
		}
	}
	if len(unparsed) > 0 {
		say("Fixed version %s could not be compared under %s rules and was left out.", strings.Join(unparsed, ", "), eco)
	}

	// Release data and lifecycle facts, whatever is recommended.
	rel := in.Release
	switch {
	case IsDistro(in.PurlType):
		rec.ReleaseData = ReleaseNotApplicable
		rel = nil
	case rel == nil:
		rec.ReleaseData = ReleaseNone
	case rel.LatestStable == "" && len(rel.StableVersions) == 0 && rel.LastError != "":
		rec.ReleaseData = ReleaseFailed
		rec.ReleaseSource, rec.ReleaseCheckedAt = rel.Source, &rel.CheckedAt
		rel = nil
	default:
		rec.ReleaseData = ReleaseAvailable
		rec.ReleaseSource, rec.ReleaseCheckedAt = rel.Source, &rel.CheckedAt
		rec.LatestStable, rec.Deprecated = rel.LatestStable, rel.Deprecated
		_, rec.InstalledYanked = rel.Yanked[in.Installed]
	}
	if in.Product != "" {
		if c := MatchCycle(in.Cycles, in.Installed); c != nil {
			rec.Lifecycle = lineOf(in.Product, c, in.Now)
		}
	}

	// 2-4. recommended version for the vulnerability fixes
	if rec.MinimumFixed != "" {
		switch {
		case IsDistro(in.PurlType):
			rec.Recommended, rec.Basis = rec.MinimumFixed, BasisDistroFixed
			say("%s is the highest fixed build the distribution's advisories list for the open findings.", rec.MinimumFixed)
		case rel == nil:
			rec.Recommended, rec.Basis = rec.MinimumFixed, BasisMinimumFixed
			if rec.ReleaseData == ReleaseFailed {
				say("No release data (the last registry lookup failed): recommending the minimum fixed version %s.", rec.MinimumFixed)
			} else {
				say("No release data: recommending the minimum fixed version %s.", rec.MinimumFixed)
			}
		default:
			pickInLine(&rec, in, rel, eco, cmp, say)
		}
		if reason, ok := yankedIn(rel, rec.MinimumFixed); ok {
			rec.MinimumFixedYanked = true
			if rec.Recommended != rec.MinimumFixed {
				say("The minimum fixed version %s was withdrawn by the registry%s.", rec.MinimumFixed, reasonSuffix(reason))
			}
		}
	} else if len(vulnOpen) > 0 {
		say("No source lists a fixed version for %s.", plural(len(rec.Unfixed), "open finding"))
	}

	// 5. end-of-life lines
	if rec.Lifecycle != nil && rec.Lifecycle.Status == "end_of_life" && !IsDistro(in.PurlType) {
		endOfLifeLine(&rec, in, rel, cmp, say)
	}

	if rec.Recommended == "" {
		if len(in.Findings) == 0 {
			say("No open findings on this version.")
		}
		rec.Unfixed = append(rec.Unfixed, eolKeys...)
		sort.Strings(rec.Unfixed)
		return rec
	}

	// What the recommendation resolves, its change type and its line.
	for _, f := range vulnFixed {
		if c, err := cmp(rec.Recommended, f.FixedVersion); err == nil && c >= 0 {
			rec.Fixes = appendUnique(rec.Fixes, f.Key)
		} else {
			rec.Unfixed = appendUnique(rec.Unfixed, f.Key)
		}
	}
	if in.Product != "" {
		if c := MatchCycle(in.Cycles, rec.Recommended); c != nil && (rec.Lifecycle == nil || c.Cycle != rec.Lifecycle.Cycle) {
			rec.TargetLifecycle = lineOf(in.Product, c, in.Now)
		}
	}
	targetLine := rec.Lifecycle
	if rec.TargetLifecycle != nil {
		targetLine = rec.TargetLifecycle
	}
	for _, k := range eolKeys {
		if targetLine != nil && targetLine != rec.Lifecycle && targetLine.Status != "end_of_life" {
			rec.Fixes = appendUnique(rec.Fixes, k)
		} else {
			rec.Unfixed = appendUnique(rec.Unfixed, k)
		}
	}
	sort.Strings(rec.Fixes)
	sort.Strings(rec.Unfixed)
	if ct, err := version.ChangeType(in.PurlType, in.Installed, rec.Recommended); err == nil {
		rec.ChangeType = ct
		rec.RequiresMajor = ct == "major"
	}
	if reason, ok := yankedIn(rel, rec.Recommended); ok {
		rec.RecommendedYanked, rec.YankedReason = true, reason
		say("Warning: %s was withdrawn by the registry%s and no other stable release at or above it is recorded.", rec.Recommended, reasonSuffix(reason))
	}
	if rec.RequiresMajor {
		say("This is a major upgrade (%s to %s): expect breaking changes.", in.Installed, rec.Recommended)
	}
	if rec.Subscription != "" {
		// The paid channel is an option, never the action.
		say("Fixed in %s (paid subscription); without it, upgrade to a supported release or install the update when the distribution publishes a free fix.",
			rec.Subscription)
	}
	if rec.Deprecated != "" {
		say("The package is deprecated by its maintainers: %s", rec.Deprecated)
	}
	if rec.InstalledYanked {
		say("The installed version %s was withdrawn by the registry.", in.Installed)
	}
	if targetLine != nil && targetLine.Status == "end_of_life" {
		say("%s is in the %s %s line, which is end of life.", rec.Recommended, in.Product, targetLine.Cycle)
	}
	if n := len(rec.Unfixed); n > 0 {
		say("%s remain after this upgrade: %s.", plural(n, "open finding"), strings.Join(rec.Unfixed, ", "))
	}
	return rec
}

// pickInLine is rule 3: the newest stable release in the right major line.
func pickInLine(rec *Recommendation, in Input, rel *store.Release, eco version.Ecosystem, cmp version.Comparator, say func(string, ...any)) {
	stable := stableVersions(rel, eco, cmp)
	known := false
	for _, v := range stable {
		if v == rec.MinimumFixed {
			known = true
		}
	}
	if _, yanked := rel.Yanked[rec.MinimumFixed]; !known && !yanked && len(stable) > 0 && !version.Prerelease(eco, rec.MinimumFixed) {
		rec.MinimumFixedUnknown = true
	}
	line := version.MajorLine(eco, in.Installed)
	minLine := version.MajorLine(eco, rec.MinimumFixed)
	if minLine != "" && line != "" && minLine != line {
		if c, err := cmp(rec.MinimumFixed, in.Installed); err == nil && c > 0 {
			line = minLine // the fix is only in a later major line
		}
	}
	best := ""
	for _, v := range stable {
		if _, w := rel.Yanked[v]; w || line == "" || version.MajorLine(eco, v) != line {
			continue
		}
		if c, err := cmp(v, rec.MinimumFixed); err != nil || c < 0 {
			continue
		}
		if c, err := cmp(v, in.Installed); err != nil || c <= 0 {
			continue
		}
		if best == "" {
			best = v
		} else if c, err := cmp(v, best); err == nil && c > 0 {
			best = v
		}
	}
	rec.LatestInLine = latestInLine(stable, rel, eco, cmp, line)
	if best == "" {
		rec.Recommended, rec.Basis = rec.MinimumFixed, BasisMinimumFixed
		switch {
		case version.Prerelease(eco, rec.MinimumFixed):
			say("The minimum fixed version %s is a pre-release and no stable release at or above it is recorded.", rec.MinimumFixed)
		case len(stable) == 0:
			say("The release data lists no stable versions: recommending the minimum fixed version %s.", rec.MinimumFixed)
		default:
			say("The release data has no stable release at or above %s in the %s.x line: recommending the minimum fixed version.",
				rec.MinimumFixed, line)
		}
		return
	}
	rec.Recommended = best
	if best == rec.MinimumFixed {
		rec.Basis = BasisMinimumFixed
		say("%s is the minimum fixed version and the newest stable release in the %s.x line.", best, line)
	} else {
		rec.Basis = BasisLatestInLine
		say("%s is the newest stable release in the %s.x line and is at or above the minimum fixed version %s.", best, line, rec.MinimumFixed)
	}
	if rec.MinimumFixedUnknown {
		say("The release data does not list %s; the registry may not publish it.", rec.MinimumFixed)
	}
}

// stableVersions is the registry's stable, parseable versions. Data stored
// before the full list was recorded falls back to the dated versions and the
// latest stable release.
func stableVersions(rel *store.Release, eco version.Ecosystem, cmp version.Comparator) []string {
	src := rel.StableVersions
	if len(src) == 0 {
		for v := range rel.VersionDates {
			src = append(src, v)
		}
		if rel.LatestStable != "" {
			src = append(src, rel.LatestStable)
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, v := range src {
		if seen[v] || version.Prerelease(eco, v) {
			continue
		}
		if _, err := cmp(v, v); err != nil {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out) // deterministic order; selection uses cmp
	return out
}

func latestInLine(stable []string, rel *store.Release, eco version.Ecosystem, cmp version.Comparator, line string) string {
	best := ""
	for _, v := range stable {
		if _, w := rel.Yanked[v]; w || line == "" || version.MajorLine(eco, v) != line {
			continue
		}
		if best == "" {
			best = v
		} else if c, err := cmp(v, best); err == nil && c > 0 {
			best = v
		}
	}
	return best
}

// latestInCycle is the newest stable, non-withdrawn release in a lifecycle
// cycle according to release data, or "".
func latestInCycle(in Input, rel *store.Release, cmp version.Comparator, cycle string) string {
	if rel == nil {
		return ""
	}
	eco := version.ForPurlType(in.PurlType)
	best := ""
	for _, v := range stableVersions(rel, eco, cmp) {
		if _, w := rel.Yanked[v]; w {
			continue
		}
		if c := MatchCycle(in.Cycles, v); c == nil || c.Cycle != cycle {
			continue
		}
		if best == "" {
			best = v
		} else if c, err := cmp(v, best); err == nil && c > 0 {
			best = v
		}
	}
	return best
}

// endOfLifeLine is rule 5. A recommendation already in a supported line
// stands; otherwise the oldest supported line newer than the installed one
// whose newest release is at or above the minimum fix is recommended.
func endOfLifeLine(rec *Recommendation, in Input, rel *store.Release, cmp version.Comparator, say func(string, ...any)) {
	if rec.Recommended != "" {
		if c := MatchCycle(in.Cycles, rec.Recommended); c != nil && c.Cycle != rec.Lifecycle.Cycle && !ended(c, in.Now) {
			return
		}
	}
	lines := supportedLines(in)
	if len(lines) == 0 {
		say("The %s %s line is end of life and no supported later line is recorded.", in.Product, rec.Lifecycle.Cycle)
		return
	}
	for _, c := range lines {
		target := latestInCycle(in, rel, cmp, c.Cycle)
		if target == "" {
			target = c.Latest
		}
		if target == "" {
			continue
		}
		if n, err := cmp(target, in.Installed); err != nil || n <= 0 {
			continue
		}
		if rec.MinimumFixed != "" {
			if n, err := cmp(target, rec.MinimumFixed); err != nil || n < 0 {
				continue
			}
		}
		rec.SupportedLine = lineOf(in.Product, c, in.Now)
		rec.Recommended, rec.Basis = target, BasisSupportedLine
		src := "the lifecycle data"
		if rel != nil && target != c.Latest {
			src = "the release data"
		}
		say("The %s %s line is end of life; %s is the newest release of %s, the oldest supported line after it (per %s).",
			in.Product, rec.Lifecycle.Cycle, target, c.Cycle, src)
		return
	}
	rec.SupportedLine = lineOf(in.Product, lines[0], in.Now)
	say("The %s %s line is end of life; the oldest supported line after it is %s, but no release of it at or above the fix is recorded.",
		in.Product, rec.Lifecycle.Cycle, lines[0].Cycle)
}

// supportedLines are the supported, released lines newer than the installed
// one, oldest first.
func supportedLines(in Input) []*store.LifecycleCycle {
	cur := MatchCycle(in.Cycles, in.Installed)
	if cur == nil {
		return nil
	}
	var out []*store.LifecycleCycle
	for i := range in.Cycles {
		c := &in.Cycles[i]
		if ended(c, in.Now) || (c.ReleaseDate != nil && c.ReleaseDate.After(in.Now)) {
			continue
		}
		if n, _ := version.CompareGeneric(c.Cycle, cur.Cycle); n > 0 {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		n, _ := version.CompareGeneric(out[i].Cycle, out[j].Cycle)
		return n < 0
	})
	return out
}

func ended(c *store.LifecycleCycle, now time.Time) bool {
	return c.IsEOL || (c.EOLUntil != nil && !c.EOLUntil.After(now))
}

func lineOf(product string, c *store.LifecycleCycle, now time.Time) *Line {
	l := &Line{Product: product, Cycle: c.Cycle, Status: "supported", SupportUntil: c.SupportUntil, EOLDate: c.EOLUntil,
		Latest: c.Latest, Link: c.Link}
	switch {
	case ended(c, now):
		l.Status = "end_of_life"
	case c.SupportUntil != nil && !c.SupportUntil.After(now):
		l.Status = "security_only"
	}
	return l
}

// MatchCycle finds the release cycle for a version: exact, then the longest
// dotted prefix ("3.19.1" -> "3.19" -> "3").
func MatchCycle(cycles []store.LifecycleCycle, v string) *store.LifecycleCycle {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+~_ "); i > 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	for n := len(parts); n >= 1; n-- {
		cand := strings.Join(parts[:n], ".")
		for i := range cycles {
			if cycles[i].Cycle == cand {
				return &cycles[i]
			}
		}
	}
	return nil
}

// yankedIn reports whether the registry withdrew v, and why.
func yankedIn(rel *store.Release, v string) (string, bool) {
	if rel == nil || v == "" {
		return "", false
	}
	reason, ok := rel.Yanked[v]
	return reason, ok
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
