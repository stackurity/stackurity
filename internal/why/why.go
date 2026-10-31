// Package why builds the one-sentence answer to "why does Stackurity
// believe this finding?" and its structured parts, from what the matcher
// stored at evaluation time (findings.evidence, including "match"), the
// inventory row it matched, the source's last successful refresh and the
// independent second check. It reads the stored rule; it never re-runs or
// re-derives the match. See docs/verification.md.
package why

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
)

// Explanation types: a common core with type-specific detail, so other
// evidence types (an SBOM attestation, a binary signature) fit later.
const (
	TypePackageAdvisory = "package_advisory" // a language package against an advisory
	TypeOSPackage       = "os_package"       // a distro package against its distro's advisory
	TypeContainerImage  = "container_image"  // either, found in a container image
	TypeEndOfLife       = "end_of_life"      // a release line past its end of life
	TypeBehindRelease   = "behind_release"   // below its supported release line's latest release
)

// behindRule is the matcher's rule for a version behind its release line's
// latest release (internal/intel/behind.go).
const behindRule = store.BehindRule

// NotAnExploit is said wherever a match could be read as more than it is.
const NotAnExploit = "A confirmed match means the installed version is in the advisory's affected range. " +
	"It does not show that the issue can be exploited on this asset."

// Explanation is the why of one finding.
type Explanation struct {
	// Sentence leads the finding page and the explain tool.
	Sentence string `json:"sentence"`
	Type     string `json:"type"`

	Installed Installed `json:"installed"`
	Source    Source    `json:"source"`
	Rule      Rule      `json:"rule"`
	Fixed     string    `json:"fixed_version,omitempty"`

	// EvidenceState is confirmed, needs_validation, stale or rejected (see
	// docs/verification.md, "Evidence states"); StateText says what it
	// means for this finding.
	EvidenceState string `json:"evidence_state"`
	StateText     string `json:"evidence_state_text"`
	// AsOf is the date of the only scan of an asset scanned once: the
	// finding is true as of then, and AsOfText says so.
	AsOf     *time.Time `json:"as_of,omitempty"`
	AsOfText string     `json:"as_of_text,omitempty"`
	// Missing says what exactly would resolve a finding that is not
	// confirmed. Empty when confirmed.
	Missing []string `json:"missing_information"`

	SecondCheck *store.SecondCheck `json:"second_check"`
	// NeedsReview is set while the second check disagrees. It never lowers
	// priority or SOS (docs/risk.md); it asks a person to look.
	NeedsReview bool `json:"needs_review"`
	// SecondCheckText says what the second check concluded, or that it
	// does not cover this finding, or has not run yet.
	SecondCheckText string `json:"second_check_text"`

	// EPSS is FIRST's exploit prediction for the finding's CVE (the
	// highest-scored one when its advisories cover several) and what it does
	// to the priority; nil for findings without a CVE.
	EPSS *EPSSDetail `json:"epss,omitempty"`

	Package   *PackageDetail   `json:"package,omitempty"`
	OS        *OSDetail        `json:"os_package,omitempty"`
	Image     *ImageDetail     `json:"container_image,omitempty"`
	Lifecycle *LifecycleDetail `json:"end_of_life,omitempty"`
}

// EPSSDetail is the EPSS part of "why this priority".
type EPSSDetail struct {
	// CVE is the CVE the score is for: the finding's key, or the CVE with
	// the highest score among those its advisories list as aliases or
	// upstream ids.
	CVE string `json:"cve"`
	// Score is the probability (0 to 1) of exploitation in the next 30
	// days and Percentile its rank among all scored CVEs; nil when FIRST has
	// not scored the CVE (yet).
	Score        *float32 `json:"score"`
	Percentile   *float32 `json:"percentile"`
	Date         string   `json:"date,omitempty"`
	ModelVersion string   `json:"model_version,omitempty"`
	// Threshold is the policy's, and Release the score below which a
	// finding that crossed it loses the points again.
	Threshold float64 `json:"threshold"`
	Release   float64 `json:"release_below"`
	Points    float64 `json:"points"`
	// Counted says the stored priority includes the EPSS factor.
	Counted bool   `json:"counted"`
	Text    string `json:"text"`
}

// Installed is the version evidence: what was observed, where and when.
type Installed struct {
	Version    string     `json:"version"`
	Compared   string     `json:"compared,omitempty"` // the version compared, when normalised
	From       string     `json:"from"`               // file, package database or collector
	Collector  string     `json:"collector"`
	Confidence string     `json:"confidence"`
	ObservedAt *time.Time `json:"observed_at"`
}

// Source is where the claim comes from and how fresh it is.
type Source struct {
	Record      string     `json:"record,omitempty"` // the advisory record that decided
	Ecosystem   string     `json:"ecosystem,omitempty"`
	Feed        string     `json:"feed"`
	RefreshedAt *time.Time `json:"refreshed_at"`
	Stale       bool       `json:"stale"`
}

// Rule is the matching rule that was applied.
type Rule struct {
	// Kind: range, last_affected, no_fix_listed, listed_version (advisories);
	// exact_cycle, version_prefix, package_name, windows_build (end of life).
	Kind       string `json:"kind"`
	Range      string `json:"range,omitempty"`
	Comparator string `json:"comparator,omitempty"`
	Text       string `json:"text"`
	// Ambiguous lists what made the matcher ask for a second check.
	Ambiguous []string `json:"ambiguous,omitempty"`
}

type PackageDetail struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Direct    *bool  `json:"direct"`
	Location  string `json:"location,omitempty"`
}

type OSDetail struct {
	Release       string `json:"release"`
	SourcePackage string `json:"source_package,omitempty"`
	Backport      bool   `json:"backport"`
	Subscription  string `json:"subscription,omitempty"`
}

type ImageDetail struct {
	Image string `json:"image"`
	Inner string `json:"inner_type"` // package_advisory or os_package
}

type LifecycleDetail struct {
	Product string `json:"product"`
	Cycle   string `json:"cycle"`
	EOLDate string `json:"eol_date,omitempty"`
	Latest  string `json:"latest_in_cycle,omitempty"`
}

// Input is everything the explanation reads.
type Input struct {
	Finding     *store.Finding
	Evidence    map[string]any // the finding's evidence, decoded
	Inventory   store.InventoryProvenance
	Feed        *store.Feed // the source that produced the claim; nil if unknown
	SecondCheck *store.SecondCheck
	// Covered says the finding is one the second check covers.
	Covered bool
	// Policy is the current risk policy, for the EPSS threshold; nil leaves
	// EPSS out.
	Policy *risk.Policy
}

var comparatorText = map[string]string{
	"semver": "SemVer rules", "composer": "Composer version rules", "debian": "Debian version rules (dpkg)",
	"rpm": "RPM version rules (epoch:version-release)", "apk": "Alpine version rules", "pep440": "PEP 440 rules",
	"rubygems": "RubyGems version rules", "maven": "Maven version ordering", "nuget": "NuGet version rules",
	"generic": "dotted-number comparison",
}

// Build assembles the explanation. now is used for "2 h ago".
func Build(in Input, now time.Time) Explanation {
	f, ev := in.Finding, in.Evidence
	if ev == nil {
		ev = map[string]any{}
	}
	m, _ := ev["match"].(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	e := Explanation{Fixed: f.FixedVersion, EvidenceState: f.Verification, SecondCheck: in.SecondCheck, Missing: []string{}}
	inv := in.Inventory
	e.Installed = Installed{Version: f.Version, From: versionSource(inv), Collector: inv.CollectorID, Confidence: inv.Confidence,
		ObservedAt: inv.LastSeen}
	if n := str(m, "normalised"); n != "" {
		e.Installed.Compared = n
	}
	if in.Feed != nil {
		e.Source.Feed, e.Source.RefreshedAt, e.Source.Stale = in.Feed.Name, in.Feed.LastSuccess, in.Feed.Stale
	} else {
		e.Source.Feed = firstNonEmpty(str(ev, "feed"), str(ev, "source"))
	}
	if e.Source.Stale || ev["feed_stale"] == true {
		e.Source.Stale = true
	}
	seen := "seen " + ago(inv.LastSeen, now)
	installed := fmt.Sprintf("Installed %s (from %s, %s)", orUnknown(f.Version), e.Installed.From, seen)
	refreshed := "never refreshed"
	if e.Source.RefreshedAt != nil {
		refreshed = "refreshed " + ago(e.Source.RefreshedAt, now)
	}

	if f.Kind == "end_of_life" {
		e.Type = TypeEndOfLife
		lc := &LifecycleDetail{Product: str(ev, "product"), Cycle: str(ev, "cycle"), EOLDate: str(ev, "eol_date"), Latest: str(ev, "latest_in_cycle")}
		e.Lifecycle = lc
		e.Rule.Kind = str(m, "rule")
		switch e.Rule.Kind {
		case "package_name":
			e.Rule.Text = fmt.Sprintf("the package name carries release line %s", lc.Cycle)
		case "exact_cycle":
			e.Rule.Text = fmt.Sprintf("the version is release line %s", lc.Cycle)
		case "version_prefix":
			e.Rule.Text = fmt.Sprintf("release line %s is the longest dotted prefix of the version", lc.Cycle)
		case "windows_build":
			e.Rule.Text = fmt.Sprintf("Windows build %v is release line %s (with the product name and edition telling Server from client)", m["build"], lc.Cycle)
		default:
			e.Rule.Text = fmt.Sprintf("release line %s was matched from the version (stored before 1.0, rule not recorded)", lc.Cycle)
		}
		ended := "is past its end of life"
		if lc.EOLDate != "" {
			ended = "reached end of life on " + lc.EOLDate
		}
		e.Sentence = fmt.Sprintf("%s belongs to %s release line %s, which %s (%s, %s); %s.",
			installed, orUnknown(lc.Product), orUnknown(lc.Cycle), ended, e.Source.Feed, refreshed, e.Rule.Text)
	} else if str(m, "rule") == behindRule {
		e.Type = TypeBehindRelease
		lc := &LifecycleDetail{Product: str(ev, "product"), Cycle: str(ev, "cycle"), Latest: str(ev, "latest_in_cycle")}
		e.Lifecycle = lc
		e.Rule.Kind = behindRule
		e.Rule.Text = fmt.Sprintf("the version is lower than %s, the latest release of release line %s", orUnknown(lc.Latest), orUnknown(lc.Cycle))
		n := fmt.Sprint(ev["releases_behind"])
		if n == "1" {
			n += " release"
		} else {
			n += " releases"
		}
		e.Sentence = fmt.Sprintf("%s is %s behind %s, the latest release of %s release line %s (%s, %s). "+
			"%s point releases on a supported release line are its security and maintenance releases; "+
			"vulnerability (CVE) matching for %s core is not available yet, so the missing releases are reported instead. Update to %s.",
			installed, n, orUnknown(lc.Latest), productName(lc.Product), orUnknown(lc.Cycle), e.Source.Feed, refreshed,
			productName(lc.Product), productName(lc.Product), orUnknown(lc.Latest))
	} else {
		e.Source.Record = str(m, "record")
		e.Source.Ecosystem = str(ev, "target_ecosystem")
		e.Rule.Kind = str(m, "rule")
		e.Rule.Comparator = str(ev, "comparator")
		if str(m, "range_type") == "SEMVER" {
			e.Rule.Comparator = "semver"
		}
		e.Rule.Ambiguous = strs(m["ambiguous"])
		e.Rule.Range = rangeOf(strs(ev["matched_ranges"]), e.Source.Record)
		cmpText := comparatorText[e.Rule.Comparator]
		if cmpText == "" {
			cmpText = orUnknown(e.Rule.Comparator) + " rules"
		}
		record := e.Source.Record
		if record == "" {
			record = strings.Join(f.Sources, ", ")
		}
		var verdict string
		switch e.Rule.Kind {
		case "listed_version":
			e.Rule.Text = "the advisory lists this exact version as affected"
			verdict = fmt.Sprintf("is listed as affected by %s", record)
		case "last_affected":
			e.Rule.Text = fmt.Sprintf("in range %s (up to and including the last affected version), compared with %s", e.Rule.Range, cmpText)
			verdict = fmt.Sprintf("is in the affected range %s (last affected version included) of %s", e.Rule.Range, record)
		case "no_fix_listed":
			e.Rule.Text = fmt.Sprintf("in range %s, which has no fixed version, compared with %s", e.Rule.Range, cmpText)
			verdict = fmt.Sprintf("is in the affected range %s of %s, which lists no fix", e.Rule.Range, record)
		case "range":
			e.Rule.Text = fmt.Sprintf("in range %s, compared with %s", e.Rule.Range, cmpText)
			verdict = fmt.Sprintf("is in the affected range %s of %s", e.Rule.Range, record)
		default:
			e.Rule.Text = fmt.Sprintf("matched ranges %s, compared with %s (stored before 1.0, rule not recorded)",
				strings.Join(strs(ev["matched_ranges"]), "; "), cmpText)
			verdict = fmt.Sprintf("matched %s", record)
		}
		fix := "; no fixed version is listed"
		sub := str(ev, "requires_subscription")
		backport := m["backport"] == true
		fixed := f.FixedVersion
		if kb := str(ev, "kb"); kb != "" && fixed != "" {
			fixed += " (" + kb + ")" // a Windows build and the update that brings it
		}
		switch {
		case f.FixedVersion != "" && sub != "":
			fix = fmt.Sprintf("; fixed in %s, only with %s", fixed, sub)
		case f.FixedVersion != "" && backport:
			fix = fmt.Sprintf("; fixed in %s (the distribution backported the fix to this upstream release)", f.FixedVersion)
		case f.FixedVersion != "":
			fix = "; fixed in " + fixed
		}
		e.Sentence = fmt.Sprintf("%s %s (%s, %s), compared with %s%s.", installed, verdict, e.Source.Feed, refreshed, cmpText, fix)

		purlType := f.ComponentType
		switch {
		case str(ev, "update_line") != "":
			// A Windows host's build against Microsoft's fixed builds.
			e.Type = TypeOSPackage
			e.OS = &OSDetail{Release: str(ev, "update_line"), Subscription: sub}
		case purlType == "deb" || purlType == "rpm" || purlType == "apk":
			e.Type = TypeOSPackage
			e.OS = &OSDetail{Release: str(ev, "target_ecosystem"), SourcePackage: str(ev, "osv_package"), Backport: backport, Subscription: sub}
		default:
			e.Type = TypePackageAdvisory
			e.Package = &PackageDetail{Ecosystem: str(ev, "target_ecosystem"), Name: str(ev, "osv_package"), Direct: f.Direct, Location: f.Location}
		}
	}
	if in.Policy != nil && f.Kind == "vulnerability" && (strings.HasPrefix(f.Key, "CVE-") || f.EPSSCVE != nil) {
		e.EPSS = epssDetail(f, *in.Policy)
	}
	if f.AssetKind == "image" {
		e.Image = &ImageDetail{Image: f.AssetName, Inner: e.Type}
		e.Type = TypeContainerImage
	}

	// Evidence state and what is missing.
	switch f.Verification {
	case "confirmed":
		e.StateText = "Confirmed: the installed version was read from an authoritative source and the rule above matched. " + NotAnExploit
		if f.Kind == "end_of_life" {
			e.StateText = "Confirmed: the installed version was read from an authoritative source and its release line has ended. " +
				"End of life means no more security fixes; it is not a known vulnerability."
		}
		if e.Type == TypeBehindRelease {
			e.StateText = "Confirmed: the installed version was read from an authoritative source and is below its release line's latest release. " +
				"It misses that release's security fixes; which vulnerabilities they fix is not matched."
		}
	case "needs_validation":
		e.StateText = "Needs validation: the match cannot be relied on until the missing information below is resolved."
		if by := inv.Evidence["bundled_with"]; by != "" && inv.Confidence != "confirmed" {
			e.Missing = append(e.Missing, fmt.Sprintf("Whether %s's own copy is affected. %s maintains the copy of %s %s it bundles "+
				"and updates it with its own releases, sometimes patching it without changing its version: check %s's security releases, "+
				"and update %s rather than the library.", by, by, orUnknown(f.ComponentName), orUnknown(f.Version), by, by))
		} else if inv.Confidence != "" && inv.Confidence != "confirmed" {
			how := ""
			if d := inv.Evidence["detected_by"]; d != "" {
				how = " (detected by " + d + ")"
			}
			e.Missing = append(e.Missing, fmt.Sprintf("A confirmed installed version. %s reported %s with confidence %q%s. "+
				"A version read from the package database or a lockfile, for example by the agent on the host, would confirm or clear this finding.",
				orUnknown(inv.CollectorID), orUnknown(f.Version), inv.Confidence, how))
		}
		for _, a := range e.Rule.Ambiguous {
			if a == "version_line_unlisted" {
				e.Missing = append(e.Missing, fmt.Sprintf("Whether the advisory covers this version line. It lists fixes for other lines of %s only, "+
					"and %s is on none of them: check the vendor's advisory for this line, or move to a listed line's fixed version.",
					orUnknown(f.ComponentName), orUnknown(f.Version)))
			}
		}
	case "stale":
		e.StateText = "Stale: this was true when the asset last reported, but nothing has reported it since."
		e.Missing = append(e.Missing, fmt.Sprintf("A fresh report from the asset. It was last seen %s; a new collection (Check again) would confirm or clear this finding.",
			ago(inv.LastSeen, now)))
	case "rejected":
		e.StateText = "Rejected: a person reviewed the evidence and marked this a false positive."
	}
	if sc := in.SecondCheck; sc != nil && sc.Result == store.SecondCheckDisagreed {
		e.NeedsReview = true
		e.StateText = "Needs validation: the second check disagreed (" + sc.Reason + "). " +
			"Priority, SOS and alerts are unchanged, so a real issue is never hidden; a person should compare the installed version with the advisory record. " +
			e.StateText
		e.Missing = append(e.Missing, "Agreement between the matcher and the independent second check, which disagreed: "+sc.Reason+
			". Compare the installed version with the advisory record. The disagreement stands until the match or the record changes.")
	}
	if f.AsOf != nil && f.Verification != "rejected" {
		e.AsOf = f.AsOf
		e.AsOfText = fmt.Sprintf("As of %s: the asset was scanned once, and its results stay as of that scan. "+
			"Nothing more is expected from it, so it is not scored as stale; set up a scheduled scan to keep it current.",
			f.AsOf.UTC().Format("2 Jan 2006"))
		if days := int(now.Sub(*f.AsOf).Hours() / 24); now.Sub(*f.AsOf) >= store.OneOffAging {
			e.AsOfText += fmt.Sprintf(" These results are %d days old.", days)
		}
	}
	if e.Source.Stale && f.Verification != "rejected" {
		e.Missing = append(e.Missing, fmt.Sprintf("A current copy of the source. %s was %s and is stale; a successful refresh would confirm or change this result.",
			orUnknown(e.Source.Feed), refreshed))
	}
	switch sc := in.SecondCheck; {
	case sc == nil && in.Covered:
		e.SecondCheckText = "The independent second check covers this finding and has not run on its current match yet (it runs in the background within minutes)."
	case sc == nil:
		e.SecondCheckText = "Not covered by the independent second check, which re-derives P1, SOS, known exploited, regressed, unconfirmed and ambiguous findings."
	case sc.Result == store.SecondCheckAgreed:
		e.SecondCheckText = "The independent second check re-derived this from the raw advisory record and the raw observed version, and agreed."
	case sc.Result == store.SecondCheckDisagreed:
		e.SecondCheckText = "The independent second check disagreed: " + sc.Reason + "."
	default:
		e.SecondCheckText = "The independent second check could not check this finding: " + sc.Reason + "."
	}
	return e
}

// epssDetail says what FIRST's EPSS predicts for the finding's CVE and
// whether, and why, it counts towards the stored priority.
func epssDetail(f *store.Finding, p risk.Policy) *EPSSDetail {
	cve := f.Key
	if f.EPSSCVE != nil {
		cve = *f.EPSSCVE
	}
	d := &EPSSDetail{CVE: cve, Score: f.EPSS, Percentile: f.EPSSPercentile, Threshold: p.EPSSThreshold,
		Release: p.EPSSThreshold * risk.EPSSRelease, Points: p.EPSS, Counted: hasFactor(f, risk.FactorEPSS)}
	if f.EPSSDate != nil {
		d.Date = f.EPSSDate.Format("2006-01-02")
	}
	if f.EPSSModel != nil {
		d.ModelVersion = *f.EPSSModel
	}
	thr, rel := risk.Percent(d.Threshold), risk.Percent(d.Release)
	if f.EPSS == nil {
		d.Text = fmt.Sprintf("FIRST EPSS has no score for %s yet (new CVEs are usually scored within a few days), so it adds nothing to the priority.", f.Key)
		return d
	}
	pct := ""
	if f.EPSSPercentile != nil {
		pct = fmt.Sprintf(", higher than %s of scored CVEs", risk.Percent(float64(*f.EPSSPercentile)))
	}
	// The score is the highest among the finding's CVEs (its key and its
	// advisories' aliases and upstream ids): name the one it is for.
	which := cve
	switch {
	case cve == f.Key:
	case strings.HasPrefix(f.Key, "CVE-"):
		which = fmt.Sprintf("%s (the highest score among the CVEs this issue's advisories cover; the issue is listed as %s)", cve, f.Key)
	default:
		which = fmt.Sprintf("%s (the highest-scored CVE behind %s)", cve, f.Key)
	}
	text := fmt.Sprintf("FIRST EPSS gives %s a %s chance of exploitation in the next 30 days%s (model %s, scores of %s).",
		which, risk.Percent(float64(*f.EPSS)), pct, orUnknown(d.ModelVersion), orUnknown(d.Date))
	score := *f.EPSS
	switch {
	case d.Counted && p.EPSSCounts(score, false):
		text += fmt.Sprintf(" That is at or above the risk policy's %s threshold, so it adds %.1f points; it keeps them until it falls below %s.", thr, p.EPSS, rel)
	case d.Counted:
		text += fmt.Sprintf(" It crossed the risk policy's %s threshold earlier and is still at %s or more, so it keeps its %.1f points: a small daily change does not move the priority.", thr, rel, p.EPSS)
	case f.KnownExploited:
		text += " It adds nothing: the CVE is in CISA KEV, which already counts exploitation."
	case p.EPSS == 0:
		text += " The risk policy gives EPSS no points."
	case p.EPSSCounts(score, false):
		text += fmt.Sprintf(" That is at or above the risk policy's %s threshold; it adds %.1f points from the next prioritisation, within minutes.", thr, p.EPSS)
	default:
		text += fmt.Sprintf(" That is below the risk policy's %s threshold, so it adds nothing.", thr)
	}
	d.Text = text
	return d
}

func hasFactor(f *store.Finding, name string) bool {
	var fs []risk.Factor
	_ = json.Unmarshal(f.PriorityFactors, &fs)
	for _, x := range fs {
		if x.Name == name {
			return true
		}
	}
	return false
}

// versionSource names where the version came from: the file it was read
// from, else the collector's own words.
func versionSource(inv store.InventoryProvenance) string {
	for _, k := range []string{"lockfile", "lock_path"} {
		if v := inv.Evidence[k]; v != "" {
			return v
		}
	}
	// Front-end libraries a site loads from a CDN or keeps a copy of.
	switch inv.Evidence["source"] {
	case "cdn":
		if u := inv.Evidence["url"]; u != "" {
			return fmt.Sprintf("the CDN address %s in %s", u, orUnknown(inv.Location))
		}
	case "version-file":
		// A CMS's own release file (WordPress's wp-includes/version.php).
		if p := inv.Evidence["product"]; p != "" && inv.Location != "" {
			return p + ", read from " + inv.Location
		}
	case "vendored":
		if inv.Location != "" && inv.Evidence["bundled_with"] != "" {
			return "the version banner of " + inv.Location + ", a copy " + inv.Evidence["bundled_with"] + " maintains"
		} else if inv.Location != "" {
			return "the version banner of " + inv.Location
		}
	}
	if inv.Location != "" {
		return inv.Location
	}
	switch {
	case strings.Contains(inv.CollectorID, "linux"), strings.Contains(inv.CollectorID, "windows"):
		return "the package database, read by the " + inv.CollectorID + " agent"
	case inv.CollectorID != "":
		return "the " + inv.CollectorID + " collector"
	}
	return "an unknown source"
}

func rangeOf(ranges []string, record string) string {
	for _, r := range ranges {
		if id, rest, ok := strings.Cut(r, ": "); ok && (record == "" || id == record) {
			return rest
		}
	}
	if len(ranges) > 0 {
		return ranges[0]
	}
	return "not recorded"
}

// ago says how long ago t was, in the largest whole unit.
func ago(t *time.Time, now time.Time) string {
	if t == nil || t.IsZero() {
		return "never"
	}
	d := now.Sub(*t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%d min ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d h ago", int(math.Round(d.Hours())))
	}
	return fmt.Sprintf("%d d ago", int(d.Hours()/24))
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func strs(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// productName is how a product of a behind finding is named in text:
// WordPress, the only one so far (internal/intel/behind.go).
func productName(product string) string {
	if product == "wordpress" {
		return "WordPress"
	}
	return orUnknown(product)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
