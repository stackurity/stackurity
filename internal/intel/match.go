package intel

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
	"github.com/stackurity/stackurity/internal/version"
)

// Evaluator turns inventory plus intelligence into findings.
type Evaluator struct {
	Store *store.Store
	Now   func() time.Time
}

type EvalStats struct {
	Rows     int   `json:"rows"`
	Opened   int64 `json:"opened_or_updated"`
	Resolved int64 `json:"resolved"`
	Gaps     int   `json:"gaps"`
}

// versionedDeb matches Debian and Ubuntu packages that carry the upstream
// release in their name, which endoflife.date's package identifiers do not
// cover. One package per installation is matched (PHP's -common is always
// installed) so each runtime yields one finding, not one per module.
var versionedDeb = regexp.MustCompile(`^pkg:deb/[^/]+/(php)(\d+\.\d+)-common$|^pkg:deb/[^/]+/(ruby)(\d+\.\d+)$`)

// versionedDebProduct returns the endoflife.date product and release cycle
// named by a versioned distro package, e.g. php7.4-common -> php 7.4.
func versionedDebProduct(purlKey string) (product, cycle string, ok bool) {
	m := versionedDeb.FindStringSubmatch(purlKey)
	switch {
	case m == nil:
		return "", "", false
	case m[1] != "":
		return m[1], m[2], true
	default:
		return m[3], m[4], true
	}
}

// osProducts maps os-release IDs to endoflife.date product names.
var osProducts = map[string]string{
	"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux", "rocky": "rocky-linux",
	"almalinux": "almalinux", "rhel": "rhel", "centos": "centos", "amzn": "amazon-linux",
	"fedora": "fedora", "opensuse-leap": "opensuse", "sles": "sles", "ol": "oracle-linux",
}

// Evaluate re-evaluates the given components (nil means all) or one asset.
func (e *Evaluator) Evaluate(ctx context.Context, componentIDs []int64, assetID int64) (*EvalStats, error) {
	rows, err := e.Store.EvalRows(ctx, componentIDs, assetID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	purlProducts, err := e.Store.LifecycleProductsByPurl(ctx)
	if err != nil {
		return nil, err
	}
	productNames, err := e.Store.LifecycleProductNames(ctx)
	if err != nil {
		return nil, err
	}
	feeds, err := e.Store.ListFeeds(ctx)
	if err != nil {
		return nil, err
	}
	feedState := map[string]store.Feed{}
	for _, f := range feeds {
		feedState[f.Name] = f
	}

	advCache := map[store.PackageRef][]store.AdvisoryMatch{}
	cycleCache := map[string][]store.LifecycleCycle{}
	releaseCache := map[string]bool{}
	var want []store.FindingInput
	coverage := make([]store.RowCoverage, 0, len(rows))
	invIDs := make([]int64, 0, len(rows))
	stats := &EvalStats{Rows: len(rows)}

	for _, r := range rows {
		invIDs = append(invIDs, r.InventoryID)

		// --- vulnerabilities. Every row ends up evaluated, unsupported or
		// not evaluated with a reason; none is left looking clean by default.
		rc := store.RowCoverage{InventoryID: r.InventoryID, State: store.CoverageEvaluated}
		unsupported := func(reason string) { rc.State, rc.Reason = store.CoverageUnsupported, reason }
		notEvaluated := func(reason string) { rc.State, rc.Reason = store.CoverageNotEvaluated, reason }
		t, ok := osv.TargetFor(r.Purl, r.Version, r.Evidence)
		switch {
		case r.Type == "generic" && r.Evidence["kind"] == "operating-system":
			// The OS itself is covered by lifecycle, its packages by the distro feed.
		case r.Type == "generic" && r.Evidence["kind"] == "runtime":
			unsupported("runtime installed outside a package manager: lifecycle is tracked, vulnerabilities are not matched")
		case r.Type == "generic" && r.Evidence["kind"] == "kubernetes":
			unsupported("Kubernetes component reported by the API server: lifecycle is tracked, vulnerabilities are not matched")
		case r.Type == "generic" && r.Evidence["kind"] == "managed-service":
			unsupported("managed service: the provider patches the engine and publishes its own advisories; lifecycle is tracked")
		case !ok:
			if reason, none := osv.WhyNoTarget(r.Purl, r.Version); none {
				unsupported(reason)
			} else {
				notEvaluated(reason)
			}
		default:
			base := osv.BaseEcosystem(t.Ecosystem)
			name := VulnFeed(base)
			feed, configured := feedState[name]
			switch {
			case !configured:
				notEvaluated(fmt.Sprintf("vulnerability feed %s has not been set up yet", name))
			case !feed.Enabled:
				notEvaluated(fmt.Sprintf("vulnerability feed %s is disabled", name))
			case feed.LastSuccess == nil:
				notEvaluated(fmt.Sprintf("vulnerability feed %s has not completed a sync", name))
			}
			if rc.State == store.CoverageEvaluated && feed.Ecosystems != nil {
				covered, seen := releaseCache[t.Ecosystem]
				if !seen {
					covered = coversRelease(feed.Ecosystems, t.Ecosystem)
					releaseCache[t.Ecosystem] = covered
				}
				if !covered {
					notEvaluated(fmt.Sprintf("%s has no advisories for %s: the release is newer than the source's data, no longer covered by it, or not published there",
						name, t.Ecosystem))
				}
			}
			if rc.State != store.CoverageEvaluated {
				break
			}
			key := store.PackageRef{BaseEcosystem: base, Name: t.Name}
			advs, cached := advCache[key]
			if !cached {
				if advs, err = e.Store.AdvisoriesFor(ctx, base, t.Name); err != nil {
					return nil, err
				}
				advCache[key] = advs
			}
			found, perr := matchAdvisories(r, t, advs, feed)
			if perr != "" {
				notEvaluated(perr)
			} else {
				rc.Feed = feed.Name
			}
			want = append(want, found...)
		}
		if rc.State != store.CoverageEvaluated {
			stats.Gaps++
		}
		coverage = append(coverage, rc)

		// --- lifecycle
		product, cycleVersion := "", r.Version
		if r.Type == "generic" && r.Evidence["kind"] == "operating-system" {
			name := strings.TrimPrefix(r.PurlKey, "pkg:generic/")
			product = osProducts[name]
		} else {
			product = purlProducts[strings.ToLower(r.PurlKey)]
			// pkg:generic/<name> where <name> is an endoflife.date product
			// (e.g. amazon-eks, aws-lambda, nginx).
			if name := strings.TrimPrefix(r.PurlKey, "pkg:generic/"); product == "" && r.Type == "generic" && productNames[name] {
				product = name
			}
			if product == "" && r.Type == "deb" {
				if p, cycle, ok := versionedDebProduct(r.PurlKey); ok && productNames[p] {
					product, cycleVersion = p, cycle
				}
			}
		}
		if product == "" {
			continue
		}
		cycles, cached := cycleCache[product]
		if !cached {
			if cycles, err = e.Store.LifecycleCycles(ctx, product); err != nil {
				return nil, err
			}
			cycleCache[product] = cycles
		}
		if c := matchCycle(cycles, cycleVersion); c != nil {
			if f := eolFinding(r, c, now); f != nil {
				want = append(want, *f)
			}
		}
	}
	if err := e.Store.SetCoverage(ctx, coverage); err != nil {
		return nil, err
	}
	if len(invIDs) > 0 {
		opened, resolved, err := e.Store.SyncFindings(ctx, []string{"vulnerability", "end_of_life"}, invIDs, want)
		if err != nil {
			return nil, err
		}
		stats.Opened, stats.Resolved = opened, resolved
	}
	n, err := e.Store.ResolveRemovedFindings(ctx)
	stats.Resolved += n
	return stats, err
}

// coversRelease reports whether a feed holding advisories for ecosystems
// has any for the target's (release-specific) ecosystem. A distro release
// the source has never published for would otherwise match nothing and look
// clean.
func coversRelease(ecosystems []string, target string) bool {
	for _, e := range ecosystems {
		if osv.MatchEcosystem(e, target) {
			return true
		}
	}
	return false
}

type groupMatch struct {
	key        string
	ids        []string
	severity   string
	score      *float32
	title      string
	fixed      string // from the free channel
	proFixed   string // from a paid channel (Ubuntu Pro, SUSE LTSS)
	proChannel string
	ranges     []string
	ecosystems []string
	exploited  bool
	freeHit    bool // a free-channel advisory says the version is affected
	proHit     bool // a Pro advisory says it is affected
}

// matchAdvisories returns findings for one inventory row. perr is non-empty
// when the installed version could not be compared at all.
func matchAdvisories(r store.EvalRow, t osv.Target, advs []store.AdvisoryMatch, feed store.Feed) ([]store.FindingInput, string) {
	groups := map[string]*groupMatch{}
	var order []string
	parseFailures, checked := 0, 0
	cmp := version.For(t.Compare)
	// freeChecked records issues the free channel has evaluated. A Pro-only
	// "affected" verdict is used only when the free channel has nothing to
	// say about that issue, so ESM data never contradicts a free fix.
	freeChecked := map[string]bool{}
	higher := func(cur, v string) string {
		if v == "" {
			return cur
		}
		if cur == "" {
			return v
		}
		if c, err := cmp(v, cur); err == nil && c > 0 {
			return v
		}
		return cur
	}
	for _, a := range advs {
		if a.Withdrawn != nil || !osv.MatchEcosystem(a.Ecosystem, t.Ecosystem) {
			continue
		}
		// Ubuntu's FIPS channels describe FIPS builds only, and a FIPS build
		// takes its fixes from them, never from the regular channels.
		if strings.HasPrefix(t.Ecosystem, "Ubuntu:") && osv.FIPSChannel(a.Ecosystem) != osv.FIPSBuild(t.Version) {
			continue
		}
		channel := osv.SubscriptionFor(a.Ecosystem, t)
		pro := channel != ""
		checked++
		m, err := osv.Check(a.Affected, t)
		if err != nil {
			parseFailures++
			continue
		}
		if !pro {
			freeChecked[a.GroupKey] = true
		}
		if !m.Affected {
			continue
		}
		g := groups[a.GroupKey]
		if g == nil {
			g = &groupMatch{key: a.GroupKey, severity: "unknown"}
			groups[a.GroupKey] = g
			order = append(order, a.GroupKey)
		}
		g.ids = appendUnique(g.ids, a.ID)
		g.ranges = appendUnique(g.ranges, a.ID+": "+m.Range)
		g.ecosystems = appendUnique(g.ecosystems, a.Ecosystem)
		if osv.LevelRank(a.SeverityLevel) > osv.LevelRank(g.severity) {
			g.severity, g.score = a.SeverityLevel, a.SeverityScore
		}
		if g.title == "" && a.Summary != "" {
			g.title = a.Summary
		}
		// The fix to recommend is the highest "first fixed" across sources,
		// so every source agrees the target is fixed.
		if pro {
			g.proHit, g.proFixed = true, higher(g.proFixed, m.FixedVersion)
			if g.proChannel == "" || osv.PreferredSubscription(channel, g.proChannel) {
				g.proChannel = channel
			}
		} else {
			g.freeHit, g.fixed = true, higher(g.fixed, m.FixedVersion)
		}
		g.exploited = g.exploited || a.KnownExploited
	}
	// Keep a group if the free channel says affected, or only Pro has data.
	kept := order[:0]
	for _, k := range order {
		if g := groups[k]; g.freeHit || (g.proHit && !freeChecked[k]) {
			kept = append(kept, k)
		}
	}
	order = kept
	// An installed version the ecosystem's rules cannot read is not
	// evaluated, even when a record matched without comparing (a listed
	// version, an "all versions" range): the other records were not checked.
	perr := ""
	if _, verr := cmp(t.Version, t.Version); checked > 0 && (parseFailures == checked || verr != nil) {
		perr = fmt.Sprintf("installed version %q could not be compared using %s rules", t.Version, t.Compare)
	}
	verification := "confirmed"
	switch {
	case r.AssetStale:
		verification = "stale" // the evidence that it is still installed is old
	case r.Confidence != "confirmed":
		verification = "needs_validation"
	}
	var out []store.FindingInput
	for _, k := range order {
		g := groups[k]
		sev := g.severity
		if verification == "needs_validation" {
			// FR-15: no definitive severity until the version is confirmed.
			sev = "unknown"
		}
		title := g.title
		if title == "" {
			// Distro advisories often have no summary.
			title = g.key + " in " + t.Name
		}
		fixed := g.fixed
		requiresPro := !g.freeHit
		if requiresPro {
			fixed = g.proFixed // only obtainable with a subscription
		}
		ev := map[string]any{
			"matched_ranges":   g.ranges,
			"osv_ecosystems":   g.ecosystems,
			"osv_package":      t.Name,
			"target_ecosystem": t.Ecosystem,
			"installed":        t.Version,
			"comparator":       string(t.Compare),
			"feed":             feed.Name,
			"inventory_conf":   r.Confidence,
			"known_exploited":  g.exploited,
			"advisory_level":   g.severity,
		}
		if feed.LastSuccess != nil {
			ev["feed_last_success"] = feed.LastSuccess.UTC().Format(time.RFC3339)
		}
		if feed.Stale {
			ev["feed_stale"] = true
		}
		if requiresPro {
			ev["requires_subscription"] = g.proChannel
			if g.proChannel == "Ubuntu Pro" {
				ev["requires_ubuntu_pro"] = true
			}
		}
		if pu, err := packageurl.FromString(r.Purl); err == nil && osv.KernelNotRunning(r.Type, pu.Name, r.Version, r.RunningKernel) {
			ev["not_running_kernel"] = true
			ev["running_kernel"] = r.RunningKernel
		}
		sort.Strings(g.ids)
		out = append(out, store.FindingInput{
			Kind: "vulnerability", Key: g.key, InventoryID: r.InventoryID, AssetID: r.AssetID, ComponentID: r.ComponentID,
			Verification: verification, Severity: sev, Score: g.score, Title: title, FixedVersion: fixed,
			Sources: g.ids, Evidence: ev,
		})
	}
	return out, perr
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// matchCycle finds the release cycle for a version: exact, then the longest
// dotted prefix ("3.19.1" -> "3.19" -> "3").
func matchCycle(cycles []store.LifecycleCycle, v string) *store.LifecycleCycle {
	return upgrade.MatchCycle(cycles, v)
}

func eolFinding(r store.EvalRow, c *store.LifecycleCycle, now time.Time) *store.FindingInput {
	ended := c.IsEOL || (c.EOLUntil != nil && !c.EOLUntil.After(now))
	if !ended {
		return nil
	}
	ev := map[string]any{"product": c.Product, "cycle": c.Cycle, "source": FeedEndOfLife, "link": c.Link}
	if c.EOLUntil != nil {
		ev["eol_date"] = c.EOLUntil.Format("2006-01-02")
	}
	if c.Latest != "" {
		ev["latest_in_cycle"] = c.Latest
	}
	verification := "confirmed"
	if r.AssetStale {
		verification = "stale"
	} else if r.Confidence != "confirmed" {
		verification = "needs_validation"
	}
	title := fmt.Sprintf("%s %s is end-of-life", c.ProductLabel, c.Cycle)
	if c.EOLUntil != nil {
		title += " since " + c.EOLUntil.Format("2006-01-02")
	}
	return &store.FindingInput{
		Kind: "end_of_life", Key: c.Product + ":" + c.Cycle, InventoryID: r.InventoryID, AssetID: r.AssetID,
		ComponentID: r.ComponentID, Verification: verification, Severity: "medium", Title: title,
		Sources: []string{FeedEndOfLife}, Evidence: ev,
	}
}

// --- version helpers for release data

func latestStableSemver(versions []string, fallback string) string {
	best := ""
	for _, v := range versions {
		if version.SemverPrerelease(v) {
			continue
		}
		if _, ok := version.ParseSemver(v); !ok {
			continue
		}
		if best == "" {
			best = v
		} else if c, _ := version.CompareSemver(v, best); c > 0 {
			best = v
		}
	}
	if best == "" {
		return fallback
	}
	return best
}

func isStableComposer(v string) bool { return !version.ComposerPrerelease(v) }

func latestComposer(vs []string) string {
	best := ""
	for _, v := range vs {
		if best == "" {
			best = v
			continue
		}
		if c, err := version.CompareComposer(v, best); err == nil && c > 0 {
			best = v
		}
	}
	return best
}
