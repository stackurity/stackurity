package intel

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
	"github.com/stackurity/stackurity/internal/version"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// Evaluator turns inventory plus intelligence into findings.
type Evaluator struct {
	Store *store.Store
	Now   func() time.Time
	// Overlay is the lifecycle mapping data applied on top of
	// endoflife.date; nil uses the one embedded in the binary.
	Overlay *eoloverlay.Overlay
	// Programs is the Windows program catalogue; nil uses the embedded one.
	Programs *winprograms.Catalogue
	// afterRead, in tests, runs once everything is read and before
	// anything is written.
	afterRead func()
}

type EvalStats struct {
	Rows     int   `json:"rows"`
	Opened   int64 `json:"opened_or_updated"`
	Resolved int64 `json:"resolved"`
	Gaps     int   `json:"gaps"`
}

// versionedPackages match distro packages that carry the upstream release
// in their name, which endoflife.date's package identifiers do not cover
// (its dotnet identifiers name pkg:rpm/redhat/dotnet-sdk-X.Y, a namespace
// the agent never reports). One package per installation is matched (PHP's
// -common is always installed, as is dotnet-runtime-X.Y under the SDK and
// ASP.NET Core runtime) so each runtime yields one finding, not one per
// module.
var versionedPackages = []struct {
	re      *regexp.Regexp // the first group is the release
	product string
}{
	{regexp.MustCompile(`^pkg:deb/[^/]+/php(\d+\.\d+)-common$`), "php"},
	{regexp.MustCompile(`^pkg:deb/[^/]+/ruby(\d+\.\d+)$`), "ruby"},
	// Ubuntu's and Microsoft's deb packages, RHEL's and Microsoft's rpm
	// packages: dotnet-runtime-8.0 is .NET 8 (endoflife.date cycle "8").
	{regexp.MustCompile(`^pkg:(?:deb|rpm)/[^/]+/dotnet-runtime-(\d+\.\d+)$`), "dotnet"},
}

// versionedPackagesPattern is every versionedPackages expression as one
// alternation, for a database regular-expression match (Postgres ~ reads the
// same \d, [^/] and (?:...) syntax).
func versionedPackagesPattern() string {
	res := make([]string, len(versionedPackages))
	for i, p := range versionedPackages {
		res[i] = p.re.String()
	}
	return strings.Join(res, "|")
}

// versionedDebProduct returns the endoflife.date product and release cycle
// named by a versioned distro package, e.g. php7.4-common -> php 7.4,
// dotnet-runtime-8.0 -> dotnet 8.0.
func versionedDebProduct(purlKey string) (product, cycle string, ok bool) {
	for _, p := range versionedPackages {
		if m := p.re.FindStringSubmatch(purlKey); m != nil {
			return p.product, m[1], true
		}
	}
	return "", "", false
}

// osProducts maps os-release IDs to endoflife.date product names.
var osProducts = store.OSProducts

// Evaluate re-evaluates the given components (nil means all) or one asset.
//
// Evaluations of one workspace run one at a time (Store.LockEvaluations):
// one that read the feeds before a sync committed must not write after one
// that read them afterwards, or it would resolve the findings the newer one
// opened, and the next evaluation would open them again. While another
// evaluation runs it returns store.ErrEvaluationBusy without doing anything.
func (e *Evaluator) Evaluate(ctx context.Context, componentIDs []int64, assetID int64) (*EvalStats, error) {
	release, err := e.Store.LockEvaluations(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return e.EvaluateLocked(ctx, componentIDs, assetID)
}

// EvaluateLocked is Evaluate for a caller that holds the workspace's
// evaluation lock (Store.LockEvaluations), to do more under it.
func (e *Evaluator) EvaluateLocked(ctx context.Context, componentIDs []int64, assetID int64) (*EvalStats, error) {
	rows, err := e.Store.EvalRows(ctx, componentIDs, assetID)
	if err != nil {
		return nil, err
	}
	if componentIDs != nil {
		// Kernel packages are reported per kernel version, which needs every
		// package of that version on the asset, not only the changed ones.
		if rows, err = e.withKernelSiblings(ctx, rows); err != nil {
			return nil, err
		}
		// A program seen twice on a host is reported once, on one of its rows.
		if rows, err = e.withProgramSiblings(ctx, rows); err != nil {
			return nil, err
		}
	}
	kernels := planKernels(rows)
	programs := planPrograms(e.catalogue(), rows)
	programAdvs := map[string][]store.AdvisoryMatch{}
	kernelFound := map[string]map[int64][]store.FindingInput{}
	now := time.Now()
	if e.Now != nil {
		now = e.Now()
	}
	ov := e.overlay()
	lifecycle, err := newLifecycleResolver(ctx, e.Store, ov)
	if err != nil {
		return nil, err
	}
	feeds, err := e.Store.ListFeeds(ctx)
	if err != nil {
		return nil, err
	}
	assetOS, err := e.Store.AssetOperatingSystems(ctx)
	if err != nil {
		return nil, err
	}
	feedState := map[string]store.Feed{}
	for _, f := range feeds {
		feedState[f.Name] = f
	}
	// The unfixed counts in the Windows programs feed's cursor, read once.
	programUnfixed := programsUnfixed(feedState[FeedWindowsPrograms].Cursor)

	// A package's advisories are read once and dropped after the last row
	// that needs them, so an evaluation holds the advisories of the packages
	// it is working on rather than of every package it has seen: a full
	// evaluation of a workspace with 8,800 installed rows reached 765 MiB of
	// heap with every package's advisories kept to the end.
	// Entries are read for the row's own ecosystem (release), so the cache
	// is per package and ecosystem.
	type advKey struct {
		pkg       store.PackageRef
		ecosystem string
	}
	advCache := map[advKey][]store.AdvisoryMatch{}
	lastUse := map[advKey]int{}
	for i, r := range rows {
		if t, ok := osv.TargetFor(r.Purl, r.Version, r.Evidence); ok {
			lastUse[advKey{store.PackageRef{BaseEcosystem: osv.BaseEcosystem(t.Ecosystem), Name: t.Name}, t.Ecosystem}] = i
		}
	}
	cycleCache := map[string][]store.LifecycleCycle{}
	updateCache := map[string]*lineUpdates{}
	releaseCache := map[string]bool{}
	var want []store.FindingInput
	coverage := make([]store.RowCoverage, 0, len(rows))
	invIDs := make([]int64, 0, len(rows))
	stats := &EvalStats{Rows: len(rows)}

	for ri, r := range rows {
		invIDs = append(invIDs, r.InventoryID)

		// --- vulnerabilities. Every row ends up evaluated, unsupported or
		// not evaluated with a reason; none is left looking clean by default.
		rc := store.RowCoverage{InventoryID: r.InventoryID, State: store.CoverageEvaluated}
		unsupported := func(reason string) { rc.State, rc.Reason = store.CoverageUnsupported, reason }
		notEvaluated := func(reason string) { rc.State, rc.Reason = store.CoverageNotEvaluated, reason }
		t, ok := osv.TargetFor(r.Purl, r.Version, r.Evidence)
		vendor := thirdPartyRepo(ov, r.Type, r.PurlKey, r.Purl, r.Version)
		switch {
		case isWindowsOS(r):
			// Its build is evaluated against Windows updates below, with
			// its end of life.
		case isWindowsProgram(r):
			// An installed program: matched only if the curated catalogue
			// lists it (internal/winprograms).
			found, err := e.evaluateProgram(ctx, r, programs[r.InventoryID], feedState, programAdvs, programUnfixed, &rc)
			if err != nil {
				return nil, err
			}
			want = append(want, found...)
		case r.Type == "generic" && r.Evidence["kind"] == "operating-system":
			// The OS itself is covered by lifecycle, its packages by the distro feed.
		case r.Type == "generic" && r.Evidence["kind"] == "runtime":
			unsupported("runtime installed outside a package manager: lifecycle is tracked, vulnerabilities are not matched")
		case r.Type == "generic" && r.Evidence["kind"] == "cms":
			// WordPress core: no vulnerability source used here lists it
			// (OSV has no WordPress ecosystem).
			unsupported("content management system core: lifecycle is tracked, vulnerabilities are not matched (no vulnerability source lists it)")
		case r.Type == "generic" && (r.Evidence["kind"] == "wordpress-plugin" || r.Evidence["kind"] == "wordpress-theme"):
			// Their latest release comes from wordpress.org (wporg.go); no
			// vulnerability source is read for them yet.
			unsupported("WordPress plugin or theme: vulnerabilities are not matched yet (the latest release is read from wordpress.org)")
		case r.Type == "generic" && r.Evidence["kind"] == "kubernetes":
			unsupported("Kubernetes component reported by the API server: lifecycle is tracked, vulnerabilities are not matched")
		case r.Type == "generic" && r.Evidence["kind"] == "managed-service":
			unsupported("managed service: the provider patches the engine and publishes its own advisories; lifecycle is tracked")
		case ok && vendor != "":
			// A vendor's build (MongoDB's mongodb-org-server, Docker's
			// docker-ce, PGDG's postgresql-16): the distribution's advisories
			// describe the distribution's own builds and versions, so they
			// would match nothing, or the wrong thing, and look clean.
			unsupported(fmt.Sprintf("built by %s, not by the distribution: the distribution's advisories do not cover it and no other vulnerability source is used for it", vendor))
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
			key := advKey{store.PackageRef{BaseEcosystem: base, Name: t.Name}, t.Ecosystem}
			advs, cached := advCache[key]
			if !cached {
				if advs, err = e.Store.AdvisoriesFor(ctx, base, t.Name, t.Ecosystem); err != nil {
					return nil, err
				}
				advCache[key] = advs
			}
			if lastUse[key] == ri {
				delete(advCache, key)
			}
			found, perr := matchAdvisories(r, t, advs, feed)
			if perr != "" {
				notEvaluated(perr)
			} else {
				rc.Feed = feed.Name
			}
			if k, ok := kernels[r.InventoryID]; ok {
				// Kernel packages: no findings on files that do not run,
				// and one finding per issue per kernel version.
				switch {
				case k.role == osv.KernelNoCode:
					found = nil
					if rc.State == store.CoverageEvaluated {
						rc.Reason = "kernel headers or build files, not running code: kernel vulnerabilities are reported on the kernel image"
					}
				default:
					if kernelFound[k.group] == nil {
						kernelFound[k.group] = map[int64][]store.FindingInput{}
					}
					kernelFound[k.group][r.InventoryID] = found
					found = nil
					if rc.State == store.CoverageEvaluated && r.InventoryID != k.rep.InventoryID {
						rc.Reason = fmt.Sprintf("part of kernel %s: its findings are reported once, on %s", k.release, k.repName)
					}
				}
			}
			want = append(want, found...)
		}
		if rc.State != store.CoverageEvaluated {
			stats.Gaps++
		}
		ci := len(coverage)
		coverage = append(coverage, rc)

		// --- lifecycle
		if isWindowsOS(r) {
			f, gap, cycle, err := e.windowsLifecycle(ctx, r, cycleCache, now)
			if err != nil {
				return nil, err
			}
			msrc, configured := feedState[FeedMSRC]
			found, vc, err := e.windowsUpdates(ctx, r, msrc, configured, cycle, windowsReleaseEnded(cycle, now), updateCache)
			if err != nil {
				return nil, err
			}
			want = append(want, found...)
			// Never left looking supported: a host whose release is
			// unknown has an unknown end of life too.
			coverage[ci] = mergeWindowsCoverage(vc, gap)
			if coverage[ci].State != store.CoverageEvaluated {
				stats.Gaps++
			}
			if f != nil {
				want = append(want, *f)
			}
			continue
		}
		lm, ok := lifecycle.resolve(r.Type, r.PurlKey, r.Version, r.Evidence["kind"])
		if !ok {
			continue
		}
		product, cycleVersion := lm.product, lm.cycleVersion
		cycles, cached := cycleCache[product]
		if !cached {
			if cycles, err = e.Store.LifecycleCycles(ctx, product); err != nil {
				return nil, err
			}
			cycleCache[product] = cycles
		}
		if c := matchCycle(cycles, cycleVersion); c != nil {
			if f := eolFinding(r, c, now); f != nil {
				f.Evidence["match"] = eolMatch(r.Version, cycleVersion, c.Cycle)
				behindEndOfLife(f, r, c)
				if lm.rule == "overlay" || lm.rule == "namespace_family" {
					// Mapped by Stackurity's lifecycle overlay, not by
					// endoflife.date's own identifiers.
					f.Evidence["mapping"] = map[string]any{"rule": lm.rule, "overlay_version": ov.Version()}
				}
				dist, err := e.distroCycle(ctx, r, cycleCache)
				if err != nil {
					return nil, err
				}
				note, keep := distroLifecycle(r, c, dist, assetOS[r.AssetID], vendor, cycleCache, now)
				coverage[ci].Lifecycle = note
				if keep {
					if note != nil {
						f.Evidence["distribution"] = note
					}
					want = append(want, *f)
				}
			} else if coverage[ci].State != store.CoverageEvaluated && lm.cycleVersion == r.Version {
				// A supported branch, behind its latest release, for a product
				// whose point releases are its security fixes (behind.go). Not
				// for an ended branch: its end-of-life finding names the latest
				// release already. Not once a vulnerability source evaluates
				// the row: its findings replace this one.
				if f := behindFinding(r, c); f != nil {
					want = append(want, *f)
				}
			}
		}
	}
	for _, g := range sortedKeys(kernelFound) {
		want = append(want, mergeKernelFindings(kernelFound[g], kernels)...)
	}
	if e.afterRead != nil {
		e.afterRead()
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

func (e *Evaluator) overlay() *eoloverlay.Overlay {
	if e.Overlay != nil {
		return e.Overlay
	}
	return eoloverlay.Default()
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
	// lined: a record matched on a version line it has a fix for;
	// unlisted: one matched only because the version is on none of the
	// lines its advisory lists fixes for (osv.UnlistedLine).
	lined, unlisted bool
	freeHit         bool // a free-channel advisory says the version is affected
	proHit          bool // a Pro advisory says it is affected
	// The record that decided the verdict in each channel: the one whose
	// fixed version is recommended, else the first that matched.
	freeRec, proRec decisive
}

// decisive is one advisory record's verdict, kept for the match explanation.
type decisive struct {
	id    string
	match osv.Match
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
	// freeClear counts free-channel records of an issue that say the
	// version is not affected: if another says it is, the match is ambiguous.
	freeClear := map[string]int{}
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
	fipsBuild := strings.HasPrefix(t.Ecosystem, "Ubuntu:") && osv.FIPSBuild(t.Version)
	// Oracle's Ksplice and FIPS builds (another epoch) are matched against
	// their own channel's records, and a regular build never is. Records of
	// the regular packages apply to every build, as in Oracle's OVAL, but
	// their "not affected" says nothing about a Ksplice or FIPS build.
	oracle := strings.HasPrefix(t.Ecosystem, "Oracle Linux:")
	// Advisories with a fix per version line, one affected entry per line.
	program := strings.HasPrefix(t.Ecosystem, winprograms.Ecosystem+":")
	perLine := oracle || program
	oracleBuild := ""
	if oracle {
		oracleBuild = osv.OracleBuild(t.Version)
	}
	for _, a := range advs {
		if a.Withdrawn != nil || !osv.MatchEcosystem(a.Ecosystem, t.Ecosystem) {
			continue
		}
		recordChannel := ""
		if oracle {
			if recordChannel = osv.OracleChannel(a.Ecosystem); recordChannel != "" && recordChannel != oracleBuild {
				continue
			}
		}
		// Ubuntu's FIPS channels describe FIPS builds only, and a FIPS build
		// takes its fixes from them, never from the regular channels.
		if strings.HasPrefix(t.Ecosystem, "Ubuntu:") && osv.FIPSChannel(a.Ecosystem) != fipsBuild {
			continue
		}
		channel := osv.SubscriptionFor(a.Ecosystem, t)
		pro := channel != ""
		if fipsBuild {
			// For a FIPS build, FIPS-updates plays the part of the free
			// channel: the certified FIPS channel is frozen and lists no fix
			// for most issues, so its "affected" counts only where
			// FIPS-updates has nothing to say. Either way it needs Ubuntu Pro.
			pro = !strings.HasPrefix(a.Ecosystem, "Ubuntu:Pro:FIPS-updates:")
		}
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
			// A record for another version line (or for versions on no
			// listed line) says nothing about this version's line.
			otherLine := perLine && (osv.OtherLine(a.Affected, t) || osv.UnlistedLine(a.Ecosystem, a.Affected) ||
				(program && otherMajor(a.Affected, t.Version)))
			if !pro && recordChannel == oracleBuild && !otherLine {
				freeClear[a.GroupKey]++
			}
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
			prev := g.proFixed
			g.proHit, g.proFixed = true, higher(g.proFixed, m.FixedVersion)
			if g.proRec.id == "" || (g.proFixed != prev && g.proFixed == m.FixedVersion) {
				g.proRec = decisive{a.ID, m}
			}
			if g.proChannel == "" || osv.PreferredSubscription(channel, g.proChannel) {
				g.proChannel = channel
			}
		} else {
			prev := g.fixed
			g.freeHit, g.fixed = true, higher(g.fixed, m.FixedVersion)
			if g.freeRec.id == "" || (g.fixed != prev && g.fixed == m.FixedVersion) {
				g.freeRec = decisive{a.ID, m}
			}
		}
		g.exploited = g.exploited || a.KnownExploited
		if osv.UnlistedLine(a.Ecosystem, a.Affected) {
			g.unlisted = true
		} else {
			g.lined = true
		}
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
		verification := verification
		// Matched only for being on none of the version lines the advisory
		// fixes (an Oracle Cloud Native Environment kubeadm 1.20 against
		// fixes for 1.22, 1.23 and 1.24): it may be affected or never have
		// been, so it needs validation rather than a plain match.
		lineUnlisted := g.unlisted && !g.lined
		if lineUnlisted && verification == "confirmed" {
			verification = "needs_validation"
		}
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
		if fipsBuild {
			requiresPro, g.proChannel = true, "Ubuntu Pro"
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
		rec := g.freeRec
		if requiresPro && g.proRec.id != "" {
			rec = g.proRec
		}
		var ambiguous []string
		if parseFailures > 0 {
			ambiguous = append(ambiguous, "some_records_unreadable")
		}
		if g.freeHit && freeClear[k] > 0 {
			ambiguous = append(ambiguous, "sources_disagree")
		}
		if lineUnlisted {
			ambiguous = append(ambiguous, "version_line_unlisted")
		}
		ev["match"] = matchExplanation(r, t, rec, fixed, ambiguous)
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

// matchExplanation is the compact record of the rule that produced a
// vulnerability finding (evidence "match"), stored at evaluation time so the
// explanation shown later is the rule that really matched, not a
// reconstruction. See internal/why for how it is read.
//
//	rule        range, last_affected, no_fix_listed or listed_version
//	record      the advisory record that decided the verdict
//	range_type  SEMVER when a SEMVER range decided (compared with SemVer
//	            rules whatever the ecosystem); omitted for ECOSYSTEM
//	backport    the fixed version is a distro revision of the installed
//	            upstream release (a backported fix)
//	normalised  the version compared differs from the one reported (a Go
//	            "go" prefix, a gem platform suffix)
//	ambiguous   why a second check is wanted: some_records_unreadable,
//	            sources_disagree, version_normalised, semver_range
func matchExplanation(r store.EvalRow, t osv.Target, rec decisive, fixed string, ambiguous []string) map[string]any {
	m := map[string]any{"record": rec.id}
	switch {
	case rec.match.Exact:
		m["rule"] = "listed_version"
	case strings.Contains(rec.match.Range, "<="):
		m["rule"] = "last_affected"
	case !strings.Contains(rec.match.Range, "<"):
		m["rule"] = "no_fix_listed"
	default:
		m["rule"] = "range"
	}
	if rec.match.RangeType == "SEMVER" && t.Compare != version.SemVer {
		m["range_type"] = "SEMVER"
		ambiguous = append(ambiguous, "semver_range")
	}
	if fixed != "" && distroBackport(t.Compare, t.Version, fixed) {
		m["backport"] = true
	}
	if t.Version != r.Version && r.Version != "" && t.Compare != version.RPM {
		m["normalised"] = t.Version
		ambiguous = append(ambiguous, "version_normalised")
	}
	if len(ambiguous) > 0 {
		m["ambiguous"] = ambiguous
	}
	return m
}

// distroBackport reports whether a distro fixed version keeps the installed
// upstream release and changes only the distro revision: the distribution
// backported the fix instead of moving to the upstream release that has it.
func distroBackport(cmp version.Ecosystem, installed, fixed string) bool {
	upstream := func(v string) string {
		if _, rest, ok := strings.Cut(v, ":"); ok {
			v = rest
		}
		if cmp == version.APK {
			v, _, _ = strings.Cut(v, "-r")
			return v
		}
		if i := strings.LastIndexByte(v, '-'); i > 0 {
			return v[:i]
		}
		return v
	}
	switch cmp {
	case version.Debian, version.RPM, version.APK:
		u := upstream(installed)
		return u != "" && u == upstream(fixed) && installed != fixed
	}
	return false
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

// eolMatch records how the release line was chosen (evidence "match"):
// exact_cycle (the version is the cycle), version_prefix (its longest dotted
// prefix is) or package_name (a versioned distro package such as
// php8.1-common names the line); windows_build is set by windowsLifecycle.
func eolMatch(installed, compared, cycle string) map[string]any {
	switch {
	case compared != installed:
		return map[string]any{"rule": "package_name"}
	case installed == cycle:
		return map[string]any{"rule": "exact_cycle"}
	}
	return map[string]any{"rule": "version_prefix"}
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

// otherMajor reports a Windows program entry that starts on another major
// version than the installed one: a line's fix ([8, 8.0.32) for a .NET 9
// install), whose "not affected" says nothing about the installed line.
func otherMajor(a osv.Affected, installed string) bool {
	m, ok := majorOf(installed)
	if !ok || len(a.Ranges) == 0 {
		return false
	}
	for _, r := range a.Ranges {
		if len(r.Events) == 0 {
			return false
		}
		start, _, _ := strings.Cut(r.Events[0].Introduced, ".")
		if s, err := strconv.Atoi(start); err != nil || s == m {
			return false
		}
	}
	return true
}
