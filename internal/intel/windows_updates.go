package intel

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
	"github.com/stackurity/stackurity/internal/winrelease"
)

// windowsPurlKey is the Windows agent's operating system row.
const windowsPurlKey = "pkg:generic/windows"

// isWindowsOS reports whether a row is a Windows host's operating system.
func isWindowsOS(r store.EvalRow) bool {
	return r.Type == "generic" && r.Evidence["kind"] == "operating-system" && r.PurlKey == windowsPurlKey
}

// ESUChannel names the paid channel that fixes a Windows release after its
// end of support (in finding evidence requires_subscription).
const ESUChannel = "Windows Extended Security Updates"

// windowsCumulativeOnly is how an evaluated Windows row's coverage reads:
// what the build tells, and what it does not.
const windowsCumulativeOnly = "cumulative updates only, from the build number: .NET Framework, Office and servicing stack updates are not evaluated"

// windowsUpdates evaluates a Windows host's build (10.0.<build>.<UBR>)
// against the fixed builds of its update line in Microsoft's Security Update
// Guide (feed msrc:Windows): one finding per CVE fixed in a build above the
// host's, naming the update (KB) that brings that build. cycle is the host's
// endoflife.date release when known, and ended whether it is past its end of
// life: a fix released after that date comes only with paid Extended Security
// Updates.
func (e *Evaluator) windowsUpdates(ctx context.Context, r store.EvalRow, feed store.Feed, configured bool, cycle *store.LifecycleCycle,
	ended bool, cache map[string]*lineUpdates) ([]store.FindingInput, store.RowCoverage, error) {
	rc := store.RowCoverage{InventoryID: r.InventoryID, State: store.CoverageEvaluated}
	tgt, gap := winrelease.UpdateLine(winrelease.Info{Version: r.Version, ProductName: r.Evidence["product_name"],
		EditionID: r.Evidence["edition_id"], DisplayVersion: r.Evidence["display_version"]})
	if gap != nil {
		rc.State, rc.Reason = windowsGapCoverage(gap)
		return nil, rc, nil
	}
	notEvaluated := func(reason string) ([]store.FindingInput, store.RowCoverage, error) {
		rc.State, rc.Reason = store.CoverageNotEvaluated, reason
		return nil, rc, nil
	}
	if why := feedGapReason(FeedMSRC, feed, configured); why != "" {
		return notEvaluated(why)
	}
	eco := "Windows:" + tgt.Line
	if feed.Ecosystems != nil && !coversRelease(feed.Ecosystems, eco) {
		return notEvaluated(fmt.Sprintf("%s has no updates for Windows %s in the months it reads: the release left support before them, "+
			"or is newer than the data", FeedMSRC, tgt.Line))
	}
	lu, ok := cache[tgt.Line]
	if !ok {
		ups, err := e.Store.WindowsUpdates(ctx, tgt.Line)
		if err != nil {
			return nil, rc, err
		}
		lu = newLineUpdates(ups)
		cache[tgt.Line] = lu
	}
	// A host enrolled in hotpatching runs hotpatch builds between quarterly
	// baselines; they are not numbered like cumulative updates, so the
	// comparison would be wrong either way.
	if u, hp := lu.hotpatch[tgt.Version]; hp {
		if _, regular := lu.regular[tgt.Version]; !regular {
			rc.State = store.CoverageUnsupported
			rc.Reason = fmt.Sprintf("build %s is a hotpatch build (KB%s): hotpatched hosts are not evaluated for missing updates", tgt.Version, u.KB)
			return nil, rc, nil
		}
	}
	advs, err := e.Store.AdvisoriesFor(ctx, "Windows", "windows", eco)
	if err != nil {
		return nil, rc, err
	}
	t := osv.Target{Ecosystem: eco, Name: "windows", Version: tgt.Version, Compare: version.Generic}
	found, perr := matchAdvisories(r, t, advs, feed)
	if perr != "" {
		return notEvaluated(perr)
	}
	rc.Feed, rc.Reason = feed.Name, windowsCumulativeOnly
	older := ""
	if len(lu.monthly) > 0 && compareBuild(tgt.Version, lu.monthly[0].Build) < 0 {
		first := lu.monthly[0]
		older = first.Released.Format("2006-01")
		rc.Reason = fmt.Sprintf("build %s is older than the oldest update read (KB%s, %s): only CVEs fixed since then are listed, "+
			"and the latest cumulative update fixes the older ones too; %s", tgt.Version, first.KB, first.Released.Format("January 2006"),
			windowsCumulativeOnly)
	}
	for i := range found {
		f := &found[i]
		f.Evidence["update_line"] = "Windows " + tgt.Line
		f.Evidence["installed_build"] = tgt.Version
		f.Evidence["fixed_build"] = f.FixedVersion
		if older != "" {
			f.Evidence["older_than_data"] = older
		}
		if u, ok := lu.regular[f.FixedVersion]; ok {
			f.Evidence["update_kind"] = u.Kind
			if u.KB != "" {
				f.Evidence["kb"] = "KB" + u.KB
				f.Evidence["kb_url"] = "https://support.microsoft.com/help/" + u.KB
			}
		}
		released, ok := lu.released(f.FixedVersion)
		if !ok {
			continue
		}
		// The Patch Tuesday of the update's month (an out-of-band update is
		// dated by its month).
		f.Evidence["update_released"] = released.Format("2006-01-02")
		if ended && cycle != nil && cycle.EOLUntil != nil && released.After(*cycle.EOLUntil) {
			// Released after the release's end of support: only paid
			// Extended Security Updates bring it, as Ubuntu Pro does for
			// Ubuntu. The action plan upgrades the release instead.
			f.Evidence["requires_subscription"] = ESUChannel
		}
	}
	return found, rc, nil
}

// lineUpdates is what windows_updates says about one update line.
type lineUpdates struct {
	// regular is the update that brings each build: a cumulative update
	// ("Security Update") when a standalone one brings the same build, else
	// the one listed first.
	regular  map[string]store.WindowsUpdate
	hotpatch map[string]store.WindowsUpdate
	// monthly are the Patch Tuesday builds, lowest first, each with the
	// earliest document that has it as its own.
	monthly []store.WindowsUpdate
}

func newLineUpdates(ups []store.WindowsUpdate) *lineUpdates {
	l := &lineUpdates{regular: map[string]store.WindowsUpdate{}, hotpatch: map[string]store.WindowsUpdate{}}
	seen := map[string]bool{}
	for _, u := range ups { // oldest document first
		if u.Hotpatch {
			if _, ok := l.hotpatch[u.Build]; !ok {
				l.hotpatch[u.Build] = u
			}
			continue
		}
		if cur, ok := l.regular[u.Build]; !ok || (cur.Kind != "Security Update" && u.Kind == "Security Update") {
			l.regular[u.Build] = u
		}
		if u.Monthly && !seen[u.Build] {
			seen[u.Build] = true
			l.monthly = append(l.monthly, u)
		}
	}
	sort.SliceStable(l.monthly, func(i, j int) bool { return compareBuild(l.monthly[i].Build, l.monthly[j].Build) < 0 })
	return l
}

// released dates a build: the release of the highest Patch Tuesday build at
// or below it (an out-of-band update comes out after its month's). ok is
// false for a build older than every Patch Tuesday build read.
func (l *lineUpdates) released(build string) (time.Time, bool) {
	var at time.Time
	ok := false
	for _, m := range l.monthly {
		if compareBuild(m.Build, build) > 0 {
			break
		}
		at, ok = m.Released, true
	}
	return at, ok
}

// mergeWindowsCoverage combines the coverage of a Windows row's updates
// (vuln) with its end-of-life gap (lifecycle, "" when its release is known).
// A row whose updates are unsupported stays unsupported, so the coverage-gap
// report counts it; otherwise an unknown end of life makes it not evaluated,
// as before updates were read.
func mergeWindowsCoverage(vuln store.RowCoverage, lifecycle string) store.RowCoverage {
	const eolGap, updGap = "end of life not evaluated: ", "missing updates not evaluated: "
	switch {
	case lifecycle == "":
		return vuln
	case strings.TrimPrefix(lifecycle, eolGap) == strings.TrimPrefix(vuln.Reason, updGap):
		// One cause (an unknown build): said once.
		vuln.Reason = "end of life and missing updates not evaluated: " + strings.TrimPrefix(lifecycle, eolGap)
	case vuln.State == store.CoverageEvaluated:
		vuln.State, vuln.Reason = store.CoverageNotEvaluated, lifecycle+"; missing updates: "+vuln.Reason
	default:
		vuln.Reason = strings.TrimSuffix(vuln.Reason, ".") + "; " + lifecycle
	}
	return vuln
}

// windowsReleaseEnded reports whether a Windows release is past its end of
// life at now.
func windowsReleaseEnded(c *store.LifecycleCycle, now time.Time) bool {
	return c != nil && (c.IsEOL || (c.EOLUntil != nil && !c.EOLUntil.After(now)))
}

// windowsGapCoverage is the coverage of a host whose missing updates are not
// compared.
func windowsGapCoverage(gap *winrelease.UpdateGap) (state, reason string) {
	if gap.Unsupported {
		return store.CoverageUnsupported, gap.Reason
	}
	return store.CoverageNotEvaluated, "missing updates not evaluated: " + gap.Reason
}
