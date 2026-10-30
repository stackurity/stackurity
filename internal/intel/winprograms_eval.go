package intel

import (
	"context"
	"fmt"
	"sort"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
	"github.com/stackurity/stackurity/internal/winprograms"
)

// isWindowsProgram reports whether a row is an installed program the
// Windows agent read from the registry (an Add/Remove Programs entry).
func isWindowsProgram(r store.EvalRow) bool {
	return r.Type == "generic" && r.Evidence["registry_view"] != "" && r.Evidence["kind"] == ""
}

// programPlan is what the catalogue says about one program row.
type programPlan struct {
	ident   winprograms.Identity
	version string // normalised; "" when verr is set
	verr    error
	// rep is the row a host's findings for this program and version are
	// reported on; the others are the same installation seen twice (the
	// 32- and 64-bit registry views, "7-Zip 24.09" and "7-Zip 24.09 (x64)").
	rep     bool
	repName string
}

// programName is a row's DisplayName (the component name).
func programName(r store.EvalRow) string {
	if n := r.Evidence["display_name"]; n != "" {
		return n
	}
	return purlName(r.Purl)
}

// planPrograms identifies every Windows program row and picks, per host,
// program and version, the row its findings go on: the native registry
// view's, then the lowest inventory id.
func planPrograms(cat *winprograms.Catalogue, rows []store.EvalRow) map[int64]*programPlan {
	plans := map[int64]*programPlan{}
	type key struct {
		asset   int64
		program string
		version string
	}
	groups := map[key][]store.EvalRow{}
	for _, r := range rows {
		if !isWindowsProgram(r) {
			continue
		}
		pp := &programPlan{ident: cat.Identify(programName(r), r.Evidence["publisher"], r.Version)}
		plans[r.InventoryID] = pp
		p := pp.ident.Program
		if p == nil || p.Source == nil {
			continue
		}
		pp.version, pp.verr = p.NormaliseVersion(programName(r), r.Version)
		if pp.verr != nil {
			continue
		}
		k := key{r.AssetID, p.ID, pp.version}
		groups[k] = append(groups[k], r)
	}
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool {
			ni, nj := g[i].Evidence["registry_view"] == "native", g[j].Evidence["registry_view"] == "native"
			if ni != nj {
				return ni
			}
			return g[i].InventoryID < g[j].InventoryID
		})
		for i, r := range g {
			pp := plans[r.InventoryID]
			pp.rep = i == 0
			pp.repName = programName(g[0])
		}
	}
	return plans
}

// withProgramSiblings adds the other Windows program rows of the hosts
// whose program rows are being evaluated, so a program seen in both
// registry views is reported once whichever of its rows changed.
func (e *Evaluator) withProgramSiblings(ctx context.Context, rows []store.EvalRow) ([]store.EvalRow, error) {
	have := map[int64]bool{}
	var assets []int64
	seen := map[int64]bool{}
	for _, r := range rows {
		have[r.InventoryID] = true
		if isWindowsProgram(r) && !seen[r.AssetID] {
			seen[r.AssetID] = true
			assets = append(assets, r.AssetID)
		}
	}
	for _, a := range assets {
		all, err := e.Store.EvalRows(ctx, nil, a)
		if err != nil {
			return nil, err
		}
		for _, r := range all {
			if !have[r.InventoryID] && isWindowsProgram(r) {
				have[r.InventoryID] = true
				rows = append(rows, r)
			}
		}
	}
	return rows, nil
}

// evaluateProgram matches one Windows program row. It sets rc's state and
// reason and returns the findings.
func (e *Evaluator) evaluateProgram(ctx context.Context, r store.EvalRow, pp *programPlan, feeds map[string]store.Feed,
	cache map[string][]store.AdvisoryMatch, rc *store.RowCoverage) ([]store.FindingInput, error) {
	unsupported := func(reason string) { rc.State, rc.Reason = store.CoverageUnsupported, reason }
	notEvaluated := func(reason string) { rc.State, rc.Reason = store.CoverageNotEvaluated, reason }
	p := pp.ident.Program
	feedName, source := FeedWindowsPrograms, "NVD"
	if p != nil && p.Source != nil {
		switch p.Source.Type {
		case winprograms.SourceMSRC:
			feedName, source = FeedMSRC, "Microsoft's Security Update Guide"
		case winprograms.SourceMozilla:
			source = "Mozilla's security advisories"
		}
	}
	feed, configured := feeds[feedName]
	switch {
	case p == nil:
		unsupported(pp.ident.Reason)
		return nil, nil
	case p.Source == nil:
		unsupported(fmt.Sprintf("recognised as %s by the curated catalogue, but not matched: %s", p.Label, p.Unmatched))
		return nil, nil
	case pp.verr != nil:
		notEvaluated(pp.verr.Error() + ", so it is not matched")
		return nil, nil
	case !pp.rep:
		rc.Reason = fmt.Sprintf("the same %s %s as %q (another registry entry): its findings are reported once, there", p.Label, pp.version, pp.repName)
		return nil, nil
	case !configured:
		notEvaluated(fmt.Sprintf("vulnerability feed %s has not been set up yet", feedName))
		return nil, nil
	case !feed.Enabled:
		notEvaluated(fmt.Sprintf("vulnerability feed %s is disabled", feed.Name))
		return nil, nil
	case feed.LastSuccess == nil:
		notEvaluated(fmt.Sprintf("vulnerability feed %s has not completed a sync", feed.Name))
		return nil, nil
	case feed.Ecosystems != nil && !coversRelease(feed.Ecosystems, p.Ecosystem()):
		notEvaluated(fmt.Sprintf("the advisories of %s have not been read from %s yet (feed %s): they are read by the next sync after a host first reports it",
			p.Label, source, feed.Name))
		return nil, nil
	}
	advs, ok := cache[p.ID]
	if !ok {
		var err error
		if advs, err = e.Store.AdvisoriesFor(ctx, winprograms.Ecosystem, p.ID, p.Ecosystem()); err != nil {
			return nil, err
		}
		cache[p.ID] = advs
	}
	t := osv.Target{Ecosystem: p.Ecosystem(), Name: p.ID, Version: pp.version, Compare: version.Generic}
	row := r
	if pp.ident.PublisherMissing && row.Confidence == "confirmed" {
		// Matched by name alone: the findings need validation (their
		// severity is withheld and their priority lowered).
		row.Confidence = "inferred"
		rc.Reason = "matched by name only: the registry entry records no publisher, so its findings need validation"
	}
	found, perr := matchAdvisories(row, t, advs, feed)
	if perr != "" {
		notEvaluated(perr)
		return nil, nil
	}
	rc.Feed = feed.Name
	note := func(s string) {
		if rc.Reason != "" {
			rc.Reason += "; "
		}
		rc.Reason += s
	}
	if n := programsUnfixed(feed.Cursor)[p.ID]; n > 0 && feed.Name == FeedWindowsPrograms {
		cves := fmt.Sprintf("%d CVEs", n)
		if n == 1 {
			cves = "1 CVE"
		}
		note(fmt.Sprintf("NVD also names %s in %s with no fixed version or no version bound, which are not matched", p.Label, cves))
	}
	if p.CoverageNote != "" {
		note(p.CoverageNote)
	}
	for i := range found {
		ev := found[i].Evidence
		ev["program"] = p.ID
		ev["program_label"] = p.Label
		ev["catalogue_version"] = e.catalogue().Version()
		ev["display_name"] = programName(r)
		ev["program_version"] = pp.version
		if line := p.Line(pp.version); line != "" {
			ev["program_line"] = line
		}
		if pp.ident.PublisherMissing {
			ev["publisher_missing"] = true
		}
	}
	return found, nil
}

func (e *Evaluator) catalogue() *winprograms.Catalogue {
	if e.Programs != nil {
		return e.Programs
	}
	return winprograms.Default()
}

// purlName is a purl's decoded name ("Google Chrome").
func purlName(purl string) string {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return ""
	}
	return p.Name
}

// programComponents is what a Windows program sync re-evaluates: every
// Windows program component when the feed's coverage changed, otherwise
// those the catalogue maps to a program whose advisories changed.
func programComponents(ctx context.Context, s *store.Store, res *SyncResult) ([]int64, error) {
	progs, err := s.WindowsPrograms(ctx)
	if err != nil {
		return nil, err
	}
	cat := winprograms.Default()
	seen := map[int64]bool{}
	var out []int64
	for _, p := range progs {
		if seen[p.ComponentID] {
			continue
		}
		id := cat.Identify(p.Name, p.Publisher, p.Version)
		if res.All || (id.Program != nil && res.Packages[store.PackageRef{BaseEcosystem: winprograms.Ecosystem, Name: id.Program.ID}]) {
			seen[p.ComponentID] = true
			out = append(out, p.ComponentID)
		}
	}
	return out, nil
}
