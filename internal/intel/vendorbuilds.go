package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/vendorbuilds"
	"github.com/stackurity/stackurity/internal/version"
)

// FeedVendorBuilds holds advisories for vendor builds of Linux packages
// (nginx.org's nginx, NodeSource's nodejs, PGDG's postgresql-16...): the
// upstream product's NVD records, for the products of the curated vendor
// build catalogue (internal/vendorbuilds) installed on some host. A vendor
// build the catalogue does not list stays a coverage gap.
const FeedVendorBuilds = "nvd:vendor-builds"

// vendorPlan is what the catalogue says about one vendor build row.
type vendorPlan struct {
	product *vendorbuilds.Product
	repo    string // the repository that built it, as thirdPartyRepo names it
	version string // upstream; "" when verr is set
	verr    error
	// rep is the row a host's findings for this product and version are
	// reported on; the others are its other packages (php8.3-cli next to
	// php8.3-common), one installation of the same build.
	rep     bool
	repName string
	rank    int
}

// vendorCandidate reports whether a row is a package the vendor build
// catalogue lists, whoever built it.
func vendorCandidate(cat *vendorbuilds.Catalogue, r store.EvalRow) bool {
	if r.Type != "deb" && r.Type != "rpm" {
		return false
	}
	p, _ := cat.Identify(r.Type, purlName(r.Purl))
	return p != nil
}

// planVendorBuilds identifies every vendor build row the catalogue lists
// and picks, per host, product and upstream version, the row its findings
// go on: the package of the earliest pattern, then the lowest inventory id.
func planVendorBuilds(cat *vendorbuilds.Catalogue, ov *eoloverlay.Overlay, rows []store.EvalRow) map[int64]*vendorPlan {
	plans := map[int64]*vendorPlan{}
	type key struct {
		asset   int64
		product string
		version string
	}
	groups := map[key][]store.EvalRow{}
	for _, r := range rows {
		if r.Type != "deb" && r.Type != "rpm" {
			continue
		}
		p, rank := cat.Identify(r.Type, purlName(r.Purl))
		if p == nil {
			continue
		}
		repo := thirdPartyRepo(ov, r.Type, r.PurlKey, r.Purl, r.Version)
		if repo == "" {
			continue // the distribution's own build: its advisories apply
		}
		vp := &vendorPlan{product: p, repo: repo, rank: rank}
		plans[r.InventoryID] = vp
		vp.version, vp.verr = p.UpstreamVersion(r.Version)
		if vp.verr != nil {
			continue
		}
		k := key{r.AssetID, p.ID, vp.version}
		groups[k] = append(groups[k], r)
	}
	for _, g := range groups {
		sort.Slice(g, func(i, j int) bool {
			ri, rj := plans[g[i].InventoryID].rank, plans[g[j].InventoryID].rank
			if ri != rj {
				return ri < rj
			}
			return g[i].InventoryID < g[j].InventoryID
		})
		for i, r := range g {
			vp := plans[r.InventoryID]
			vp.rep = i == 0
			vp.repName = purlName(g[0].Purl)
		}
	}
	return plans
}

// withVendorSiblings adds the other catalogued package rows of the hosts
// whose catalogued package rows are being evaluated, so a product with
// several packages installed is reported once whichever of them changed.
func (e *Evaluator) withVendorSiblings(ctx context.Context, rows []store.EvalRow) ([]store.EvalRow, error) {
	cat := e.vendorCatalogue()
	have := map[int64]bool{}
	var assets []int64
	seen := map[int64]bool{}
	for _, r := range rows {
		have[r.InventoryID] = true
		if vendorCandidate(cat, r) && !seen[r.AssetID] {
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
			if !have[r.InventoryID] && vendorCandidate(cat, r) {
				have[r.InventoryID] = true
				rows = append(rows, r)
			}
		}
	}
	return rows, nil
}

// vendorUnsupported is the reason on a vendor build the catalogue does not
// read; the store groups it by its "built by <repository>" start
// (store.unsupportedCategorySQL).
func vendorUnsupported(repo, why string) string {
	return fmt.Sprintf("built by %s, not by the distribution: %s", repo, why)
}

// evaluateVendorBuild matches one vendor build row against its product's
// NVD records. It sets rc's state and reason and returns the findings.
func (e *Evaluator) evaluateVendorBuild(ctx context.Context, r store.EvalRow, vp *vendorPlan, feeds map[string]store.Feed,
	cache map[string][]store.AdvisoryMatch, unfixed map[string]int, rc *store.RowCoverage) ([]store.FindingInput, error) {
	notEvaluated := func(reason string) { rc.State, rc.Reason = store.CoverageNotEvaluated, reason }
	p := vp.product
	feed, configured := feeds[FeedVendorBuilds]
	switch {
	case vp.verr != nil:
		// Not the user's to fix: an edition or pre-release the catalogue
		// does not read.
		rc.State, rc.Reason = store.CoverageUnsupported, vendorUnsupported(vp.repo, vp.verr.Error())
		return nil, nil
	case !vp.rep:
		rc.Reason = fmt.Sprintf("the same %s %s build as %s: its findings are reported once, there", p.Label, vp.version, vp.repName)
		return nil, nil
	case feedGapReason(FeedVendorBuilds, feed, configured) != "":
		notEvaluated(feedGapReason(FeedVendorBuilds, feed, configured))
		return nil, nil
	case feed.Ecosystems != nil && !coversRelease(feed.Ecosystems, p.Ecosystem()):
		notEvaluated(programNotReadReason(p.Label, "NVD", feed.Name))
		return nil, nil
	}
	advs, ok := cache[p.ID]
	if !ok {
		var err error
		if advs, err = e.Store.AdvisoriesFor(ctx, vendorbuilds.Ecosystem, p.ID, p.Ecosystem()); err != nil {
			return nil, err
		}
		cache[p.ID] = advs
	}
	if p.SideBySide != "" {
		// Lines installed side by side are fixed each on its own line.
		advs = sameLineOnly(p.Line, p.Line(vp.version), advs)
	}
	t := osv.Target{Ecosystem: p.Ecosystem(), Name: p.ID, Version: vp.version, Compare: version.Generic}
	found, perr := matchAdvisories(r, t, advs, feed)
	if perr != "" {
		notEvaluated(perr)
		return nil, nil
	}
	rc.Feed = feed.Name
	rc.FeedCursor, rc.FeedLastSuccess, rc.FeedRead = feed.Cursor, feed.LastSuccess, true
	notes := []string{fmt.Sprintf("built by %s: matched as %s %s against NVD's records for %s", vp.repo, p.Label, vp.version, p.Label)}
	if n := unfixed[p.ID]; n > 0 {
		cves := fmt.Sprintf("%d CVEs", n)
		if n == 1 {
			cves = "1 CVE"
		}
		notes = append(notes, fmt.Sprintf("NVD also names %s in %s with no fixed version or no version bound, which are not matched", p.Label, cves))
	}
	if p.CoverageNote != "" {
		notes = append(notes, p.CoverageNote)
	}
	rc.Reason = strings.Join(notes, "; ")
	for i := range found {
		ev := found[i].Evidence
		// The action plan groups these as one update per host and line
		// (fixplan ProgramUpdate); "vendor:" keeps the ids apart from the
		// Windows program catalogue's.
		ev["program"] = VendorProgramKey(p.ID)
		ev["program_label"] = p.Label
		ev["program_version"] = vp.version
		if line := p.Line(vp.version); line != "" {
			ev["program_line"] = line
		}
		ev["vendor_build"] = p.ID
		ev["vendor_repository"] = vp.repo
		ev["vendor_catalogue_version"] = e.vendorCatalogue().Version()
	}
	return found, nil
}

// VendorProgramKey is the "program" evidence of a vendor build's findings.
func VendorProgramKey(id string) string { return "vendor:" + id }

func (e *Evaluator) vendorCatalogue() *vendorbuilds.Catalogue {
	if e.Vendors != nil {
		return e.Vendors
	}
	return vendorbuilds.Default()
}

// installedVendorBuilds returns the catalogued products installed as a
// vendor build on any host of the installation (system scope, so one
// workspace's refresh does not narrow what is read for the others).
func installedVendorBuilds(ctx context.Context, st *store.Store) ([]*vendorbuilds.Product, error) {
	cat := vendorbuilds.Default()
	rows, err := st.PackagesNamed(ctx, cat.NamePattern())
	if err != nil {
		return nil, err
	}
	ov := eoloverlay.Default()
	seen := map[string]bool{}
	var out []*vendorbuilds.Product
	for _, r := range rows {
		p, _ := cat.Identify(r.Type, r.Name)
		if p == nil || seen[p.ID] || thirdPartyRepo(ov, r.Type, r.PurlKey, r.Purl, r.Version) == "" {
			continue
		}
		if _, err := p.UpstreamVersion(r.Version); err != nil {
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// syncVendorBuilds reads, for each catalogued product installed as a vendor
// build, every CVE NVD names its CPE products in (full, weekly or after a
// catalogue change), or those modified since the last read.
func (s *Syncer) syncVendorBuilds(ctx context.Context, feed, cursor string) (*SyncResult, string, error) {
	prods, err := installedVendorBuilds(tenant.System(ctx), s.Store)
	if err != nil {
		return nil, "", err
	}
	var cur programsCursor
	if cursor != "" {
		_ = json.Unmarshal([]byte(cursor), &cur) // unusable: read everything
	}
	next := programsCursor{Catalogue: vendorbuilds.Default().Version(), Programs: map[string]programCursor{}}
	for id, c := range cur.Programs {
		next.Programs[id] = c
	}
	res := &SyncResult{Packages: map[store.PackageRef]bool{}, Full: true, Ecosystems: map[string]bool{}}
	var failed []string
	for _, p := range prods {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		now := s.clock()
		pc := next.Programs[p.ID]
		full := pc.Full.IsZero() || now.Sub(pc.Full) >= nvdFullRead || now.Sub(pc.Read) >= nvdIncrMax || cur.Catalogue != next.Catalogue
		unfixed, err := s.syncProgram(ctx, feed, p, full, pc.Read, now, res)
		if err != nil {
			if ctx.Err() != nil {
				return nil, "", ctx.Err()
			}
			s.Log.Warn("vendor build advisories not read", "product", p.ID, "err", err)
			failed = append(failed, p.Label+": "+err.Error())
			continue
		}
		if full {
			pc.Unfixed, pc.Full = unfixed, now
		}
		pc.Read = now
		next.Programs[p.ID] = pc
	}
	if len(prods) > 0 && len(failed) == len(prods) {
		return nil, "", fmt.Errorf("no vendor build's advisories could be read: %s", strings.Join(failed, "; "))
	}
	if len(failed) > 0 {
		res.Warning = fmt.Sprintf("advisories of %d vendor builds could not be read and are kept as last read: %s",
			len(failed), strings.Join(failed, "; "))
	}
	// A product's ecosystem is listed once its advisories have been read
	// completely, so one never read is "not evaluated" rather than clean.
	for id, pc := range next.Programs {
		if !pc.Full.IsZero() {
			res.Ecosystems[vendorbuilds.Ecosystem+":"+id] = true
		}
	}
	b, _ := json.Marshal(next)
	return res, string(b), nil
}

// vendorComponents is what a vendor build sync re-evaluates: every
// catalogued package when the feed's coverage changed, otherwise those of
// the products whose advisories changed.
func vendorComponents(ctx context.Context, st *store.Store, res *SyncResult) ([]int64, error) {
	cat := vendorbuilds.Default()
	rows, err := st.PackagesNamed(ctx, cat.NamePattern())
	if err != nil {
		return nil, err
	}
	seen := map[int64]bool{}
	var out []int64
	for _, r := range rows {
		if seen[r.ComponentID] {
			continue
		}
		p, _ := cat.Identify(r.Type, r.Name)
		if p != nil && (res.All || res.Packages[store.PackageRef{BaseEcosystem: vendorbuilds.Ecosystem, Name: p.ID}]) {
			seen[r.ComponentID] = true
			out = append(out, r.ComponentID)
		}
	}
	return out, nil
}
