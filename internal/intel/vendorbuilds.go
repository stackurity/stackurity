package intel

import (
	"context"
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
	// install is set for a runtime found outside a package manager
	// (runtimebuilds.go): "unmanaged" or "homebrew"; repo is "" then.
	install string
	binary  string // the runtime's binary, when the agent said
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
	case vp.verr != nil && vp.install != "":
		rc.State, rc.Reason = store.CoverageUnsupported, runtimeNotMatched+": "+vp.verr.Error()
		return nil, nil
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
	var notes []string
	switch vp.install {
	case "":
		notes = append(notes, fmt.Sprintf("built by %s: matched as %s %s against NVD's records for %s", vp.repo, p.Label, vp.version, p.Label))
	case "homebrew":
		notes = append(notes, fmt.Sprintf("installed by Homebrew, which builds the upstream release: matched as %s %s against NVD's records for %s", p.Label, vp.version, p.Label))
	default:
		where := ""
		if vp.binary != "" {
			where = " (" + vp.binary + ")"
		}
		notes = append(notes, fmt.Sprintf("installed outside a package manager%s: matched as %s %s, the release it reports, against NVD's records for %s; a build with fixes patched in by hand still matches its release", where, p.Label, vp.version, p.Label))
	}
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
		if vp.install != "" {
			ev["program"] = RuntimeProgramKey(p.ID)
		}
		ev["program_label"] = p.Label
		ev["program_version"] = vp.version
		if line := p.Line(vp.version); line != "" {
			ev["program_line"] = line
		}
		ev["vendor_build"] = p.ID
		if vp.install != "" {
			ev["runtime_install"] = vp.install
		} else {
			ev["vendor_repository"] = vp.repo
		}
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
	rt, err := installedRuntimeBuilds(ctx, st)
	if err != nil {
		return nil, err
	}
	// Read for the website check too (SiteCheckProducts), installed or not.
	return mergeProducts(mergeProducts(out, rt), siteCheckVendorBuilds()), nil
}

// syncVendorBuilds reads, for each catalogued product installed as a vendor
// build, every CVE NVD names its CPE products in (full, weekly or after a
// catalogue change), or those modified since the last read.
func (s *Syncer) syncVendorBuilds(ctx context.Context, feed, cursor string) (*SyncResult, string, error) {
	prods, err := installedVendorBuilds(tenant.System(ctx), s.Store)
	if err != nil {
		return nil, "", err
	}
	items := make([]nvdCatalogueProduct, len(prods))
	for i, p := range prods {
		items[i] = nvdCatalogueProduct{ID: p.ID, Label: p.Label, Product: p}
	}
	return s.syncNVDCatalogue(ctx, feed, cursor, nvdCatalogueKind{
		Ecosystem: vendorbuilds.Ecosystem, Catalogue: vendorbuilds.Default().Version(),
		LogMsg: "vendor build advisories not read", One: "vendor build", Many: "vendor builds",
	}, items)
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
	rt, err := runtimeBuildComponents(ctx, st, res)
	if err != nil {
		return nil, err
	}
	for _, id := range rt {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}
