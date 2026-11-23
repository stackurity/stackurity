package intel

import (
	"context"
	"fmt"
	"sort"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/vendorbuilds"
)

// Runtimes the agent finds outside a package manager (pkg:generic/<name>,
// evidence kind "runtime") are, for the products the vendor build catalogue
// lists with a runtime name (nginx), the upstream release they print: a
// source build in /usr/local/nginx, the nginx an ingress controller's image
// compiles in, a Homebrew keg. They are matched against the same NVD records
// as the vendor's packages (FeedVendorBuilds). Other runtimes keep lifecycle
// only.

// runtimeNotMatched starts every reason a catalogued runtime is not matched
// with, so the coverage-gap report keeps it under "runtime"
// (store.unsupportedCategorySQL).
const runtimeNotMatched = "runtime installed outside a package manager"

// editionLabels names the editions the agent reports for builds of a
// runtime that are not the catalogued one.
var editionLabels = map[string]string{
	"nginx-plus": "NGINX Plus",
	"openresty":  "OpenResty",
	"tengine":    "Tengine",
	"angie":      "Angie",
}

// runtimePlan returns the plan for a generic runtime row the catalogue
// matches, or, when the catalogue lists the runtime but this row cannot be
// matched, the reason; nil and "" for a runtime the catalogue does not list.
func runtimePlan(cat *vendorbuilds.Catalogue, r store.EvalRow) (*vendorPlan, string) {
	if r.Type != "generic" || r.Evidence["kind"] != "runtime" {
		return nil, ""
	}
	p := cat.ForRuntime(purlName(r.Purl))
	if p == nil {
		return nil, ""
	}
	install := r.Evidence["install"]
	switch install {
	case "homebrew":
		// Homebrew's formula builds the upstream release, open-source edition.
	case "unmanaged", "":
		install = "unmanaged"
		switch ed := r.Evidence["edition"]; {
		case ed == p.RuntimeEdition:
		case ed == "":
			return nil, fmt.Sprintf("%s: this agent did not say whether this %s is %s's %s edition or another build of it, so its vulnerabilities are not matched; upgrade the agent to check it",
				runtimeNotMatched, p.Label, p.Label, p.RuntimeEdition)
		default:
			label := editionLabels[ed]
			if label == "" {
				label = ed
			}
			return nil, fmt.Sprintf("%s: %s is %s, a build of %s with releases and advisories of its own; its vulnerabilities are not matched (lifecycle is tracked)",
				runtimeNotMatched, p.Label, label, p.Label)
		}
	default:
		return nil, ""
	}
	vp := &vendorPlan{product: p, install: install, binary: r.Evidence["binary"], rep: true}
	if v, ok := p.SourceVersion(r.Version); ok {
		vp.version = v
	} else {
		vp.verr = fmt.Errorf("the version %q of %s is not a release version, so it cannot be matched", r.Version, p.Label)
	}
	return vp, ""
}

// RuntimeProgramKey is the "program" evidence of the findings of a runtime
// matched through the vendor build catalogue.
func RuntimeProgramKey(id string) string { return "runtime:" + id }

// installedRuntimeBuilds returns the catalogued products installed as a
// runtime outside a package manager anywhere in the installation.
func installedRuntimeBuilds(ctx context.Context, st *store.Store) ([]*vendorbuilds.Product, error) {
	var out []*vendorbuilds.Product
	for _, p := range vendorbuilds.Default().Products() {
		if p.Runtime == "" {
			continue
		}
		ids, err := st.ComponentsWithPurlKey(ctx, "pkg:generic/"+p.Runtime)
		if err != nil {
			return nil, err
		}
		if len(ids) > 0 {
			out = append(out, p)
		}
	}
	return out, nil
}

// runtimeBuildComponents is what a vendor build sync re-evaluates of the
// runtimes it covers.
func runtimeBuildComponents(ctx context.Context, st *store.Store, res *SyncResult) ([]int64, error) {
	var out []int64
	for _, p := range vendorbuilds.Default().Products() {
		if p.Runtime == "" || !(res.All || res.Packages[store.PackageRef{BaseEcosystem: vendorbuilds.Ecosystem, Name: p.ID}]) {
			continue
		}
		ids, err := st.ComponentsWithPurlKey(ctx, "pkg:generic/"+p.Runtime)
		if err != nil {
			return nil, err
		}
		out = append(out, ids...)
	}
	return out, nil
}

// mergeProducts adds b's products to a, once each, sorted by id.
func mergeProducts(a, b []*vendorbuilds.Product) []*vendorbuilds.Product {
	seen := map[string]bool{}
	var out []*vendorbuilds.Product
	for _, p := range append(append([]*vendorbuilds.Product(nil), a...), b...) {
		if !seen[p.ID] {
			seen[p.ID] = true
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
