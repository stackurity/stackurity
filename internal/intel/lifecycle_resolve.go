package intel

import (
	"context"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
)

// lifecycleResolver decides which endoflife.date product, and which release
// line of it, an inventory row is: endoflife.date's identifiers, the lifecycle
// overlay (eoloverlay), runtimes and operating systems by name, and versioned
// distro package names.
type lifecycleResolver struct {
	byPurl  map[string]string // endoflife.date purl -> product
	names   map[string]bool   // every endoflife.date product
	overlay *eoloverlay.Overlay
}

func newLifecycleResolver(ctx context.Context, st *store.Store, ov *eoloverlay.Overlay) (*lifecycleResolver, error) {
	byPurl, err := st.LifecycleProductsByPurl(ctx)
	if err != nil {
		return nil, err
	}
	names, err := st.LifecycleProductNames(ctx)
	if err != nil {
		return nil, err
	}
	if ov == nil {
		ov = eoloverlay.Default()
	}
	return &lifecycleResolver{byPurl: byPurl, names: names, overlay: ov}, nil
}

// lifecycleMatch is a row's product and the version its release line is read
// from (the installed version, or the line a package name carries).
type lifecycleMatch struct {
	product, cycleVersion string
	rule                  string // endoflife.date, namespace_family, overlay, name, package_name
}

// resolve maps one row. kind is the row's evidence kind (operating-system,
// runtime, ...) for generic purls.
func (lr *lifecycleResolver) resolve(purlType, purlKey, version, kind string) (lifecycleMatch, bool) {
	if purlType == "generic" && kind == "operating-system" {
		p := osProducts[strings.TrimPrefix(purlKey, "pkg:generic/")]
		return lifecycleMatch{p, version, "name"}, p != ""
	}
	if m, ok := lr.overlay.Product(purlKey, func(k string) string { return lr.byPurl[k] }); ok && lr.names[m.Product] {
		cv := version
		if m.Cycle != "" {
			cv = m.Cycle
		}
		return lifecycleMatch{m.Product, cv, m.Rule}, true
	}
	// pkg:generic/<name> where <name> is an endoflife.date product
	// (e.g. amazon-eks, aws-lambda, nginx).
	if name := strings.TrimPrefix(purlKey, "pkg:generic/"); purlType == "generic" && lr.names[name] {
		return lifecycleMatch{name, version, "name"}, true
	}
	if purlType == "deb" {
		if p, cycle, ok := versionedDebProduct(purlKey); ok && lr.names[p] {
			return lifecycleMatch{p, cycle, "package_name"}, true
		}
	}
	return lifecycleMatch{}, false
}

// thirdPartyRepo names the repository a distro-type package (deb, rpm) was
// built by when it is not the distribution's own build: a vendor-only
// package name or a vendor version pattern from the overlay, or a version
// marker of a known third-party repository. "" when it looks like the
// distribution's own package. The agent does not record the repository a
// package came from, so a third-party build whose name and version look
// like the distribution's is not caught.
func thirdPartyRepo(ov *eoloverlay.Overlay, purlType, purlKey, purl, version string) string {
	if !upgrade.IsDistro(purlType) {
		return ""
	}
	if repo, ok := ov.VendorBuild(purlKey, version); ok {
		return repo
	}
	release := ""
	if pu, err := packageurl.FromString(purl); err == nil {
		_, release = distroProduct(pu.Qualifiers.Map()["distro"])
	}
	if thirdPartyBuild(purlType, version, release) {
		return "another repository"
	}
	return ""
}
