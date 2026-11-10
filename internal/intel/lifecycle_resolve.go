package intel

import (
	"context"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/lifecycle"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
)

// lifecycleResolver wraps lifecycle.Resolver (shared with the standalone
// scanner) with the catalogue the store holds.
type lifecycleResolver struct{ r lifecycle.Resolver }

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
	return &lifecycleResolver{lifecycle.Resolver{ByPurl: byPurl, Names: names, Overlay: ov}}, nil
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
	m, ok := lr.r.Resolve(purlType, purlKey, version, kind)
	return lifecycleMatch{m.Product, m.CycleVersion, m.Rule}, ok
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
