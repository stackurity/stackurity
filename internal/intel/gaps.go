package intel

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// GapReport is what Stackurity cannot check across the whole installation,
// for instance administrators: files nothing reads, components no
// vulnerability source covers, and products without lifecycle data. It holds
// counts and type names only (file kinds, package types, repository and
// product names), never workspace or asset names, paths or package lists.
type GapReport struct {
	CheckedAt  time.Time `json:"checked_at"`
	Workspaces int64     `json:"workspaces"` // active workspaces in the installation
	Assets     int64     `json:"assets"`     // current assets in them
	// OverlayVersion is the lifecycle overlay the lifecycle counts used.
	OverlayVersion string `json:"overlay_version"`
	// UnreadFiles are files a scan found that no built-in reader or
	// installed stack pack reads, by file kind.
	UnreadFiles []Gap `json:"unread_files"`
	// NoVulnerabilitySource are components with no vulnerability source
	// (coverage unsupported), by package type and reason.
	NoVulnerabilitySource []Gap `json:"no_vulnerability_source"`
	// NoLifecycle are products Stackurity recognises but cannot give an
	// end-of-life date: no lifecycle source tracks them, the installed
	// release line is not in the data, or a runtime or operating system has
	// no lifecycle product.
	NoLifecycle []Gap `json:"no_lifecycle"`
}

// Gap is one kind of gap.
type Gap struct {
	// Kind is stable for machines: "hex:mix.lock", "deb|vendor_build|<repository>",
	// "untracked|NestJS", "no_release_line|elasticsearch", "no_product|<name>".
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Detail string `json:"detail,omitempty"`
	Assets int64  `json:"assets"`
	// Workspaces counts the workspaces those assets are in.
	Workspaces int64 `json:"workspaces"`
	// Components counts distinct components (no_vulnerability_source only).
	Components int64 `json:"components,omitempty"`
}

// unreadKinds names the file kinds of the coverage scopes the scanners write
// for files they recognise but cannot read.
var unreadKinds = map[string][2]string{
	"npm:bun.lockb":          {"bun.lockb", "Bun's binary lockfile"},
	"npm:bun.lock":           {"bun.lock", "Bun's text lockfile"},
	"npm:deno.lock":          {"deno.lock", "Deno"},
	"maven:pom.xml":          {"pom.xml", "Maven, without the Java stack pack"},
	"maven:gradle.lockfile":  {"gradle.lockfile", "Gradle, without the Java stack pack"},
	"maven:build.gradle":     {"build.gradle", "Gradle, without the Java stack pack"},
	"maven:build.gradle.kts": {"build.gradle.kts", "Gradle, without the Java stack pack"},
	"maven:build.sbt":        {"build.sbt", "sbt (Scala)"},
	"hex:mix.lock":           {"mix.lock", "Elixir (Hex)"},
	"hex:rebar.lock":         {"rebar.lock", "Erlang (Hex)"},
	"cargo:Cargo.lock":       {"Cargo.lock", "Rust, without the Cargo stack pack"},
	"swift:Package.resolved": {"Package.resolved", "Swift Package Manager"},
	"swift:Package.swift":    {"Package.swift", "Swift Package Manager"},
	"cocoapods:Podfile.lock": {"Podfile.lock", "CocoaPods"},
	"conan:conanfile.txt":    {"conanfile.txt", "Conan (C/C++)"},
	"conan:conanfile.py":     {"conanfile.py", "Conan (C/C++)"},
	"conan:conan.lock":       {"conan.lock", "Conan (C/C++)"},
	"vcpkg:vcpkg.json":       {"vcpkg.json", "vcpkg (C/C++)"},
	"pypi:uv.lock":           {"uv.lock", "uv (Python)"},
	"pypi:pdm.lock":          {"pdm.lock", "PDM (Python)"},
	"nuget:packages.config":  {"packages.config", "NuGet, legacy format"},
	"os-packages":            {"no package database", "a host with no dpkg, rpm or apk database"},
	"windows:hotfixes":       {"Windows updates (KBs)", "installed Windows updates are not inventoried"},
	"windows:store-apps":     {"Microsoft Store apps", "AppX packages are not inventoried"},
	"other":                  {"other", "other scopes reported as unsupported"},
}

// UnreadKinds are the file kinds the report names: those the lockfile scan
// recognises but cannot read, and the fixed unsupported scopes of the host
// collectors. Scopes of any other kind are counted as "other".
func UnreadKinds() []string {
	out := append(lockfile.UnsupportedKinds(), "os-packages", "windows:hotfixes", "windows:store-apps")
	sort.Strings(out)
	return out
}

func unreadLabel(kind string) (label, detail string) {
	if n, ok := unreadKinds[kind]; ok {
		return n[0], n[1]
	}
	_, file, _ := strings.Cut(kind, ":")
	return file, ""
}

var vulnReasons = map[string]string{
	"vendor_build":    "built by a vendor's repository; the distribution's advisories do not cover it",
	"runtime":         "runtime installed outside a package manager (lifecycle only)",
	"kubernetes":      "Kubernetes component version (lifecycle only)",
	"managed_service": "managed service version (lifecycle only)",
	"distribution":    "distribution without a vulnerability source",
	"ecosystem":       "package type without a vulnerability source",
	"other":           "other",
}

// CoverageGaps builds the report across every active workspace. It reads in
// system scope; callers must be instance administrators.
func CoverageGaps(ctx context.Context, st *store.Store, ov *eoloverlay.Overlay) (*GapReport, error) {
	ctx = tenant.System(ctx)
	if ov == nil {
		ov = eoloverlay.Default()
	}
	now, err := st.DBNow(ctx)
	if err != nil {
		return nil, err
	}
	r := &GapReport{CheckedAt: now, OverlayVersion: ov.Version(), UnreadFiles: []Gap{}, NoVulnerabilitySource: []Gap{}, NoLifecycle: []Gap{}}
	if r.Workspaces, r.Assets, err = st.GapTotals(ctx); err != nil {
		return nil, err
	}

	files, err := st.UnreadFileGaps(ctx, UnreadKinds())
	if err != nil {
		return nil, err
	}
	for _, g := range files {
		label, detail := unreadLabel(g.Kind)
		r.UnreadFiles = append(r.UnreadFiles, Gap{Kind: g.Kind, Label: label, Detail: detail, Assets: g.Assets, Workspaces: g.Workspaces})
	}

	vulns, err := st.VulnerabilitySourceGaps(ctx)
	if err != nil {
		return nil, err
	}
	for _, g := range vulns {
		parts := strings.SplitN(g.Kind, "|", 3)
		typ, cat := parts[0], parts[1]
		gap := Gap{Kind: g.Kind, Label: typ + " packages", Detail: vulnReasons[cat], Assets: g.Assets, Workspaces: g.Workspaces, Components: g.Components}
		if cat == "vendor_build" && len(parts) == 3 {
			gap.Detail = "built by " + parts[2] + "; the distribution's advisories do not cover it"
		}
		r.NoVulnerabilitySource = append(r.NoVulnerabilitySource, gap)
	}

	if r.NoLifecycle, err = lifecycleGaps(ctx, st, ov); err != nil {
		return nil, err
	}
	return r, nil
}

func lifecycleGaps(ctx context.Context, st *store.Store, ov *eoloverlay.Overlay) ([]Gap, error) {
	lr, err := newLifecycleResolver(ctx, st, ov)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(lr.byPurl))
	for k := range lr.byPurl {
		keys = append(keys, k)
	}
	keys = append(keys, ov.FamilyKeys(keys)...)
	cands, err := st.LifecycleCandidates(ctx, keys, ov.LikePatterns(), versionedPackagesPattern())
	if err != nil {
		return nil, err
	}
	type bucket struct {
		gap               Gap
		assets, workspace map[int64]bool
	}
	buckets := map[string]*bucket{}
	add := func(kind, label, detail string, c store.LifecycleCandidate) {
		b := buckets[kind]
		if b == nil {
			b = &bucket{gap: Gap{Kind: kind, Label: label, Detail: detail}, assets: map[int64]bool{}, workspace: map[int64]bool{}}
			buckets[kind] = b
		}
		for _, id := range c.Assets {
			b.assets[id] = true
		}
		for _, id := range c.Workspaces {
			b.workspace[id] = true
		}
	}
	cycles := map[string][]store.LifecycleCycle{}
	labels := map[string]string{}
	for _, c := range cands {
		if label, ok := ov.Untracked(c.PurlKey); ok {
			add("untracked|"+label, label, "no lifecycle source tracks it", c)
			continue
		}
		m, ok := lr.resolve(c.Type, c.PurlKey, c.Version, c.Kind)
		if !ok {
			if c.Type == "generic" && c.PurlKey == "pkg:generic/windows" {
				// Windows is evaluated by its build number (windowsLifecycle),
				// not through an endoflife.date product of osProducts.
				continue
			}
			if c.Type == "generic" {
				// Names of runtimes, operating systems, clusters and managed
				// services come from Stackurity's own collectors.
				name := strings.TrimPrefix(c.PurlKey, "pkg:generic/")
				add("no_product|"+name, name, strings.ReplaceAll(c.Kind, "-", " ")+" with no lifecycle product", c)
			}
			continue
		}
		cs, cached := cycles[m.product]
		if !cached {
			if cs, err = st.LifecycleCycles(ctx, m.product); err != nil {
				return nil, err
			}
			cycles[m.product] = cs
			if len(cs) > 0 {
				labels[m.product] = cs[0].ProductLabel
			}
		}
		if matchCycle(cs, m.cycleVersion) == nil {
			label := labels[m.product]
			if label == "" {
				label = m.product
			}
			add("no_release_line|"+m.product, label, "the installed release line is not in the lifecycle data", c)
		}
	}
	out := make([]Gap, 0, len(buckets))
	for _, b := range buckets {
		b.gap.Assets, b.gap.Workspaces = int64(len(b.assets)), int64(len(b.workspace))
		out = append(out, b.gap)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Assets != out[j].Assets {
			return out[i].Assets > out[j].Assets
		}
		return out[i].Kind < out[j].Kind
	})
	return out, nil
}
