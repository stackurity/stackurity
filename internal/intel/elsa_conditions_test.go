package intel

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// What Oracle's criteria require besides the version: the host's
// architecture, the package's signing key and the enabled module stream.
// The fixture ol8-conditions holds libvirt of virt:ol, built separately per
// architecture, and podman of container-tools:4.0 and container-tools:ol8.

// olRow is an rpm package as an agent reports it.
type olRow struct {
	name, evr, arch string
	ev              map[string]string
}

// olAsset ingests an Oracle Linux host with the given attributes and rows.
func olAsset(t *testing.T, st *store.Store, name, distro string, attrs map[string]string, rows ...olRow) int64 {
	t.Helper()
	var obs []model.Observation
	for _, r := range rows {
		ver := r.evr
		if _, rest, ok := strings.Cut(r.evr, ":"); ok {
			ver = rest
		}
		q := url.Values{"distro": {distro}}
		if r.arch != "" {
			q.Set("arch", r.arch)
		}
		ev := map[string]string{"evr": r.evr}
		for k, v := range r.ev {
			ev[k] = v
		}
		obs = append(obs, confirmed("pkg:rpm/ol/"+r.name+"@"+ver+"?"+q.Encode(), ev))
	}
	b := model.NewBatch(model.Collector{ID: "t-host", Method: "test"},
		model.AssetRef{Kind: model.AssetHost, Name: name, Identifiers: []model.Identifier{{Scheme: "test", Value: name}}, Attributes: attrs})
	b.Observations, b.Complete = obs, true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := st.Ingest(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

// fromAdvisory returns the open findings of a host that an advisory gives.
func fromAdvisory(t *testing.T, st *store.Store, ctx context.Context, host int64, id string) []store.Finding {
	t.Helper()
	var out []store.Finding
	for _, f := range openKeys(t, st, ctx, host) {
		if slices.Contains(f.Sources, id) {
			out = append(out, f)
		}
	}
	return out
}

const (
	virtAdvisory = "OL8-ELSA-2021-4191"
	// libvirt of virt:ol as built for aarch64; the x86_64 build of the same
	// fix has a higher module build number.
	libvirtARM = "0:6.0.0-37.0.1.module+el8.5.0+20363+3abb8f5b"
	libvirtX86 = "0:6.0.0-37.0.1.module+el8.5.0+20365+3abb8f5b"
	// ol8Key signs Oracle Linux 8 packages; epelKey signs EPEL 8's.
	ol8Key  = "82562ea9ad986da3"
	epelKey = "21ea45ab2f86d6a1"
)

func TestParseELSAConditions(t *testing.T) {
	ol8 := parseELSAFixture(t, "ol8-conditions", "8")
	virt := ol8[virtAdvisory]
	if virt == nil {
		t.Fatalf("%s missing: %v", virtAdvisory, keys(ol8))
	}
	// A fix built separately per architecture: one entry each, with its
	// architecture, rather than the higher of the two for both.
	var libvirt []string
	for _, a := range virt.Affected {
		if a.Package.Name == "libvirt" {
			libvirt = append(libvirt, a.Ranges[0].Events[1].Fixed+" "+string(a.EcosystemSpecific))
		}
	}
	slices.Sort(libvirt)
	keys := `"signing_keys":["` + ol8Key + `"]}`
	if !slices.Equal(libvirt, []string{libvirtARM + ` {"arch":["aarch64"],` + keys, libvirtX86 + ` {"arch":["x86_64"],` + keys}) {
		t.Errorf("libvirt entries: %v", libvirt)
	}
	for _, a := range virt.Affected {
		c := osv.OracleConditionsOf(a)
		switch a.Package.Name {
		case "seavgabios-bin", "sgabios":
			// Listed under x86_64 only.
			if !slices.Equal(c.Arch, []string{"x86_64"}) {
				t.Errorf("%s: arch %v, want x86_64 only", a.Package.Name, c.Arch)
			}
		}
	}
	// Every entry names the key Oracle signs Oracle Linux 8 packages with.
	for _, v := range ol8 {
		for _, a := range v.Affected {
			if c := osv.OracleConditionsOf(a); !slices.Equal(c.SigningKeys, []string{ol8Key}) {
				t.Errorf("%s %s: signing keys %v", v.ID, a.Package.Name, c.SigningKeys)
			}
		}
	}
	// A package with the same fix on every architecture records none.
	for _, v := range ol8 {
		for _, a := range v.Affected {
			if a.Package.Name == "podman" && len(osv.OracleConditionsOf(a).Arch) > 0 {
				t.Errorf("%s podman: %s", v.ID, a.EcosystemSpecific)
			}
		}
	}
	// Entries share one stored value per distinct condition.
	var first json.RawMessage
	for _, a := range virt.Affected {
		if string(a.EcosystemSpecific) == `{"arch":["x86_64"],"signing_keys":["`+ol8Key+`"]}` {
			if first == nil {
				first = a.EcosystemSpecific
			} else if &first[0] != &a.EcosystemSpecific[0] {
				t.Errorf("conditions are not shared between entries")
				break
			}
		}
	}
}

func TestOracleArchApplies(t *testing.T) {
	for _, c := range []struct {
		arches []string
		arch   string
		want   bool
	}{
		{nil, "aarch64", true},
		{[]string{"x86_64"}, "x86_64", true},
		{[]string{"x86_64"}, "aarch64", false},
		{[]string{"aarch64"}, "x86_64", false},
		{[]string{"x86_64"}, "i686", true}, // a 32-bit package on a 64-bit host
		{[]string{"aarch64"}, "i686", false},
		{[]string{"aarch64"}, "noarch", true}, // says nothing of the host
		{[]string{"aarch64"}, "", true},       // not reported
	} {
		if got := osv.OracleArchApplies(c.arches, c.arch); got != c.want {
			t.Errorf("OracleArchApplies(%v, %q) = %v, want %v", c.arches, c.arch, got, c.want)
		}
	}
}

func TestOracleLinuxArchitecture(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	arm := olAsset(t, st, "ol8-arm", "ol-8.10", nil, olRow{name: "libvirt", evr: libvirtARM, arch: "aarch64"})
	x86 := olAsset(t, st, "ol8-x86", "ol-8.10", nil, olRow{name: "libvirt", evr: libvirtARM, arch: "x86_64"})
	armOld := olAsset(t, st, "ol8-arm-old", "ol-8.10", nil, olRow{name: "libvirt", evr: "0:6.0.0-35.module+el8.4.0+20100+aaaa", arch: "aarch64"})
	unknown := olAsset(t, st, "ol8-sbom", "ol-8.10", nil, olRow{name: "libvirt", evr: libvirtARM}) // no arch qualifier
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	serveELSA(t, up, map[string]string{"ol8": "ol8-conditions"})
	if _, err := sy.Sync(ctx, FeedOracleLinux); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	// The aarch64 package is at its own architecture's fix: the x86_64
	// build's higher number does not make it affected.
	if got := fromAdvisory(t, st, ctx, arm, virtAdvisory); len(got) != 0 {
		t.Errorf("aarch64 libvirt at the aarch64 fix: %d findings from %s", len(got), virtAdvisory)
	}
	want := func(host int64, fixed, what string) {
		t.Helper()
		got := fromAdvisory(t, st, ctx, host, virtAdvisory)
		if len(got) != 1 || got[0].FixedVersion != fixed || got[0].Verification != "confirmed" {
			t.Errorf("%s: %+v, want one confirmed finding fixed in %s", what, got, fixed)
		}
	}
	want(x86, libvirtX86, "x86_64 libvirt below the x86_64 fix")
	want(armOld, libvirtARM, "aarch64 libvirt below the aarch64 fix")
	// With no architecture reported, every entry applies, as before.
	want(unknown, libvirtX86, "libvirt with no architecture")

	stats, err := (&secondcheck.Runner{Store: st, All: true}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Checked == 0 || stats.Agreed != stats.Checked {
		t.Errorf("second check: %+v", stats)
	}
}

func TestOracleLinuxSigningKey(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	old := "0:6.0.0-35.module+el8.4.0+20100+aaaa" // below both fixes
	host := func(name string, ev map[string]string, evr string) int64 {
		return olAsset(t, st, name, "ol-8.10", nil, olRow{name: "libvirt", evr: evr, arch: "x86_64", ev: ev})
	}
	oracle := host("ol8-oracle", map[string]string{"signing_key": ol8Key}, old)
	unknown := host("ol8-old-agent", nil, old) // an agent that does not report the key
	foreign := host("ol8-foreign", map[string]string{"signing_key": epelKey}, old)
	unsigned := host("ol8-unsigned", map[string]string{"signing_key": "none"}, old)
	foreignFixed := host("ol8-foreign-fixed", map[string]string{"signing_key": epelKey}, libvirtX86)
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	serveELSA(t, up, map[string]string{"ol8": "ol8-conditions"})
	if _, err := sy.Sync(ctx, FeedOracleLinux); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	one := func(host int64, what string) store.Finding {
		t.Helper()
		got := fromAdvisory(t, st, ctx, host, virtAdvisory)
		if len(got) != 1 || got[0].FixedVersion != libvirtX86 {
			t.Fatalf("%s: %+v, want one finding fixed in %s", what, got, libvirtX86)
		}
		return got[0]
	}
	// Oracle's build, or a key not reported: as before.
	for _, h := range []int64{oracle, unknown} {
		if f := one(h, "Oracle's libvirt"); f.Verification != "confirmed" || f.Severity == "unknown" || strings.Contains(string(f.Evidence), "signing_key") {
			t.Errorf("host %d: %s %s %s", h, f.Verification, f.Severity, f.Evidence)
		}
	}
	// Another vendor's build, or an unsigned one: still reported, as
	// needing validation, with the keys, never confirmed or dropped.
	for h, key := range map[int64]string{foreign: epelKey, unsigned: "none"} {
		f := one(h, "libvirt not signed by Oracle")
		var e map[string]any
		_ = json.Unmarshal(f.Evidence, &e)
		m, _ := e["match"].(map[string]any)
		if f.Verification != "needs_validation" || f.Severity != "unknown" || e["signing_key"] != key ||
			!slices.Equal(strs(e["advisory_signing_keys"]), []string{ol8Key}) || !slices.Contains(strs(m["ambiguous"]), "signing_key_mismatch") {
			t.Errorf("host %d: %s %s %s", h, f.Verification, f.Severity, f.Evidence)
		}
	}
	// The row says why, also when nothing matched.
	reason := func(host int64) string {
		rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: host, Page: store.Page{Limit: 10}})
		if err != nil || len(rows) != 1 {
			t.Fatalf("inventory of %d: %v %v", host, rows, err)
		}
		if rows[0].Coverage != store.CoverageEvaluated {
			t.Errorf("host %d: coverage %s", host, rows[0].Coverage)
		}
		return rows[0].CoverageReason
	}
	if got := reason(foreignFixed); len(fromAdvisory(t, st, ctx, foreignFixed, virtAdvisory)) != 0 ||
		!strings.Contains(got, "signed with key "+epelKey+", not Oracle's ("+ol8Key+")") {
		t.Errorf("foreign build at the fix: reason %q", got)
	}
	if got := reason(unsigned); !strings.Contains(got, "is not signed") {
		t.Errorf("unsigned build: reason %q", got)
	}
	if got := reason(oracle); got != "" {
		t.Errorf("Oracle's build: reason %q", got)
	}
	stats, err := (&secondcheck.Runner{Store: st, All: true}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Checked != 4 || stats.Agreed != stats.Checked {
		t.Errorf("second check: %+v", stats)
	}
}

func strs(v any) []string {
	xs, _ := v.([]any)
	var out []string
	for _, x := range xs {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
