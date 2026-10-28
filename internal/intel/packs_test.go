package intel

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/packs"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// loadPackSource compiles an official pack from its sources to WebAssembly
// and loads it unsigned, as pack development does: the official archives
// are signed by hand by the maintainers.
func loadPackSource(t *testing.T, id string) *packs.Loaded {
	t.Helper()
	dir := filepath.Join("..", "..", "packs", id)
	manifest, err := os.ReadFile(filepath.Join(dir, "pack.json"))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), id+".wasm")
	cmd := exec.Command("go", "build", "-o", out, "./"+filepath.ToSlash(dir))
	cmd.Env = append(os.Environ(), "GOOS=wasip1", "GOARCH=wasm", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", id, err, b)
	}
	wasm, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	data, err := (&packs.Archive{ManifestRaw: manifest, Wasm: wasm}).Bytes()
	if err != nil {
		t.Fatal(err)
	}
	a, err := packs.ReadArchive(data)
	if err != nil {
		t.Fatal(err)
	}
	l, err := packs.Load(context.Background(), a, packs.TrustUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close(context.Background()) })
	return l
}

// TestPacksEndToEnd runs the Swift, Hex and C/C++ packs in the sandbox on
// real lock files (packs/*/testdata), stores what they report, syncs OSV
// records from the matching corpus and evaluates: a known-vulnerable
// version in a real lock file becomes a finding, and libraries with no
// vulnerability source are inventoried and say so.
func TestPacksEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles three packs")
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)

	scan := func(id, fixture string) []model.Observation {
		l := loadPackSource(t, id)
		obs, cov, err := lockfile.ScanWith(ctx, os.DirFS(filepath.Join("..", "..", "packs", id, "testdata", fixture)), []lockfile.Extension{l})
		if err != nil {
			t.Fatal(err)
		}
		if len(obs) == 0 || len(cov) == 0 || !strings.HasPrefix(cov[0].Scope, "pack:"+id+":") {
			t.Fatalf("%s/%s: %d packages, coverage %+v", id, fixture, len(obs), cov)
		}
		for _, o := range obs {
			if o.Evidence["pack"] != id+"@1.0.0" {
				t.Fatalf("%s: pack evidence %v", o.Purl, o.Evidence)
			}
		}
		return obs
	}
	swift := ingest(t, st, model.AssetRepository, "penny-bot", true, scan("swift", "penny-bot-v1")...)
	hex := ingest(t, st, model.AssetRepository, "phoenix", true, scan("hex", "phoenix-1.2.1")...)
	cpp := ingest(t, st, model.AssetRepository, "cpp", true,
		append(scan("cpp", "user-management-conan1"), scan("cpp", "joequake-vcpkg-installed")...)...)

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	for dir, feed := range map[string]string{"swift": "osv:SwiftURL", "hex": "osv:Hex"} {
		serveCorpus(t, filepath.Join("testdata", "corpus", dir), feed, sy, up)
		if _, err := sy.Sync(ctx, feed); err != nil {
			t.Fatalf("sync %s: %v", feed, err)
		}
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}

	findings := func(asset int64) map[string]string {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Kind: "vulnerability"})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, f := range fs {
			got[f.Key] = f.ComponentName + "@" + f.Version + " fix " + f.FixedVersion
		}
		return got
	}
	if got := findings(swift); got["CVE-2026-28980"] != "github.com/apple/swift-nio@2.38.0 fix 2.100.0" || len(got) != 1 {
		t.Errorf("Swift findings: %v", got)
	}
	if got := findings(hex); got["CVE-2017-1000052"] != "plug@1.1.6 fix 1.1.7" || got["CVE-2018-1000883"] != "plug@1.1.6 fix 1.1.9" || len(got) != 2 {
		t.Errorf("Hex findings: %v", got)
	}
	if got := findings(cpp); len(got) != 0 {
		t.Errorf("C/C++ findings with no source: %v", got)
	}
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: cpp})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, r := range rows {
		seen[r.Purl] = r.Coverage + " " + r.CoverageReason
	}
	for purl, want := range map[string]string{
		"pkg:conan/openssl@1.1.1n":      "OSV publishes no ConanCenter advisories",
		"pkg:generic/vcpkg/curl@8.13.0": "vcpkg ports have no vulnerability source",
	} {
		if got := seen[purl]; !strings.HasPrefix(got, store.CoverageUnsupported) || !strings.Contains(got, want) {
			t.Errorf("%s: coverage %q, want unsupported %q (inventory %v)", purl, got, want, seen)
		}
	}
}
