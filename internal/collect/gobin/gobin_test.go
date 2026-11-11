package gobin

import (
	"context"
	"debug/buildinfo"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/collect/gobin/gobintest"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
)

func put(t *testing.T, root, name string, body []byte, mode os.FileMode) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

// at returns the purls (without qualifiers) reported at one location.
func at(obs []model.Observation, loc string) []string {
	var out []string
	for _, o := range obs {
		if o.Location == loc {
			out = append(out, o.Purl)
		}
	}
	slices.Sort(out)
	return out
}

func find(obs []model.Observation, loc, purlPrefix string) *model.Observation {
	for i, o := range obs {
		if o.Location == loc && strings.HasPrefix(o.Purl, purlPrefix) {
			return &obs[i]
		}
	}
	return nil
}

func stdlibPurl(t *testing.T, obs []model.Observation, loc string) string {
	t.Helper()
	o := find(obs, loc, "pkg:golang/stdlib@")
	if o == nil {
		t.Fatalf("no stdlib at %s: %v", loc, at(obs, loc))
	}
	if want := StdlibVersion(o.Evidence["go_version"]); want == "" || o.Version != want {
		t.Errorf("stdlib version %q from toolchain %q", o.Version, o.Evidence["go_version"])
	}
	return o.Purl
}

// A Go binary yields its toolchain and dependency modules, a replaced
// module as its replacement, located at the binary. The (devel) main
// module and the local-directory replacement are project code and not
// reported. Stripping symbols does not remove the build information.
// Scripts, non-Go ELF files and files without an execute bit give nothing.
func TestScanGoBinary(t *testing.T) {
	bins := gobintest.Build(t)
	root := t.TempDir()
	put(t, root, "usr/local/bin/app", bins.Plain, 0o755)
	put(t, root, "opt/tools/app-stripped", bins.Stripped, 0o755)
	put(t, root, "srv/data/app.bin", bins.Plain, 0o644) // not executable
	put(t, root, "usr/local/bin/cprog", append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 4096)...), 0o755)
	put(t, root, "usr/local/bin/run.sh", []byte("#!/bin/sh\necho hi\n"), 0o755)
	put(t, root, "proc/1/exe", bins.Plain, 0o755) // never walked
	if err := os.Symlink("app", filepath.Join(root, "usr/local/bin/app-link")); err != nil {
		t.Fatal(err)
	}

	obs, cov := (&Scanner{Root: root}).Scan(context.Background())
	if len(cov) != 1 || cov[0] != (model.CoverageItem{Scope: Scope, Status: "checked"}) {
		t.Errorf("coverage = %+v", cov)
	}
	for _, loc := range []string{"/usr/local/bin/app", "/opt/tools/app-stripped"} {
		std := stdlibPurl(t, obs, loc)
		want := []string{"pkg:golang/example.com/dep@v1.4.0", "pkg:golang/example.com/new@v1.2.0", std}
		slices.Sort(want)
		if got := at(obs, loc); !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", loc, got, want)
		}
		rep := find(obs, loc, "pkg:golang/example.com/new@")
		if rep == nil || rep.Evidence["replaces"] != "example.com/old@v1.0.0" || rep.Version != "v1.2.0" ||
			rep.Evidence["binary"] != loc || rep.Confidence != model.ConfidenceConfirmed || rep.Evidence["detected_by"] != "go-buildinfo" {
			t.Errorf("%s: replaced module = %+v", loc, rep)
		}
	}
	if len(obs) != 6 {
		t.Errorf("observations outside the two binaries: %+v", obs)
	}
	for _, o := range obs {
		b := model.NewBatch(model.Collector{ID: "t"}, model.AssetRef{Kind: model.AssetImage, Name: "x",
			Identifiers: []model.Identifier{{Scheme: "s", Value: "v"}}})
		b.Observations = []model.Observation{o}
		if err := b.Validate(); err != nil {
			t.Errorf("%s: %v", o.Purl, err)
		}
	}
}

// Binaries an OS package installed are left to that package.
func TestScanSkipsOwned(t *testing.T) {
	bins := gobintest.Build(t)
	root := t.TempDir()
	put(t, root, "usr/bin/packaged", bins.Plain, 0o755)
	put(t, root, "usr/local/bin/app", bins.Plain, 0o755)
	obs, _ := (&Scanner{Root: root, Owned: func(p string) bool { return p == "/usr/bin/packaged" }}).Scan(context.Background())
	if len(at(obs, "/usr/bin/packaged")) != 0 || len(at(obs, "/usr/local/bin/app")) != 3 {
		t.Errorf("observations = %+v", obs)
	}
}

// Every limit stops the walk with partial coverage that says why, never a
// clean "checked".
func TestScanLimits(t *testing.T) {
	bins := gobintest.Build(t)
	root := t.TempDir()
	put(t, root, "a/bin/one", bins.Plain, 0o755)
	put(t, root, "b/bin/two", bins.Plain, 0o755)
	cases := []struct {
		name   string
		lim    Limits
		reason string
	}{
		{"binaries", Limits{MaxDirs: 100, MaxEntries: 100, MaxBinaries: 1, MaxFileSize: 1 << 30, MaxBytes: 1 << 30}, "stopped after 1 executables"},
		{"bytes", Limits{MaxDirs: 100, MaxEntries: 100, MaxBinaries: 100, MaxFileSize: 1 << 30, MaxBytes: 64}, "stopped after reading 64 bytes"},
		{"dirs", Limits{MaxDirs: 2, MaxEntries: 100, MaxBinaries: 100, MaxFileSize: 1 << 30, MaxBytes: 1 << 30}, "stopped after 2 directories"},
		{"entries", Limits{MaxDirs: 100, MaxEntries: 3, MaxBinaries: 100, MaxFileSize: 1 << 30, MaxBytes: 1 << 30}, "stopped after 3 files"},
		{"file size", Limits{MaxDirs: 100, MaxEntries: 100, MaxBinaries: 100, MaxFileSize: 1024, MaxBytes: 1 << 30}, "2 executable(s) larger than 1024 bytes were not read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, cov := (&Scanner{Root: root, Limits: c.lim}).Scan(context.Background())
			if len(cov) != 1 || cov[0].Scope != Scope || cov[0].Status != "partial" || !strings.Contains(cov[0].Reason, c.reason) {
				t.Errorf("coverage = %+v, want partial with %q", cov, c.reason)
			}
		})
	}
	// Within the limits, both binaries are read.
	obs, cov := (&Scanner{Root: root}).Scan(context.Background())
	if cov[0].Status != "checked" || len(at(obs, "/a/bin/one")) != 3 || len(at(obs, "/b/bin/two")) != 3 {
		t.Errorf("coverage %+v, observations %+v", cov, obs)
	}
	// A cancelled scan says so.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 2000 {
		put(t, root, filepath.Join("many", strings.Repeat("x", 1+i%5), string(rune('a'+i%26))+strings.Repeat("y", i/26)), nil, 0o644)
	}
	if _, cov := (&Scanner{Root: root}).Scan(ctx); cov[0].Status != "partial" || !strings.Contains(cov[0].Reason, "context canceled") {
		t.Errorf("cancelled: %+v", cov)
	}
}

// The main module is reported when it has a real version; a development
// toolchain gives no stdlib version to match.
func TestObservationsMainModule(t *testing.T) {
	bi := &buildinfo.BuildInfo{GoVersion: "go1.22.1", Main: debug.Module{Path: "github.com/acme/tool", Version: "v1.2.3"},
		Deps: []*debug.Module{{Path: "golang.org/x/text", Version: "v0.3.7"}}}
	got := Observations(bi, "/usr/local/bin/tool")
	var purls []string
	for _, o := range got {
		purls = append(purls, o.Purl)
	}
	want := []string{"pkg:golang/stdlib@1.22.1", "pkg:golang/github.com/acme/tool@v1.2.3", "pkg:golang/golang.org/x/text@v0.3.7"}
	if !slices.Equal(purls, want) {
		t.Errorf("purls = %v, want %v", purls, want)
	}
	if got[1].Evidence["main_module"] != "true" || got[2].Evidence["main_module"] != "" {
		t.Errorf("main_module evidence: %+v", got)
	}
	bi.Main.Version, bi.GoVersion = "(devel)", "devel go1.23-abcdef"
	got = Observations(bi, "/x")
	if len(got) != 1 || got[0].Purl != "pkg:golang/golang.org/x/text@v0.3.7" {
		t.Errorf("devel: %+v", got)
	}
}

func TestStdlibVersion(t *testing.T) {
	for in, want := range map[string]string{
		"go1.22.1":                 "1.22.1",
		"go1.24.0 X:boringcrypto":  "1.24.0",
		"go1.20":                   "1.20.0",
		"go1.21rc2":                "1.21.0-rc.2",
		"go1.18beta1":              "1.18.0-beta.1",
		"devel go1.23-abc Tue Jan": "",
		"":                         "",
		"go1.x":                    "",
	} {
		if got := StdlibVersion(in); got != want {
			t.Errorf("StdlibVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// End to end at unit level: what a binary reports maps to OSV's Go
// ecosystem and matches Go advisories, the toolchain's through stdlib.
func TestBinaryMatchesOSV(t *testing.T) {
	bins := gobintest.Build(t)
	root := t.TempDir()
	put(t, root, "app", bins.Plain, 0o755)
	obs, _ := (&Scanner{Root: root}).Scan(context.Background())
	check := func(prefix string, a osv.Affected, want bool) {
		t.Helper()
		o := find(obs, "/app", prefix)
		if o == nil {
			t.Fatalf("no %s", prefix)
		}
		tg, ok := osv.TargetFor(o.Purl, o.Version, o.Evidence)
		if !ok || tg.Ecosystem != "Go" || tg.Name != a.Package.Name {
			t.Fatalf("TargetFor(%s) = %+v, %v", o.Purl, tg, ok)
		}
		m, err := osv.Check(a, tg)
		if err != nil || m.Affected != want {
			t.Errorf("%s against %+v: %+v, %v; want affected=%v", o.Purl, a.Ranges, m, err, want)
		}
	}
	rng := func(fixed string) []osv.Range {
		return []osv.Range{{Type: "SEMVER", Events: []osv.Event{{Introduced: "0"}, {Fixed: fixed}}}}
	}
	// The replacement is what the binary contains.
	check("pkg:golang/example.com/new@", osv.Affected{Package: osv.Package{Ecosystem: "Go", Name: "example.com/new"}, Ranges: rng("1.2.1")}, true)
	check("pkg:golang/example.com/new@", osv.Affected{Package: osv.Package{Ecosystem: "Go", Name: "example.com/new"}, Ranges: rng("1.2.0")}, false)
	check("pkg:golang/example.com/dep@", osv.Affected{Package: osv.Package{Ecosystem: "Go", Name: "example.com/dep"}, Ranges: rng("1.5.0")}, true)
	check("pkg:golang/stdlib@", osv.Affected{Package: osv.Package{Ecosystem: "Go", Name: "stdlib"}, Ranges: rng("99.0.0")}, true)
	check("pkg:golang/stdlib@", osv.Affected{Package: osv.Package{Ecosystem: "Go", Name: "stdlib"}, Ranges: rng("1.0.1")}, false)
}
