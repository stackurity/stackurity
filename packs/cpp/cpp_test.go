package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/pkg/pack"
)

// The fixtures are real files from public repositories; testdata/README.md
// says where each one comes from.
func scanFixture(t *testing.T, path string) *pack.Response {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Scan(&pack.Request{Files: []pack.File{{Path: path, Content: data}}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func find(out *pack.Response, purl string) *pack.Observation {
	for i := range out.Observations {
		if out.Observations[i].Purl == purl {
			return &out.Observations[i]
		}
	}
	return nil
}

func direct(o *pack.Observation) string {
	switch {
	case o == nil:
		return "missing"
	case o.Direct == nil:
		return "unknown"
	case *o.Direct:
		return "direct"
	}
	return "transitive"
}

func TestConan1Lock(t *testing.T) {
	// Lockfile 0.4 (Conan 1.x): a graph whose node 0 is the conanfile.
	out := scanFixture(t, "user-management-conan1/conan.lock")
	if len(out.Observations) != 14 {
		t.Errorf("%d packages: %+v", len(out.Observations), out.Observations)
	}
	if find(out, "pkg:conan/user-management@1.0.0-dev.1") != nil {
		t.Error("the project itself was reported")
	}
	o := find(out, "pkg:conan/openssl@1.1.1n")
	if direct(o) != "transitive" || o.Scope != "" || o.Evidence["recipe_revision"] != "2f4f1e70c94733801aa604f0399db280" {
		t.Errorf("openssl: %+v", o)
	}
	if o := find(out, "pkg:conan/restinio@0.6.15"); direct(o) != "direct" {
		t.Errorf("restinio: %+v", o)
	}
	// A build requirement of the project (here a test framework).
	if o := find(out, "pkg:conan/catch2@2.13.9"); direct(o) != "direct" || o.Scope != "build" {
		t.Errorf("catch2: %+v", o)
	}
	if out.Coverage[0].Scope != "conan:user-management-conan1/conan.lock" || out.Coverage[0].Status != "checked" {
		t.Errorf("coverage: %+v", out.Coverage)
	}

	// The Conan documentation's example: user and channel, no revisions,
	// and a consumer that is itself a package (pkgb, with a path).
	out = scanFixture(t, "conan-docs-conan1/conan.lock")
	if len(out.Observations) != 1 || out.Observations[0].Purl != "pkg:conan/pkga@0.1?channel=testing&user=user" {
		t.Errorf("user/channel: %+v", out.Observations)
	}
}

func TestConan2Lock(t *testing.T) {
	// Lockfile 0.5 (Conan 2.x): flat lists with revisions and timestamps,
	// overrides, packages both required and build-required.
	out := scanFixture(t, "rippled-conan2/conan.lock")
	if len(out.Observations) != 37 {
		t.Errorf("%d packages", len(out.Observations))
	}
	for purl, scope := range map[string]string{
		"pkg:conan/openssl@3.6.3":             "", // in requires and build_requires: needed at run time
		"pkg:conan/boost@1.91.0":              "",
		"pkg:conan/libbacktrace@cci.20210118": "",
		"pkg:conan/cmake@4.3.3":               "build",
		"pkg:conan/msys2@cci.latest":          "build",
	} {
		o := find(out, purl)
		if o == nil || o.Scope != scope || direct(o) != "unknown" {
			t.Errorf("%s: %+v", purl, o)
		}
	}
	if o := find(out, "pkg:conan/zlib@1.3.2"); o.Evidence["recipe_revision"] != "1cb806da49011867778ffb6ac7190fcb" {
		t.Errorf("revision without its timestamp: %+v", o.Evidence)
	}
	out = scanFixture(t, "openvino-conan2/conan.lock")
	if len(out.Observations) != 26 || out.Coverage[0].Status != "checked" {
		t.Errorf("openvino: %d %+v", len(out.Observations), out.Coverage)
	}
}

func TestConanRef(t *testing.T) {
	for in, want := range map[string]string{
		"zlib/1.2.13":                          "zlib 1.2.13   ",
		"zlib/1.2.13#97d5%1692672717.049":      "zlib 1.2.13   97d5",
		"pkg/1.0@user/channel#rev":             "pkg 1.0 user channel rev",
		"pkg/1.0@_/_":                          "pkg 1.0   ",
		"zlib/1.2.11@conan/stable#r1:abc123#p": "zlib 1.2.11 conan stable r1",
		"protobuf/[>=5.27.0 <7]":               "",
		"noversion":                            "",
	} {
		r, ok := parseConanRef(in)
		got := ""
		if ok {
			got = strings.Join([]string{r.name, r.version, r.user, r.channel, r.rrev}, " ")
		}
		if got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestVcpkgManifest(t *testing.T) {
	// Ladybird pins every port under overrides, some with a port version.
	out := scanFixture(t, "ladybird-vcpkg/vcpkg.json")
	if len(out.Observations) != 46 || out.Coverage[0].Status != "checked" {
		t.Errorf("ladybird: %d %+v", len(out.Observations), out.Coverage)
	}
	o := find(out, "pkg:generic/vcpkg/angle@chromium_7258")
	if direct(o) != "direct" || o.Evidence["port_version"] != "2" || o.Confidence != pack.ConfidenceConfirmed {
		t.Errorf("angle: %+v", o)
	}
	// A pin for a port the manifest does not name directly.
	if o := find(out, "pkg:generic/vcpkg/dav1d@1.5.4"); direct(o) != "transitive" || o.Confidence != pack.ConfidenceInferred {
		t.Errorf("dav1d: %+v", o)
	}

	// Multipass pins one port; vcpkg resolves the rest from the baseline.
	out = scanFixture(t, "multipass-vcpkg/vcpkg.json")
	if len(out.Observations) != 1 || out.Observations[0].Purl != "pkg:generic/vcpkg/libssh@0.12.0" {
		t.Errorf("multipass: %+v", out.Observations)
	}
	c := out.Coverage[0]
	if c.Scope != "vcpkg:multipass-vcpkg/vcpkg.json" || c.Status != "partial" ||
		!strings.Contains(c.Reason, "13 dependencies have no exact version") || !strings.Contains(c.Reason, "fbb0f7bb200b") {
		t.Errorf("coverage: %+v", c)
	}
}

func TestVcpkgVersionKeys(t *testing.T) {
	m := `{"dependencies":["a",{"name":"b","version>=":"1.0"},"c","d"],
	  "overrides":[{"name":"a","version-semver":"1.2.3"},{"name":"b","version-date":"2024-01-02","port-version":3},
	    {"name":"c","version-string":"vista"},{"name":"d","version":"2.0#1","port-version":0}]}`
	out, _ := Scan(&pack.Request{Files: []pack.File{{Path: "vcpkg.json", Content: []byte(m)}}})
	got := []string{}
	for _, o := range out.Observations {
		got = append(got, o.Purl+" "+o.Evidence["port_version"])
	}
	want := "pkg:generic/vcpkg/a@1.2.3  pkg:generic/vcpkg/b@2024-01-02 3 pkg:generic/vcpkg/c@vista  pkg:generic/vcpkg/d@2.0 "
	if strings.Join(got, " ") != want {
		t.Errorf("got  %q\nwant %q", strings.Join(got, " "), want)
	}
}

func TestVcpkgInstalled(t *testing.T) {
	p := "joequake-vcpkg-installed/curl/share/curl/vcpkg.spdx.json"
	out := scanFixture(t, p)
	if len(out.Observations) != 1 || out.Observations[0].Purl != "pkg:generic/vcpkg/curl@8.13.0" ||
		out.Observations[0].Evidence["port_version"] != "1" || out.Coverage[0].Status != "checked" {
		t.Errorf("%+v %+v", out.Observations, out.Coverage)
	}
	out, _ = Scan(&pack.Request{Files: []pack.File{{Path: "vcpkg.spdx.json", Content: []byte(`{"spdxVersion":"SPDX-2.2","packages":[]}`)}}})
	if out.Coverage[0].Status != "failed" {
		t.Errorf("no port: %+v", out.Coverage)
	}
}

func TestBrokenFiles(t *testing.T) {
	for name, content := range map[string]string{
		"conan.lock":      `{"something": 1}`,
		"vcpkg.json":      `[1]`,
		"vcpkg.spdx.json": `{"not": "spdx"}`,
	} {
		out, _ := Scan(&pack.Request{Files: []pack.File{{Path: name, Content: []byte(content)}}})
		if len(out.Coverage) != 1 || out.Coverage[0].Status != "failed" {
			t.Errorf("%s: %+v", name, out.Coverage)
		}
	}
}
