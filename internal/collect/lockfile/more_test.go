package lockfile

import (
	"context"
	"github.com/stackurity/stackurity/pkg/pack"
	"testing"
	"testing/fstest"

	"github.com/stackurity/stackurity/internal/model"
)

func purls(obs []model.Observation) map[string]model.Observation {
	m := map[string]model.Observation{}
	for _, o := range obs {
		m[o.Purl] = o
	}
	return m
}

func scan(t *testing.T, files map[string]string, exts ...Extension) (map[string]model.Observation, []model.CoverageItem) {
	t.Helper()
	fs := fstest.MapFS{}
	for k, v := range files {
		fs[k] = &fstest.MapFile{Data: []byte(v)}
	}
	obs, cov, err := ScanWith(context.Background(), fs, exts)
	if err != nil {
		t.Fatal(err)
	}
	b := model.NewBatch(model.Collector{ID: "t", Method: "lockfile"}, model.AssetRef{Kind: model.AssetRepository, Name: "r",
		Identifiers: []model.Identifier{{Scheme: "x", Value: "y"}}})
	b.Observations, b.Coverage = obs, cov
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	return purls(obs), cov
}

func mustHave(t *testing.T, m map[string]model.Observation, purl string, direct *bool) model.Observation {
	t.Helper()
	o, ok := m[purl]
	if !ok {
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		t.Fatalf("missing %s; have %v", purl, keys)
	}
	if direct != nil && (o.Direct == nil || *o.Direct != *direct) {
		t.Errorf("%s direct = %v, want %v", purl, o.Direct, *direct)
	}
	return o
}

var yes, no = true, false

func TestYarnV1(t *testing.T) {
	m, _ := scan(t, map[string]string{
		"package.json": `{"dependencies": {"@babel/core": "^7"}}`,
		"yarn.lock": `# yarn lockfile v1


"@babel/core@^7.0.0", "@babel/core@^7.23.0":
  version "7.23.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.23.0.tgz"
  integrity sha512-x
  dependencies:
    debug "^4.1.0"

debug@^4.1.0:
  version "4.3.4"

lodash-alias@npm:lodash@4.17.21:
  version "4.17.21"
`,
	})
	mustHave(t, m, "pkg:npm/%40babel/core@7.23.0", &yes)
	mustHave(t, m, "pkg:npm/debug@4.3.4", &no)
	if len(m) != 3 {
		t.Errorf("got %d", len(m))
	}
}

func TestYarnBerry(t *testing.T) {
	m, _ := scan(t, map[string]string{
		"yarn.lock": `__metadata:
  version: 8
  cacheKey: 10

"@babel/core@npm:^7.0.0":
  version: 7.23.0
  resolution: "@babel/core@npm:7.23.0"
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"lodash@npm:4.17.15":
  version: 4.17.15
  resolution: "lodash@npm:4.17.15"
`,
	})
	mustHave(t, m, "pkg:npm/%40babel/core@7.23.0", nil)
	mustHave(t, m, "pkg:npm/lodash@4.17.15", nil)
	if len(m) != 2 {
		t.Errorf("workspace must be skipped: %v", m)
	}
}

func TestPnpm(t *testing.T) {
	v9 := `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react-dom:
        specifier: ^18.2.0
        version: 18.2.0(react@18.2.0)
packages:
  react-dom@18.2.0:
    resolution: {integrity: sha512-x}
  react@18.2.0:
    resolution: {integrity: sha512-y}
  '@types/node@20.10.0':
    resolution: {integrity: sha512-z}
`
	m, _ := scan(t, map[string]string{"pnpm-lock.yaml": v9})
	mustHave(t, m, "pkg:npm/react-dom@18.2.0", &yes)
	mustHave(t, m, "pkg:npm/react@18.2.0", &no)
	mustHave(t, m, "pkg:npm/%40types/node@20.10.0", &no)

	v6 := `lockfileVersion: '6.0'
dependencies:
  lodash:
    specifier: ^4
    version: 4.17.21
packages:
  /lodash@4.17.21:
    resolution: {integrity: sha512-x}
    dev: false
  /jest@29.7.0(@types/node@20.10.0):
    resolution: {integrity: sha512-y}
    dev: true
`
	m, _ = scan(t, map[string]string{"pnpm-lock.yaml": v6})
	mustHave(t, m, "pkg:npm/lodash@4.17.21", &yes)
	if j := mustHave(t, m, "pkg:npm/jest@29.7.0", nil); j.Scope != "dev" {
		t.Errorf("jest scope = %s", j.Scope)
	}
}

func TestPython(t *testing.T) {
	m, cov := scan(t, map[string]string{
		"pyproject.toml": `[tool.poetry.dependencies]
python = "^3.11"
Django = "^4.2"
[tool.poetry.group.dev.dependencies]
pytest = "^7"
`,
		"poetry.lock": `[[package]]
name = "Django"
version = "4.2.7"
groups = ["main"]

[[package]]
name = "sqlparse"
version = "0.4.4"
groups = ["main"]

[[package]]
name = "pytest"
version = "7.4.3"
groups = ["dev"]

[[package]]
name = "mylib"
version = "0.1.0"
[package.source]
type = "directory"
url = "../mylib"
`,
		"svc/requirements.txt": `# pinned
requests==2.31.0 \
    --hash=sha256:abc
Flask[async]==3.0.0 ; python_version >= "3.8"
-r base.txt
numpy>=1.20
`,
		"web/Pipfile.lock": `{"_meta": {}, "default": {"urllib3": {"version": "==1.26.18"}}, "develop": {"black": {"version": "==23.11.0"}}}`,
	})
	mustHave(t, m, "pkg:pypi/django@4.2.7", &yes)
	mustHave(t, m, "pkg:pypi/sqlparse@0.4.4", &no)
	if p := mustHave(t, m, "pkg:pypi/pytest@7.4.3", &yes); p.Scope != "dev" {
		t.Errorf("pytest scope = %s", p.Scope)
	}
	if _, ok := m["pkg:pypi/mylib@0.1.0"]; ok {
		t.Error("local directory package must be skipped")
	}
	mustHave(t, m, "pkg:pypi/requests@2.31.0", &yes)
	mustHave(t, m, "pkg:pypi/flask@3.0.0", &yes)
	mustHave(t, m, "pkg:pypi/urllib3@1.26.18", nil)
	partial := false
	for _, c := range cov {
		if c.Scope == "lockfile:svc/requirements.txt" && c.Status == "partial" {
			partial = true
		}
	}
	if !partial {
		t.Errorf("unpinned requirement must make coverage partial: %+v", cov)
	}
}

// cargoExt stands in for the Cargo stack pack: the core hands it Cargo.lock.
type cargoExt struct{}

func (cargoExt) ID() string               { return "cargo" }
func (cargoExt) Matches(name string) bool { return name == "Cargo.lock" }
func (cargoExt) Scan(_ context.Context, files []pack.File) ([]model.Observation, []model.CoverageItem, error) {
	fsys := fstest.MapFS{}
	for _, f := range files {
		fsys[f.Path] = &fstest.MapFile{Data: f.Content}
	}
	var obs []model.Observation
	var cov []model.CoverageItem
	for _, f := range files {
		found, err := ParseCargoLock(fsys, f.Path)
		if err != nil {
			return nil, nil, err
		}
		obs = append(obs, found...)
		cov = append(cov, model.CoverageItem{Scope: "pack:cargo:" + f.Path, Status: "checked"})
	}
	return obs, cov, nil
}

func TestCargoNeedsItsPack(t *testing.T) {
	files := map[string]string{"Cargo.lock": "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.193\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"}
	m, cov := scan(t, files)
	if len(m) != 0 || len(cov) != 1 || cov[0].Status != "unsupported" || cov[0].Scope != "cargo:Cargo.lock:Cargo.lock" {
		t.Errorf("without the pack: %v %+v", m, cov)
	}
	m, cov = scan(t, files, cargoExt{})
	mustHave(t, m, "pkg:cargo/serde@1.0.193", nil)
	if len(cov) != 1 || cov[0].Scope != "pack:cargo:Cargo.lock" {
		t.Errorf("with the pack: %+v", cov)
	}
}

func TestGoCargoGemNuGet(t *testing.T) {
	m, _ := scan(t, map[string]string{
		"go.mod": `module example.com/app

go 1.22

require (
	github.com/go-chi/chi/v5 v5.0.12
	golang.org/x/text v0.14.0 // indirect
	example.com/local v0.0.0
)

replace example.com/local => ../local
`,
		"Cargo.lock": `version = 3

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
`,
		"Gemfile.lock": `GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.15.5-x86_64-linux)
      racc (~> 1.4)
    racc (1.7.3)
    rails (7.1.2)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  nokogiri
  rails (~> 7.1)
`,
		"dotnet/packages.lock.json": `{"version": 1, "dependencies": {"net8.0": {
  "Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.1, )", "resolved": "13.0.1"},
  "System.Text.Json": {"type": "Transitive", "resolved": "8.0.0"},
  "MyProject": {"type": "Project"}}}}`,
	}, cargoExt{})
	mustHave(t, m, "pkg:golang/github.com/go-chi/chi/v5@v5.0.12", &yes)
	mustHave(t, m, "pkg:golang/golang.org/x/text@v0.14.0", &no)
	if _, ok := m["pkg:golang/example.com/local@v0.0.0"]; ok {
		t.Error("locally replaced module must be skipped")
	}
	mustHave(t, m, "pkg:cargo/serde@1.0.193", nil)
	if _, ok := m["pkg:cargo/app@0.1.0"]; ok {
		t.Error("workspace crate must be skipped")
	}
	mustHave(t, m, "pkg:gem/nokogiri@1.15.5", &yes)
	mustHave(t, m, "pkg:gem/racc@1.7.3", &no)
	mustHave(t, m, "pkg:nuget/Newtonsoft.Json@13.0.1", &yes)
	mustHave(t, m, "pkg:nuget/System.Text.Json@8.0.0", &no)
}

func TestPubspecLock(t *testing.T) {
	m, cov := scan(t, map[string]string{"app/pubspec.lock": `# Generated by pub
packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "abc"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
  collection:
    dependency: transitive
    description:
      name: collection
      url: "https://pub.dartlang.org"
    source: hosted
    version: "1.18.0"
  lints:
    dependency: "direct dev"
    description:
      name: lints
      url: "https://pub.dev"
    source: hosted
    version: "3.0.0"
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: "0.0.0"
  internal_ui:
    dependency: "direct main"
    description:
      name: internal_ui
      url: "https://pub.example.com"
    source: hosted
    version: "2.0.0"
  local_pkg:
    dependency: "direct main"
    description:
      path: "../local_pkg"
      relative: true
    source: path
    version: "0.1.0"
sdks:
  dart: ">=3.2.0 <4.0.0"
`})
	if len(m) != 3 {
		t.Errorf("want http, collection and lints only, got %v", m)
	}
	mustHave(t, m, "pkg:pub/http@1.2.0", &yes)
	mustHave(t, m, "pkg:pub/collection@1.18.0", &no)
	if o := mustHave(t, m, "pkg:pub/lints@3.0.0", &yes); o.Scope != "dev" || o.Location != "app/pubspec.lock" {
		t.Errorf("lints = %+v", o)
	}
	if len(cov) != 1 || cov[0].Status != "checked" {
		t.Errorf("coverage = %+v", cov)
	}
}

func TestPackBatches(t *testing.T) {
	f := func(path string, n int) pack.File { return pack.File{Path: path, Content: make([]byte, n)} }
	got := batches([]pack.File{f("big.jar", 40), f("pom.xml", 2), f("a/pom.xml", 3), f("other.jar", 30)}, 50)
	if len(got) != 2 || len(got[0]) != 3 || got[0][0].Path != "pom.xml" || got[0][1].Path != "a/pom.xml" || got[1][0].Path != "big.jar" {
		t.Errorf("batches: %+v", got)
	}
	if batches(nil, 10) != nil {
		t.Error("no files should give no batches")
	}
}
