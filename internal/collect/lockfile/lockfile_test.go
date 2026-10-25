package lockfile

import (
	"testing"
	"testing/fstest"

	"github.com/stackurity/stackurity/internal/model"
)

const npmV3Lock = `{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"express": "^4.18.0", "@babel/core": "^7"}, "devDependencies": {"jest": "^29"}},
    "node_modules/express": {"version": "4.18.2", "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz", "integrity": "sha512-x"},
    "node_modules/@babel/core": {"version": "7.23.0"},
    "node_modules/jest": {"version": "29.7.0", "dev": true},
    "node_modules/debug": {"version": "2.6.9"},
    "node_modules/express/node_modules/debug": {"version": "4.3.4"},
    "node_modules/my-alias": {"name": "lodash", "version": "4.17.21"},
    "node_modules/local-lib": {"resolved": "packages/local-lib", "link": true},
    "packages/local-lib": {"version": "1.0.0"}
  }
}`

const npmV1Lock = `{
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": {"version": "4.17.15"},
    "a": {"version": "1.0.0", "dev": true, "dependencies": {"b": {"version": "2.0.0"}}},
    "alias": {"version": "npm:left-pad@1.3.0"}
  }
}`

const composerLockJSON = `{
  "packages": [
    {"name": "laravel/framework", "version": "v10.48.4", "source": {"reference": "abc"}},
    {"name": "symfony/console", "version": "v6.4.4"},
    {"name": "acme/thing", "version": "dev-main"}
  ],
  "packages-dev": [{"name": "phpunit/phpunit", "version": "10.5.10"}]
}`

func index(obs []model.Observation) map[string]model.Observation {
	m := map[string]model.Observation{}
	for _, o := range obs {
		m[o.Purl+" "+o.Evidence["lock_path"]] = o
	}
	return m
}

func TestNpmV3(t *testing.T) {
	obs, cov, err := Scan(fstest.MapFS{"package-lock.json": {Data: []byte(npmV3Lock)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(cov) != 1 || cov[0].Status != "checked" {
		t.Fatalf("coverage = %+v", cov)
	}
	m := index(obs)
	if len(obs) != 6 {
		t.Fatalf("want 6 observations, got %d: %v", len(obs), m)
	}
	ex := m["pkg:npm/express@4.18.2 node_modules/express"]
	if ex.Direct == nil || !*ex.Direct || ex.Scope != "runtime" || ex.Evidence["integrity"] != "sha512-x" {
		t.Errorf("express = %+v", ex)
	}
	if b := m["pkg:npm/%40babel/core@7.23.0 node_modules/@babel/core"]; b.Direct == nil || !*b.Direct {
		t.Errorf("@babel/core = %+v", b)
	}
	if j := m["pkg:npm/jest@29.7.0 node_modules/jest"]; j.Scope != "dev" {
		t.Errorf("jest = %+v", j)
	}
	if d := m["pkg:npm/debug@4.3.4 node_modules/express/node_modules/debug"]; d.Direct == nil || *d.Direct {
		t.Errorf("nested debug must be transitive: %+v", d)
	}
	if _, ok := m["pkg:npm/lodash@4.17.21 node_modules/my-alias"]; !ok {
		t.Errorf("alias should resolve to lodash: %v", m)
	}
}

func TestNpmV1(t *testing.T) {
	obs, _, err := Scan(fstest.MapFS{"sub/package-lock.json": {Data: []byte(npmV1Lock)}})
	if err != nil {
		t.Fatal(err)
	}
	m := index(obs)
	if len(obs) != 4 {
		t.Fatalf("got %v", m)
	}
	if b := m["pkg:npm/b@2.0.0 node_modules/a/node_modules/b"]; b.Location != "sub/package-lock.json" {
		t.Errorf("b = %+v", b)
	}
	if _, ok := m["pkg:npm/left-pad@1.3.0 node_modules/left-pad"]; !ok {
		t.Errorf("alias not resolved: %v", m)
	}
}

func TestComposer(t *testing.T) {
	obs, _, err := Scan(fstest.MapFS{
		"composer.lock": {Data: []byte(composerLockJSON)},
		"composer.json": {Data: []byte(`{"require": {"laravel/framework": "^10.0"}, "require-dev": {"phpunit/phpunit": "^10"}}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := index(obs)
	lf := m["pkg:composer/laravel/framework@10.48.4 "]
	if lf.Direct == nil || !*lf.Direct || lf.Evidence["raw_version"] != "v10.48.4" {
		t.Errorf("laravel = %+v", lf)
	}
	if sc := m["pkg:composer/symfony/console@6.4.4 "]; sc.Direct == nil || *sc.Direct {
		t.Errorf("symfony/console should be transitive: %+v", sc)
	}
	if a := m["pkg:composer/acme/thing@dev-main "]; a.Confidence != model.ConfidenceLow {
		t.Errorf("dev branch should be low confidence: %+v", a)
	}
	if p := m["pkg:composer/phpunit/phpunit@10.5.10 "]; p.Scope != "dev" {
		t.Errorf("phpunit = %+v", p)
	}
}

func TestSkipsVendoredAndReportsUnsupported(t *testing.T) {
	obs, cov, err := Scan(fstest.MapFS{
		"node_modules/x/package-lock.json": {Data: []byte(npmV3Lock)},
		"vendor/y/composer.lock":           {Data: []byte(composerLockJSON)},
		"web/pom.xml":                      {Data: []byte("<project/>")},
		"bad/package-lock.json":            {Data: []byte("{not json")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != 0 {
		t.Errorf("vendored lockfiles must be skipped, got %d", len(obs))
	}
	statuses := map[string]string{}
	for _, c := range cov {
		statuses[c.Scope] = c.Status
	}
	if statuses["maven:pom.xml:web/pom.xml"] != "unsupported" || statuses["lockfile:bad/package-lock.json"] != "failed" {
		t.Errorf("coverage = %+v", cov)
	}
}

func TestBatchValidates(t *testing.T) {
	obs, cov, _ := Scan(fstest.MapFS{"package-lock.json": {Data: []byte(npmV3Lock)}, "composer.lock": {Data: []byte(composerLockJSON)}})
	b := model.NewBatch(model.Collector{ID: CollectorID, Method: "lockfile"},
		model.AssetRef{Kind: model.AssetRepository, Name: "app", Identifiers: []model.Identifier{{Scheme: "path", Value: "/x"}}})
	b.Observations, b.Coverage = obs, cov
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
}
