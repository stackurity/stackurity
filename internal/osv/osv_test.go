package osv

import (
	"encoding/json"
	"testing"

	"github.com/stackurity/stackurity/internal/version"
)

func TestTargetFor(t *testing.T) {
	cases := []struct {
		purl, ver string
		ev        map[string]string
		eco, name string
		ok        bool
	}{
		{"pkg:npm/%40babel/core@7.23.0", "", nil, "npm", "@babel/core", true},
		{"pkg:composer/laravel/framework@10.48.4", "", nil, "Packagist", "laravel/framework", true},
		{"pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl", "", nil, "Debian:12", "openssl", true},
		{"pkg:deb/ubuntu/libc6@2.35-0ubuntu3?distro=ubuntu-22.04&upstream=glibc", "", nil, "Ubuntu:22.04", "glibc", true},
		{"pkg:apk/alpine/libcrypto3@3.1.4-r5?distro=alpine-3.19.1&upstream=openssl", "", nil, "Alpine:v3.19", "openssl", true},
		{"pkg:rpm/rocky/openssl-libs@3.0.7-24.el9?distro=rocky-9.3&epoch=1", "1:3.0.7-24.el9", map[string]string{"evr": "1:3.0.7-24.el9"}, "Rocky Linux:9", "openssl-libs", true},
		{"pkg:rpm/redhat/openssl@3.0.7?distro=rhel-9", "", nil, "", "", false},
		{"pkg:generic/debian@12", "", nil, "", "", false},
		{"pkg:deb/debian/bash@5.2", "", nil, "", "", false}, // no distro qualifier
	}
	for _, c := range cases {
		got, ok := TargetFor(c.purl, c.ver, c.ev)
		if ok != c.ok || got.Ecosystem != c.eco || got.Name != c.name {
			t.Errorf("TargetFor(%s) = %+v %v", c.purl, got, ok)
		}
	}
}

func TestMatchEcosystem(t *testing.T) {
	if !MatchEcosystem("Ubuntu:22.04:LTS", "Ubuntu:22.04") || !MatchEcosystem("Ubuntu:Pro:18.04:LTS", "Ubuntu:18.04") ||
		!IsPro("Ubuntu:Pro:18.04:LTS") || IsPro("Ubuntu:18.04:LTS") || MatchEcosystem("Ubuntu:Pro:20.04:LTS", "Ubuntu:18.04") ||
		MatchEcosystem("Debian:11", "Debian:12") || !MatchEcosystem("npm", "npm") {
		t.Error("MatchEcosystem")
	}
}

func affected(t *testing.T, js string) Affected {
	var a Affected
	if err := json.Unmarshal([]byte(js), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestCheck(t *testing.T) {
	npm := affected(t, `{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}`)
	two := affected(t, `{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.2.5"},{"introduced":"2.0.0"},{"fixed":"2.0.3"}]}]}`)
	last := affected(t, `{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"3.1"}]}]}`)
	deb := affected(t, `{"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.11-1~deb12u2"}]}]}`)
	listed := affected(t, `{"versions":["1.0.0","1.0.1"]}`)

	semver := func(v string) Target { return Target{Version: v, Compare: version.SemVer} }
	cases := []struct {
		name string
		a    Affected
		t    Target
		hit  bool
		fix  string
	}{
		{"lodash old", npm, semver("4.17.15"), true, "4.17.21"},
		{"lodash fixed", npm, semver("4.17.21"), false, ""},
		{"lodash newer", npm, semver("4.18.0"), false, ""},
		{"first span", two, semver("1.2.0"), true, "1.2.5"},
		{"between spans", two, semver("1.5.0"), false, ""},
		{"second span", two, semver("2.0.1"), true, "2.0.3"},
		{"before intro", two, semver("0.9.0"), false, ""},
		{"last affected equal", last, semver("3.1"), true, ""},
		{"last affected above", last, semver("3.1.1"), false, ""},
		{"debian backport fixed", deb, Target{Version: "3.0.11-1~deb12u2", Compare: version.Debian}, false, ""},
		{"debian vulnerable", deb, Target{Version: "3.0.11-1~deb12u1", Compare: version.Debian}, true, "3.0.11-1~deb12u2"},
		{"listed", listed, semver("1.0.1"), true, ""},
		{"not listed", listed, semver("1.0.2"), false, ""},
	}
	for _, c := range cases {
		m, err := Check(c.a, c.t)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if m.Affected != c.hit || m.FixedVersion != c.fix {
			t.Errorf("%s: got %+v", c.name, m)
		}
	}
	if _, err := Check(npm, semver("not-a-version")); err == nil {
		t.Error("unparseable installed version must surface an error, not a clean result")
	}
}

func TestSeverity(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1,
		"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	}
	for vec, want := range cases {
		if got, ok := CVSS3Score(vec); !ok || got != want {
			t.Errorf("%s = %v %v, want %v", vec, got, ok, want)
		}
	}
	var v Vulnerability
	_ = json.Unmarshal([]byte(`{"id":"GHSA-x","database_specific":{"severity":"MODERATE"},"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N"}]}`), &v)
	if r := Rate(&v); r.Level != "medium" || r.Source != "database" {
		t.Errorf("rate = %+v", r)
	}
	// An all-None v3 vector must not override a HIGH vendor rating.
	var mixed Vulnerability
	_ = json.Unmarshal([]byte(`{"id":"GHSA-gv7v","database_specific":{"severity":"HIGH"},"severity":[
	  {"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"},
	  {"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"}]}`), &mixed)
	if r := Rate(&mixed); r.Level != "high" || r.Source != "database" {
		t.Errorf("mixed = %+v", r)
	}
	// A real v3 score above the label is kept with its vector.
	var scored Vulnerability
	_ = json.Unmarshal([]byte(`{"id":"x","database_specific":{"severity":"MODERATE"},"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`), &scored)
	if r := Rate(&scored); r.Level != "critical" || r.Score != 9.8 {
		t.Errorf("scored = %+v", r)
	}
	var none Vulnerability
	if r := Rate(&none); r.Level != "unknown" {
		t.Errorf("no data should be unknown, got %+v", r)
	}
	if GroupKey("GHSA-1", []string{"CVE-2024-2", "CVE-2023-9"}) != "CVE-2023-9" || GroupKey("DSA-1", nil) != "DSA-1" ||
		GroupKey("DEBIAN-CVE-2023-52426", nil, "CVE-2023-52426") != "CVE-2023-52426" {
		t.Error("GroupKey")
	}
}
