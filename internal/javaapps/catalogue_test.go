package javaapps

import (
	"strings"
	"testing"
)

func TestDefaultParses(t *testing.T) {
	c := Default()
	if c.Version() == "" || len(c.Products()) == 0 {
		t.Fatalf("catalogue %q with %d products", c.Version(), len(c.Products()))
	}
	p := c.Identify("pkg:generic/apache-roller")
	if p == nil || p.Label != "Apache Roller" || p.PurlKey() != "pkg:generic/apache-roller" {
		t.Fatalf("apache-roller: %+v", p)
	}
	for _, k := range []string{"pkg:generic/wordpress", "pkg:maven/org.apache.roller/roller-webapp", "apache-roller", "pkg:generic/apache-roller-x"} {
		if c.Identify(k) != nil {
			t.Errorf("Identify(%q) found a product", k)
		}
	}
}

func TestRelease(t *testing.T) {
	p := Default().Product("apache-roller")
	for in, want := range map[string]string{"6.1.4": "6.1.4", " 4.0.1 ": "4.0.1", "5.2": "5.2"} {
		if got, err := p.Release(in); err != nil || got != want {
			t.Errorf("Release(%q) = %q, %v", in, got, err)
		}
	}
	for _, in := range []string{"", "6.1.6-SNAPSHOT", "UNKNOWN", "${project.version}"} {
		if _, err := p.Release(in); err == nil {
			t.Errorf("Release(%q) read a release", in)
		}
	}
}

func TestOwnsCPE(t *testing.T) {
	p := Default().Product("apache-roller")
	for crit, want := range map[string]bool{
		"cpe:2.3:a:apache:roller:*:*:*:*:*:*:*:*":       true,
		"cpe:2.3:a:apache:roller:5.2.0:-:*:*:*:*:*:*":   true,
		"cpe:2.3:a:apache:roller:5.2.0:rc2:*:*:*:*:*:*": true,
		"cpe:2.3:a:apache:roller:*:*:*:*:*:android:*:*": false,
		"cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*":       false,
		"cpe:2.3:o:apache:roller:*:*:*:*:*:*:*:*":       false,
	} {
		if got := p.OwnsCPE(crit); got != want {
			t.Errorf("OwnsCPE(%s) = %v", crit, got)
		}
	}
	if !p.PlatformAllows("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*") || !p.PlatformAllows("cpe:2.3:o:linux:linux_kernel:-:*:*:*:*:*:*:*") ||
		p.PlatformAllows("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*") {
		t.Error("PlatformAllows")
	}
}

func TestParseRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown field": `{"schema":1,"version":"1","products":[],"x":1}`,
		"schema":        `{"schema":2,"version":"1","products":[]}`,
		"no version":    `{"schema":1,"products":[]}`,
		"bad id":        `{"schema":1,"version":"1","products":[{"id":"Roller","label":"R","cpes":["cpe:2.3:a:apache:roller"],"sources":["s"],"verified":"2026-11-22"}]}`,
		"bad cpe":       `{"schema":1,"version":"1","products":[{"id":"r","label":"R","cpes":["cpe:2.3:a:apache:*"],"sources":["s"],"verified":"2026-11-22"}]}`,
		"no sources":    `{"schema":1,"version":"1","products":[{"id":"r","label":"R","cpes":["cpe:2.3:a:apache:roller"],"verified":"2026-11-22"}]}`,
		"bad date":      `{"schema":1,"version":"1","products":[{"id":"r","label":"R","cpes":["cpe:2.3:a:apache:roller"],"sources":["s"],"verified":"soon"}]}`,
		"twice": `{"schema":1,"version":"1","products":[{"id":"r","label":"R","cpes":["cpe:2.3:a:apache:roller"],"sources":["s"],"verified":"2026-11-22"},` +
			`{"id":"r","label":"R","cpes":["cpe:2.3:a:apache:other"],"sources":["s"],"verified":"2026-11-22"}]}`,
	} {
		if _, err := Parse([]byte(doc)); err == nil || !strings.Contains(err.Error(), "catalogue") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
