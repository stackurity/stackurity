package apps

import (
	"context"
	"strings"
	"testing"
)

// TestReleaseLinkStaysInsideApp: a release layout's current link is
// followed only to a release inside the application, never out of it,
// whether the link itself or the release it names points outside.
func TestReleaseLinkStaysInsideApp(t *testing.T) {
	tr := newTree(t)
	tr.file("secret/composer.lock", `{"packages":[{"name":"private/outside","version":"1.0.0"}]}`)
	tr.file("srv/a/releases/1/composer.lock", `{"packages":[{"name":"acme/a","version":"1.0.0"}]}`)
	tr.link("srv/a/current", "../../secret")
	tr.file("srv/b/releases/1/composer.lock", `{"packages":[{"name":"acme/b","version":"1.0.0"}]}`)
	tr.link("srv/b/releases/2", "../../../secret")
	tr.link("srv/b/current", "releases/2")
	tr.file("srv/c/releases/1/composer.lock", `{"packages":[{"name":"acme/c","version":"1.0.0"}]}`)
	tr.link("srv/c/current", tr.root+"/secret")
	s := &Scanner{Root: tr.root}
	for _, dir := range []string{"/srv/a", "/srv/b", "/srv/c"} {
		a := s.ScanApp(context.Background(), dir)
		for _, o := range a.Observations {
			if strings.Contains(o.Purl, "outside") {
				t.Errorf("%s: followed a link out of the application: %s (dir %s)", dir, o.Purl, a.Dir)
			}
		}
		if strings.Contains(a.Dir, "secret") {
			t.Errorf("%s: scanned %s", dir, a.Dir)
		}
	}
}

// TestHostilePackageMetadata: a package in node_modules with an absurd
// name or version (anyone publishing a package controls both) must not
// make the application's batch invalid and so hide its other packages.
func TestHostilePackageMetadata(t *testing.T) {
	tr := newTree(t)
	app := "srv/shop"
	tr.file(app+"/package.json", `{"name":"shop","dependencies":{"express":"^4"}}`)
	tr.npm(app+"/node_modules/express", "express", "4.17.1")
	tr.npm(app+"/node_modules/evil", strings.Repeat("e", 3000), "1.0.0")
	tr.npm(app+"/node_modules/evil2", "evil2", strings.Repeat("9", 3000))
	tr.file(app+"/node_modules/evil3/package.json", `{"name":"evil3","version":"1.0.0","x":"`+strings.Repeat("{", 10)+`"}`)
	a := (&Scanner{Root: tr.root}).ScanApp(context.Background(), "/"+app)
	if _, ok := purls(a.Observations)["pkg:npm/express@4.17.1"]; !ok {
		t.Fatalf("express missing: %v", keys(purls(a.Observations)))
	}
	validate(t, a)
}
