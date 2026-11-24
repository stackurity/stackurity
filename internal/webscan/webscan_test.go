package webscan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/netguard"
)

func TestScanRefusesPrivateAddresses(t *testing.T) {
	for _, u := range []string{"http://127.0.0.1:8080", "http://169.254.169.254/latest/meta-data", "http://10.0.0.1", "http://[::1]/", "localhost", "http://2130706433/"} {
		if _, err := Scan(context.Background(), u, Options{}); err == nil {
			t.Errorf("%s: scanned a private address", u)
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":                "https://example.com/",
		" HTTP://Example.com/a#x ":   "http://example.com/a",
		"https://shop.example.co.uk": "https://shop.example.co.uk/",
	} {
		u, err := Normalize(in)
		if err != nil || u.String() != want {
			t.Errorf("Normalize(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://example.com", "https://user:pw@example.com", "intranet"} {
		if _, err := Normalize(bad); err == nil {
			t.Errorf("Normalize(%q) accepted", bad)
		}
	}
}

func TestParseRobots(t *testing.T) {
	r := parseRobots([]byte("User-agent: Googlebot\nDisallow: /g\n\nUser-agent: *\nDisallow: /admin\nDisallow: /tmp$\nSitemap: https://x.test/s.xml\n"))
	if r.allowed("/admin/x") || r.allowed("/tmp") || !r.allowed("/tmp/x") || !r.allowed("/g") {
		t.Errorf("rules applied wrongly: %+v", r)
	}
	if len(r.sitemaps) != 1 {
		t.Errorf("sitemaps = %v", r.sitemaps)
	}
}

// TestScanSite runs a whole scan against a local site with known problems.
func TestScanSite(t *testing.T) {
	netguard.Set(netguard.Config{Mode: "all"}) // the test site is on loopback
	t.Cleanup(func() { netguard.Set(netguard.Config{Mode: "default"}) })
	npmVulns = func(_ context.Context, libs [][2]string) (map[string][]Vuln, error) {
		out := map[string][]Vuln{}
		for _, l := range libs {
			if l[0] == "jquery" && l[1] == "1.12.4" {
				out["jquery@1.12.4"] = []Vuln{{ID: "GHSA-1", Aliases: []string{"CVE-2020-11022"}, Summary: "XSS", Severity: "medium", Fixed: "3.5.0"}}
			}
		}
		return out, nil
	}
	t.Cleanup(func() { npmVulns = osvNpmVulns })

	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/about" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "abc"})
		w.Header().Set("Server", "Apache/2.4.1 (Unix) PHP/5.6.40")
		fmt.Fprint(w, `<!doctype html><html><head><title>Shop</title>
<meta name="generator" content="Hugo 0.1">
<script src="https://code.jquery.com/jquery-1.12.4.min.js"></script>
<script src="/js/app.js"></script>
<script>var k = "sk_live_`+strings.Repeat("a1B2", 7)+`";</script>
</head><body><a href="/about">About</a>
<form action="http://example.test/login"><input type="password" name="p"></form></body></html>`)
	})
	mux.HandleFunc("/js/app.js", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "/*! jQuery UI - v1.10.0 */\nconsole.log(1)")
	})
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "User-agent: *\nDisallow: /private\nSitemap: "+base+"/sitemap.xml\n")
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?><urlset><url><loc>`+base+`/about</loc></url><url><loc>`+base+`/private/x</loc></url></urlset>`)
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "APP_KEY=x\nDB_PASSWORD=y\n") })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL

	rep, err := Scan(context.Background(), srv.URL, Options{Owner: true})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]Finding{}
	for _, f := range rep.Findings {
		ids[f.ID] = f
	}
	for _, want := range []string{"no-https", "vulnerable-library", "leak-stripe-live-key", "password-over-http", "version-disclosure", "exposed-env", "no-csp"} {
		if _, ok := ids[want]; !ok {
			t.Errorf("missing finding %s; got %v", want, keys(ids))
		}
	}
	if f := ids["leak-stripe-live-key"]; strings.Contains(f.Detail, strings.Repeat("a1B2", 7)) {
		t.Errorf("the report shows the key: %s", f.Detail)
	}
	if f := ids["vulnerable-library"]; !strings.Contains(f.Fix, "3.5.0") {
		t.Errorf("fix = %q", f.Fix)
	}
	libs := map[string]bool{}
	for _, l := range rep.Libraries {
		libs[l.Name+"@"+l.Version+"/"+l.Source] = true
	}
	if !libs["jquery@1.12.4/CDN address"] || !libs["jquery-ui@1.10.0/file banner"] {
		t.Errorf("libraries = %v", libs)
	}
	for _, p := range rep.Pages {
		if strings.Contains(p, "/private") {
			t.Errorf("read %s, which robots.txt disallows", p)
		}
	}
	if len(rep.Pages) != 2 {
		t.Errorf("pages = %v", rep.Pages)
	}
	if rep.Grade != "F" && rep.Grade != "D" {
		t.Errorf("grade %s (score %d) for a site with a leaked key and an exposed .env", rep.Grade, rep.Score)
	}
}

func keys(m map[string]Finding) (out []string) {
	for k := range m {
		out = append(out, k)
	}
	return out
}

var _ = errors.New
