package sitecheck

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The key is assembled at run time so this file is not itself reported by
// a secret scanner.
var testStripeKey = strings.Join([]string{"sk", "_live_", "51HqT9xK2mLr8VbN4cWzP7yJd3"}, "")

type fakeDNS map[string][]string

func (d fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) { return d[name], nil }
func (d fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if len(d["mx:"+name]) > 0 {
		return []*net.MX{{Host: d["mx:"+name][0]}}, nil
	}
	return nil, nil
}

func findingIDs(fs []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}

func TestCheckFindings(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "x", Path: "/"})
		_, _ = w.Write([]byte(`<html><head><title>Shop</title>
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://code.jquery.com/ui/1.13.2/jquery-ui.min.js" integrity="sha384-x" crossorigin="anonymous"></script>
<script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.4"></script>
<script src="/js/app.js"></script>
<script>var stripe = "` + testStripeKey + `";</script>
</head><body><form action="/login" method="post"><input name="u"><input type="password" name="p"></form></body></html>`))
	})
	mux.HandleFunc("/js/app.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`const k = "` + testStripeKey + `";`)) // the same key: one finding, two places
	})
	mux.HandleFunc("/wp-content/plugins/contact-form-7/includes/js/index.js", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("(function(){})();"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL, _ := url.Parse(srv.URL)

	probed := false
	c := &Checker{Intel: fakeIntel{}, Client: &http.Client{Transport: rewrite{srvURL.Host}, CheckRedirect: checkRedirect},
		DNS:    fakeDNS{"_dmarc.example.com": {"v=DMARC1; p=none"}, "mx:example.com": {"mx.example.com"}},
		OldTLS: func(context.Context, *url.URL) bool { probed = true; return true }}
	target, _ := Target("http://shop.example.com/")
	r, err := c.Check(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	got := findingIDs(r.Findings)
	leak := got["leak-stripe-live-key"]
	if leak.Severity != "critical" || len(leak.Where) != 2 {
		t.Errorf("leaked key: %+v", leak)
	}
	for _, f := range r.Findings {
		if strings.Contains(f.Title+f.Detail+strings.Join(f.Where, " "), testStripeKey) {
			t.Fatalf("finding reveals the key: %+v", f)
		}
	}
	if f := got["password-over-http"]; f.Severity != "high" {
		t.Errorf("password form on an http page: %+v", f)
	}
	if f := got["cookie-no-httponly"]; !strings.Contains(f.Detail, "PHPSESSID") {
		t.Errorf("session cookie without HttpOnly: %+v", f)
	}
	if _, ok := got["cookie-no-secure"]; ok {
		t.Error("Secure is not asked of cookies on an http page")
	}
	if f := got["no-sri"]; len(f.Where) != 1 || !strings.Contains(f.Where[0], "jquery-3.7.1") {
		t.Errorf("CDN script without integrity: %+v", f)
	}
	if f := got["no-spf"]; f.Severity != "medium" {
		t.Errorf("no SPF on a domain with mail: %+v", f)
	}
	if _, ok := got["dmarc-none"]; !ok {
		t.Error("DMARC p=none not reported")
	}
	if probed {
		t.Error("TLS versions probed for an http page")
	}
	if r.Findings[0].Severity != "critical" {
		t.Errorf("findings not worst first: %+v", r.Findings[0])
	}
	if r.Summary.Findings != len(r.Findings) || r.Teaser().Summary.Findings != len(r.Findings) {
		t.Errorf("summary counts %d findings, report has %d", r.Summary.Findings, len(r.Findings))
	}

	var plugin *Software
	for i := range r.Software {
		if r.Software[i].Kind == "plugin" {
			plugin = &r.Software[i]
		}
	}
	if plugin == nil || plugin.Name != "contact-form-7" || plugin.Version != "5.8.4" || plugin.Coverage == "" || plugin.EndOfLife != nil {
		t.Errorf("WordPress plugin: %+v", plugin)
	}
}

func TestHTTPSFindings(t *testing.T) {
	final, _ := url.Parse("https://www.example.com/")
	body := []byte(`<html><head><title>Index of /files</title><script src="http://cdn.example.net/a.js"></script></head>
<body><img src="http://img.example.net/x.png"><form action="http://www.example.com/login"><input type="password"></form></body></html>`)
	h := http.Header{}
	h.Add("Set-Cookie", "session=1; Path=/; HttpOnly; SameSite=Lax")
	h.Set("Server", "cloudflare")
	c := &Checker{DNS: fakeDNS{"example.com": {"v=spf1 +all"}, "_dmarc.example.com": {"v=DMARC1; p=reject"}},
		OldTLS: func(_ context.Context, u *url.URL) bool { return u.Hostname() == "www.example.com" }}
	got := findingIDs(c.findings(context.Background(), final, h, parsePage(final, body), nil))
	for _, id := range []string{"tls-old-versions", "cookie-no-secure", "mixed-content-active", "mixed-content-passive", "password-over-http", "directory-listing", "spf-allows-all"} {
		if _, ok := got[id]; !ok {
			t.Errorf("missing %s; got %v", id, got)
		}
	}
	if !strings.Contains(got["tls-old-versions"].Fix, "Cloudflare") {
		t.Errorf("a site behind Cloudflare is told where the setting is: %q", got["tls-old-versions"].Fix)
	}
	if got["cookie-no-secure"].Severity != "medium" {
		t.Errorf("a session cookie without Secure is medium: %+v", got["cookie-no-secure"])
	}
	for _, id := range []string{"no-dmarc", "dmarc-none", "no-spf", "cookie-no-httponly"} {
		if _, ok := got[id]; ok {
			t.Errorf("unexpected %s", id)
		}
	}
}

// A site on a hosting platform's domain has no email records of its own.
func TestEmailSkippedOnPlatformDomains(t *testing.T) {
	final, _ := url.Parse("https://my-app.herokuapp.com/")
	c := &Checker{DNS: fakeDNS{}, OldTLS: func(context.Context, *url.URL) bool { return false }}
	for _, f := range c.findings(context.Background(), final, http.Header{}, parsePage(final, nil), nil) {
		if f.Category == "Email" {
			t.Errorf("email finding on a platform domain: %+v", f)
		}
	}
}
