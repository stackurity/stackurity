package sitecheck

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTarget(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":                     "https://example.com/",
		"  Example.com/shop ":             "https://Example.com/shop",
		"http://example.com":              "http://example.com/",
		"https://www.example.com:443/a#b": "https://www.example.com:443/a",
	} {
		u, err := Target(in)
		if err != nil || u.String() != want {
			t.Errorf("Target(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "http://localhost:8080", "127.0.0.1", "https://10.0.0.1/", "http://[::1]/",
		"ftp://example.com", "https://user:pw@example.com", "https://example.com:8443/", "intranet", "db.internal",
		"printer.local", "http://2130706433/", "http://0x7f000001/", "https://example.com:22"} {
		if _, err := Target(in); !errors.Is(err, ErrTarget) {
			t.Errorf("Target(%q) = %v, want ErrTarget", in, err)
		}
	}
}

// fakeIntel answers from tables.
type fakeIntel struct{}

func (fakeIntel) Vulnerabilities(_ context.Context, sw Software) ([]Issue, string, error) {
	switch sw.Package + "@" + sw.Version {
	case "jquery@1.12.4":
		return []Issue{{ID: "GHSA-low", Severity: "medium", Score: 6.1, FixedIn: "3.5.0"},
			{ID: "GHSA-kev", Severity: "high", Score: 7.5, KnownExploited: true, FixedIn: "3.5.0"}}, "", nil
	case "nginx@1.18.0":
		return nil, "no vulnerability data stored for nginx yet", nil
	}
	return nil, "", nil
}

func (fakeIntel) EndOfLife(_ context.Context, sw Software) (*EOL, error) {
	if sw.Lifecycle == "php" && strings.HasPrefix(sw.Version, "7.4") {
		return &EOL{Product: "php", Cycle: "7.4", Ended: true, Latest: "7.4.33"}, nil
	}
	return nil, nil
}

func TestCheck(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0 (Ubuntu)")
		w.Header().Set("X-Powered-By", "PHP/7.4.3")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.3.1/dist/js/bootstrap.min.js"></script>
<script src="/js/jquery.min.js?ver=1"></script><script src="/missing.js"></script>
<link rel="stylesheet" href="/css/site.css"></head><body>hi</body></html>`))
	})
	mux.HandleFunc("/js/jquery.min.js", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") == "" {
			t.Error("script read without a Range header")
		}
		_, _ = w.Write([]byte("/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(){}"))
	})
	mux.HandleFunc("/missing.js", http.NotFound)
	mux.HandleFunc("/css/site.css", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("body{}")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// The test server is on loopback, which Target refuses; the client
	// routes example.test to it instead.
	srvURL, _ := url.Parse(srv.URL)
	client := &http.Client{Transport: rewrite{srvURL.Host}, CheckRedirect: checkRedirect}
	c := &Checker{Intel: fakeIntel{}, Client: client, Now: func() time.Time { return time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC) }}
	target, err := Target("http://shop.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	r, err := c.Check(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Software{}
	for _, sw := range r.Software {
		got[sw.Name+" "+sw.Version] = sw
	}
	for _, want := range []string{"nginx 1.18.0", "PHP 7.4.3", "WordPress 6.4.2", "bootstrap 4.3.1", "jquery 1.12.4"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, keys(got))
		}
	}
	if r.Software[0].Kind != "server" {
		t.Errorf("servers first, got %+v", r.Software[0])
	}
	jq := got["jquery 1.12.4"]
	if len(jq.Issues) != 2 || jq.Issues[0].ID != "GHSA-kev" || !strings.HasSuffix(jq.Where, "/js/jquery.min.js?ver=1") {
		t.Errorf("jquery: %+v", jq)
	}
	if got["nginx 1.18.0"].Coverage == "" || got["WordPress 6.4.2"].Coverage == "" {
		t.Error("software without vulnerability data must say so")
	}
	if eol := got["PHP 7.4.3"].EndOfLife; eol == nil || !eol.Ended {
		t.Errorf("PHP 7.4 end of life: %+v", eol)
	}
	s := r.Summary
	if s.Issues != 2 || s.High != 1 || s.KnownExploited != 1 || s.EndOfLife != 1 || s.Software != 5 {
		t.Errorf("summary %+v", s)
	}
	if !hasNote(r.Notes, "plain http") || !hasNote(r.Notes, "1 of the page's scripts") {
		t.Errorf("notes %v", r.Notes)
	}
	for _, h := range r.Headers {
		if h.Name == "Strict-Transport-Security" {
			t.Error("HSTS is not checked on a plain http page")
		}
		if h.Name == "X-Content-Type-Options" && !h.Present {
			t.Error("nosniff was sent")
		}
	}

	tz := r.Teaser()
	if tz.Worst == nil || tz.Worst.ID != "GHSA-kev" || tz.Worst.Summary != "" || tz.WorstIn != "jquery 1.12.4" {
		t.Errorf("teaser worst %+v in %q", tz.Worst, tz.WorstIn)
	}
	if len(tz.Software) != 5 || tz.Summary != r.Summary {
		t.Errorf("teaser %+v", tz)
	}
}

func TestRedirectToPrivateRefused(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost/", nil)
	if err := checkRedirect(req, nil); !errors.Is(err, ErrTarget) {
		t.Errorf("redirect to localhost: %v", err)
	}
	req = httptest.NewRequest("GET", "https://example.com/", nil)
	if err := checkRedirect(req, make([]*http.Request, maxRedirects+1)); err == nil {
		t.Error("too many redirects allowed")
	}
}

// The guarded client must not reach loopback even when a name resolves
// there.
func TestGuardedClientRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, _, err := get(context.Background(), guardedClient(), srv.URL, 100, false)
	if err == nil {
		t.Fatal("reached a loopback server")
	}
}

type rewrite struct{ host string }

func (rw rewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.URL.Host = rw.host
	resp, err := http.DefaultTransport.RoundTrip(c)
	if resp != nil {
		resp.Request = r // as a real request to the named host would
	}
	return resp, err
}

func keys(m map[string]Software) (out []string) {
	for k := range m {
		out = append(out, k)
	}
	return out
}

func hasNote(notes []string, s string) bool {
	for _, n := range notes {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}
