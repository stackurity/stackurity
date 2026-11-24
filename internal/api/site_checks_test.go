package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// siteOnLoopback serves a small site and returns a client that sends every
// request for any host to it (the guarded client refuses loopback).
func siteOnLoopback(t *testing.T) *http.Client {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		_, _ = w.Write([]byte(`<html><script src="https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js"></script></html>`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return &http.Client{Transport: hostRewrite{u.Host}}
}

type hostRewrite struct{ host string }

func (h hostRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.URL.Scheme, c.URL.Host = "http", h.host
	resp, err := http.DefaultTransport.RoundTrip(c)
	if resp != nil {
		resp.Request = r
	}
	return resp, err
}

func seedJQueryAdvisory(t *testing.T, e *env) {
	ctx := tenant.System(context.Background())
	if err := e.st.EnsureFeed(ctx, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.UpsertAdvisories(ctx, "osv:npm", []*osv.Vulnerability{{ID: "GHSA-gxr4-xjj5-5px2", Aliases: []string{"CVE-2020-11022"},
		Summary: "Potential XSS vulnerability in jQuery", Modified: time.Now(),
		Severity: []osv.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}},
		Affected: []osv.Affected{{Package: osv.Package{Ecosystem: "npm", Name: "jquery"},
			Ranges: []osv.Range{{Type: "SEMVER", Events: []osv.Event{{Introduced: "1.2.0"}, {Fixed: "3.5.0"}}}}}}}}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.ReplaceKnownExploited(ctx, [][]any{{"CVE-2020-11022", "jQuery", "jQuery", "jQuery XSS", time.Now(), time.Now(), false, "x"}}); err != nil {
		t.Fatal(err)
	}
}

// TestSiteChecks: a check runs, is stored and listed, matches the stored
// advisories (with the known-exploited flag), takes one of the plan's
// allowance and is refused with 402 when it is used up; an API token is
// refused on a plan with no_site_check_api; a bad address is 400 and gives
// nothing back to take.
func TestSiteChecks(t *testing.T) {
	o := newOrgWith(t, func(s *api.Server) {})
	o.e.api.SetSiteCheckClient(siteOnLoopback(t))
	seedJQueryAdvisory(t, o.e)
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Starter", SiteChecksPerMonth: one(1), NoSiteCheckAPI: true})

	var res struct {
		store.SiteCheck
		Report struct {
			Host     string
			Software []struct {
				Name, Version string
				Issues        []struct {
					ID             string
					KnownExploited bool   `json:"known_exploited"`
					FixedIn        string `json:"fixed_in"`
				}
				Coverage string
			}
			Summary struct {
				Issues         int
				KnownExploited int `json:"known_exploited"`
			}
		} `json:"report"`
	}
	if code := o.admin.do("POST", "/api/v1/site-checks", map[string]string{"url": "not a host"}, nil); code != 400 {
		t.Errorf("bad address: %d", code)
	}
	if code := o.admin.do("POST", "/api/v1/site-checks", map[string]string{"url": "shop.example.com"}, &res); code != 201 {
		t.Fatalf("check: %d", code)
	}
	if res.ID == 0 || res.Report.Host != "shop.example.com" || res.Report.Summary.Issues != 1 || res.Report.Summary.KnownExploited != 1 || res.KnownExploited != 1 {
		t.Errorf("result %+v", res)
	}
	var sawJQ, sawNginx bool
	for _, sw := range res.Report.Software {
		switch sw.Name + " " + sw.Version {
		case "jquery 3.4.1":
			sawJQ = len(sw.Issues) == 1 && sw.Issues[0].ID == "CVE-2020-11022" && sw.Issues[0].KnownExploited && sw.Issues[0].FixedIn == "3.5.0"
		case "nginx 1.18.0":
			sawNginx = sw.Coverage != "" // no NVD records stored in the test
		}
	}
	if !sawJQ || !sawNginx {
		t.Errorf("software %+v", res.Report.Software)
	}

	// Stored, listed and opened again.
	var list struct{ Items []store.SiteCheck }
	if o.admin.do("GET", "/api/v1/site-checks", nil, &list); len(list.Items) != 1 || list.Items[0].Host != "shop.example.com" || list.Items[0].Report != nil {
		t.Errorf("list %+v", list)
	}
	var again struct {
		store.SiteCheck
		Report map[string]any `json:"report"`
	}
	if code := o.admin.do("GET", "/api/v1/site-checks/"+itoa(res.ID), nil, &again); code != 200 || again.Report["host"] != "shop.example.com" {
		t.Errorf("open: %d %+v", code, again)
	}

	// The allowance is used up; usage shows it.
	resp := o.admin.req("POST", "/api/v1/site-checks", strings.NewReader(`{"url":"shop.example.com"}`), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 402 || !strings.Contains(string(b), "1 website checks a month") || !strings.Contains(string(b), "Upgrade to Starter") {
		t.Errorf("over the allowance: %d %s", resp.StatusCode, b)
	}
	var usage store.AssetUsage
	if o.admin.do("GET", "/api/v1/usage", nil, &usage); usage.Plan == nil || usage.Plan.SiteChecks.Used != 1 || usage.Plan.SiteCheckAPI {
		t.Errorf("usage %+v", usage.Plan)
	}

	// An API token on a plan without API access.
	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Team", SiteChecksPerMonth: one(100), NoSiteCheckAPI: true})
	var tok struct{ Secret string }
	if code := o.admin.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "engineer"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	code, body := bearerBody(o.e, tok.Secret, "POST", "/api/v1/site-checks", []byte(`{"url":"shop.example.com"}`))
	if code != 402 || !strings.Contains(body, "not through the API") || !strings.Contains(body, "Upgrade to Team") {
		t.Errorf("token on a plan without API: %d %s", code, body)
	}
	// With API access it works.
	setPlanLimits(t, o.e, store.PlanLimits{SiteChecksPerMonth: one(100)})
	if code, body := bearerBody(o.e, tok.Secret, "POST", "/api/v1/site-checks", []byte(`{"url":"shop.example.com"}`)); code != 201 || !strings.Contains(body, `"via_api":true`) {
		t.Errorf("token with API access: %d %s", code, body)
	}
}

// TestPublicSiteCheck: the website's endpoint needs its key, answers the
// teaser only and stores nothing.
func TestPublicSiteCheck(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) { s.SiteCheckPublicKey = "site-key" })
	e.api.SetSiteCheckClient(siteOnLoopback(t))
	seedJQueryAdvisory(t, e)
	post := func(key string) (int, string) {
		req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/public/site-check", bytes.NewReader([]byte(`{"url":"shop.example.com"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Stackurity-CSRF", "1")
		if key != "" {
			req.Header.Set("X-Site-Check-Key", key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, _ := post(""); code != 404 {
		t.Errorf("without the key: %d", code)
	}
	if code, _ := post("wrong"); code != 404 {
		t.Errorf("wrong key: %d", code)
	}
	code, body := post("site-key")
	var tz struct {
		Summary  struct{ Issues int }
		Software []map[string]any
		Worst    map[string]any
	}
	_ = json.Unmarshal([]byte(body), &tz)
	if code != 200 || tz.Summary.Issues != 1 || tz.Worst["id"] != "CVE-2020-11022" || tz.Worst["summary"] != nil ||
		strings.Contains(body, "fixed_in") || strings.Contains(body, "Potential XSS") {
		t.Errorf("teaser: %d %s", code, body)
	}
}

// TestRunWebsiteCheckThroughMCP: run_website_check through /mcp with a
// personal token runs a check only after its preview's confirm code, and
// applies the API's own rules: a plan that runs checks from the dashboard
// only and a used-up allowance are refused with the plan line, and an
// address the API refuses never reaches it.
func TestRunWebsiteCheckThroughMCP(t *testing.T) {
	o := newOrgWith(t, func(s *api.Server) {})
	withBaseURL(o.e)
	o.e.api.SetSiteCheckClient(siteOnLoopback(t))
	seedJQueryAdvisory(t, o.e)
	var tok struct{ Secret string }
	if code := o.admin.do("POST", "/api/v1/tokens", map[string]any{"name": "assistant", "role": "engineer"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	run := func(args map[string]any) (map[string]any, string) {
		t.Helper()
		text, isErr := callMCPTool(t, o.e, tok.Secret, "run_website_check", args)
		if isErr {
			return nil, text
		}
		var out map[string]any
		if err := json.Unmarshal([]byte(text), &out); err != nil {
			t.Fatalf("%s", text)
		}
		return out, ""
	}
	checks := func() int {
		var list struct{ Items []store.SiteCheck }
		o.admin.do("GET", "/api/v1/site-checks", nil, &list)
		return len(list.Items)
	}

	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Team", SiteChecksPerMonth: one(10), NoSiteCheckAPI: true})
	if _, msg := run(map[string]any{"url": "shop.example.com"}); !strings.Contains(msg, "from an assistant or API token is not included") ||
		!strings.Contains(msg, "the Team plan") {
		t.Errorf("dashboard-only plan: %q", msg)
	}

	setPlanLimits(t, o.e, store.PlanLimits{NextPlan: "Team", SiteChecksPerMonth: one(1)})
	pv, msg := run(map[string]any{"url": "shop.example.com"})
	if pv == nil || pv["status"] != "preview" || checks() != 0 {
		t.Fatalf("preview: %v %s", pv, msg)
	}
	done, msg := run(map[string]any{"url": "shop.example.com", "confirm": pv["confirm"]})
	if done == nil || done["status"] != "done" || checks() != 1 {
		t.Fatalf("confirmed: %v %s", done, msg)
	}
	res := done["result"].(map[string]any)
	if res["check_id"] == nil || res["host"] != "shop.example.com" || res["known_exploited"] != 1.0 {
		t.Errorf("result: %v", res)
	}
	if _, msg := run(map[string]any{"url": "shop.example.com"}); !strings.Contains(msg, "used all 1 website checks") {
		t.Errorf("allowance used up: %q", msg)
	}

	setPlanLimits(t, o.e, store.PlanLimits{})
	if _, msg := run(map[string]any{"url": "http://127.0.0.1/", "confirm": "000000000000"}); !strings.Contains(msg, "not a public website address") || checks() != 1 {
		t.Errorf("loopback address: %q", msg)
	}
}
