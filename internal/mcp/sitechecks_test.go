package mcp

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/client"
)

// siteCheckAPI answers what run_website_check reads and writes. usage is
// GET /api/v1/usage's body; post is POST /api/v1/site-checks's error, if
// any.
type siteCheckAPI struct {
	writeAPI
	usage string
	off   bool
	post  error
}

func (f *siteCheckAPI) Do(ctx context.Context, method, path string, body io.Reader, h map[string]string, out any) error {
	switch {
	case path == "/api/v1/usage":
		f.reqs = append(f.reqs, "GET "+path)
		return json.Unmarshal([]byte(f.usage), out)
	case strings.HasPrefix(path, "/api/v1/site-checks") && f.off:
		f.reqs = append(f.reqs, method+" "+path)
		return &client.APIError{Status: 404, Code: "not_found", Message: "not found"}
	case path == "/api/v1/site-checks" && method == "POST":
		b, _ := io.ReadAll(body)
		f.reqs = append(f.reqs, "POST "+path+" "+string(b))
		if f.post != nil {
			return f.post
		}
		return json.Unmarshal([]byte(`{"id":42,"url":"https://shop.example.com/","final_url":"https://shop.example.com/","host":"shop.example.com",
			"issues":3,"known_exploited":1,"end_of_life":0,"created_at":"2026-11-25T10:00:00Z",
			"report":{"summary":{"issues":3,"known_exploited":1,"end_of_life":0},"software":[{"name":"jquery"}]}}`), out)
	}
	return f.writeAPI.Do(ctx, method, path, body, h, out)
}

const usageOK = `{"plan":{"plan":"Free","next_plan":"Team","site_checks":{"used":3,"limit":10},"site_check_api":true}}`

func siteServer(api API) *Server { return &Server{API: api, Version: "test", AllowWrites: true} }

// TestRunWebsiteCheckPreviewThenConfirm: the preview checks nothing yet
// and says what the check uses of the allowance; the confirm code runs
// one check of the normalised address and answers its id and how to read
// the report.
func TestRunWebsiteCheckPreviewThenConfirm(t *testing.T) {
	api := &siteCheckAPI{writeAPI: writeAPI{role: "engineer"}, usage: usageOK}
	s := siteServer(api)
	args := map[string]any{"url": "shop.example.com"}
	pv := callTool(t, s, "run_website_check", args)
	if pv["status"] != "preview" || len(api.writes()) != 0 {
		t.Fatalf("preview: %v, writes %v", pv, api.writes())
	}
	d, _ := pv["details"].(map[string]any)
	if d["url"] != "https://shop.example.com/" || !strings.Contains(d["allowance"].(string), "of the organisation's 10 website checks this month (3 used") {
		t.Errorf("preview details = %v", d)
	}
	args["confirm"] = pv["confirm"]
	done := callTool(t, s, "run_website_check", args)
	if done["status"] != "done" {
		t.Fatalf("confirmed: %v", done)
	}
	if w := api.writes(); len(w) != 1 || w[0] != `POST /api/v1/site-checks {"url":"https://shop.example.com/"}` {
		t.Errorf("writes = %v", w)
	}
	res := done["result"].(map[string]any)
	if res["check_id"] != 42.0 || res["issues"] != 3.0 || res["known_exploited"] != 1.0 ||
		!strings.Contains(res["next"].(string), "website_check_report with id 42") || res["software"] != nil {
		t.Errorf("result = %v", res)
	}

	// No plan limits (self-hosted): no allowance to use.
	api = &siteCheckAPI{writeAPI: writeAPI{role: "admin"}, usage: `{"plan":null}`}
	if pv := callTool(t, siteServer(api), "run_website_check", map[string]any{"url": "example.org"}); pv["status"] != "preview" ||
		!strings.Contains(pv["details"].(map[string]any)["allowance"].(string), "no monthly limit") {
		t.Errorf("without plan limits: %v", pv)
	}
}

// TestRunWebsiteCheckPlanRequired: an allowance used up, a plan without
// checks, or a plan that runs them from the dashboard only is answered
// with one plan_required line and no confirm code; the API's own
// plan_limit refusal at confirm time (used up since the preview) is
// answered the same way.
func TestRunWebsiteCheckPlanRequired(t *testing.T) {
	cases := map[string]struct{ usage, want string }{
		"used up": {`{"plan":{"next_plan":"Team","site_checks":{"used":10,"limit":10},"site_check_api":true}}`,
			"used all 10 website checks its plan includes this month; more are available on the 1st (UTC)"},
		"none": {`{"plan":{"next_plan":"Starter","site_checks":{"used":0,"limit":0},"site_check_api":true}}`,
			"Website checks are not included in this organisation's plan; they are part of the Starter plan."},
		"dashboard only": {`{"plan":{"next_plan":"Team","site_checks":{"used":0,"limit":10},"site_check_api":false}}`,
			"from an assistant or API token is not included in this organisation's plan"},
	}
	for name, c := range cases {
		api := &siteCheckAPI{writeAPI: writeAPI{role: "admin"}, usage: c.usage}
		out := callTool(t, siteServer(api), "run_website_check", map[string]any{"url": "shop.example.com"})
		msg, _ := out["error"].(string)
		if !strings.Contains(msg, c.want) || !strings.Contains(msg, "Plans: https://") || strings.Contains(msg, "server returned") ||
			out["confirm"] != nil || len(api.writes()) != 0 {
			t.Errorf("%s: %v", name, out)
		}
	}

	// Used up between the preview and the confirmation: the API refuses.
	api := &siteCheckAPI{writeAPI: writeAPI{role: "admin"}, usage: usageOK}
	s := siteServer(api)
	pv := callTool(t, s, "run_website_check", map[string]any{"url": "shop.example.com"})
	api.usage = `{"plan":{"next_plan":"Team","site_checks":{"used":10,"limit":10},"site_check_api":true}}`
	api.post = &client.APIError{Status: 402, Code: "plan_limit", Message: "your plan allows 10 website checks a month and this organisation has used them all"}
	out := callTool(t, s, "run_website_check", map[string]any{"url": "shop.example.com", "confirm": pv["confirm"]})
	if msg, _ := out["error"].(string); !strings.Contains(msg, "used all 10 website checks") || strings.Contains(msg, "server returned") {
		t.Errorf("refused at confirmation: %v", out)
	}
}

// TestRunWebsiteCheckRefusesBadAddresses: what the API would refuse as
// not a public website address (sitecheck.Target) is refused before
// anything is read or run, confirm code or not.
func TestRunWebsiteCheckRefusesBadAddresses(t *testing.T) {
	for _, u := range []string{"", "localhost", "http://127.0.0.1/", "https://10.0.0.5", "http://[::1]/", "http://169.254.169.254/latest/meta-data",
		"http://user:pw@example.com", "ftp://example.com", "https://example.com:8443", "intranet", "db.internal", "printer.local",
		"http://0x7f000001/", "http://2130706433/"} {
		api := &siteCheckAPI{writeAPI: writeAPI{role: "admin"}, usage: usageOK}
		out := callTool(t, siteServer(api), "run_website_check", map[string]any{"url": u, "confirm": "000000000000"})
		if msg, _ := out["error"].(string); !strings.Contains(msg, "not a public website address") || len(api.reqs) != 0 {
			t.Errorf("%q: %v, requests %v", u, out, api.reqs)
		}
	}
}

// TestRunWebsiteCheckRoleAndAvailability: a viewer is told the role it
// needs; a server with website checks off (or too old) says so.
func TestRunWebsiteCheckRoleAndAvailability(t *testing.T) {
	api := &siteCheckAPI{writeAPI: writeAPI{role: "viewer"}, usage: usageOK}
	if out := callTool(t, siteServer(api), "run_website_check", map[string]any{"url": "shop.example.com"}); !strings.Contains(out["error"].(string), "engineer role") {
		t.Errorf("viewer: %v", out)
	}
	api = &siteCheckAPI{writeAPI: writeAPI{role: "admin"}, usage: usageOK, off: true}
	if out := callTool(t, siteServer(api), "run_website_check", map[string]any{"url": "shop.example.com"}); !strings.Contains(out["error"].(string), "turned off") {
		t.Errorf("checks off: %v", out)
	}
}
