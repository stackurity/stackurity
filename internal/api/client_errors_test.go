package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

// What the dashboard sends for Settings → Plan and billing's 404, with an
// address, an email and an id it should never have sent.
var billingReport = map[string]any{"reports": []map[string]any{{
	"source": "api", "route": "/settings/billing?ws=42", "method": "GET", "api_route": "/api/v1/billing/7?x=1",
	"status": 404, "code": "not_found", "name": "ApiError", "message": "not found for ops@acme.example",
	"version": "0.15.0", "browser": "Chrome 131", "page_id": "k3j4h5g6f7d8s9a0",
	"stack": []string{"https://app.example/static/index-AbCdEf12.js:1:2", "chrome-extension://x/y.js:1:1"},
}}}

func clientErrorsEnv(t *testing.T, on bool) *env {
	return newEnvWith(t, func(s *api.Server) { s.ClientErrors = on })
}

func (e *env) clientErrorRows(ctx context.Context) []map[string]any {
	e.t.Helper()
	rows, err := e.st.Pool.Query(ctx, `SELECT workspace_id, kind, route, method, api_route, status, code, name, top_frame, count, sample
		FROM client_errors ORDER BY id`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		v, err := rows.Values()
		if err != nil {
			e.t.Fatal(err)
		}
		names := []string{"workspace_id", "kind", "route", "method", "api_route", "status", "code", "name", "top_frame", "count", "sample"}
		m := map[string]any{}
		for i, n := range names {
			m[n] = v[i]
		}
		out = append(out, m)
	}
	return out
}

func TestClientErrorsReported(t *testing.T) {
	e := clientErrorsEnv(t, true)
	e.user("owner@x.io", auth.RoleAdmin)
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	owner, admin := e.login("owner@x.io"), e.login("admin@x.io")
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	sys := tenant.System(context.Background())

	var meta map[string]any
	if e.anon().do("GET", "/api/v1/meta", nil, &meta); meta["client_errors"] != true {
		t.Errorf("meta does not say reports are kept: %v", meta)
	}
	if code := admin.do("POST", "/api/v1/client-errors", billingReport, nil); code != 204 {
		t.Fatalf("report: %d", code)
	}
	rows := e.clientErrorRows(ws)
	if len(rows) != 1 {
		t.Fatalf("rows: %+v", rows)
	}
	r := rows[0]
	if r["route"] != "/settings/billing" || r["api_route"] != "/api/v1/billing/{id}" || r["status"] != int32(404) ||
		r["code"] != "not_found" || r["top_frame"] != "static/index.js:1:2" || r["count"] != int64(1) || r["kind"] != "client" {
		t.Errorf("row: %+v", r)
	}
	sample, _ := json.Marshal(r["sample"])
	for _, leak := range []string{"ops@acme", "42", "x=1", "chrome-extension"} {
		if strings.Contains(string(sample), leak) {
			t.Errorf("sample keeps %q: %s", leak, sample)
		}
	}

	// A real route is stored as the router's pattern.
	known := map[string]any{"reports": []map[string]any{{"source": "api", "route": "/assets/:id", "method": "GET",
		"api_route": "/api/v1/assets/31/stack", "status": 500, "code": "internal"}}}
	if code := admin.do("POST", "/api/v1/client-errors", known, nil); code != 204 {
		t.Fatalf("report: %d", code)
	}
	if rows := e.clientErrorRows(ws); len(rows) != 2 || rows[1]["api_route"] != "/api/v1/assets/{id}/stack" {
		t.Errorf("pattern: %+v", rows)
	}

	// Before sign-in: kept with no workspace.
	if code := e.anon().do("POST", "/api/v1/client-errors", billingReport, nil); code != 204 {
		t.Fatalf("anonymous report: %d", code)
	}
	if n := len(e.clientErrorRows(sys)); n != 3 {
		t.Errorf("%d rows in all, want 3", n)
	}
	if n := len(e.clientErrorRows(ws)); n != 2 {
		t.Errorf("the workspace sees %d rows, want its own 2", n)
	}

	// API tokens are not the dashboard.
	var tok struct {
		Secret string `json:"secret"`
	}
	if code := owner.do("POST", "/api/v1/tokens", map[string]string{"name": "ci", "role": "viewer"}, &tok); code != 201 {
		t.Fatalf("token: %d", code)
	}
	b, _ := json.Marshal(billingReport)
	if code := bearer(e, tok.Secret, "POST", "/api/v1/client-errors", b, nil); code != 403 {
		t.Errorf("token: %d, want 403", code)
	}
	// Too large.
	big := map[string]any{"reports": []map[string]any{{"source": "error", "route": "/x", "message": strings.Repeat("x", 17<<10)}}}
	if code := admin.do("POST", "/api/v1/client-errors", big, nil); code != 413 {
		t.Errorf("17 KB: %d, want 413", code)
	}
	// A beacon has no CSRF header; the browser's Sec-Fetch-Site does instead.
	post := func(hdr map[string]string) int {
		resp := admin.req("POST", "/api/v1/client-errors", bytes.NewReader(b), hdr)
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := post(map[string]string{"Content-Type": "text/plain"}); code != 403 {
		t.Errorf("no CSRF header: %d, want 403", code)
	}
	if code := post(map[string]string{"Content-Type": "text/plain", "Sec-Fetch-Site": "cross-site"}); code != 403 {
		t.Errorf("cross-site beacon: %d, want 403", code)
	}
	if code := post(map[string]string{"Content-Type": "text/plain", "Sec-Fetch-Site": "same-origin"}); code != 204 {
		t.Errorf("same-origin beacon: %d, want 204", code)
	}

	// Instance administrators see them on Platform health; nobody else.
	if code := admin.do("GET", "/api/v1/admin/client-errors", nil, nil); code != 403 {
		t.Errorf("workspace admin: %d, want 403", code)
	}
	var sum struct {
		Enabled bool `json:"enabled"`
		New     []struct {
			Route      string          `json:"route"`
			Count      int             `json:"count"`
			Workspaces int             `json:"workspaces"`
			Sample     json.RawMessage `json:"sample"`
		} `json:"new"`
		Top []struct {
			Count int `json:"count"`
		} `json:"top"`
	}
	if code := owner.do("GET", "/api/v1/admin/client-errors", nil, &sum); code != 200 {
		t.Fatalf("instance admin: %d", code)
	}
	if !sum.Enabled || len(sum.New) != 2 || len(sum.Top) != 2 || sum.Top[0].Count != 3 {
		t.Errorf("summary: %+v", sum)
	}
}

func TestClientErrorsRateLimited(t *testing.T) {
	e := clientErrorsEnv(t, true)
	anon := e.anon()
	for i := range 31 {
		code := anon.do("POST", "/api/v1/client-errors", billingReport, nil)
		if i < 30 && code != 204 || i == 30 && code != 429 {
			t.Fatalf("report %d: %d", i+1, code)
		}
	}
}

func TestClientErrorsOff(t *testing.T) {
	e := clientErrorsEnv(t, false)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var meta map[string]any
	if e.anon().do("GET", "/api/v1/meta", nil, &meta); meta["client_errors"] != nil {
		t.Errorf("meta with reports off: %v", meta)
	}
	for range 40 { // no rate limit either: nothing is counted
		if code := admin.do("POST", "/api/v1/client-errors", billingReport, nil); code != 204 {
			t.Fatalf("report while off: %d", code)
		}
	}
	if rows := e.clientErrorRows(tenant.System(context.Background())); len(rows) != 0 {
		t.Errorf("kept while off: %+v", rows)
	}
	var n int
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM rate_limits WHERE key LIKE 'client-errors%'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d rate limit rows while off (%v)", n, err)
	}
}
