package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeAPI struct{ paths []string }

func (f *fakeAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	f.paths = append(f.paths, method+" "+path)
	var body string
	switch {
	case strings.HasPrefix(path, "/api/v1/findings?"):
		body = `{"items":[{"id":7,"key":"CVE-1","severity":"critical","asset_name":"shop","fixed_version":"1.2.3","evidence":{"big":"x"}}],"total":1}`
	case strings.HasPrefix(path, "/api/v1/fix-groups?"):
		body = `{"items":[{"id":"3:package_upgrade:9","kind":"package_upgrade","asset_id":3,"component":"lodash","from_version":"4.17.15",
			"to_version":"4.17.21","recommended_version":"4.17.23","target_version":"4.17.23","change_type":"patch","finding_count":2,"top_priority":"P2",
			"by_severity":{"high":2}}],"total":1}`
	case strings.HasSuffix(path, "/explain"), strings.HasSuffix(path, "/upgrade"), strings.HasPrefix(path, "/api/v1/findings/verify?"):
		body = `{"ok":true}`
	default:
		body = `{"items":[],"total":0}`
	}
	return json.Unmarshal([]byte(body), out)
}

func run(t *testing.T, api API, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	s := &Server{API: api, Version: "test", AllowWrites: true}
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	dec := json.NewDecoder(&out)
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatal(err)
		}
		res = append(res, m)
	}
	return res
}

func TestProtocol(t *testing.T) {
	api := &fakeAPI{}
	res := run(t, api,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"asset_id":3,"severity":"critical,high","known_exploited":true}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"get_finding","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}`,
		`{"jsonrpc":"2.0","id":6,"method":"resources/list"}`,
		`not json`,
	)
	if len(res) != 7 {
		t.Fatalf("want 7 responses (the notification gets none), got %d: %v", len(res), res)
	}
	init := res[0]["result"].(map[string]any)
	if init["protocolVersion"] != "2025-03-26" || init["serverInfo"].(map[string]any)["name"] != "stackurity" {
		t.Errorf("initialize = %v", init)
	}
	tl := res[1]["result"].(map[string]any)["tools"].([]any)
	if len(tl) != len(readTools)+len(writeTools) || len(readTools) != 11 || len(writeTools) != 10 {
		t.Errorf("tools = %d", len(tl))
	}
	for i, x := range tl {
		ann := x.(map[string]any)["annotations"].(map[string]any)
		if ann["readOnlyHint"] != (i < len(readTools)) {
			t.Errorf("tool %d marked readOnlyHint %v: %v", i, ann["readOnlyHint"], x)
		}
		if _, ok := tools[x.(map[string]any)["name"].(string)]; !ok {
			t.Errorf("listed tool without an implementation: %v", x)
		}
	}
	if len(tools) != len(tl) {
		t.Errorf("%d tools implemented, %d listed", len(tools), len(tl))
	}
	call := res[2]["result"].(map[string]any)
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"id": 7`) || !strings.Contains(text, `"fixed_version": "1.2.3"`) || strings.Contains(text, "big") {
		t.Errorf("list_findings text = %s", text)
	}
	if got := api.paths[0]; !strings.Contains(got, "asset_id=3") || !strings.Contains(got, "known_exploited=true") ||
		!strings.Contains(got, "severity=critical%2Chigh") {
		t.Errorf("request = %s", got)
	}
	if res[3]["result"].(map[string]any)["isError"] != true {
		t.Errorf("missing argument should be a tool error: %v", res[3])
	}
	if res[4]["error"] == nil || res[5]["error"] == nil {
		t.Errorf("unknown tool/method should be protocol errors: %v %v", res[4], res[5])
	}
	if e := res[6]["error"].(map[string]any); e["code"] != float64(-32700) {
		t.Errorf("parse error = %v", e)
	}
	for _, p := range api.paths {
		if !strings.HasPrefix(p, "GET ") {
			t.Errorf("tools must only read: %s", p)
		}
	}
}

func TestAssistantTools(t *testing.T) {
	api := &fakeAPI{}
	res := run(t, api,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"explain_finding","arguments":{"finding_id":7}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"upgrade_recommendation","arguments":{"finding_id":7}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"upgrade_recommendation","arguments":{"component_id":9}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"upgrade_recommendation","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"remediation_plan","arguments":{"asset_id":3,"limit":500}}}`,
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"verify_since","arguments":{"since":"2026-10-20","asset_id":3,"limit":1000}}}`,
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"verify_since","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"explain_finding","arguments":{"finding_id":"x"}}}`,
	)
	text := func(i int) string {
		return res[i]["result"].(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	}
	for _, i := range []int{3, 6, 7} {
		if res[i]["result"].(map[string]any)["isError"] != true {
			t.Errorf("call %d should be a tool error: %v", i+1, res[i])
		}
	}
	want := []string{
		"GET /api/v1/findings/7/explain",
		"GET /api/v1/findings/7/upgrade",
		"GET /api/v1/components/9/upgrade",
		"GET /api/v1/fix-groups?asset_id=3&limit=100",
		"GET /api/v1/findings/verify?asset_id=3&limit=200&since=2026-10-20",
	}
	if strings.Join(api.paths, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests = %v", api.paths)
	}
	plan := text(4)
	for _, s := range []string{`"minimum_fixed_version": "4.17.21"`, `"recommended_version": "4.17.23"`, `"target_version": "4.17.23"`, `"installed_version": "4.17.15"`, `"shown": 1`} {
		if !strings.Contains(plan, s) {
			t.Errorf("remediation_plan lacks %s: %s", s, plan)
		}
	}
	if strings.Contains(plan, "by_severity") {
		t.Errorf("remediation_plan passes through unbounded fields: %s", plan)
	}
}

// writeAPI answers the reads write tools make and records every request.
type writeAPI struct {
	reqs []string
	role string
}

func (f *writeAPI) Do(_ context.Context, method, path string, body io.Reader, _ map[string]string, out any) error {
	var b []byte
	if body != nil {
		b, _ = io.ReadAll(body)
	}
	f.reqs = append(f.reqs, strings.TrimSpace(method+" "+path+" "+string(b)))
	var resp string
	switch {
	case path == "/api/v1/auth/me":
		resp = `{"user":{"id":5,"email":"me@x.io"},"role":"` + f.role + `","project_role":""}`
	case strings.HasPrefix(path, "/api/v1/projects/") && method == "GET":
		resp = `{"project":{"id":3,"name":"Shop"}}`
	case strings.HasPrefix(path, "/api/v1/assets/") && method == "GET":
		resp = `{"asset":{"id":9,"name":"web-1"}}`
	case strings.HasPrefix(path, "/api/v1/findings/") && method == "GET":
		resp = `{"finding":{"id":7,"key":"CVE-1","asset_name":"web-1"}}`
	case strings.HasPrefix(path, "/api/v1/fix-groups/") && method == "GET":
		resp = `{"group":{"title":"Upgrade lodash","asset_name":"web-1"},"findings":{"items":[{"id":7},{"id":8}],"total":2}}`
	case path == "/api/v1/findings/actions":
		resp = `{"applied":2}`
	case path == "/api/v1/invitations":
		resp = `{"invitation":{"id":2},"emailed":false,"link":"https://stk.example/invite#inv_secret"}`
	case path == "/api/v1/enrollments":
		resp = `{"enrollment":{"id":4},"code":"enr_abc"}`
	default:
		resp = `{"id":1}`
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal([]byte(resp), out)
}

func (f *writeAPI) writes() []string {
	var w []string
	for _, r := range f.reqs {
		if !strings.HasPrefix(r, "GET ") {
			w = append(w, r)
		}
	}
	return w
}

func callTool(t *testing.T, s *Server, name string, args map[string]any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	res, rerr := s.handle(context.Background(), request{Method: "tools/call", Params: raw})
	if rerr != nil {
		t.Fatalf("%s: %v", name, rerr)
	}
	m := res.(map[string]any)
	text := m["content"].([]map[string]any)[0]["text"].(string)
	if m["isError"] == true {
		return map[string]any{"error": text}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("%s: %s", name, text)
	}
	return out
}

// TestWriteToolsNeedConfirmation: every write tool answers a preview and
// changes nothing without the preview's code; with it, it makes exactly
// one change; a code for other arguments is refused.
func TestWriteToolsNeedConfirmation(t *testing.T) {
	future := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	cases := map[string]map[string]any{
		"create_project":             {"name": "Shop", "asset_ids": []any{9.0}},
		"rename_project":             {"project_id": 3.0, "name": "Shop 2"},
		"add_assets_to_project":      {"project_id": 3.0, "asset_ids": []any{9.0}},
		"remove_assets_from_project": {"project_id": 3.0, "asset_ids": []any{9.0}},
		"create_enrollment":          {"servers": 3.0, "project_id": 3.0},
		"assign":                     {"fix_group": "9:package_upgrade:1", "assignee": "me"},
		"snooze":                     {"finding_ids": []any{7.0}, "until": future},
		"ignore":                     {"finding_ids": []any{7.0}, "reason": "mitigated", "note": "behind the WAF", "expiry": "date", "until": future},
		"check_again":                {"fix_group": "9:package_upgrade:1"},
		"invite_to_project":          {"email": "new@x.io", "project_id": 3.0, "role": "viewer"},
	}
	if len(cases) != len(writeTools) {
		t.Fatalf("a write tool has no case here")
	}
	for name, args := range cases {
		api := &writeAPI{role: "admin"}
		s := &Server{API: api, Version: "test", BaseURL: "https://stk.example", AllowWrites: true}
		pv := callTool(t, s, name, args)
		if pv["status"] != "preview" || pv["confirm"] == "" || len(api.writes()) != 0 {
			t.Errorf("%s without confirm: %v, writes %v", name, pv, api.writes())
			continue
		}
		wrong := map[string]any{"confirm": "000000000000"}
		for k, v := range args {
			wrong[k] = v
		}
		if out := callTool(t, s, name, wrong); out["status"] != "preview" || out["note"] == nil || len(api.writes()) != 0 {
			t.Errorf("%s with a wrong code: %v", name, out)
		}
		changed := map[string]any{"confirm": pv["confirm"]}
		for k, v := range args {
			changed[k] = v
		}
		if name == "rename_project" {
			changed["name"] = "Something else"
			if out := callTool(t, s, name, changed); out["status"] != "preview" || len(api.writes()) != 0 {
				t.Errorf("%s: the code worked for other arguments: %v", name, out)
			}
			changed["name"] = args["name"]
		}
		done := callTool(t, s, name, changed)
		if done["status"] != "done" || len(api.writes()) != 1 {
			t.Errorf("%s confirmed: %v, writes %v", name, done, api.writes())
		}
	}

	// The install command, and an ignore by someone without security: a
	// request for approval.
	api := &writeAPI{role: "admin"}
	s := &Server{API: api, BaseURL: "http://stk.internal:8080", AllowWrites: true}
	pv := callTool(t, s, "create_enrollment", map[string]any{"servers": 2.0})
	done := callTool(t, s, "create_enrollment", map[string]any{"servers": 2.0, "confirm": pv["confirm"]})
	cmd, _ := done["result"].(map[string]any)["install_command"].(string)
	if cmd != "curl -fsSL http://stk.internal:8080/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_abc STACKURITY_ALLOW_HTTP=1 sh" {
		t.Errorf("install command = %q", cmd)
	}
	// Servers enrolled from a chat look for websites and apps too, unless told not to.
	if w := api.writes(); len(w) != 1 || !strings.Contains(w[0], `"discover_apps":true`) {
		t.Errorf("create_enrollment sent %v", w)
	}
	pv = callTool(t, s, "create_enrollment", map[string]any{"servers": 1.0, "check_apps": false})
	callTool(t, s, "create_enrollment", map[string]any{"servers": 1.0, "check_apps": false, "confirm": pv["confirm"]})
	if w := api.writes(); len(w) != 2 || !strings.Contains(w[1], `"discover_apps":false`) {
		t.Errorf("create_enrollment without apps sent %v", w)
	}
	api = &writeAPI{role: "engineer"}
	s = &Server{API: api, AllowWrites: true}
	args := map[string]any{"fix_group": "9:package_upgrade:1", "reason": "no_fix", "note": "n", "expiry": "until_fix"}
	pv = callTool(t, s, "ignore", args)
	if !strings.HasPrefix(pv["will"].(string), "Ask to ignore 2 issues") {
		t.Errorf("ignore as engineer: %v", pv)
	}
	args["confirm"] = pv["confirm"]
	callTool(t, s, "ignore", args)
	if w := api.writes(); len(w) != 1 || !strings.HasPrefix(w[0], "POST /api/v1/ignore-requests ") || !strings.Contains(w[0], `"fix_group":"9:package_upgrade:1"`) {
		t.Errorf("ignore as engineer sent %v", w)
	}
	if out := callTool(t, s, "snooze", map[string]any{"finding_ids": []any{7.0}, "until_fix": true}); !strings.Contains(fmt.Sprint(out["error"]), "security role") {
		t.Errorf("snooze as engineer: %v", out)
	}
}

// TestModernEra: requests with per-request _meta (2026-07-28) need no
// initialize, get resultType, and an unknown version lists the supported.
func TestModernEra(t *testing.T) {
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"%s","io.modelcontextprotocol/clientInfo":{"name":"t","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	res := run(t, &fakeAPI{},
		`{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+fmt.Sprintf(meta, "2026-07-28")+`}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{`+fmt.Sprintf(meta, "2026-07-28")+`}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{`+fmt.Sprintf(meta, "1900-01-01")+`}}`,
	)
	d := res[0]["result"].(map[string]any)
	if d["resultType"] != "complete" || d["supportedVersions"].([]any)[0] != "2026-07-28" {
		t.Errorf("discover = %v", d)
	}
	if res[1]["result"].(map[string]any)["resultType"] != "complete" {
		t.Errorf("tools/list = %v", res[1])
	}
	e := res[2]["error"].(map[string]any)
	if e["code"] != float64(-32022) || e["data"].(map[string]any)["requested"] != "1900-01-01" {
		t.Errorf("unsupported version = %v", e)
	}
}

func TestHTTPTransport(t *testing.T) {
	post := func(body string, hdr map[string]string) (int, map[string]any) {
		r := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		(&Server{API: &fakeAPI{}, Version: "t"}).ServeHTTP(w, r)
		var m map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &m)
		return w.Code, m
	}
	modern := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_assets","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	hdr := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "list_assets"}
	if code, m := post(modern, hdr); code != 200 || m["result"].(map[string]any)["resultType"] != "complete" {
		t.Errorf("modern call: %d %v", code, m)
	}
	hdr["Mcp-Name"] = "=?base64?" + base64.StdEncoding.EncodeToString([]byte("list_assets")) + "?="
	if code, _ := post(modern, hdr); code != 200 {
		t.Errorf("base64 Mcp-Name: %d", code)
	}
	for _, h := range []string{"MCP-Protocol-Version", "Mcp-Method", "Mcp-Name"} {
		bad := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "list_assets"}
		bad[h] = "search"
		if code, m := post(modern, bad); code != 400 || m["error"].(map[string]any)["code"] != float64(-32020) {
			t.Errorf("mismatched %s: %d %v", h, code, m)
		}
	}
	unknown := `{"jsonrpc":"2.0","id":2,"method":"nope/x","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
	if code, _ := post(unknown, map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "nope/x"}); code != 404 {
		t.Errorf("unknown modern method: %d", code)
	}
	legacy := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	if code, m := post(legacy, nil); code != 200 || m["result"].(map[string]any)["protocolVersion"] != "2025-06-18" {
		t.Errorf("initialize: %d %v", code, m)
	}
	if code, _ := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, map[string]string{"MCP-Protocol-Version": "1999-01-01"}); code != 400 {
		t.Errorf("unsupported legacy header: %d", code)
	}
	if code, _ := post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); code != 202 {
		t.Errorf("notification: %d", code)
	}
	if code, _ := post(`[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil); code != 400 {
		t.Errorf("batch: %d", code)
	}
}

// TestReadOnlyByDefault: without AllowWrites the tools that change
// something are neither listed nor callable, and the instructions say so.
func TestReadOnlyByDefault(t *testing.T) {
	api := &writeAPI{role: "admin"}
	s := &Server{API: api}
	res, _ := s.handle(context.Background(), request{Method: "tools/list"})
	if n := len(res.(map[string]any)["tools"].([]map[string]any)); n != len(readTools) {
		t.Errorf("read-only server lists %d tools", n)
	}
	raw, _ := json.Marshal(map[string]any{"name": "create_project", "arguments": map[string]any{"name": "x"}})
	if _, rerr := s.handle(context.Background(), request{Method: "tools/call", Params: raw}); rerr == nil || !strings.Contains(rerr.Message, "read-only") {
		t.Errorf("write tool on a read-only server: %v", rerr)
	}
	init, _ := s.handle(context.Background(), request{Method: "initialize", Params: json.RawMessage(`{}`)})
	if !strings.Contains(init.(map[string]any)["instructions"].(string), "read-only") || len(api.reqs) != 0 {
		t.Errorf("instructions or requests: %v %v", init, api.reqs)
	}
}

// TestInviteNeverReturnsTheLink: an invitation link is a credential; the
// model gets a sentence instead.
func TestInviteNeverReturnsTheLink(t *testing.T) {
	s := &Server{API: &writeAPI{role: "admin"}, AllowWrites: true}
	args := map[string]any{"email": "new@x.io", "project_id": 3.0, "role": "viewer"}
	pv := callTool(t, s, "invite_to_project", args)
	args["confirm"] = pv["confirm"]
	out, _ := json.Marshal(callTool(t, s, "invite_to_project", args))
	if strings.Contains(string(out), "inv_secret") || strings.Contains(string(out), "/invite") || !strings.Contains(string(out), "does not send email") {
		t.Errorf("invite answer: %s", out)
	}
	if out := callTool(t, s, "create_enrollment", map[string]any{"servers": 51.0}); !strings.Contains(fmt.Sprint(out["error"]), "1 to 50") {
		t.Errorf("51 servers: %v", out)
	}
	if out := callTool(t, s, "create_enrollment", map[string]any{"valid_hours": 48.0}); !strings.Contains(fmt.Sprint(out["error"]), "1 to 24") {
		t.Errorf("48 hours: %v", out)
	}
}
