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

	"github.com/stackurity/stackurity/internal/client"
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
			"by_severity":{"high":2}},
			{"id":"3:no_fix","kind":"no_fix","asset_id":3,"finding_count":1,"top_priority":"P2","no_fix_advice":{"sections":[{"kind":"renamed",
			"title":"Fixed under another name","issues":1,"items":[{"component":"babel-traverse","version":"6.26.0","issues":["CVE-2023-45133"],
			"text":"Fixed in @babel/traverse 7.23.2","move_to":"@babel/traverse","fixed_version":"7.23.2"}]}]}}],"total":2}`
	case strings.HasPrefix(path, "/api/v1/leaks?"):
		body = `{"items":[{"id":4,"title":"GitHub token","severity":"critical","state":"still_found","assignee_email":"ravi@x.io",
			"due_at":"2026-11-07T10:00:00Z","overdue":true,"rotated_at":"2026-11-06T09:00:00Z"}],"total":1}`
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
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_findings","arguments":{"asset_id":3,"severity":"critical,high","known_exploited":true,"epss_min":0.1}}}`,
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
	if len(tl) != len(readTools)+len(writeTools) || len(readTools) != 16 || len(writeTools) != 10 {
		t.Errorf("tools = %d", len(tl))
	}
	for i, x := range tl {
		ann := x.(map[string]any)["annotations"].(map[string]any)
		// Directories require a title and all three behaviour hints on every tool.
		if title, _ := x.(map[string]any)["title"].(string); title == "" || ann["title"] != title {
			t.Errorf("tool without a title: %v", x)
		}
		for _, h := range []string{"readOnlyHint", "destructiveHint", "openWorldHint"} {
			if _, ok := ann[h].(bool); !ok {
				t.Errorf("tool %v does not set %s", x.(map[string]any)["name"], h)
			}
		}
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
	hints := map[string][2]bool{} // destructive, open world
	for _, x := range tl {
		ann := x.(map[string]any)["annotations"].(map[string]any)
		hints[x.(map[string]any)["name"].(string)] = [2]bool{ann["destructiveHint"].(bool), ann["openWorldHint"].(bool)}
	}
	for _, n := range []string{"rename_project", "assign", "snooze", "ignore", "remove_assets_from_project"} {
		if !hints[n][0] {
			t.Errorf("%s is not marked destructive", n)
		}
	}
	if !hints["invite_to_project"][1] || hints["create_project"][1] || hints["search"][0] {
		t.Errorf("hints = %v", hints)
	}
	call := res[2]["result"].(map[string]any)
	text := call["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"id": 7`) || !strings.Contains(text, `"fixed_version": "1.2.3"`) || strings.Contains(text, "big") {
		t.Errorf("list_findings text = %s", text)
	}
	if got := api.paths[0]; !strings.Contains(got, "asset_id=3") || !strings.Contains(got, "known_exploited=true") ||
		!strings.Contains(got, "severity=critical%2Chigh") || !strings.Contains(got, "epss_min=0.1") {
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
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"updates_available","arguments":{"asset_id":3,"update_type":"minor","limit":5}}}`,
		`{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"updates_available","arguments":{}}}`,
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
		"GET /api/v1/inventory/updates?asset_id=3&limit=5&update_type=minor",
		"GET /api/v1/inventory/updates?",
	}
	if strings.Join(api.paths, "\n") != strings.Join(want, "\n") {
		t.Errorf("requests = %v", api.paths)
	}
	plan := text(4)
	for _, s := range []string{`"minimum_fixed_version": "4.17.21"`, `"recommended_version": "4.17.23"`, `"target_version": "4.17.23"`, `"installed_version": "4.17.15"`, `"shown": 2`,
		`"move_to": "@babel/traverse"`} {
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
	win, _ := done["result"].(map[string]any)["windows_install_command"].(string)
	if win != "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor 3072; "+
		"$env:STACKURITY_ENROLL_CODE = 'enr_abc'; $env:STACKURITY_ALLOW_HTTP = '1'; irm http://stk.internal:8080/install/agent.ps1 | iex" {
		t.Errorf("windows install command = %q", win)
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

// list_leaks passes the state filter and returns each leak's workflow:
// state, owner, deadline and rotation.
func TestListLeaksWorkflow(t *testing.T) {
	api := &fakeAPI{}
	out := callTool(t, &Server{API: api, Version: "t"}, "list_leaks", map[string]any{"state": "still_found", "severity": "critical,high"})
	if len(api.paths) != 1 || api.paths[0] != "GET /api/v1/leaks?limit=50&severity=critical%2Chigh&state=still_found" {
		t.Errorf("requests = %v", api.paths)
	}
	leaks, _ := out["leaks"].([]any)
	if len(leaks) != 1 {
		t.Fatalf("leaks: %v", out)
	}
	l := leaks[0].(map[string]any)
	if l["state"] != "still_found" || l["assignee_email"] != "ravi@x.io" || l["overdue"] != true || l["due_at"] == nil || l["rotated_at"] == nil {
		t.Errorf("leak: %v", l)
	}
}

// accountAPI answers the account tools' endpoints as a person with role:
// the role checks are the API's (users for admins, channels and rules for
// security, integrations for engineers), as in internal/api. Every answer
// carries the secrets the real endpoints hold, so a test can check that
// none of them gets through.
type accountAPI struct {
	role  string
	paths []string
}

const (
	leakWebhook  = "https://hooks.slack.com/services/T000/B000/sEcReTwEbHoOk"
	leakTeams    = "https://acme.webhook.office.com/webhookb2/abc@def/IncomingWebhook/xyz/teamssecret"
	leakSMTPPass = "smtp-pass-hunter2"
	leakToken    = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	leakEmail    = "colleague.admin@acme.io"
)

func (f *accountAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	f.paths = append(f.paths, method+" "+path)
	rank := map[string]int{"viewer": 1, "engineer": 2, "security": 3, "admin": 4}[f.role]
	need := map[string]int{"/api/v1/users": 4, "/api/v1/channels": 3, "/api/v1/routes": 3, "/api/v1/settings/notifications": 3,
		"/api/v1/integrations": 2, "/api/v1/integrations/github": 2, "/api/v1/integrations/gitlab": 2,
		"/api/v1/integrations/jira/connections": 4, "/api/v1/integrations/digitalocean": 4}[path]
	if rank < need {
		return &client.APIError{Status: 403, Code: "forbidden", Message: "requires a higher role"}
	}
	var body string
	switch path {
	case "/api/v1/auth/me":
		body = `{"user":{"id":1,"email":"me@acme.io","name":"Me"},"role":"` + f.role + `","token":null,"edition":"pro",
			"features":["remediation","teams"],"access":"organisation","project_role":null,"projects":[{"id":1},{"id":2}],
			"workspace":{"id":9,"name":"Acme","slug":"acme","read_only":null,"report_mode":"full"},
			"license_key":{"state":"installed","upgraded":false,"signup_url":"https://stackurity.ai/signup?k=` + leakToken + `"}}`
	case "/api/v1/usage":
		body = `{"monitored":42,"limit":50,"at_limit":false,"by_kind":{"host":30,"repository":12},"stale":3,"workloads":7,
			"refused":[{"name":"secret-host"}],"refused_recently":0,"projects":4,"project_limit":5,"projects_at_limit":false,
			"plan":{"plan":"team","next_plan":"business","members":{"used":6,"limit":10},"allowed_channel_kinds":["email","slack"],
			"sbom_imports":{"used":1,"limit":20},"history_days":365,"api_requests_per_hour":1000}}`
	case "/api/v1/users":
		body = `{"items":[{"id":1,"email":"me@acme.io","name":"Me","role":"admin"},
			{"id":2,"email":"` + leakEmail + `","name":"Priya Admin","role":"admin","phone":"+1 555 0100"},
			{"id":3,"email":"eng@acme.io","name":"Eng","role":"engineer"},
			{"id":4,"email":"p@acme.io","name":"Proj","role":"","access":"projects"},
			{"id":5,"email":"gone@acme.io","name":"Gone","role":"viewer","disabled":true}],"total":5}`
	case "/api/v1/ask/status":
		body = `{"available":true,"reason":"","questions_used":30,"questions_limit":100,"question_period":"month","resets_at":"2026-12-01T00:00:00Z"}`
	case "/api/v1/channels":
		body = `{"items":[
			{"id":1,"kind":"slack","name":"Slack #alerts","enabled":true,"config":{"webhook_url":"` + leakWebhook + `"},
			 "secret_ref":"secret:SLACK_HOOK","secret_source":"stored","last_ok_at":"2026-11-10T00:00:00Z",
			 "last_error":"Post \"` + leakWebhook + `\": 404"},
			{"id":2,"kind":"teams","name":"Teams ops","enabled":false,"config":{"url":"` + leakTeams + `"},"secret_source":"missing"},
			{"id":3,"kind":"email","name":"Security email","enabled":true,"owner_project_id":4,
			 "config":{"to":["` + leakEmail + `"],"smtp_host":"smtp.acme.io","smtp_password":"` + leakSMTPPass + `"}}],"total":3}`
	case "/api/v1/routes":
		body = `{"items":[
			{"id":10,"name":"Critical to Slack","channel_id":1,"enabled":true,"min_priority":"P2","events":["urgent","new_issues"],
			 "mode":"urgent_summary","timezone":"UTC","event_channels":{"daily_summary":3}},
			{"id":11,"name":"Teams digest","channel_id":2,"enabled":true,"min_priority":"P3","events":["daily_summary"],"mode":"daily",
			 "quiet_start":"22:00","quiet_end":"07:00","owner_project_id":4}],"total":2}`
	case "/api/v1/settings/notifications":
		body = `{"project_chat_apps":false}`
	case "/api/v1/integrations":
		body = `{"items":[{"id":5,"kind":"git_repository","name":"shop","enabled":true,"schedule_minutes":360,
			"config":{"url":"https://x-access-token:` + leakToken + `@github.com/acme/shop.git"},"secret_ref":"secret:GH",
			"last_error":"clone https://x-access-token:` + leakToken + `@github.com/acme/shop.git failed"}],"total":1}`
	case "/api/v1/integrations/github":
		body = `{"configured":true,"app_url":"https://github.com/apps/stackurity","installations":[
			{"account_login":"acme","account_type":"Organization","status":"active","repositories":12,"installed_by":2},
			{"account_login":"priya-personal","account_type":"User","status":"active","repositories":1}]}`
	case "/api/v1/integrations/gitlab":
		body = `{"configured":false,"connections":[]}`
	case "/api/v1/integrations/jira/connections":
		body = `{"items":[{"id":1,"sites":[{"id":"c1","name":"acme","url":"https://acme.atlassian.net"}],"status":"active",
			"connected_by":2,"connected_at":"2026-10-01T00:00:00Z"}],"total":1}`
	case "/api/v1/integrations/digitalocean":
		body = `{"connected":true,"connected_at":"2026-10-02T00:00:00Z","secrets_enabled":true}`
	default:
		return &client.APIError{Status: 404, Code: "not_found", Message: "no route " + path}
	}
	return json.Unmarshal([]byte(body), out)
}

func TestAccountOverview(t *testing.T) {
	api := &accountAPI{role: "admin"}
	out := callTool(t, &Server{API: api, Version: "t"}, "account_overview", nil)
	if e, ok := out["error"]; ok {
		t.Fatal(e)
	}
	b, _ := json.Marshal(out)
	var got struct {
		You          map[string]any `json:"you"`
		Organisation map[string]any `json:"organisation"`
		Edition      struct{ Name string }
		Plan         map[string]any `json:"plan"`
		Assets       map[string]any `json:"assets"`
		Projects     map[string]any `json:"projects"`
		Members      struct {
			Active, Disabled int
			ByRole           map[string]int `json:"by_role"`
		} `json:"members"`
		Ask          map[string]any `json:"ask_stackurity"`
		NotAvailable []unavailable  `json:"not_available"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.You["role"] != "admin" || got.You["projects_you_can_see"] != 2.0 || got.Organisation["name"] != "Acme" || got.Edition.Name != "pro" {
		t.Errorf("you/organisation/edition: %s", b)
	}
	if got.Plan["name"] != "team" || got.Assets["monitored"] != 42.0 || got.Assets["limit"] != 50.0 || got.Projects["limit"] != 5.0 {
		t.Errorf("plan/usage: %s", b)
	}
	if got.Members.Active != 4 || got.Members.Disabled != 1 || got.Members.ByRole["admin"] != 2 || got.Members.ByRole["engineer"] != 1 ||
		got.Members.ByRole["project_access_only"] != 1 {
		t.Errorf("members: %+v", got.Members)
	}
	if got.Ask["questions_left"] != 70.0 || got.Ask["questions_limit"] != 100.0 {
		t.Errorf("ask: %v", got.Ask)
	}
	if len(got.NotAvailable) != 0 {
		t.Errorf("an admin can read everything: %v", got.NotAvailable)
	}
	// Members are counted, never named, and the refused assets' names and
	// the sign-up link are not passed on.
	for _, s := range []string{"Priya", leakEmail, "me@acme.io", "555", "secret-host", leakToken, "signup"} {
		if strings.Contains(string(b), s) {
			t.Errorf("account_overview shows %q: %s", s, b)
		}
	}
}

// A viewer gets what a viewer may read, and is told what is missing and
// why, instead of the tool failing or showing zeros.
func TestAccountToolsForAViewer(t *testing.T) {
	s := &Server{API: &accountAPI{role: "viewer"}, Version: "t"}
	out := callTool(t, s, "account_overview", nil)
	if _, ok := out["members"]; ok || out["assets"] == nil || out["you"].(map[string]any)["role"] != "viewer" {
		t.Errorf("viewer overview: %v", out)
	}
	if na := fmt.Sprint(out["not_available"]); !strings.Contains(na, "members") || !strings.Contains(na, "role") {
		t.Errorf("not_available: %v", na)
	}
	out = callTool(t, s, "integrations_status", nil)
	if _, ok := out["channels"]; ok {
		t.Errorf("a viewer read the channels: %v", out)
	}
	if na := fmt.Sprint(out["not_available"]); !strings.Contains(na, "channels") || !strings.Contains(na, "sources") {
		t.Errorf("not_available: %v", na)
	}
	out = callTool(t, s, "notification_settings", nil)
	if _, ok := out["rules"]; ok || !strings.Contains(fmt.Sprint(out["not_available"]), "rules") {
		t.Errorf("viewer rules: %v", out)
	}
}

func TestIntegrationsAndNotificationSettings(t *testing.T) {
	s := &Server{API: &accountAPI{role: "admin"}, Version: "t"}
	out := callTool(t, s, "integrations_status", nil)
	chans := out["channels"].([]any)
	if len(chans) != 3 {
		t.Fatalf("channels: %v", out)
	}
	slack, teams, email := chans[0].(map[string]any), chans[1].(map[string]any), chans[2].(map[string]any)
	if slack["kind"] != "slack" || slack["enabled"] != true || slack["belongs_to"] != "organisation" || slack["last_worked_at"] == nil {
		t.Errorf("slack: %v", slack)
	}
	if teams["enabled"] != false || teams["credential_missing"] != true || email["belongs_to"] != "project 4" {
		t.Errorf("teams/email: %v %v", teams, email)
	}
	if src := out["sources"].([]any); len(src) != 1 || src[0].(map[string]any)["name"] != "shop" {
		t.Errorf("sources: %v", out["sources"])
	}
	gh := out["github"].(map[string]any)["installations"].([]any)
	if gh[0].(map[string]any)["account_login"] != "acme" || gh[1].(map[string]any)["account_login"] != nil {
		t.Errorf("github: a personal account's login is shown, or the organisation's is not: %v", gh)
	}
	if out["digitalocean"].(map[string]any)["connected"] != true || len(out["not_available"].([]any)) != 0 {
		t.Errorf("digitalocean / not_available: %v", out)
	}

	out = callTool(t, s, "notification_settings", nil)
	rules := out["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules: %v", out)
	}
	crit, digest := rules[0].(map[string]any), rules[1].(map[string]any)
	if crit["min_priority"] != "P2" || crit["sends"] != true || crit["channel"].(map[string]any)["name"] != "Slack #alerts" ||
		crit["event_channels"].(map[string]any)["daily_summary"].(map[string]any)["kind"] != "email" {
		t.Errorf("critical rule: %v", crit)
	}
	// Enabled, but its channel is off: it sends nothing.
	if digest["sends"] != false || digest["belongs_to"] != "project 4" || digest["quiet_hours"] == nil {
		t.Errorf("digest rule: %v", digest)
	}
	if out["project_chat_apps"] != false {
		t.Errorf("project_chat_apps: %v", out)
	}
}

// No account tool returns a webhook URL, an SMTP password, a token, a
// secret reference or a colleague's email, wherever the API had it:
// configuration, error text or a link.
func TestAccountToolsNeverReturnSecrets(t *testing.T) {
	for _, role := range []string{"admin", "security", "engineer", "viewer"} {
		s := &Server{API: &accountAPI{role: role}, Version: "t"}
		for _, name := range []string{"account_overview", "integrations_status", "notification_settings"} {
			b, _ := json.Marshal(callTool(t, s, name, nil))
			for _, leak := range []string{leakWebhook, "sEcReTwEbHoOk", leakTeams, "teamssecret", leakSMTPPass, leakToken, leakEmail,
				"hooks.slack.com", "webhook.office.com", "x-access-token", "secret:", "SLACK_HOOK", "smtp", "config", "secret_ref",
				"installed_by", "connected_by", "atlassian.net", "app_url"} {
				if strings.Contains(string(b), leak) {
					t.Errorf("%s as %s returns %q: %s", name, role, leak, b)
				}
			}
		}
	}
}
