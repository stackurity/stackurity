package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

type fakeAPI struct{ paths []string }

func (f *fakeAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	f.paths = append(f.paths, method+" "+path)
	var body string
	switch {
	case strings.HasPrefix(path, "/api/v1/findings?"):
		body = `{"items":[{"id":7,"key":"CVE-1","severity":"critical","asset_name":"shop","fixed_version":"1.2.3","evidence":{"big":"x"}}],"total":1}`
	default:
		body = `{"items":[],"total":0}`
	}
	return json.Unmarshal([]byte(body), out)
}

func run(t *testing.T, api API, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	s := &Server{API: api, Version: "test"}
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
	if len(tl) != 6 {
		t.Errorf("tools = %d", len(tl))
	}
	for _, x := range tl {
		ann := x.(map[string]any)["annotations"].(map[string]any)
		if ann["readOnlyHint"] != true {
			t.Errorf("tool not marked read-only: %v", x)
		}
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
