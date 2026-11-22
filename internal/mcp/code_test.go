package mcp

import "testing"

func TestListCodeFindings(t *testing.T) {
	api := &fakeAPI{}
	out := callTool(t, &Server{API: api, Version: "t"}, "list_code_findings", map[string]any{"severity": "critical,high", "source": "deepsec"})
	if len(api.paths) != 1 || api.paths[0] != "GET /api/v1/code-findings?limit=50&severity=critical%2Chigh&source=deepsec" {
		t.Errorf("requests = %v", api.paths)
	}
	if out["note"] == nil || out["code_findings"] == nil {
		t.Errorf("out: %v", out)
	}
	api = &fakeAPI{}
	callTool(t, &Server{API: api, Version: "t"}, "list_code_findings", map[string]any{"asset_id": 4.0, "status": "all", "limit": 500.0})
	if api.paths[0] != "GET /api/v1/assets/4/code-findings?limit=200&status=all" {
		t.Errorf("asset requests = %v", api.paths)
	}
}
