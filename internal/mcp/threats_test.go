package mcp

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/client"
)

// threatAPI answers the endpoints threat_check reads. configStatus 400
// plays a server without the attack_tool category.
type threatAPI struct {
	paths        []string
	configStatus int
	config       string
	assets       string
	kev          string
	critical     string
}

func (f *threatAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	f.paths = append(f.paths, method+" "+path)
	body := `{"items":[],"total":0}`
	switch {
	case strings.HasPrefix(path, "/api/v1/config-findings?"), strings.Contains(path, "/config-findings?"):
		if f.configStatus != 0 {
			return &client.APIError{Status: f.configStatus, Code: "bad_request", Message: "category must be agent_hook, ssh or ci"}
		}
		if f.config != "" {
			body = f.config
		}
	case strings.HasPrefix(path, "/api/v1/assets?"):
		if f.assets != "" {
			body = f.assets
		}
	case strings.Contains(path, "known_exploited=true"):
		if f.kev != "" {
			body = f.kev
		}
	case strings.Contains(path, "severity=critical"):
		if f.critical != "" {
			body = f.critical
		}
	}
	return json.Unmarshal([]byte(body), out)
}

const (
	hostsAndImages = `{"items":[
		{"id":1,"kind":"host","name":"web-1","exposed":true,"reporting":{"mode":"agent"}},
		{"id":2,"kind":"host","name":"db-1","exposed":false,"reporting":{"mode":"agent"}},
		{"id":3,"kind":"image","name":"shop:latest","exposed":null,"reporting":{"mode":"agent"}}],"total":3}`
	artexFound = `{"items":[
		{"id":9,"asset_id":1,"asset_name":"web-1","rule":"attack-tool-artex","category":"attack_tool","severity":"high","title":"ARTEX attack console found"},
		{"id":10,"asset_id":1,"asset_name":"web-1","rule":"attack-tool-other","category":"attack_tool","severity":"high","title":"Other tool"}],"total":2}`
)

func TestThreatCheckFound(t *testing.T) {
	api := &threatAPI{assets: hostsAndImages, config: artexFound}
	out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "  ARTEX "})
	if out["verdict"] != "found" || out["threat"] != "artex" {
		t.Fatalf("verdict: %v", out)
	}
	found := out["found"].([]any)
	if len(found) != 1 || found[0].(map[string]any)["rule"] != "attack-tool-artex" {
		t.Errorf("found keeps only the threat's own rules: %v", found)
	}
	if api.paths[0] != "GET /api/v1/config-findings?category=attack_tool&limit=200&status=open" {
		t.Errorf("requests = %v", api.paths)
	}
	cov := out["coverage"].(map[string]any)
	missing := cov["missing"].([]any)
	if len(missing) != 1 || missing[0].(map[string]any)["kind"] != "repository" || missing[0].(map[string]any)["connect"] != "/help/repositories" {
		t.Errorf("missing: %v", missing)
	}
}

func TestThreatCheckExposed(t *testing.T) {
	api := &threatAPI{assets: hostsAndImages,
		kev: `{"items":[
			{"id":1,"key":"CVE-A","severity":"high","asset_id":1,"asset_name":"web-1","known_exploited":true},
			{"id":2,"key":"CVE-B","severity":"critical","asset_id":2,"asset_name":"db-1","known_exploited":true}],"total":2}`,
		critical: `{"items":[
			{"id":3,"key":"CVE-C","severity":"critical","asset_id":3,"asset_name":"shop:latest"},
			{"id":1,"key":"CVE-A","severity":"high","asset_id":1,"asset_name":"web-1","known_exploited":true}],"total":2}`}
	out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "scopeweaver"})
	if out["verdict"] != "exposed" {
		t.Fatalf("verdict: %v", out)
	}
	list := out["exposed_assets"].([]any)
	if len(list) != 2 {
		t.Fatalf("db-1 is not internet-facing and must be left out: %v", list)
	}
	first, second := list[0].(map[string]any), list[1].(map[string]any)
	if first["asset_name"] != "web-1" || first["exposure"] != "internet_facing" || first["known_exploited"] != 1.0 ||
		second["asset_name"] != "shop:latest" || second["exposure"] != "may_be_internet_facing" || second["critical"] != 1.0 {
		t.Errorf("exposed assets: %v", list)
	}
}

func TestThreatCheckNotCheckedOnOlderServer(t *testing.T) {
	api := &threatAPI{assets: hostsAndImages, configStatus: 400}
	out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "artex"})
	if out["verdict"] != "not_checked" {
		t.Fatalf("verdict: %v", out)
	}
	gaps, _ := json.Marshal(out["data_gaps"])
	if !strings.Contains(string(gaps), "upgraded to the latest version") {
		t.Errorf("gaps: %s", gaps)
	}
}

func TestThreatCheckNeedsAnAgent(t *testing.T) {
	api := &threatAPI{assets: `{"items":[{"id":5,"kind":"repository","name":"shop","reporting":{"mode":"scheduled"}}],"total":1}`}
	out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "artex"})
	if out["verdict"] != "not_checked" {
		t.Fatalf("no server agent: %v", out)
	}
	api = &threatAPI{assets: hostsAndImages}
	if out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "artex"}); out["verdict"] != "covered" {
		t.Errorf("checked, nothing found: %v", out)
	}
}

func TestThreatCheckUnknown(t *testing.T) {
	api := &threatAPI{}
	out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "no-such-thing"})
	if out["known"] != false || len(out["known_threats"].([]any)) != len(threats) || len(api.paths) != 0 {
		t.Errorf("unknown: %v %v", out, api.paths)
	}
}

func TestListRiskySettings(t *testing.T) {
	api := &threatAPI{config: artexFound}
	out := callTool(t, &Server{API: api, Version: "t"}, "list_risky_settings", map[string]any{"category": "attack_tool", "severity": "high"})
	if len(api.paths) != 1 || api.paths[0] != "GET /api/v1/config-findings?category=attack_tool&limit=50&severity=high" {
		t.Errorf("requests = %v", api.paths)
	}
	if out["shown"] != 2.0 || out["note"] == nil {
		t.Errorf("out: %v", out)
	}
	api = &threatAPI{}
	callTool(t, &Server{API: api, Version: "t"}, "list_risky_settings", map[string]any{"asset_id": 4.0})
	if api.paths[0] != "GET /api/v1/assets/4/config-findings?limit=50" {
		t.Errorf("asset requests = %v", api.paths)
	}
}

// Every threat names its rules, a required connection and its sources.
func TestThreatTable(t *testing.T) {
	for _, th := range threats {
		req := false
		for _, n := range th.Needs {
			req = req || n.Required
			if !strings.HasPrefix(n.Connect, "/help/") {
				t.Errorf("%s: connect %q", th.ID, n.Connect)
			}
		}
		if !req || len(th.Rules) == 0 || len(th.Sources) == 0 || th.ID != strings.ToLower(th.ID) {
			t.Errorf("threat %s is incomplete", th.ID)
		}
	}
}
