package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/threats"
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
	// catalogue answers GET /api/v1/threats ("": 404, an older server);
	// search answers GET /api/v1/search; notices GET /api/v1/threat-notices
	// (noticesStatus: an error status instead).
	catalogue     string
	search        string
	notices       string
	noticesStatus int
}

func (f *threatAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	f.paths = append(f.paths, method+" "+path)
	body := `{"items":[],"total":0}`
	switch {
	case path == "/api/v1/threats":
		if f.catalogue == "" {
			return &client.APIError{Status: 404, Code: "not_found", Message: "not found"}
		}
		body = f.catalogue
	case strings.HasPrefix(path, "/api/v1/search?"):
		body = `{"vulnerabilities":[]}`
		if f.search != "" {
			body = f.search
		}
	case path == "/api/v1/threat-notices":
		if f.noticesStatus != 0 {
			return &client.APIError{Status: f.noticesStatus, Code: "forbidden", Message: "forbidden"}
		}
		if f.notices != "" {
			body = f.notices
		}
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
	if api.paths[0] != "GET /api/v1/threats" || api.paths[1] != "GET /api/v1/config-findings?category=attack_tool&limit=200&status=open" {
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
	if out["known"] != false || len(out["known_threats"].([]any)) != len(threats.Embedded().Threats) || len(api.paths) != 1 {
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

// The server's catalogue wins over this build's: a threat it added from
// the feed (a known-exploited CVE) is checked through search, and a threat
// whose check is newer than the server says to upgrade.
func TestThreatCheckServerCatalogue(t *testing.T) {
	artex, _ := threats.Embedded().Get("artex")
	cve := threats.Threat{ID: "fooshell", Revision: 1, Name: "FooShell", Kind: threats.KindExploitedVuln, Severity: "critical",
		Summary: "An exploited flaw.", FirstSeen: "2026-11-18", PublishedAt: "2026-11-21", MinVersion: "0.1.0",
		Detects: threats.Detects{CVEs: []string{"CVE-2026-1111"}},
		Needs:   []threats.Need{{Connection: threats.ConnHostAgent, Required: true, Checks: "installed packages", Help: "/help/add-server"}}}
	cat, _ := json.Marshal(map[string]any{"threats": []any{
		map[string]any{"id": artex.ID, "name": artex.Name, "aliases": artex.Aliases, "kind": artex.Kind, "summary": artex.Summary,
			"min_version": "0.99.0", "detects": artex.Detects, "needs": artex.Needs, "has_check": false},
		struct {
			threats.Threat
			HasCheck bool `json:"has_check"`
		}{cve, true},
	}})
	api := &threatAPI{assets: hostsAndImages, catalogue: string(cat),
		search: `{"vulnerabilities":[{"key":"GHSA-xxxx","title":"FooShell","severity":"critical","known_exploited":true,"open_findings":3,"affected_assets":2,"assets":[{"id":1,"name":"web-1"}]},
			{"key":"CVE-2026-1111","open_findings":0}]}`}
	out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "fooshell"})
	found, _ := out["found"].([]any)
	if out["verdict"] != "found" || len(found) != 1 || found[0].(map[string]any)["vulnerability"] != "GHSA-xxxx" {
		t.Fatalf("CVE threat from the feed: %v", out)
	}
	if !slices.Contains(api.paths, "GET /api/v1/search?q=CVE-2026-1111") {
		t.Errorf("requests = %v", api.paths)
	}
	api = &threatAPI{assets: hostsAndImages, catalogue: string(cat)}
	out = callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": "artex"})
	gaps, _ := json.Marshal(out["data_gaps"])
	if out["verdict"] != "not_checked" || !strings.Contains(string(gaps), "older than 0.99.0") {
		t.Errorf("server without the check: %v", out)
	}
}

func TestListThreatNotices(t *testing.T) {
	api := &threatAPI{notices: `{"items":[{"id":4,"threat_id":"artex","name":"ARTEX","verdict":"needs_connection","dismissed":true,
		"missing_connections":[{"connection":"host_agent","help":"/help/add-server"}]}]}`}
	out := callTool(t, &Server{API: api, Version: "t"}, "list_threat_notices", nil)
	items, _ := out["notices"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["verdict"] != "needs_connection" || api.paths[0] != "GET /api/v1/threat-notices" {
		t.Fatalf("notices: %v %v", out, api.paths)
	}
	if strings.Contains(strings.ToLower(fmt.Sprint(out)), "upgrade your plan") {
		t.Error("no upsell in a normal answer")
	}
	api = &threatAPI{noticesStatus: 403}
	out = callTool(t, &Server{API: api, Version: "t"}, "list_threat_notices", nil)
	if out["notices"] != nil || !strings.Contains(fmt.Sprint(out["message"]), "security or admin role") {
		t.Errorf("a viewer: %v", out)
	}
}
