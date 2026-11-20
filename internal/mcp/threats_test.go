package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/client"
)

type tAsset struct {
	ID      int64
	Kind    string
	Exposed *bool
	Mode    string
	Status  string
}

type tFinding struct {
	ID       int64
	Asset    int64
	Severity string
	KEV      bool
}

// threatAPI answers the endpoints threat_check reads, pages its lists
// and refuses any filter threat_check should not send. configStatus 400
// plays a server without the attack_tool category.
type threatAPI struct {
	paths        []string
	configStatus int
	config       []map[string]any
	assets       []tAsset
	findings     []tFinding
	scanned      map[int64]bool // hosts whose config checks ran
	// extraTotal is added to the assets' total, as if more existed.
	extraTotal int
}

func ptr(b bool) *bool { return &b }

func pageOf[T any](items []T, q url.Values, extra int) map[string]any {
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 50
	}
	end := min(offset+limit, len(items))
	if offset > len(items) {
		offset = end
	}
	return map[string]any{"items": items[offset:end], "total": len(items) + extra}
}

func (f *threatAPI) Do(_ context.Context, method, path string, _ io.Reader, _ map[string]string, out any) error {
	f.paths = append(f.paths, method+" "+path)
	p, raw, _ := strings.Cut(path, "?")
	q, _ := url.ParseQuery(raw)
	bad := func(why string) error { return fmt.Errorf("fake API: %s: %s", why, path) }
	var body any
	switch {
	case p == "/api/v1/config-findings":
		if f.configStatus != 0 {
			return &client.APIError{Status: f.configStatus, Code: "bad_request", Message: "category must be agent_hook, ssh or ci"}
		}
		if q.Get("category") != "attack_tool" || q.Get("status") != "open" {
			return bad("config findings without category=attack_tool&status=open")
		}
		body = pageOf(f.config, q, 0)
	case strings.HasPrefix(p, "/api/v1/assets/") && strings.HasSuffix(p, "/config-findings"):
		id, _ := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(p, "/api/v1/assets/"), "/config-findings"), 10, 64)
		scans := []map[string]any{}
		if f.scanned[id] {
			scans = append(scans, map[string]any{"collector_id": "agent", "complete": true})
		}
		body = map[string]any{"items": []any{}, "total": 0, "scans": scans}
	case p == "/api/v1/assets":
		var sel []map[string]any
		for _, x := range f.assets {
			switch {
			case q.Get("exposed") == "true":
				if x.Exposed == nil || !*x.Exposed {
					continue
				}
			case q.Get("kind") != "":
				if x.Kind != q.Get("kind") {
					continue
				}
			default:
				return bad("assets read without a kind or exposed filter")
			}
			sel = append(sel, map[string]any{"id": x.ID, "kind": x.Kind, "name": fmt.Sprintf("a%d", x.ID), "exposed": x.Exposed,
				"collection_status": x.Status, "reporting": map[string]any{"mode": x.Mode}})
		}
		body = pageOf(sel, q, f.extraTotal)
	case p == "/api/v1/findings":
		if q.Get("state") != "active" {
			return bad("findings without state=active")
		}
		kev, crit := q.Get("known_exploited") == "true", q.Get("severity") == "critical"
		if kev == crit {
			return bad("findings need exactly one of known_exploited=true or severity=critical")
		}
		var sel []map[string]any
		for _, x := range f.findings {
			if (kev && x.KEV) || (crit && x.Severity == "critical") {
				sel = append(sel, map[string]any{"id": x.ID, "asset_id": x.Asset, "asset_name": fmt.Sprintf("a%d", x.Asset),
					"severity": x.Severity, "known_exploited": x.KEV})
			}
		}
		body = pageOf(sel, q, 0)
	default:
		return bad("unexpected request")
	}
	b, _ := json.Marshal(body)
	return json.Unmarshal(b, out)
}

// estate: web-1 (internet-facing host), db-1 (not exposed host), app (an
// application of unknown exposure), shop (an image of unknown exposure)
// and a repository of unknown exposure. Both hosts ran config checks.
func estate() *threatAPI {
	return &threatAPI{
		assets: []tAsset{
			{ID: 1, Kind: "host", Exposed: ptr(true), Mode: "agent", Status: "ok"},
			{ID: 2, Kind: "host", Exposed: ptr(false), Mode: "agent", Status: "ok"},
			{ID: 3, Kind: "application", Mode: "agent", Status: "ok"},
			{ID: 4, Kind: "image", Mode: "agent", Status: "ok"},
			{ID: 5, Kind: "repository", Mode: "scheduled", Status: "ok"},
		},
		scanned: map[int64]bool{1: true, 2: true},
	}
}

func check(t *testing.T, api *threatAPI, name string) map[string]any {
	t.Helper()
	out := callTool(t, &Server{API: api, Version: "t"}, "threat_check", map[string]any{"threat": name})
	if e, ok := out["error"]; ok {
		t.Fatalf("tool error: %v", e)
	}
	return out
}

func TestThreatCheckFound(t *testing.T) {
	api := estate()
	api.config = []map[string]any{
		{"id": 9, "asset_id": 1, "rule": "attack-tool-artex", "category": "attack_tool", "severity": "high"},
		{"id": 10, "asset_id": 1, "rule": "attack-tool-other", "category": "attack_tool", "severity": "high"},
	}
	out := check(t, api, "  ARTEX ")
	if out["verdict"] != "found" || out["threat"] != "artex" || out["checked"] != true {
		t.Fatalf("verdict: %v", out)
	}
	if found := out["found"].([]any); len(found) != 1 || found[0].(map[string]any)["rule"] != "attack-tool-artex" {
		t.Errorf("found keeps only the threat's own rules: %v", found)
	}
}

// Only kinds that can face the internet count with unknown exposure: the
// image and the repository do not, the not-exposed host does not.
func TestThreatCheckExposed(t *testing.T) {
	api := estate()
	api.findings = []tFinding{
		{ID: 1, Asset: 1, Severity: "high", KEV: true},
		{ID: 2, Asset: 2, Severity: "critical", KEV: true},
		{ID: 3, Asset: 3, Severity: "critical"},
		{ID: 4, Asset: 4, Severity: "critical"},
		{ID: 5, Asset: 5, Severity: "critical", KEV: true},
	}
	out := check(t, api, "scopeweaver")
	if out["verdict"] != "exposed" || out["checked"] != true {
		t.Fatalf("verdict: %v", out)
	}
	list := out["exposed_assets"].([]any)
	if len(list) != 2 {
		t.Fatalf("exposed assets: %v", list)
	}
	first, second := list[0].(map[string]any), list[1].(map[string]any)
	if first["asset_id"] != 1.0 || first["exposure"] != "internet_facing" || first["known_exploited"] != 1.0 ||
		second["asset_id"] != 3.0 || second["exposure"] != "may_be_internet_facing" || second["critical"] != 1.0 {
		t.Errorf("exposed assets: %v", list)
	}
}

// A repository's critical findings alone leave the verdict covered.
func TestThreatCheckCovered(t *testing.T) {
	api := estate()
	api.findings = []tFinding{{ID: 5, Asset: 5, Severity: "critical", KEV: true}, {ID: 6, Asset: 4, Severity: "critical"}}
	if out := check(t, api, "artex"); out["verdict"] != "covered" || out["checked"] != true {
		t.Errorf("verdict: %v", out)
	}
}

// Without attack-tool checks on the server, exposure is still reported,
// but checked is false and the gap says to upgrade.
func TestThreatCheckOlderServer(t *testing.T) {
	api := estate()
	api.configStatus = 400
	out := check(t, api, "artex")
	if out["verdict"] != "not_checked" || out["checked"] != false {
		t.Fatalf("verdict: %v", out)
	}
	gaps, _ := json.Marshal(out["data_gaps"])
	if !strings.Contains(string(gaps), "upgraded to the latest version") {
		t.Errorf("gaps: %s", gaps)
	}
	api = estate()
	api.configStatus = 400
	api.findings = []tFinding{{ID: 1, Asset: 1, Severity: "critical", KEV: true}}
	if out := check(t, api, "artex"); out["verdict"] != "exposed" || out["checked"] != false {
		t.Errorf("exposed without checks: %v", out)
	}
}

// A server agent whose config checks never ran is not coverage; a stale
// one is not counted at all.
func TestThreatCheckNeedsChecksToHaveRun(t *testing.T) {
	api := estate()
	api.scanned = map[int64]bool{}
	if out := check(t, api, "artex"); out["verdict"] != "not_checked" || out["checked"] != false {
		t.Errorf("no checks ran: %v", out)
	}
	api = estate()
	api.scanned = map[int64]bool{1: true}
	api.assets = append(api.assets, tAsset{ID: 6, Kind: "host", Exposed: ptr(false), Mode: "agent", Status: "stale"})
	out := check(t, api, "artex")
	if out["verdict"] != "partial" {
		t.Fatalf("one server unchecked: %v", out)
	}
	host := out["coverage"].(map[string]any)["connected"].([]any)[0].(map[string]any)
	if host["checked"] != 1.0 || host["not_checked"] != 1.0 || host["stale"] != 1.0 || host["not_checked_reason"] == nil {
		t.Errorf("host coverage: %v", host)
	}
	for _, p := range api.paths {
		if strings.HasPrefix(p, "GET /api/v1/assets/6/") {
			t.Errorf("a stale server was probed: %v", api.paths)
		}
	}
	api = &threatAPI{assets: []tAsset{{ID: 5, Kind: "repository", Mode: "scheduled"}}}
	if out := check(t, api, "artex"); out["verdict"] != "not_checked" {
		t.Errorf("no server agent: %v", out)
	}
}

// More rows than are read: never covered.
func TestThreatCheckTruncated(t *testing.T) {
	api := estate()
	for i := range threatMaxRows + 1 {
		api.findings = append(api.findings, tFinding{ID: int64(100 + i), Asset: 2, Severity: "critical"})
	}
	out := check(t, api, "artex")
	if out["verdict"] != "partial" {
		t.Fatalf("truncated findings: %v", out["verdict"])
	}
	if gaps, _ := json.Marshal(out["data_gaps"]); strings.Contains(string(gaps), "known_exploited=") || strings.Contains(string(gaps), "severity=") {
		t.Errorf("raw query in gaps: %s", gaps)
	}
	// The assets' total says more exist than the pages hold.
	api = estate()
	api.extraTotal = 1
	if out := check(t, api, "artex"); out["verdict"] != "partial" {
		t.Errorf("truncated assets: %v", out["verdict"])
	}
}

// A finding on an asset outside what was read (not internet-facing, or
// never returned) is not counted as exposure.
func TestThreatCheckAssetOutsideRead(t *testing.T) {
	api := estate()
	api.findings = []tFinding{{ID: 1, Asset: 99, Severity: "critical", KEV: true}}
	if out := check(t, api, "artex"); out["verdict"] != "covered" || len(out["exposed_assets"].([]any)) != 0 {
		t.Errorf("unknown asset: %v", out)
	}
}

func TestThreatCheckUnknown(t *testing.T) {
	api := &threatAPI{}
	out := check(t, api, "no-such-thing")
	if out["known"] != false || len(out["known_threats"].([]any)) != len(threats) || len(api.paths) != 0 {
		t.Errorf("unknown: %v %v", out, api.paths)
	}
}

func TestListRiskySettings(t *testing.T) {
	api := &fakeAPI{}
	out := callTool(t, &Server{API: api, Version: "t"}, "list_risky_settings", map[string]any{"category": "attack_tool", "severity": "high"})
	if len(api.paths) != 1 || api.paths[0] != "GET /api/v1/config-findings?category=attack_tool&limit=50&severity=high" {
		t.Errorf("requests = %v", api.paths)
	}
	if out["note"] == nil || out["risky_settings"] == nil {
		t.Errorf("out: %v", out)
	}
	api = &fakeAPI{}
	callTool(t, &Server{API: api, Version: "t"}, "list_risky_settings", map[string]any{"asset_id": 4.0, "status": "all"})
	if api.paths[0] != "GET /api/v1/assets/4/config-findings?limit=50&status=all" {
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
