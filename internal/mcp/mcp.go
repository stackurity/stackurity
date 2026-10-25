// Package mcp serves Stackurity to AI assistants over the Model Context
// Protocol (stdio transport: newline-delimited JSON-RPC 2.0). Every tool is
// read-only and goes through the HTTP API with the caller's token, so the
// assistant sees exactly what that token's user may see, and nothing it does
// can change findings, plans or hosts.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/stackurity/stackurity/internal/client"
)

// ProtocolVersion is the newest MCP revision this server implements.
const ProtocolVersion = "2025-06-18"

var supportedVersions = map[string]bool{"2025-06-18": true, "2025-03-26": true, "2024-11-05": true}

// API is the subset of the HTTP client the tools use.
type API interface {
	Do(ctx context.Context, method, path string, body io.Reader, headers map[string]string, out any) error
}

var _ API = (*client.Client)(nil)

type Server struct {
	API     API
	Version string
	mu      sync.Mutex
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

const maxMessage = 4 << 20

// Serve reads requests from in and writes responses to out until in closes.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64<<10), maxMessage)
	enc := json.NewEncoder(out)
	write := func(r response) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_ = enc.Encode(r)
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var req request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			write(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
			continue
		}
		if len(req.ID) == 0 {
			continue // a notification (initialized, cancelled): nothing to answer
		}
		result, rerr := s.handle(ctx, req)
		write(response{JSONRPC: "2.0", ID: req.ID, Result: result, Error: rerr})
	}
	return sc.Err()
}

func (s *Server) handle(ctx context.Context, req request) (any, *rpcError) {
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		v := ProtocolVersion
		if supportedVersions[p.ProtocolVersion] {
			v = p.ProtocolVersion
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "stackurity", "version": s.Version},
			"instructions": "Stackurity inventories software across hosts, deployed applications, repositories and images, and reports " +
				"vulnerabilities and end-of-life components. Use search to look up a CVE, package, host or team. Start with " +
				"list_assets to find the project or server, then action_plan for what to upgrade (each group lists the packages " +
				"and target versions), asset_stack for every layer an application relies on, and list_findings or get_finding " +
				"for details. All tools are read-only.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolList()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, &rpcError{-32602, "invalid params"}
		}
		t, ok := tools[p.Name]
		if !ok {
			return nil, &rpcError{-32602, "unknown tool " + p.Name}
		}
		args := map[string]any{}
		if len(p.Arguments) > 0 && string(p.Arguments) != "null" {
			if err := json.Unmarshal(p.Arguments, &args); err != nil {
				return toolError("arguments must be a JSON object"), nil
			}
		}
		out, err := t.run(ctx, s.API, args)
		if err != nil {
			return toolError(err.Error()), nil
		}
		text, _ := json.MarshalIndent(out, "", " ")
		return map[string]any{"content": []map[string]any{{"type": "text", "text": string(text)}}}, nil
	}
	return nil, &rpcError{-32601, "method not found: " + req.Method}
}

func toolError(msg string) map[string]any {
	return map[string]any{"isError": true, "content": []map[string]any{{"type": "text", "text": msg}}}
}

// --- tools

type tool struct {
	description string
	schema      map[string]any
	run         func(ctx context.Context, api API, args map[string]any) (any, error)
}

func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }
func num(desc string) map[string]any { return map[string]any{"type": "integer", "description": desc} }

var tools = map[string]tool{
	"search": {
		description: "Search everything in the workspace at once: a vulnerability id (CVE, GHSA, DSA, USN, RHSA...), a package " +
			"(lodash, lodash@4.17.20, 'openssl 3.0.2', a purl), a host name, machine id, repository URL, image reference or " +
			"digest, a team, words from a finding's title, or (for engineers and above) a workspace member's name or email. " +
			"Results are grouped by type, exact matches first, with the affected assets for each.",
		schema: obj(map[string]any{
			"query": str("What to look for, at least 2 characters"),
			"limit": num("At most this many results per type (default 10, max 50)"),
		}, "query"),
		run: func(ctx context.Context, api API, a map[string]any) (any, error) {
			query, _ := a["query"].(string)
			if strings.TrimSpace(query) == "" {
				return nil, fmt.Errorf("query is required")
			}
			q := url.Values{"q": {query}}
			set(q, "limit", a["limit"])
			var res any
			if err := api.Do(ctx, "GET", "/api/v1/search?"+q.Encode(), nil, nil, &res); err != nil {
				return nil, err
			}
			return res, nil
		},
	},
	"list_assets": {
		description: "List inventoried assets: hosts, deployed applications, repositories, container images and managed services. " +
			"Use it to find the asset_id of a project or server.",
		schema: obj(map[string]any{
			"kind":        map[string]any{"type": "string", "enum": []string{"host", "application", "repository", "image", "managed_service", "sbom"}},
			"query":       str("Name contains this text"),
			"environment": str("Environment label, e.g. production"),
		}),
		run: func(ctx context.Context, api API, a map[string]any) (any, error) {
			var res struct {
				Items []struct {
					ID          int64             `json:"id"`
					Kind        string            `json:"kind"`
					Name        string            `json:"name"`
					Environment string            `json:"environment"`
					Status      string            `json:"collection_status"`
					LastSeen    string            `json:"last_seen"`
					Components  int64             `json:"component_count"`
					Attributes  map[string]string `json:"attributes"`
				} `json:"items"`
				Total int64 `json:"total"`
			}
			q := url.Values{"limit": {"200"}}
			set(q, "kind", a["kind"])
			set(q, "q", a["query"])
			set(q, "environment", a["environment"])
			if err := api.Do(ctx, "GET", "/api/v1/assets?"+q.Encode(), nil, nil, &res); err != nil {
				return nil, err
			}
			type item struct {
				ID          int64  `json:"asset_id"`
				Kind        string `json:"kind"`
				Name        string `json:"name"`
				Environment string `json:"environment,omitempty"`
				Status      string `json:"collection_status"`
				LastSeen    string `json:"last_seen"`
				Components  int64  `json:"components"`
				OS          string `json:"os,omitempty"`
				Reboot      string `json:"reboot_required,omitempty"`
			}
			out := []item{}
			for _, x := range res.Items {
				out = append(out, item{x.ID, x.Kind, x.Name, x.Environment, x.Status, x.LastSeen, x.Components,
					x.Attributes["os_name"], x.Attributes["reboot_required"]})
			}
			return map[string]any{"assets": out, "total": res.Total}, nil
		},
	},
	"action_plan": {
		description: "What to fix, grouped into concrete actions (upgrade X to version Y, move off an end-of-life runtime), " +
			"ordered by urgency, with how many findings each action clears. Omit asset_id for every asset.",
		schema: obj(map[string]any{"asset_id": num("Limit to one asset")}),
		run: func(ctx context.Context, api API, a map[string]any) (any, error) {
			q := url.Values{"limit": {"100"}}
			set(q, "asset_id", a["asset_id"])
			var groups, summary any
			if err := api.Do(ctx, "GET", "/api/v1/fix-groups?"+q.Encode(), nil, nil, &groups); err != nil {
				return nil, err
			}
			if err := api.Do(ctx, "GET", "/api/v1/fix-groups/summary?"+q.Encode(), nil, nil, &summary); err != nil {
				return nil, err
			}
			return map[string]any{"summary": summary, "groups": groups}, nil
		},
	},
	"list_findings": {
		description: "Open vulnerability and end-of-life findings, most urgent first, with the installed and fixed versions.",
		schema: obj(map[string]any{
			"asset_id":        num("Limit to one asset"),
			"severity":        str("Comma-separated: critical, high, medium, low"),
			"priority":        str("Comma-separated: P1, P2, P3, P4"),
			"query":           str("Component name or advisory id contains this text"),
			"known_exploited": map[string]any{"type": "boolean", "description": "Only findings on the CISA known exploited list"},
			"limit":           num("At most this many (default 50, max 200)"),
		}),
		run: func(ctx context.Context, api API, a map[string]any) (any, error) {
			limit := 50
			if n, ok := intArg(a["limit"]); ok && n > 0 {
				limit = min(n, 200)
			}
			q := url.Values{"limit": {strconv.Itoa(limit)}}
			set(q, "asset_id", a["asset_id"])
			set(q, "severity", a["severity"])
			set(q, "priority", a["priority"])
			set(q, "q", a["query"])
			if b, _ := a["known_exploited"].(bool); b {
				q.Set("known_exploited", "true")
			}
			var res struct {
				Items []finding `json:"items"`
				Total int64     `json:"total"`
			}
			if err := api.Do(ctx, "GET", "/api/v1/findings?"+q.Encode(), nil, nil, &res); err != nil {
				return nil, err
			}
			if res.Items == nil {
				res.Items = []finding{}
			}
			return map[string]any{"findings": res.Items, "total": res.Total, "shown": len(res.Items)}, nil
		},
	},
	"get_finding": {
		description: "One finding in full: advisory text, evidence, where the component was found, workflow state and history.",
		schema:      obj(map[string]any{"finding_id": num("The id of a finding, as list_findings and asset_stack return it")}, "finding_id"),
		run: func(ctx context.Context, api API, a map[string]any) (any, error) {
			id, ok := intArg(a["finding_id"])
			if !ok || id <= 0 {
				return nil, fmt.Errorf("finding_id is required")
			}
			var f, events any
			if err := api.Do(ctx, "GET", fmt.Sprintf("/api/v1/findings/%d", id), nil, nil, &f); err != nil {
				return nil, err
			}
			if err := api.Do(ctx, "GET", fmt.Sprintf("/api/v1/findings/%d/events", id), nil, nil, &events); err != nil {
				return nil, err
			}
			return map[string]any{"finding": f, "history": events}, nil
		},
	},
	"asset_stack": {
		description: "Everything an asset relies on (for an application: its hosts, repository, images and dependencies; for a host: " +
			"the applications on it) with open findings grouped by layer: web server, OS, runtime, data store, libraries.",
		schema: obj(map[string]any{"asset_id": num("Asset id")}, "asset_id"),
		run: func(ctx context.Context, api API, a map[string]any) (any, error) {
			id, ok := intArg(a["asset_id"])
			if !ok || id <= 0 {
				return nil, fmt.Errorf("asset_id is required")
			}
			var st struct {
				Members  any `json:"members"`
				Layers   any `json:"layers"`
				Findings []struct {
					finding
					Layer string `json:"layer"`
				} `json:"findings"`
				Truncated bool `json:"truncated"`
			}
			if err := api.Do(ctx, "GET", fmt.Sprintf("/api/v1/assets/%d/stack", id), nil, nil, &st); err != nil {
				return nil, err
			}
			const show = 100
			fs := st.Findings
			if len(fs) > show {
				fs = fs[:show]
			}
			return map[string]any{"members": st.Members, "layers": st.Layers, "findings": fs,
				"findings_total": len(st.Findings), "findings_shown": len(fs)}, nil
		},
	},
	"find_component": {
		description: "Where a package, library or runtime is installed, and at which versions (e.g. 'openssl', 'lodash', 'nodejs').",
		schema:      obj(map[string]any{"name": str("Component name or part of it")}, "name"),
		run: func(ctx context.Context, api API, a map[string]any) (any, error) {
			name, _ := a["name"].(string)
			if strings.TrimSpace(name) == "" {
				return nil, fmt.Errorf("name is required")
			}
			var comps struct {
				Items []struct {
					ID   int64  `json:"id"`
					Purl string `json:"purl_key"`
					Type string `json:"type"`
					Name string `json:"name"`
				} `json:"items"`
				Total int64 `json:"total"`
			}
			if err := api.Do(ctx, "GET", "/api/v1/components?"+url.Values{"q": {name}, "limit": {"10"}}.Encode(), nil, nil, &comps); err != nil {
				return nil, err
			}
			type use struct {
				Component string `json:"component"`
				Usage     any    `json:"installed"`
			}
			out := []use{}
			for _, c := range comps.Items {
				var inv struct {
					Items []struct {
						AssetID   int64  `json:"asset_id"`
						AssetName string `json:"asset_name"`
						Version   string `json:"version"`
						Location  string `json:"location"`
						Direct    *bool  `json:"direct"`
					} `json:"items"`
				}
				q := url.Values{"component_id": {strconv.FormatInt(c.ID, 10)}, "limit": {"50"}}
				if err := api.Do(ctx, "GET", "/api/v1/inventory?"+q.Encode(), nil, nil, &inv); err != nil {
					return nil, err
				}
				out = append(out, use{c.Purl, inv.Items})
			}
			return map[string]any{"matches": out, "total_components": comps.Total}, nil
		},
	},
}

// finding is the part of a finding an assistant needs to act on it.
type finding struct {
	ID             int64   `json:"id"`
	Kind           string  `json:"kind"`
	Key            string  `json:"key"`
	Severity       string  `json:"severity"`
	Priority       string  `json:"priority"`
	State          string  `json:"state"`
	AssetID        int64   `json:"asset_id"`
	AssetName      string  `json:"asset_name"`
	ComponentName  string  `json:"component_name"`
	Version        string  `json:"version"`
	FixedVersion   string  `json:"fixed_version"`
	Location       string  `json:"location"`
	Direct         *bool   `json:"direct"`
	Title          string  `json:"title"`
	KnownExploited bool    `json:"known_exploited"`
	Overdue        bool    `json:"overdue"`
	FixDue         *string `json:"fix_due"`
}

func toolList() []map[string]any {
	names := []string{"search", "list_assets", "action_plan", "asset_stack", "list_findings", "get_finding", "find_component"}
	out := make([]map[string]any, 0, len(names))
	for _, n := range names {
		t := tools[n]
		out = append(out, map[string]any{"name": n, "description": t.description, "inputSchema": t.schema,
			"annotations": map[string]any{"readOnlyHint": true, "openWorldHint": false}})
	}
	return out
}

func set(q url.Values, key string, v any) {
	switch x := v.(type) {
	case string:
		if x = strings.TrimSpace(x); x != "" {
			q.Set(key, x)
		}
	case float64:
		if x > 0 {
			q.Set(key, strconv.FormatInt(int64(x), 10))
		}
	}
}

func intArg(v any) (int, bool) {
	switch x := v.(type) {
	case float64:
		return int(x), true
	case string:
		n, err := strconv.Atoi(x)
		return n, err == nil
	}
	return 0, false
}
