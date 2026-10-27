package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
)

// openAPIOp is the part of an operation the checks read.
type openAPIOp struct {
	OperationID string           `json:"operationId"`
	Summary     string           `json:"summary"`
	Role        string           `json:"x-stackurity-role"`
	Edition     string           `json:"x-stackurity-edition"`
	Parameters  []map[string]any `json:"parameters"`
	Responses   map[string]any   `json:"responses"`
	Security    *[]any           `json:"security"`
}

func loadOpenAPI(t *testing.T) (raw []byte, paths map[string]map[string]openAPIOp) {
	t.Helper()
	raw, err := os.ReadFile("openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		OpenAPI string                          `json:"openapi"`
		Servers []struct{ URL string }          `json:"servers"`
		Paths   map[string]map[string]openAPIOp `json:"paths"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&spec); err != nil {
		t.Fatalf("openapi.json is not valid JSON: %v", err)
	}
	if spec.OpenAPI != "3.1.0" || len(spec.Servers) != 1 || spec.Servers[0].URL != "/api/v1" {
		t.Fatalf("openapi.json: openapi %q, servers %v", spec.OpenAPI, spec.Servers)
	}
	return raw, spec.Paths
}

var pathParam = regexp.MustCompile(`\{([^}]+)\}`)

// TestOpenAPICoversEveryRoute fails when an /api/v1 route is added without
// an entry in internal/api/openapi.json, or an entry is left for a route
// that is gone. The router is the source of truth, as for the isolation
// sweeps; routes of the licensed build only are marked
// x-stackurity-edition: ee.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	e := newEnv(t)
	raw, paths := loadOpenAPI(t)

	served := map[string]bool{}
	var missing []string
	for _, r := range walkRoutes(t, e) {
		method, pattern, _ := strings.Cut(r, " ")
		rest, ok := strings.CutPrefix(pattern, "/api/v1")
		if !ok {
			continue // the dashboard, health checks, the installer, /mcp and OAuth (their own specifications)
		}
		p := strings.TrimSuffix(rest, "/")
		served[strings.ToLower(method)+" "+p] = true
		if _, ok := paths[p][strings.ToLower(method)]; !ok {
			missing = append(missing, method+" "+p)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("routes without an entry in internal/api/openapi.json (add each with its summary, role and parameters):\n  %s",
			strings.Join(missing, "\n  "))
	}

	ids := map[string]bool{}
	for p, ops := range paths {
		want := pathParam.FindAllStringSubmatch(p, -1)
		for method, op := range ops {
			where := strings.ToUpper(method) + " " + p
			if !served[method+" "+p] && (op.Edition == "" || op.Edition == api.BuildEdition) {
				t.Errorf("%s is in openapi.json but this build does not serve it", where)
			}
			if op.OperationID == "" || ids[op.OperationID] {
				t.Errorf("%s: missing or repeated operationId %q", where, op.OperationID)
			}
			ids[op.OperationID] = true
			if op.Summary == "" || op.Role == "" || len(op.Responses) == 0 {
				t.Errorf("%s needs a summary, an x-stackurity-role and responses", where)
			}
			var got []string
			for _, prm := range op.Parameters {
				if prm["in"] == "path" {
					got = append(got, prm["name"].(string))
				}
			}
			if len(got) != len(want) {
				t.Errorf("%s declares path parameters %v", where, got)
			}
			for i := range min(len(got), len(want)) {
				if got[i] != want[i][1] {
					t.Errorf("%s declares path parameter %q for {%s}", where, got[i], want[i][1])
				}
			}
			public := strings.HasPrefix(op.Role, "none") || op.Role == "setup token"
			if public != (op.Security != nil && len(*op.Security) == 0) {
				t.Errorf("%s: role %q, but security %v", where, op.Role, op.Security)
			}
		}
	}

	// Served as committed, without credentials.
	resp := e.anon().req("GET", "/api/v1/openapi.json", nil, nil)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Equal(body, raw) || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		t.Errorf("GET /api/v1/openapi.json: %d, %d bytes, %q", resp.StatusCode, len(body), resp.Header.Get("Content-Type"))
	}
}
