package docslint

import (
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/api"
)

// servedRoutes lists "METHOD /path" for every route the API server
// registers, with the /api/v1 base path removed as docs/api.md writes it.
func servedRoutes(t *testing.T) []string {
	t.Helper()
	// Registering routes touches no database.
	srv := &api.Server{Log: slog.New(slog.DiscardHandler), BaseURL: "https://stackurity.example.com"}
	routes, ok := srv.Handler().(chi.Routes)
	if !ok {
		t.Fatal("the server's handler is not a chi router")
	}
	seen := map[string]bool{}
	err := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if route == "/*" {
			return nil // the dashboard's static files
		}
		route = strings.TrimPrefix(route, "/api/v1")
		if route != "/" {
			route = strings.TrimSuffix(route, "/")
		}
		seen[method+" "+route] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

var (
	backtick  = regexp.MustCompile("`([^`]+)`")
	verbOnly  = regexp.MustCompile(`^(GET|POST|PUT|PATCH|DELETE)$`)
	verbRoute = regexp.MustCompile(`^(?:(GET|POST|PUT|PATCH|DELETE) )?(/\S*)$`)
)

// documentedRoutes reads the routes docs/api.md names, line by line, from
// its code spans, in the forms it uses:
//
//	`GET /assets/{id}`                     one method and path
//	`GET`/`POST /tokens`                   several methods for one path
//	`GET /assets/{id}/coverage`, `/collections`
//	                                       a sibling of the previous path,
//	                                       with its methods
//
// A query string or a suffix in brackets ([.sha256]) is dropped. A path
// with no method anywhere before it on the line counts for no method.
func documentedRoutes(doc string) map[string][]string {
	out := map[string][]string{} // method -> paths
	for _, line := range strings.Split(doc, "\n") {
		var pending, last []string
		var lastPath string
		for _, m := range backtick.FindAllStringSubmatch(line, -1) {
			span := strings.TrimSpace(m[1])
			if verbOnly.MatchString(span) {
				pending = append(pending, span)
				continue
			}
			v := verbRoute.FindStringSubmatch(span)
			if v == nil {
				continue
			}
			path := strings.TrimPrefix(v[2], "/api/v1")
			path, _, _ = strings.Cut(path, "?")
			if i := strings.Index(path, "["); i > 0 {
				path = path[:i]
			}
			methods := pending
			if v[1] != "" {
				methods = append(methods, v[1])
			}
			pending = nil
			if len(methods) == 0 && lastPath != "" && strings.Count(path, "/") == 1 {
				// `/collections` after `GET /assets/{id}/coverage`.
				path = lastPath[:strings.LastIndex(lastPath, "/")] + path
				methods = last
			}
			if len(methods) > 0 {
				last, lastPath = methods, path
			}
			for _, method := range methods {
				out[method] = append(out[method], path)
			}
		}
	}
	return out
}

// matches reports whether a documented path names a route pattern: equal
// segments, where a {parameter} in the route matches any documented segment
// (`/download/agent/linux-{amd64,arm64}`).
func matches(route, doc string) bool {
	r, d := strings.Split(route, "/"), strings.Split(strings.TrimSuffix(doc, "/"), "/")
	if len(r) != len(d) {
		return false
	}
	for i := range r {
		if strings.HasPrefix(r[i], "{") && strings.HasSuffix(r[i], "}") && d[i] != "" {
			continue
		}
		if r[i] != d[i] {
			return false
		}
	}
	return true
}

// TestRoutesDocumented fails when the server registers a route that
// docs/api.md does not name with its method. The routes not documented yet
// are listed in api-known-gaps.txt; a listed route that docs/api.md now
// names, or that the server no longer registers, fails too, so the list only
// shrinks.
func TestRoutesDocumented(t *testing.T) {
	doc := documentedRoutes(read(t, "docs/api.md"))
	gaps := allowlist(t, "api-known-gaps.txt", false)
	served := map[string]bool{}
	for _, r := range servedRoutes(t) {
		served[r] = true
		method, path, _ := strings.Cut(r, " ")
		documented := false
		for _, d := range doc[method] {
			if matches(path, d) {
				documented = true
				break
			}
		}
		switch {
		case !documented && !gaps[r]:
			t.Errorf("%s is not in docs/api.md: document it (and in internal/api/openapi.json)", r)
		case documented && gaps[r]:
			t.Errorf("%s is now in docs/api.md: remove it from tools/docslint/api-known-gaps.txt", r)
		}
	}
	for r := range gaps {
		if !served[r] {
			t.Errorf("tools/docslint/api-known-gaps.txt: the server no longer registers %s; remove it", r)
		}
	}
}

// TestDocumentedRoutesForms checks the forms documentedRoutes understands.
func TestDocumentedRoutesForms(t *testing.T) {
	doc := documentedRoutes("| `GET`/`POST /tokens`, `DELETE /tokens/{id}` | any |\n" +
		"| `GET /assets/{id}/coverage`, `/collections` | viewer |\n" +
		"| `GET /install/agent.sh`, `GET /download/agent/linux-{amd64,arm64}[.sha256]` | none |\n" +
		"| `GET /assets?kind=` | viewer |\n" +
		"Connect to `/mcp`.\n")
	for _, c := range []struct {
		method, route string
		want          bool
	}{
		{"GET", "/tokens", true},
		{"POST", "/tokens", true},
		{"DELETE", "/tokens/{id}", true},
		{"GET", "/tokens/{id}", false},
		{"GET", "/assets/{id}/collections", true},
		{"GET", "/download/agent/{platform}", true},
		{"GET", "/assets", true},
		{"GET", "/mcp", false},
	} {
		got := false
		for _, d := range doc[c.method] {
			got = got || matches(c.route, d)
		}
		if got != c.want {
			t.Errorf("%s %s documented = %v, want %v", c.method, c.route, got, c.want)
		}
	}
}
