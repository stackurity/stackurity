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

// routeHeading is how docs/api.md documents a route: one heading per method
// and path, followed by a "**Who:**" line.
var routeHeading = regexp.MustCompile("^### `(GET|POST|PUT|PATCH|DELETE) (/[^`\\s]*)`\\s*$")

// docRoute is one route heading in docs/api.md.
type docRoute struct {
	method, path string
	line         int
	// notServed is true for routes the Who line marks "licensed build" or
	// "Stackurity Cloud": the Community server these tests build may not
	// register them.
	notServed bool
}

// documentedRoutes reads the route headings of docs/api.md, with the /api/v1
// base path removed. A route named only in prose does not count: every route
// has its own entry.
func documentedRoutes(doc string) []docRoute {
	var out []docRoute
	lines := strings.Split(doc, "\n")
	for i, line := range lines {
		m := routeHeading.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		r := docRoute{method: m[1], path: strings.TrimPrefix(m[2], "/api/v1"), line: i + 1}
		for _, next := range lines[i+1:] {
			if strings.HasPrefix(next, "#") {
				break
			}
			if strings.HasPrefix(next, "**Who:**") {
				r.notServed = strings.Contains(next, "licensed build") || strings.Contains(next, "Stackurity Cloud")
				break
			}
		}
		out = append(out, r)
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

// TestRoutesDocumented fails when the server registers a route that has no
// heading of its own in docs/api.md. The routes not documented yet
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
		for _, d := range doc {
			if d.method == method && matches(path, d.path) {
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

// TestDocumentedRoutesServed fails when docs/api.md has a heading for a
// route the server does not register (a wrong path or method, or a removed
// route), unless the heading's Who line marks it licensed build or
// Stackurity Cloud.
func TestDocumentedRoutesServed(t *testing.T) {
	served := servedRoutes(t)
	for _, d := range documentedRoutes(read(t, "docs/api.md")) {
		if d.notServed {
			continue
		}
		found := false
		for _, r := range served {
			method, path, _ := strings.Cut(r, " ")
			if method == d.method && matches(path, d.path) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("docs/api.md:%d: %s %s is not a route the server registers: fix the heading, or mark it licensed build or Stackurity Cloud on its Who line", d.line, d.method, d.path)
		}
	}
}

// TestDocumentedRoutesForms checks what documentedRoutes reads.
func TestDocumentedRoutesForms(t *testing.T) {
	got := documentedRoutes("## Tokens\n\n" +
		"### `GET /tokens`\n\n**Who:** any signed-in user\n\nLists tokens; see `DELETE /tokens/{id}`.\n\n" +
		"### `POST /api/v1/assistants`\n\n**Who:** admin · licensed build\n\n" +
		"### `GET /billing`\n\n**Who:** admin · Stackurity Cloud\n\n" +
		"### `GET /healthz`\n\nNo Who line.\n\n### Not a route\n\n**Who:** licensed build\n")
	want := []docRoute{
		{method: "GET", path: "/tokens", line: 3},
		{method: "POST", path: "/assistants", line: 9, notServed: true},
		{method: "GET", path: "/billing", line: 13, notServed: true},
		{method: "GET", path: "/healthz", line: 17},
	}
	if len(got) != len(want) {
		t.Fatalf("documentedRoutes = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("route %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	for _, c := range []struct {
		route, doc string
		want       bool
	}{
		{"/tokens/{id}", "/tokens/{id}", true},
		{"/download/agent/{platform}", "/download/agent/linux-amd64", true},
		{"/channels", "/channels/{id}", false},
		{"/tokens", "/tokens/", true},
	} {
		if got := matches(c.route, c.doc); got != c.want {
			t.Errorf("matches(%q, %q) = %v, want %v", c.route, c.doc, got, c.want)
		}
	}
}
