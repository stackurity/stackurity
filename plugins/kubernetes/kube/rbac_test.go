package kube

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The reporter's RBAC (deploy/helm/stackurity-reporter/files/rbac-*.yaml,
// which the chart and the server's manifest use) must grant exactly what
// the code calls: a new API read without a rule fails here, and so does a
// rule the code no longer needs.

const chartFiles = "../../../deploy/helm/stackurity-reporter/files"

// grant is one permission: a verb on a resource (optionally one object by
// name), or on a non-resource URL.
type grant struct{ verb, group, resource, name, url string }

func (g grant) String() string {
	if g.url != "" {
		return g.verb + " " + g.url
	}
	s := g.verb + " " + g.group + "/" + g.resource
	if g.name != "" {
		s += "/" + g.name
	}
	return s
}

type rbacRule struct {
	APIGroups       []string `yaml:"apiGroups"`
	Resources       []string `yaml:"resources"`
	ResourceNames   []string `yaml:"resourceNames"`
	NonResourceURLs []string `yaml:"nonResourceURLs"`
	Verbs           []string `yaml:"verbs"`
}

// grants expands RBAC rules into single permissions.
func grants(rules []rbacRule) map[grant]bool {
	out := map[grant]bool{}
	for _, r := range rules {
		for _, v := range r.Verbs {
			for _, u := range r.NonResourceURLs {
				out[grant{verb: v, url: u}] = true
			}
			names := r.ResourceNames
			if len(names) == 0 {
				names = []string{""}
			}
			for _, g := range r.APIGroups {
				for _, res := range r.Resources {
					for _, n := range names {
						out[grant{verb: v, group: g, resource: res, name: n}] = true
					}
				}
			}
		}
	}
	return out
}

func readRules(t *testing.T, file string) []rbacRule {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(chartFiles, file))
	if err != nil {
		t.Fatal(err)
	}
	var rules []rbacRule
	if err := yaml.Unmarshal(b, &rules); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	for _, r := range rules {
		for _, x := range append(append(append([]string{}, r.Verbs...), r.Resources...), r.APIGroups...) {
			if x == "*" {
				t.Errorf("%s: wildcard in %+v", file, r)
			}
		}
	}
	return rules
}

// callGrant is the permission an API request needs.
func callGrant(t *testing.T, method, path string) grant {
	verb := map[string]string{http.MethodGet: "get", http.MethodPut: "update"}[method]
	if verb == "" {
		t.Errorf("%s %s: the reporter only reads, and updates its own Secret", method, path)
	}
	if path == "/version" {
		return grant{verb: verb, url: path}
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	group := ""
	switch {
	case parts[0] == "api" && len(parts) >= 3:
		parts = parts[2:]
	case parts[0] == "apis" && len(parts) >= 4:
		group, parts = parts[1], parts[3:]
	default:
		t.Errorf("unexpected path %s", path)
	}
	// namespaces/<ns>/<resource>[/<name>] is namespaced; namespaces/<name>
	// is one namespace object.
	if len(parts) >= 3 && parts[0] == "namespaces" {
		parts = parts[2:]
	}
	switch len(parts) {
	case 1:
		if verb == "get" {
			verb = "list"
		}
		return grant{verb: verb, group: group, resource: parts[0]}
	case 2:
		return grant{verb: verb, group: group, resource: parts[0], name: parts[1]}
	}
	t.Errorf("unexpected path %s", path)
	return grant{}
}

// recorder records every call the code makes and serves the reporter's
// Secret next to the fixtures.
type recorder struct {
	t     *testing.T
	api   *fakeAPI
	mu    sync.Mutex
	calls map[grant]bool
	// The Secret, as the API server stores it.
	secret map[string]any
}

func (rec *recorder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec.mu.Lock()
	rec.calls[callGrant(rec.t, r.Method, r.URL.Path)] = true
	rec.mu.Unlock()
	if strings.Contains(r.URL.Path, "/secrets/") {
		if r.Method == http.MethodPut {
			var in map[string]any
			if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
				rec.t.Error(err)
			}
			rec.secret = in
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rec.secret)
		return
	}
	rec.api.ServeHTTP(w, r)
}

// codeGrants runs everything the reporter does against the fake API, in
// each RBAC situation the collection handles, and returns the permissions
// it used.
func codegrants(t *testing.T) map[grant]bool {
	calls := map[grant]bool{}
	for _, tc := range []struct {
		api *fakeAPI
		cfg string
	}{
		{&fakeAPI{}, `{}`},
		{&fakeAPI{clusterWide403: true}, `{}`}, // namespace-scoped RBAC: namespace by namespace
		{&fakeAPI{forbiddenRes: map[string]bool{"namespaces": true}}, `{}`}, // namespaces unreadable: the kube-system object only
		{&fakeAPI{forbiddenRes: map[string]bool{"nodes": true}}, `{"namespaces": ["shop"]}`},
	} {
		rec := &recorder{t: t, api: tc.api, calls: calls, secret: map[string]any{
			"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": "stackurity-reporter", "namespace": "stackurity"},
		}}
		srv := httptest.NewTLSServer(rec)
		t.Cleanup(srv.Close)
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
		c, err := NewClient(context.Background(), srv.URL, "test-token", ca, "test")
		if err != nil {
			t.Fatal(err)
		}
		tc.api.t = t
		s, p := ParseSettings(json.RawMessage(tc.cfg))
		if len(p) > 0 {
			t.Fatal(p)
		}
		if _, err := Collect(context.Background(), c, s); err != nil {
			t.Fatal(err)
		}
		sec, err := c.GetSecret(context.Background(), "stackurity", "stackurity-reporter")
		if err != nil {
			t.Fatal(err)
		}
		sec.Set("token", "stk_x")
		if err := c.UpdateSecret(context.Background(), sec); err != nil {
			t.Fatal(err)
		}
	}
	return calls
}

func sortedgrants(m map[grant]bool) []string {
	var out []string
	for g := range m {
		out = append(out, g.String())
	}
	sort.Strings(out)
	return out
}

// tokenGrants is the Role on the reporter's own Secret (templates/rbac.yaml
// in the chart, install/kubernetes.yaml on the server).
var tokenGrants = grants([]rbacRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"stackurity-reporter"}, Verbs: []string{"get", "update"}}})

func TestReporterRBACIsExactlyWhatTheCodeReads(t *testing.T) {
	code := codegrants(t)
	granted := grants(readRules(t, "rbac-cluster.yaml"))
	for g := range tokenGrants {
		granted[g] = true
	}
	for g := range code {
		if !granted[g] {
			t.Errorf("the code needs %s, which the reporter's RBAC does not grant", g)
		}
	}
	for g := range granted {
		if !code[g] {
			t.Errorf("the reporter's RBAC grants %s, which the code never uses", g)
		}
	}
	if t.Failed() {
		t.Logf("the code uses: %s", strings.Join(sortedgrants(code), "; "))
	}
	// No Secret other than its own, and nothing but get and update on it.
	for g := range code {
		if g.resource == "secrets" && (g.name != "stackurity-reporter" || g.verb != "get" && g.verb != "update") {
			t.Errorf("secret access %s", g)
		}
	}
}

// Without cluster-wide read the reporter has the namespaced rules in each
// namespace and the cluster's identity. What it then cannot read (the
// namespace and node lists) is exactly what the collection reports as not
// assessed.
func TestReporterNamespacedRBAC(t *testing.T) {
	code := codegrants(t)
	granted := grants(readRules(t, "rbac-identity.yaml"))
	for g := range grants(readRules(t, "rbac-namespace.yaml")) {
		granted[g] = true
	}
	for g := range tokenGrants {
		granted[g] = true
	}
	for g := range granted {
		if !code[g] {
			t.Errorf("the namespaced RBAC grants %s, which the code never uses", g)
		}
	}
	var missing []string
	for g := range code {
		if !granted[g] {
			missing = append(missing, g.String())
		}
	}
	sort.Strings(missing)
	if want := "list /namespaces, list /nodes"; strings.Join(missing, ", ") != want {
		t.Errorf("namespaced RBAC lacks %v, want only %s", missing, want)
	}
	// The namespaced rules are the cluster rules on namespaced resources.
	for g := range grants(readRules(t, "rbac-namespace.yaml")) {
		if g.resource == "namespaces" || g.resource == "nodes" || g.url != "" {
			t.Errorf("a namespaced Role cannot grant %s", g)
		}
	}
}
