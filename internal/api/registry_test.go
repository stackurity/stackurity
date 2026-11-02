package api_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/registry"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const registrySecret = "Reg1stry-Secret-Value"

// fakeCatalog is a registry that wants basic authentication and, when
// refusing, echoes the Authorization header it got (as a careless
// registry might).
func fakeCatalog(t *testing.T) *httptest.Server {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "robot" || p != registrySecret {
			w.Header().Set("WWW-Authenticate", `Basic realm="fake"`)
			w.WriteHeader(401)
			_, _ = fmt.Fprintf(w, `{"errors":[{"code":"UNAUTHORIZED","message":"bad credentials %s %s"}]}`, r.Header.Get("Authorization"), p)
			return
		}
		if r.URL.Path == "/v2/_catalog" {
			_, _ = w.Write([]byte(`{"repositories":["team/shop","team/shop-test","team/web"]}`))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(registry.SetTestTLS(&tls.Config{InsecureSkipVerify: true})) //nolint:gosec // tests only
	return srv
}

func registryEnv(t *testing.T) *env {
	box, _ := secrets.NewBox([]byte("0123456789abcdef0123456789abcdef"))
	var e *env
	e = newEnvWith(t, func(s *api.Server) {
		s.SecretBox = box
		s.Secrets.Stored = func(ctx context.Context, name string) (string, error) { return e.st.SecretValue(ctx, box, name) }
	})
	return e
}

func TestRegistryIntegrationAPI(t *testing.T) {
	e := registryEnv(t)
	reg := fakeCatalog(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	admin, eng := e.login("admin@x.io"), e.login("eng@x.io")
	var bodies []string
	call := func(s *session, method, path string, in any) (int, string) {
		raw, _ := json.Marshal(in)
		resp := s.req(method, path, bytes.NewReader(raw), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		bodies = append(bodies, string(b))
		return resp.StatusCode, string(b)
	}
	if code, _ := call(admin, "PUT", "/api/v1/secrets/REG", map[string]string{"value": registrySecret}); code != 200 && code != 204 {
		t.Fatalf("store secret: %d", code)
	}
	bodies = nil // the request above is the only one that carries the value
	cfg := map[string]any{"provider": "oci", "url": reg.URL, "username": "robot", "namespace": "team", "exclude": []string{"*-test"}}

	code, body := call(admin, "POST", "/api/v1/integrations/registry/discover", map[string]any{"config": cfg, "secret_ref": "secret:REG"})
	var disc struct {
		Registry     string `json:"registry"`
		Complete     bool   `json:"complete"`
		Repositories []struct {
			Name     string `json:"name"`
			Included bool   `json:"included"`
		} `json:"repositories"`
	}
	_ = json.Unmarshal([]byte(body), &disc)
	if code != 200 || len(disc.Repositories) != 3 || !disc.Complete || !disc.Repositories[0].Included || disc.Repositories[1].Included {
		t.Fatalf("discover: %d %s", code, body)
	}
	if code, _ := call(eng, "POST", "/api/v1/integrations/registry/discover", map[string]any{"config": cfg, "secret_ref": "secret:REG"}); code != 403 {
		t.Errorf("an engineer may list a registry with the workspace's secret: %d", code)
	}

	code, body = call(admin, "POST", "/api/v1/integrations", map[string]any{"kind": "container_registry", "config": cfg, "secret_ref": "secret:REG"})
	var in store.Integration
	_ = json.Unmarshal([]byte(body), &in)
	if code != 201 || in.Kind != "container_registry" || in.Name != strings.TrimPrefix(reg.URL, "https://")+"/team" || in.SecretRef != "secret:REG" {
		t.Fatalf("create: %d %s", code, body)
	}
	// With the integration's stored secret, for changing its repositories.
	if code, body := call(admin, "POST", "/api/v1/integrations/registry/discover", map[string]any{"config": cfg, "integration_id": in.ID}); code != 200 {
		t.Errorf("discover with the integration's secret: %d %s", code, body)
	}
	// Wrong credentials: the registry's answer echoes them; ours does not.
	wrong := map[string]any{"provider": "oci", "url": reg.URL, "username": "robot2"}
	if code, body := call(admin, "POST", "/api/v1/integrations/registry/discover", map[string]any{"config": wrong, "secret_ref": "secret:REG"}); code != 502 ||
		!strings.Contains(body, "[redacted]") {
		t.Errorf("wrong credentials: %d %s", code, body)
	}
	if code, body := call(eng, "GET", fmt.Sprintf("/api/v1/integrations/%d/images", in.ID), nil); code != 200 || !strings.Contains(body, `"items":[]`) {
		t.Errorf("images: %d %s", code, body)
	}
	call(eng, "GET", "/api/v1/integrations", nil)
	call(admin, "PATCH", fmt.Sprintf("/api/v1/integrations/%d", in.ID), map[string]any{"config": map[string]any{"provider": "oci", "url": reg.URL, "username": "robot", "recent_tags": 2}})
	call(admin, "GET", "/api/v1/audit", nil)

	basic := base64.StdEncoding.EncodeToString([]byte("robot2:" + registrySecret))
	for i, b := range bodies {
		if strings.Contains(b, registrySecret) || strings.Contains(b, basic) || strings.Contains(b, strings.TrimRight(basic, "=")) {
			t.Errorf("answer %d carries the secret: %s", i, b)
		}
	}
}

func TestRegistryIntegrationValidation(t *testing.T) {
	e := registryEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("root@x.io", auth.RoleAdmin)
	e.instanceAdmin("root@x.io")
	admin, root := e.login("admin@x.io"), e.login("root@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	awsEnv, err := e.st.CreateIntegration(ctx, "plugin", "aws", map[string]any{"plugin": "aws-managed", "config": map[string]any{"regions": []string{"eu-west-1"}}},
		"env:STACKURITY_SECRET_AWS", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	k8s, err := e.st.CreateIntegration(ctx, "plugin", "k8s", map[string]any{"plugin": "kubernetes"}, "secret:K", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	bad := []map[string]any{
		{"kind": "container_registry", "config": map[string]any{"provider": "quay"}},
		{"kind": "container_registry", "config": map[string]any{"provider": "oci", "url": "http://registry.example.com"}},
		{"kind": "container_registry", "config": map[string]any{"provider": "ghcr", "namespace": "acme", "recent_tags": 9}},
		{"kind": "container_registry", "config": map[string]any{"provider": "ghcr", "namespace": "acme", "unknown": 1}},
		{"kind": "container_registry", "config": map[string]any{"provider": "ecr", "region": "eu-west-1"}}, // no keys anywhere
		{"kind": "container_registry", "config": map[string]any{"provider": "ecr", "region": "eu-west-1", "aws_integration_id": k8s.ID}},
		{"kind": "container_registry", "config": map[string]any{"provider": "ecr", "region": "eu-west-1", "aws_integration_id": 999999}},
	}
	for i, b := range bad {
		if code := root.do("POST", "/api/v1/integrations", b, nil); code != 400 {
			t.Errorf("case %d accepted: %d", i, code)
		}
	}
	// Borrowing a server secret (env:) through the aws-managed integration
	// needs an instance administrator, like referencing it directly.
	borrow := map[string]any{"kind": "container_registry", "config": map[string]any{"provider": "ecr", "region": "eu-west-1", "aws_integration_id": awsEnv.ID}}
	if code := admin.do("POST", "/api/v1/integrations", borrow, nil); code != 403 {
		t.Errorf("a workspace admin borrowed a server secret: %d", code)
	}
	if code := root.do("POST", "/api/v1/integrations", borrow, nil); code != 201 {
		t.Errorf("an instance admin may: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations/registry/discover", map[string]any{"config": borrow["config"]}, nil); code != 403 {
		t.Errorf("a workspace admin listed a registry with a server secret: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "container_registry",
		"config": map[string]any{"provider": "ghcr", "namespace": "acme", "tag_patterns": []string{"semver"}}, "secret_ref": "secret:GH"}, nil); code != 201 {
		t.Errorf("valid GHCR: %d", code)
	}
	var in store.Integration
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "container_image", "config": map[string]any{"image": "nginx:1"}}, &in); code != 201 {
		t.Fatalf("image: %d", code)
	}
	if code := admin.do("GET", fmt.Sprintf("/api/v1/integrations/%d/images", in.ID), nil, nil); code != 404 {
		t.Errorf("images of a single-image integration: %d", code)
	}
}
