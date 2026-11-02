package api_test

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/plugins"
	"github.com/stackurity/stackurity/internal/tenant"
)

const cloudAppSecret = "platform-app-secret-value"

func cloudEnv(t *testing.T) *env {
	plat, err := cloudconnect.New("https://stackurity.example", bytes.Repeat([]byte{4}, 32), "11111111-2222-3333-4444-555555555555", cloudAppSecret)
	if err != nil {
		t.Fatal(err)
	}
	return newEnvWith(t, func(s *api.Server) { s.Cloud = plat })
}

// The setup commands name the caller's workspace, never another's, and
// never carry the server's secrets.
func TestCloudSetup(t *testing.T) {
	e := cloudEnv(t)
	e.user("a@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	ws, _, err := e.st.CreateWorkspace(context.Background(), "Beta", "", "b@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	gcpQ := "/api/v1/cloud-setup/gcp?project_id=acme-prod&project_number=123456789012"
	azQ := "/api/v1/cloud-setup/azure?tenant_id=aaaaaaaa-0000-0000-0000-000000000001&subscription_id=bbbbbbbb-0000-0000-0000-000000000002"
	var a, b cloudconnect.Setup
	if code := e.login("a@x.io").do("GET", gcpQ, nil, &a); code != 200 || !a.Keyless {
		t.Fatalf("gcp setup: %d %+v", code, a)
	}
	if code := e.login("b@x.io").do("GET", gcpQ, nil, &b); code != 200 {
		t.Fatalf("gcp setup in B: %d", code)
	}
	if !strings.Contains(a.Commands, "subject/workspace:1\"") || !strings.Contains(b.Commands, "subject/workspace:"+itoa(ws.ID)+"\"") || strings.Contains(b.Commands, "workspace:1'") {
		t.Errorf("subjects: A\n%s\nB\n%s", a.Commands, b.Commands)
	}
	var az cloudconnect.Setup
	if code := e.login("a@x.io").do("GET", azQ, nil, &az); code != 200 || !strings.Contains(az.Commands, e.api.Cloud.WorkspaceProof(1)) {
		t.Fatalf("azure setup: %d %+v", code, az)
	}
	for _, path := range []string{gcpQ, azQ} {
		resp := e.login("a@x.io").req("GET", path, nil, nil)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if bytes.Contains(body, []byte(cloudAppSecret)) || bytes.Contains(body, []byte(`"d"`)) {
			t.Errorf("%s leaks a secret: %s", path, body)
		}
	}
	if code := e.login("eng@x.io").do("GET", gcpQ, nil, nil); code != 403 {
		t.Errorf("engineer: %d", code)
	}
	if code := e.login("a@x.io").do("GET", "/api/v1/cloud-setup/gcp?project_id=x;rm&project_number=1", nil, nil); code != 400 {
		t.Errorf("bad project: %d", code)
	}
	// A server without the identity offers the fallback only.
	bare := newEnv(t)
	bare.user("a@x.io", auth.RoleAdmin)
	var f cloudconnect.Setup
	if code := bare.login("a@x.io").do("GET", gcpQ, nil, &f); code != 200 || f.Keyless || f.KeylessUnavailable == "" || f.FallbackCommands == "" {
		t.Errorf("without identity: %d %+v", code, f)
	}
}

// gcp-managed and azure-managed use the server's workload identity, which
// names the workspace, so another workspace may add them without a stored
// secret; any other plugin still needs one.
func TestPlatformPluginsNeedNoStoredSecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script plugin")
	}
	dir := t.TempDir()
	write := func(name, creds string) {
		meta := `{"protocol_version":"1","metadata":{"id":"` + name + `","name":"c","version":"1","maintainer":"m","license":"MIT","schema_version":"1","permissions":[],"credentials":[` + creds + `],"network_access":[],"known_limitations":[]}}`
		script := "#!/bin/sh\ncat >/dev/null\nif [ \"$1\" = metadata ]; then echo '" + meta + "'; else echo '{\"protocol_version\":\"1\",\"validation\":{\"ok\":true}}'; fi\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write("gcp-managed", `"stackurity_identity_token (server)"`)
	write("other", `"stackurity_identity_token"`) // declares it, but is not first-party
	write("azure-managed", `"azure_client_id"`)   // first-party name, but declares no platform credential
	e := cloudEnv(t)
	e.api.Plugins = &plugins.Runner{Dir: dir, WorkDir: t.TempDir(), Timeout: time.Minute}
	if _, _, err := e.st.CreateWorkspace(context.Background(), "Beta", "", "b@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	b := e.login("b@x.io")
	body := func(p string) map[string]any {
		return map[string]any{"kind": "plugin", "config": map[string]any{"plugin": p, "config": map[string]any{}}}
	}
	if code := b.do("POST", "/api/v1/integrations", body("gcp-managed"), nil); code != 201 {
		t.Errorf("gcp-managed without a stored secret: %d", code)
	}
	for _, p := range []string{"other", "azure-managed"} {
		var out struct{ Error struct{ Message string } }
		if code := b.do("POST", "/api/v1/integrations", body(p), &out); code != 400 || !strings.Contains(out.Error.Message, "need credentials") {
			t.Errorf("%s without a stored secret: %d %+v", p, code, out)
		}
	}
	_ = tenant.DefaultWorkspace
}
