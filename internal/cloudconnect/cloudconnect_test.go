package cloudconnect

import (
	"bytes"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var testKey = bytes.Repeat([]byte{7}, 32)

func platform(t *testing.T) *Platform {
	t.Helper()
	p, err := New("https://app.stackurity.dev", testKey, "11111111-2222-3333-4444-555555555555", "platform-app-secret")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The identity token verifies against the published key set with an
// independent JOSE implementation, and names the workspace.
func TestIdentityTokenVerifiesWithJWKS(t *testing.T) {
	p := platform(t)
	now := time.Now()
	tok, err := p.IdentityToken(42, GCPAudience, now)
	if err != nil {
		t.Fatal(err)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(p.JWKS()), &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks %s: %v", p.JWKS(), err)
	}
	parsed, err := jwt.ParseSigned(tok, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	var c jwt.Claims
	if err := parsed.Claims(set.Keys[0].Key, &c); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: "https://app.stackurity.dev", Subject: "workspace:42",
		AnyAudience: jwt.Audience{GCPAudience}, Time: now}, 0); err != nil {
		t.Error(err)
	}
	if exp := c.Expiry.Time(); exp.Sub(now) > 11*time.Minute {
		t.Errorf("token lives until %s", exp)
	}
	// Another server's key does not verify it.
	other, _ := New("https://app.stackurity.dev", bytes.Repeat([]byte{8}, 32), "", "")
	var oset jose.JSONWebKeySet
	_ = json.Unmarshal([]byte(other.JWKS()), &oset)
	if err := parsed.Claims(oset.Keys[0].Key, &c); err == nil {
		t.Error("token verified with another server's key")
	}
	// The key is stable for a given secret key (customers upload it once).
	again, _ := New("https://app.stackurity.dev", testKey, "", "")
	if again.JWKS() != p.JWKS() {
		t.Error("JWKS changes between restarts")
	}
}

func TestWorkspaceProof(t *testing.T) {
	p := platform(t)
	a, b := p.WorkspaceProof(1), p.WorkspaceProof(2)
	if a == "" || a == b || len(a) < 20 {
		t.Errorf("proofs %q %q", a, b)
	}
	other, _ := New("", bytes.Repeat([]byte{9}, 32), "", "")
	if other.WorkspaceProof(1) == a {
		t.Error("proof does not depend on the server's key")
	}
	if strings.Contains(a, string(testKey)) {
		t.Error("proof leaks key")
	}
}

func TestPluginCredentials(t *testing.T) {
	p := platform(t)
	got := p.PluginCredentials([]string{"client_email", CredIdentityToken + " (server)", CredWorkspaceProof, CredAzureAppID, CredAzureAppSecret}, 5, time.Now())
	if got[CredAzureAppID] != p.AzureAppID || got[CredAzureAppSecret] != "platform-app-secret" || got[CredWorkspaceProof] != p.WorkspaceProof(5) || got[CredIdentityToken] == "" {
		t.Errorf("credentials = %v", got)
	}
	if _, ok := got["client_email"]; ok {
		t.Error("customer credential filled by the server")
	}
	// Not configured: nothing is made up.
	bare, _ := New("http://localhost:8080", nil, "", "")
	if got := bare.PluginCredentials([]string{CredIdentityToken, CredAzureAppSecret, CredWorkspaceProof}, 5, time.Now()); len(got) != 0 {
		t.Errorf("unconfigured server credentials = %v", got)
	}
	// Negative control: a server with a key but http issuer cannot sign.
	httpOnly, _ := New("http://localhost:8080", testKey, "", "")
	if ok, _ := httpOnly.GCPStatus(); ok {
		t.Error("keyless GCP offered with an http issuer")
	}
	m := map[string]string{"stackurity_workspace_proof": "forged", "STACKURITY_IDENTITY_TOKEN": "x", "azure_client_id": "a"}
	StripPlatform(m)
	if len(m) != 1 || m["azure_client_id"] != "a" {
		t.Errorf("after strip: %v", m)
	}
	if !DeclaresPlatform([]string{"x", CredIdentityToken}) || DeclaresPlatform([]string{"aws_access_key_id"}) {
		t.Error("DeclaresPlatform")
	}
}

var gcpPermsFlag = regexp.MustCompile(`--permissions="([^"]*)"`)

// The generated commands grant exactly the permission list the plugin's
// calls are checked against.
func TestGCPSetupGrantsExactlyThePermissions(t *testing.T) {
	p := platform(t)
	s, err := p.GCPSetup(42, "acme-prod", "123456789012")
	if err != nil {
		t.Fatal(err)
	}
	for _, cmds := range []string{s.Commands, s.FallbackCommands} {
		m := gcpPermsFlag.FindAllStringSubmatch(cmds, -1)
		if len(m) != 1 {
			t.Fatalf("expected one --permissions flag:\n%s", cmds)
		}
		if got := strings.Split(m[0][1], ","); !slices.Equal(got, GCPPermissions()) {
			t.Errorf("role grants %v, plugin needs %v", got, GCPPermissions())
		}
	}
	for _, want := range []string{
		`--attribute-condition="assertion.sub=='workspace:42'"`,
		`--member="principal://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/stackurity/subject/workspace:42"`,
		`--issuer-uri="https://app.stackurity.dev"`, `--allowed-audiences="stackurity-gcp"`, p.JWKS(),
		`--role=roles/iam.workloadIdentityUser`,
	} {
		if !strings.Contains(s.Commands, want) {
			t.Errorf("commands lack %s", want)
		}
	}
	if strings.Contains(s.Commands, "keys create") || !strings.Contains(s.FallbackCommands, "keys create") {
		t.Error("only the fallback creates a key")
	}
	if s.Config["auth"] != "workload_identity" || s.Config["project_number"] != "123456789012" {
		t.Errorf("config %v", s.Config)
	}
	// Input that would break out of the shell is refused.
	for _, bad := range [][2]string{{`acme"; rm -rf ~`, "1"}, {"acme-prod", "1; id"}, {"A", "1"}, {"acme-prod", ""}} {
		if _, err := p.GCPSetup(1, bad[0], bad[1]); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// Without a key only the fallback is offered.
	bare, _ := New("https://app.stackurity.dev", nil, "", "")
	if s, err := bare.GCPSetup(1, "acme-prod", "1"); err != nil || s.Keyless || s.Commands != "" || s.KeylessUnavailable == "" || s.FallbackCommands == "" {
		t.Errorf("without key: %+v %v", s, err)
	}
}

func TestAzureSetupGrantsExactlyTheActions(t *testing.T) {
	p := platform(t)
	tenant, sub := "AAAAAAAA-0000-0000-0000-000000000001", "bbbbbbbb-0000-0000-0000-000000000002"
	s, err := p.AzureSetup(42, tenant, sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, cmds := range []string{s.Commands, s.FallbackCommands} {
		start := strings.Index(cmds, "<<'EOF'\n")
		end := strings.Index(cmds, "\nEOF\n")
		var role struct {
			Actions          []string
			DataActions      []string
			AssignableScopes []string
		}
		if start < 0 || end < start || json.Unmarshal([]byte(cmds[start+8:end]), &role) != nil {
			t.Fatalf("no role definition in:\n%s", cmds)
		}
		if !slices.Equal(role.Actions, AzureActions()) || len(role.DataActions) != 0 || !slices.Equal(role.AssignableScopes, []string{"/subscriptions/" + sub}) {
			t.Errorf("role = %+v, plugin needs %v", role, AzureActions())
		}
	}
	if !strings.Contains(s.Commands, `--description "`+ProofPrefix+p.WorkspaceProof(42)+`"`) {
		t.Errorf("assignment does not carry the workspace proof:\n%s", s.Commands)
	}
	if strings.Contains(s.Commands, "platform-app-secret") || strings.Contains(s.ConsentURL, "platform-app-secret") {
		t.Error("the app secret is in the setup output")
	}
	if !strings.HasPrefix(s.ConsentURL, "https://login.microsoftonline.com/aaaaaaaa-0000-0000-0000-000000000001/adminconsent?client_id=11111111-2222-3333-4444-555555555555") ||
		!strings.Contains(s.ConsentURL, "redirect_uri=https%3A%2F%2Fapp.stackurity.dev%2Fsettings%2Fintegrations") {
		t.Errorf("consent url %s", s.ConsentURL)
	}
	if strings.Contains(s.Commands, "create-for-rbac") || !strings.Contains(s.FallbackCommands, "create-for-rbac") {
		t.Error("only the fallback creates a secret")
	}
	for _, bad := range [][2]string{{"x", sub}, {tenant, `$(id)`}} {
		if _, err := p.AzureSetup(1, bad[0], bad[1]); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	noApp, _ := New("https://app.stackurity.dev", testKey, "", "")
	if s, _ := noApp.AzureSetup(1, tenant, sub); s.Keyless || s.KeylessUnavailable == "" || s.ConsentURL != "" {
		t.Errorf("without app: %+v", s)
	}
}

// A workspace's stored secret cannot supply platform credentials, and only
// the first-party plugins receive them.
func TestForPlugin(t *testing.T) {
	p := platform(t)
	declared := []string{CredWorkspaceProof, CredAzureAppID, CredAzureAppSecret, "azure_client_id"}
	stored := map[string]string{CredWorkspaceProof: p.WorkspaceProof(7), "azure_client_id": "c"}
	got := p.ForPlugin("azure-managed", declared, stored, 8, time.Now())
	if got[CredWorkspaceProof] != p.WorkspaceProof(8) || got["azure_client_id"] != "c" || got[CredAzureAppSecret] != "platform-app-secret" {
		t.Errorf("azure-managed got %v", got)
	}
	got = p.ForPlugin("third-party", declared, stored, 8, time.Now())
	if len(got) != 1 || got["azure_client_id"] != "c" {
		t.Errorf("third-party plugin got %v", got)
	}
	if UsesPlatform("third-party", declared) || !UsesPlatform("gcp-managed", []string{CredIdentityToken + " (server)"}) || UsesPlatform("gcp-managed", []string{"client_email"}) {
		t.Error("UsesPlatform")
	}
}
