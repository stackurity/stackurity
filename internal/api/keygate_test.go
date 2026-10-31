package api_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/tenant"
)

// errorCode is the code of an API error answer ("" for others).
func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	var out struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Error.Code
}

func bearerResp(e *env, token, method, path string, body []byte) *http.Response {
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

// TestKeyGate: a self-hosted server without its key holds back the
// dashboard and API, but signing in, entering the key, health checks and
// the data path of agents, CLI scans and CI keep working; data sent
// meanwhile is kept. A free Community key or any licence opens it.
func TestKeyGate(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var req *license.Requirement
	e := newEnvWith(t, func(s *api.Server) {
		req = &license.Requirement{From: time.Now().Add(-time.Minute), Licence: s.Licence}
		s.KeyRequirement = req
		s.ParseLicence = func(k string) (*license.License, error) { return license.ParseWithKey(k, pub) }
	})
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	e.user("view@x.io", auth.RoleViewer)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, collector, err := e.st.CreateToken(ctx, "agent", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, ci, err := e.st.CreateToken(ctx, "ci", auth.RoleViewer, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// No key.
	e.api.Licence.Set(nil)
	owner := e.login("owner@x.io") // signing in works
	view := e.login("view@x.io")
	anon := e.anon()

	for _, c := range []struct {
		s            *session
		method, path string
	}{
		{owner, "GET", "/api/v1/assets"},
		{owner, "GET", "/api/v1/findings"},
		{owner, "GET", "/api/v1/users"},
		{owner, "POST", "/api/v1/tokens"},
		{owner, "GET", "/api/v1/projects"}, // a browser session is not a CLI token
		{owner, "GET", "/api/v1/admin/packs"},
		{view, "GET", "/api/v1/overview"},
		{anon, "POST", "/api/v1/invitations/accept"},
	} {
		resp := c.s.req(c.method, c.path, bytes.NewReader([]byte(`{}`)), map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"})
		if resp.StatusCode != 403 || errorCode(t, resp) != "key_required" {
			t.Errorf("%s %s without a key: %d, want 403 key_required", c.method, c.path, resp.StatusCode)
		}
	}
	for _, path := range []string{"/healthz", "/readyz", "/api/v1/meta", "/api/v1/openapi.json"} {
		if code := anon.do("GET", path, nil, nil); code != 200 {
			t.Errorf("%s without a key: %d", path, code)
		}
	}
	// The dashboard learns why, and the instance admin can see and enter the key.
	var me struct {
		LicenseKey license.KeyStatus `json:"license_key"`
	}
	if code := view.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.LicenseKey.State != license.KeyRequired || me.LicenseKey.SignupURL != license.SignupURL {
		t.Errorf("me without a key: %d %+v", code, me.LicenseKey)
	}
	if code := owner.do("GET", "/api/v1/admin/license", nil, nil); code != 200 {
		t.Errorf("instance admin reads the licence page: %d", code)
	}
	resp := view.req("PUT", "/api/v1/admin/license", bytes.NewReader([]byte(`{"key":"x"}`)), map[string]string{"X-Stackurity-CSRF": "1"})
	if resp.StatusCode != 403 || errorCode(t, resp) == "key_required" {
		t.Errorf("a viewer entering the key: %d (must be refused as not an instance admin)", resp.StatusCode)
	}

	// Agents, CLI scans and CI keep sending data.
	if code := bearer(e, collector, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Errorf("agent ingest without a key: %d", code)
	}
	cdx := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20"}]}`
	if code, body := bearerBody(e, collector, "POST", "/api/v1/sbom/import?asset_name=shop", []byte(cdx)); code/100 != 2 {
		t.Errorf("SBOM upload without a key: %d %s", code, body)
	}
	if code := bearer(e, collector, "GET", "/api/v1/agent/check", nil, nil); code == 403 {
		t.Errorf("agent check without a key: %d", code)
	}
	if resp := bearerResp(e, collector, "GET", "/api/v1/collections/999999/result", nil); errorCode(t, resp) == "key_required" {
		t.Error("scan result (--wait) held back without a key")
	}
	// stackurity scan --project looks the project up with its token.
	if code := bearer(e, ci, "GET", "/api/v1/projects", nil, nil); code != 200 {
		t.Errorf("CLI token lists projects without a key: %d", code)
	}
	if resp := bearerResp(e, ci, "GET", "/api/v1/assets", nil); resp.StatusCode != 403 || errorCode(t, resp) != "key_required" {
		t.Errorf("CLI token reads assets without a key: %d", resp.StatusCode)
	}
	if resp := bearerResp(e, ci, "GET", "/api/v1/auth/me", nil); resp.StatusCode != 200 {
		t.Errorf("stackurity doctor (auth/me) without a key: %d", resp.StatusCode)
	}

	// The free key, pasted in: everything opens, and the data is there.
	now := time.Now().UTC().Truncate(time.Second)
	key, err := license.Issue(license.License{ID: "ck_test", Customer: "Acme", Name: "Asha", Email: "asha@acme.example",
		Edition: license.Community, IssuedAt: now, ExpiresAt: now.Add(license.CommunityValidity)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if code := owner.do("PUT", "/api/v1/admin/license", map[string]string{"key": key}, nil); code != 200 {
		t.Fatalf("enter the free key: %d", code)
	}
	var assets struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if code := owner.do("GET", "/api/v1/assets", nil, &assets); code != 200 || len(assets.Items) < 2 {
		t.Errorf("assets after the key: %d %+v (the host and the SBOM sent without a key)", code, assets.Items)
	}
	if view.do("GET", "/api/v1/auth/me", nil, &me); me.LicenseKey.State != license.KeyInstalled {
		t.Errorf("me with the key: %+v", me.LicenseKey)
	}
	// It is Community: no paid features.
	if code := owner.do("GET", "/api/v1/reports/evidence", nil, nil); code != 402 {
		t.Errorf("evidence report with a Community key: %d", code)
	}
	// Removing it holds the server back again.
	if code := owner.do("DELETE", "/api/v1/admin/license", nil, nil); code != 204 {
		t.Fatalf("remove the key: %d", code)
	}
	if resp := owner.req("GET", "/api/v1/assets", nil, nil); errorCode(t, resp) != "key_required" {
		t.Error("removing the key did not hold the server back")
	}
	// A paid licence counts too.
	e.api.Licence.Set(&license.License{Version: 1, Customer: "Acme", Edition: license.Pro, ExpiresAt: now.AddDate(1, 0, 0)})
	if code := owner.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("assets with a paid licence: %d", code)
	}
}

// TestKeyGateUpgradeGrace: a server that had users or data gets 30 days,
// with a banner for administrators, before the key is needed.
func TestKeyGateUpgradeGrace(t *testing.T) {
	var req *license.Requirement
	e := newEnvWith(t, func(s *api.Server) {
		req = &license.Requirement{From: time.Now().Add(license.KeyGrace), Upgraded: true, Licence: s.Licence}
		s.KeyRequirement = req
	})
	e.user("owner@x.io", auth.RoleAdmin)
	e.api.Licence.Set(nil)
	owner := e.login("owner@x.io")
	var me struct {
		LicenseKey license.KeyStatus `json:"license_key"`
	}
	if code := owner.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me.LicenseKey.State != license.KeyGraceTime ||
		me.LicenseKey.GraceEnds == nil || !me.LicenseKey.Upgraded {
		t.Fatalf("me in the grace period: %d %+v", code, me.LicenseKey)
	}
	if code := owner.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("assets in the grace period: %d", code)
	}
	// 30 days of running later: held back.
	req.SetObserved(license.KeyGrace)
	if resp := owner.req("GET", "/api/v1/assets", nil, nil); resp.StatusCode != 403 || errorCode(t, resp) != "key_required" {
		t.Errorf("assets after the grace period: %d", resp.StatusCode)
	}
}

// TestNoKeyRequirement: Stackurity Cloud (no requirement) is never held back
// and says nothing about a key.
func TestNoKeyRequirement(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.api.Licence.Set(nil)
	owner := e.login("owner@x.io")
	var me map[string]any
	if code := owner.do("GET", "/api/v1/auth/me", nil, &me); code != 200 || me["license_key"] != nil {
		t.Errorf("me on a server with no requirement: %d %v", code, me["license_key"])
	}
	if code := owner.do("GET", "/api/v1/assets", nil, nil); code != 200 {
		t.Errorf("assets: %d", code)
	}
}
