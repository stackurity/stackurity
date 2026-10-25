package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
)

// TestCommunityAndPlans checks what stays free, what needs Pro, and that a
// workspace's plan caps the instance licence.
func TestCommunityAndPlans(t *testing.T) {
	e := newEnv(t)
	e.user("owner@x.io", auth.RoleAdmin)
	e.instanceAdmin("owner@x.io")
	owner := e.login("owner@x.io")

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e.api.ParseLicence = func(k string) (*license.License, error) { return license.ParseWithKey(k, pub) }

	// Without a licence: Community.
	e.api.Licence.Set(nil)
	var me struct {
		Edition  license.Edition
		Features []license.Feature
	}
	owner.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Edition != license.Community || len(me.Features) != 0 {
		t.Fatalf("community me: %+v", me)
	}
	gated := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/v1/reports/evidence", nil},
		{"POST", "/api/v1/remediation/policies", map[string]any{"name": "p", "target": "host_package"}},
		{"POST", "/api/v1/routes", map[string]any{"name": "esc", "channel_id": 1, "escalation": true}},
	}
	for _, g := range gated {
		if code := owner.do(g.method, g.path, g.body, nil); code != 402 {
			t.Errorf("community %s %s: %d", g.method, g.path, code)
		}
	}
	// One team is free; the second needs Pro.
	if code := owner.do("POST", "/api/v1/teams", map[string]any{"name": "ops"}, nil); code != 201 {
		t.Errorf("first team: %d", code)
	}
	if code := owner.do("POST", "/api/v1/teams", map[string]any{"name": "dev"}, nil); code != 402 {
		t.Errorf("second team on community: %d", code)
	}
	// Detection stays free.
	for _, p := range []string{"/api/v1/overview", "/api/v1/findings", "/api/v1/assets", "/api/v1/fix-groups"} {
		if code := owner.do("GET", p, nil, nil); code != 200 {
			t.Errorf("free %s: %d", p, code)
		}
	}

	// Uploading a Pro licence turns the features on.
	key, _ := license.Issue(license.License{ID: "lic_t", Customer: "Acme", Edition: license.Pro,
		IssuedAt: time.Now(), ExpiresAt: time.Now().AddDate(1, 0, 0)}, priv)
	if code := owner.do("PUT", "/api/v1/admin/license", map[string]string{"key": "garbage"}, nil); code != 400 {
		t.Errorf("garbage licence: %d", code)
	}
	if code := owner.do("PUT", "/api/v1/admin/license", map[string]string{"key": key}, nil); code != 200 {
		t.Fatalf("install licence: %d", code)
	}
	if code := owner.do("POST", "/api/v1/teams", map[string]any{"name": "dev"}, nil); code != 201 {
		t.Errorf("second team with pro: %d", code)
	}
	if k, _ := e.st.LicenseKey(context.Background()); k != key {
		t.Error("licence not stored")
	}

	// A hosted organisation on the community plan gets no Pro features.
	ws, _, err := e.st.CreateWorkspace(context.Background(), "Free Co", "", "free@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	community := "community"
	if code := owner.do("PATCH", fmt.Sprintf("/api/v1/admin/workspaces/%d", ws.ID), store.WorkspaceUpdate{Plan: &community}, nil); code != 200 {
		t.Fatalf("set plan: %d", code)
	}
	free := e.login("free@x.io")
	free.do("POST", "/api/v1/teams", map[string]any{"name": "one"}, nil)
	if code := free.do("POST", "/api/v1/teams", map[string]any{"name": "two"}, nil); code != 402 {
		t.Errorf("community workspace on a licensed server got a second team: %d", code)
	}
	// An enterprise plan is capped by the Pro licence.
	enterprise := "enterprise"
	owner.do("PATCH", fmt.Sprintf("/api/v1/admin/workspaces/%d", ws.ID), store.WorkspaceUpdate{Plan: &enterprise}, nil)
	free.do("GET", "/api/v1/auth/me", nil, &me)
	if me.Edition != license.Pro {
		t.Errorf("enterprise plan on a pro licence: %s", me.Edition)
	}
	if code := owner.do("DELETE", "/api/v1/admin/license", nil, nil); code != 204 {
		t.Errorf("remove licence: %d", code)
	}
	if code := owner.do("POST", "/api/v1/teams", map[string]any{"name": "third"}, nil); code != 402 {
		t.Errorf("after removing the licence: %d", code)
	}
}
