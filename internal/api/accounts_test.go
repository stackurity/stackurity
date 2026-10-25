package api_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// TestCredentialChangesTakeEffectImmediately: revoking a token, disabling
// its user or workspace, removing the user, expiry and a role downgrade all
// apply to the very next request; nothing is cached.
func TestCredentialChangesTakeEffectImmediately(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.user("root@x.io", auth.RoleAdmin)
	e.instanceAdmin("root@x.io")
	root := e.login("root@x.io")
	beta, betaAdmin, err := e.st.CreateWorkspace(ctx, "Beta", "", "beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	bctx := tenant.WithWorkspace(ctx, beta.ID)
	if _, err := e.st.CreateUser(bctx, "member@x.io", "", auth.RoleAdmin, pw); err != nil {
		t.Fatal(err)
	}
	member := e.login("member@x.io")
	var me struct{ User store.User }
	member.do("GET", "/api/v1/auth/me", nil, &me)
	memberID := me.User.ID
	token := func(s *session, role auth.Role) (int64, string) {
		var out struct {
			Token  store.Token
			Secret string
		}
		if code := s.do("POST", "/api/v1/tokens", map[string]any{"name": "t-" + string(role), "role": role}, &out); code != 201 {
			t.Fatalf("token %s: %d", role, code)
		}
		return out.Token.ID, out.Secret
	}
	get := func(secret, path string) int { return bearer(e, secret, "GET", path, nil, nil) }

	// Revocation.
	id, sec := token(member, auth.RoleViewer)
	if get(sec, "/api/v1/assets") != 200 {
		t.Fatal("fresh token refused")
	}
	if code := member.do("DELETE", fmt.Sprintf("/api/v1/tokens/%d", id), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code := get(sec, "/api/v1/assets"); code != 401 {
		t.Errorf("revoked token: %d", code)
	}

	// Expiry.
	id, sec = token(member, auth.RoleViewer)
	if _, err := e.st.Pool.Exec(bctx, `UPDATE api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if code := get(sec, "/api/v1/assets"); code != 401 {
		t.Errorf("expired token: %d", code)
	}

	// Role downgrade: the admin token keeps its label but acts as a viewer.
	_, adminTok := token(member, auth.RoleAdmin)
	if get(adminTok, "/api/v1/users") != 200 {
		t.Fatal("admin token refused")
	}
	bs := e.login("beta@x.io")
	if code := bs.do("PATCH", fmt.Sprintf("/api/v1/users/%d", memberID), map[string]any{"role": "viewer"}, nil); code != 200 {
		t.Fatalf("downgrade: %d", code)
	}
	if code := get(adminTok, "/api/v1/users"); code != 403 {
		t.Errorf("admin token after its owner became a viewer: %d", code)
	}
	if code := bearer(e, adminTok, "POST", "/api/v1/tokens", []byte(`{"name":"x","role":"admin"}`), nil); code != 403 {
		t.Errorf("downgraded token minted an admin token: %d", code)
	}
	if get(adminTok, "/api/v1/assets") != 200 {
		t.Error("downgraded token lost viewer access")
	}
	if code := member.do("GET", "/api/v1/users", nil, nil); code != 403 {
		t.Errorf("session after downgrade: %d", code)
	}

	// Removal from the workspace ends the user's tokens there.
	_, viewTok := token(member, auth.RoleViewer)
	if code := bs.do("DELETE", fmt.Sprintf("/api/v1/users/%d", memberID), nil, nil); code != 204 {
		t.Fatalf("remove: %d", code)
	}
	for _, s := range []string{adminTok, viewTok} {
		if code := get(s, "/api/v1/assets"); code != 401 {
			t.Errorf("token of a removed member: %d", code)
		}
	}
	if code := member.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Errorf("session of a removed member: %d", code)
	}

	// Disabling the user ends sessions and tokens.
	_, tokOfBeta := token(bs, auth.RoleAdmin)
	bctxUser := tenant.WithWorkspace(ctx, beta.ID)
	if _, err := e.st.CreateUser(bctxUser, "second@x.io", "", auth.RoleAdmin, pw); err != nil {
		t.Fatal(err)
	}
	second := e.login("second@x.io")
	_, secondTok := token(second, auth.RoleEngineer)
	var users struct{ Items []store.User }
	bs.do("GET", "/api/v1/users", nil, &users)
	for _, u := range users.Items {
		if u.Email == "second@x.io" {
			if code := bs.do("PATCH", fmt.Sprintf("/api/v1/users/%d", u.ID), map[string]any{"disabled": true}, nil); code != 200 {
				t.Fatalf("disable: %d", code)
			}
		}
	}
	if code := get(secondTok, "/api/v1/assets"); code != 401 {
		t.Errorf("token of a disabled user: %d", code)
	}
	if code := second.do("GET", "/api/v1/auth/me", nil, nil); code != 401 {
		t.Errorf("session of a disabled user: %d", code)
	}

	// Disabling the workspace ends every credential in it, collector tokens
	// included, and re-enabling restores them.
	_, collector, err := e.st.CreateToken(bctx, "agent", auth.RoleCollector, nil, betaAdmin.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, collector, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Fatalf("collector before: %d", code)
	}
	if code := root.do("PATCH", fmt.Sprintf("/api/v1/admin/workspaces/%d", beta.ID), map[string]any{"disabled": true}, nil); code != 200 {
		t.Fatalf("disable workspace: %d", code)
	}
	if code := bearer(e, collector, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 401 {
		t.Errorf("collector token of a disabled workspace: %d", code)
	}
	if code := get(tokOfBeta, "/api/v1/assets"); code != 401 {
		t.Errorf("user token of a disabled workspace: %d", code)
	}
	if code := bs.do("GET", "/api/v1/assets", nil, nil); code != 403 {
		t.Errorf("session in a disabled workspace: %d", code)
	}
	if code := root.do("PATCH", fmt.Sprintf("/api/v1/admin/workspaces/%d", beta.ID), map[string]any{"disabled": false}, nil); code != 200 {
		t.Fatalf("enable workspace: %d", code)
	}
	if code := bearer(e, collector, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Errorf("collector after re-enabling: %d", code)
	}
}

// TestWorkspaceAdminCannotTakeOverInstanceAdmin: an instance admin whose
// only workspace is someone else's must not have their password, name or
// status set by that workspace's admin.
func TestWorkspaceAdminCannotTakeOverInstanceAdmin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	beta, _, err := e.st.CreateWorkspace(ctx, "Beta", "", "beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := e.st.CreateUser(tenant.WithWorkspace(ctx, beta.ID), "ops@x.io", "", auth.RoleViewer, pw)
	if err != nil {
		t.Fatal(err)
	}
	e.instanceAdmin("ops@x.io")
	bs := e.login("beta@x.io")
	for _, body := range []map[string]any{{"password": "attacker chosen password"}, {"disabled": true}, {"name": "x"}} {
		if code := bs.do("PATCH", fmt.Sprintf("/api/v1/users/%d", ops.ID), body, nil); code != 409 {
			t.Errorf("workspace admin changed an instance admin account (%v): %d", body, code)
		}
	}
	if code := e.anon().do("POST", "/api/v1/auth/login", map[string]string{"email": "ops@x.io", "password": "attacker chosen password"}, nil); code == 200 {
		t.Fatal("signed in as the instance admin with the workspace admin's password")
	}
	e.login("ops@x.io") // the real password still works
	// The workspace role is still the workspace's to set.
	if code := bs.do("PATCH", fmt.Sprintf("/api/v1/users/%d", ops.ID), map[string]any{"role": "engineer"}, nil); code != 200 {
		t.Errorf("role change: %d", code)
	}
}
