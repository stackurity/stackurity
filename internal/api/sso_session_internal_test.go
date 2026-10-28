package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// A session started by a workspace's own single sign-on stays in that
// workspace, and an edition can refuse ordinary sessions in a workspace
// that requires its single sign-on.
func TestSSOSessions(t *testing.T) {
	st := store.New(testdb.New(t))
	bg := context.Background()
	ws1 := tenant.WithWorkspace(bg, tenant.DefaultWorkspace)
	u, err := st.CreateUser(ws1, "both@acme.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	ws2, _, err := st.CreateWorkspace(ws1, "Acme", "acme", "owner@acme.io", "Owner", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'viewer')`, ws2.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	holder := &license.Holder{}
	s := &Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Licence: holder, Gate: &license.Gate{Licence: holder}}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	type meResp struct {
		Workspace *struct {
			ID int64 `json:"id"`
		} `json:"workspace"`
		Role        string       `json:"role"`
		SSORequired *SSORequired `json:"sso_required"`
	}
	call := func(secret, method, path string) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: secret})
		req.Header.Set("X-Stackurity-CSRF", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
	me := func(secret string) meResp {
		_, b := call(secret, "GET", "/api/v1/auth/me")
		var m meResp
		_ = json.Unmarshal(b, &m)
		return m
	}

	// Pinned to workspace 2: it works there and cannot switch to 1.
	pinned, err := st.CreateSSOSession(bg, u.ID, ws2.ID)
	if err != nil {
		t.Fatal(err)
	}
	if m := me(pinned); m.Workspace == nil || m.Workspace.ID != ws2.ID {
		t.Fatalf("pinned session works in %+v", m.Workspace)
	}
	if status, _ := call(pinned, "POST", "/api/v1/workspaces/1/activate"); status != 409 {
		t.Errorf("pinned session switched workspace: %d", status)
	}
	if m := me(pinned); m.Workspace == nil || m.Workspace.ID != ws2.ID {
		t.Errorf("after the refused switch: %+v", m.Workspace)
	}
	// Removed from workspace 2: no workspace at all, never workspace 1.
	if _, err := st.Pool.Exec(tenant.System(bg), `DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`, ws2.ID, u.ID); err != nil {
		t.Fatal(err)
	}
	if m := me(pinned); m.Workspace != nil {
		t.Errorf("pinned session fell back to workspace %d", m.Workspace.ID)
	}
	if _, err := st.Pool.Exec(tenant.System(bg), `INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'viewer')`, ws2.ID, u.ID); err != nil {
		t.Fatal(err)
	}

	// An ordinary session in a workspace that requires its own sign-on is
	// refused there (no workspace, no data), told where to sign in, and
	// can still switch to another workspace.
	editionSessionAccess = func(s *Server, r *http.Request, user *store.User, ws, sso int64) *SSORequired {
		if ws == ws2.ID && sso != ws2.ID {
			return &SSORequired{WorkspaceID: ws2.ID, WorkspaceName: "Acme", LoginURL: "/sso/k/login"}
		}
		return nil
	}
	defer func() { editionSessionAccess = nil }()
	plain, err := st.CreateSession(bg, u.ID, ws2.ID)
	if err != nil {
		t.Fatal(err)
	}
	m := me(plain)
	if m.Workspace != nil || m.Role != "" || m.SSORequired == nil || m.SSORequired.LoginURL != "/sso/k/login" {
		t.Errorf("ordinary session in an SSO-only workspace: %+v %+v", m.Workspace, m.SSORequired)
	}
	if status, _ := call(plain, "GET", "/api/v1/assets"); status == 200 {
		t.Error("ordinary session read workspace data")
	}
	if status, _ := call(plain, "POST", "/api/v1/workspaces/1/activate"); status != 200 {
		t.Errorf("switching away: %d", status)
	}
	if m := me(plain); m.Workspace == nil || m.Workspace.ID != tenant.DefaultWorkspace || m.SSORequired != nil {
		t.Errorf("after switching away: %+v %+v", m.Workspace, m.SSORequired)
	}
	// The pinned session is allowed.
	if m := me(pinned); m.Workspace == nil || m.Workspace.ID != ws2.ID || m.SSORequired != nil {
		t.Errorf("pinned session refused: %+v", m.SSORequired)
	}
}
