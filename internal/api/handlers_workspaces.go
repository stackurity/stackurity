package api

import (
	"net/http"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// listMyWorkspaces lists the workspaces the signed-in user belongs to.
func (s *Server) listMyWorkspaces(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User == nil {
		writeError(w, 403, "forbidden", "not a user")
		return
	}
	ms, err := s.Store.Memberships(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(ms))
}

// activateWorkspace switches the browser session to another workspace.
// Tokens are bound to one workspace and cannot switch.
func (s *Server) activateWorkspace(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User == nil || !p.Session {
		writeError(w, 403, "forbidden", "sign in with a session to switch workspaces")
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, _ := r.Cookie(sessionCookie)
	if err := s.Store.SetSessionWorkspace(r.Context(), c.Value, p.User.ID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := tenant.WithWorkspace(r.Context(), id)
	_ = s.Store.Audit(ctx, p.Actor(r), "workspace.enter", "workspace", itoa(id), nil)
	u, err := s.Store.GetUser(ctx, p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, u)
}

func (s *Server) adminListWorkspaces(w http.ResponseWriter, r *http.Request) {
	ws, err := s.Store.ListWorkspaces(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(ws))
}

type workspaceRequest struct {
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	AdminEmail    string `json:"admin_email"`
	AdminName     string `json:"admin_name"`
	AdminPassword string `json:"admin_password"`
}

// adminCreateWorkspace creates a workspace for another organisation. Its
// first admin is an existing account, or a new one with admin_password.
func (s *Server) adminCreateWorkspace(w http.ResponseWriter, r *http.Request) {
	var req workspaceRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	ws, u, err := s.Store.CreateWorkspace(r.Context(), req.Name, req.Slug, req.AdminEmail, req.AdminName, req.AdminPassword)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), ws.ID), principal(r).Actor(r), "workspace.create", "workspace",
		itoa(ws.ID), map[string]any{"name": ws.Name, "slug": ws.Slug, "admin": u.Email})
	writeJSON(w, 201, map[string]any{"workspace": ws, "admin": u})
}

func (s *Server) adminUpdateWorkspace(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req store.WorkspaceUpdate
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.UpdateWorkspace(r.Context(), id, req); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), id), principal(r).Actor(r), "workspace.update", "workspace", itoa(id),
		map[string]any{"name": req.Name, "disabled": req.Disabled})
	ws, err := s.Store.GetWorkspace(tenant.System(r.Context()), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, ws)
}

// removeMember takes a user out of the current workspace. Their account and
// other workspaces are untouched.
func (s *Server) removeMember(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.RemoveMember(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "user.remove", "user", itoa(id), nil)
	w.WriteHeader(204)
}
