package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Projects and permissions (docs/design/projects.md).
//
// Every authenticated route declares how it treats project access in
// projectRoutes. A route that is not listed is for organisation-wide roles
// only: a member with project access only gets 403, so a new route cannot
// leak by being forgotten. TestEveryRouteIsClassified checks that the list
// and the isolation sweeps agree.

type projectScope int

const (
	// orgOnly: organisation-wide roles only (the default).
	orgOnly projectScope = iota
	// accountScope: the caller's own account (profile, tokens, workspaces).
	accountScope
	// globalScope: data shared by every workspace (feeds, advisories, packs).
	globalScope
	// scopedRead: workspace data, narrowed by row-level security to the
	// caller's projects and to the project chosen in the switcher.
	scopedRead
	// scopedWrite: as scopedRead; the handler also checks the caller's role
	// on each asset it changes (allowedOn).
	scopedWrite
)

var projectScopeNames = map[projectScope]string{
	orgOnly: "org", accountScope: "account", globalScope: "global", scopedRead: "scoped", scopedWrite: "scoped-write",
}

var projectRoutes = map[string]projectScope{
	// The caller's own account.
	"GET /api/v1/auth/me":                   accountScope,
	"POST /api/v1/auth/password":            accountScope,
	"GET /api/v1/auth/email-preferences":    accountScope,
	"PUT /api/v1/auth/email-preferences":    accountScope,
	"PUT /api/v1/auth/default-project":      accountScope,
	"POST /api/v1/feedback":                 accountScope,
	"GET /api/v1/workspaces":                accountScope,
	"POST /api/v1/workspaces/{id}/activate": accountScope,
	"GET /api/v1/tokens":                    accountScope,
	"POST /api/v1/tokens":                   accountScope,
	"DELETE /api/v1/tokens/{id}":            accountScope,
	// The caller's own linked Slack accounts (rows narrowed to them too).
	"GET /api/v1/slack/links": accountScope,
	// Ask Stackurity: the caller's own conversations and questions; the
	// tools it runs are narrowed as the caller's own requests are.
	"GET /api/v1/ask/status":                       accountScope,
	"POST /api/v1/ask/notice":                      accountScope,
	"GET /api/v1/ask/conversations":                accountScope,
	"POST /api/v1/ask/conversations":               accountScope,
	"DELETE /api/v1/ask/conversations":             accountScope,
	"GET /api/v1/ask/conversations/{id}":           accountScope,
	"DELETE /api/v1/ask/conversations/{id}":        accountScope,
	"POST /api/v1/ask/conversations/{id}/messages": accountScope,
	"DELETE /api/v1/slack/links/{id}":              accountScope,
	"POST /api/v1/slack/links/preview":             accountScope,
	"POST /api/v1/slack/links/confirm":             accountScope,
	// Connecting AI assistants: the consent page and the caller's own
	// connections, in every workspace they belong to.
	"POST /api/v1/oauth/authorize/preview": accountScope,
	"POST /api/v1/oauth/authorize":         accountScope,
	"GET /api/v1/assistants":               accountScope,
	"DELETE /api/v1/assistants/{id}":       accountScope,
	"PATCH /api/v1/assistants/{id}":        accountScope,

	// Shared by every workspace.
	"GET /api/v1/packs":              globalScope,
	"GET /api/v1/packs/{id}/archive": globalScope,
	"GET /api/v1/feeds":              globalScope,
	"GET /api/v1/advisories/{key}":   globalScope,

	// Narrowed by row-level security.
	"GET /api/v1/projects":                     scopedRead,
	"GET /api/v1/projects/{id}":                scopedRead,
	"GET /api/v1/overview":                     scopedRead,
	"GET /api/v1/facets":                       scopedRead,
	"GET /api/v1/search":                       scopedRead,
	"GET /api/v1/assets":                       scopedRead,
	"GET /api/v1/assets/{id}":                  scopedRead,
	"GET /api/v1/assets/{id}/inventory":        scopedRead,
	"GET /api/v1/assets/{id}/coverage":         scopedRead,
	"GET /api/v1/assets/{id}/coverage-summary": scopedRead,
	"GET /api/v1/assets/{id}/collections":      scopedRead,
	"GET /api/v1/assets/{id}/relations":        scopedRead,
	"GET /api/v1/assets/{id}/drift":            scopedRead,
	"GET /api/v1/assets/{id}/stack":            scopedRead,
	"GET /api/v1/assets/{id}/sbom":             scopedRead,
	"GET /api/v1/assets/{id}/remediation":      scopedRead,
	"GET /api/v1/components":                   scopedRead,
	"GET /api/v1/components/{id}":              scopedRead,
	"GET /api/v1/components/{id}/intel":        scopedRead,
	"GET /api/v1/components/{id}/upgrade":      scopedRead,
	"GET /api/v1/findings":                     scopedRead,
	"GET /api/v1/findings/summary":             scopedRead,
	"GET /api/v1/findings/verify":              scopedRead,
	"GET /api/v1/findings/{id}":                scopedRead,
	"GET /api/v1/findings/{id}/events":         scopedRead,
	"GET /api/v1/findings/{id}/upgrade":        scopedRead,
	"GET /api/v1/findings/{id}/explain":        scopedRead,
	"GET /api/v1/fix-groups":                   scopedRead,
	"GET /api/v1/fix-groups/summary":           scopedRead,
	"GET /api/v1/fix-groups/{id}":              scopedRead,
	"GET /api/v1/evaluation-gaps":              scopedRead,
	"GET /api/v1/reports/outcomes":             scopedRead,
	"GET /api/v1/reports/evidence":             scopedRead,
	"GET /api/v1/incidents":                    scopedRead,
	"GET /api/v1/incidents/{id}":               scopedRead,
	"GET /api/v1/risk-policy":                  scopedRead,
	"GET /api/v1/settings/fix-grouping":        scopedRead,
	"GET /api/v1/inventory":                    scopedRead,
	"GET /api/v1/inventory/updates":            scopedRead,
	"GET /api/v1/coverage":                     scopedRead,
	"GET /api/v1/coverage/unchecked":           scopedRead,
	"GET /api/v1/dashboard/trend":              scopedRead,
	"GET /api/v1/audit":                        scopedRead,
	// Members with project access only see the people of their projects.
	"GET /api/v1/users/directory": scopedRead,
	// The loop (0.7): checks, ignore rules and the approval inbox.
	"GET /api/v1/checks":         scopedRead,
	"GET /api/v1/checks/options": scopedRead,
	// Proof (1.0): second checks follow their findings' assets.
	"GET /api/v1/second-checks":        scopedRead,
	"GET /api/v1/checks/{id}":          scopedRead,
	"GET /api/v1/ignore-rules":         scopedRead,
	"GET /api/v1/ignore-requests":      scopedRead,
	"GET /api/v1/ignore-requests/{id}": scopedRead,
	// VEX export: our decisions about the assets the caller sees.
	"GET /api/v1/vex/export": scopedRead,
	// Onboarding (0.9): the waiting screen's poll, narrowed like assets.
	"GET /api/v1/onboarding/results": scopedRead,

	// Narrowed, and the handler checks the role on each asset.
	"PATCH /api/v1/assets/{id}":            scopedWrite,
	"POST /api/v1/assets/{id}/relations":   scopedWrite,
	"DELETE /api/v1/assets/{id}/relations": scopedWrite,
	"POST /api/v1/findings/{id}/actions":   scopedWrite,
	"POST /api/v1/findings/actions":        scopedWrite,
	"POST /api/v1/incidents/{id}/actions":  scopedWrite,
	"POST /api/v1/assets/{id}/check":       scopedWrite,
	"POST /api/v1/fix-groups/{id}/check":   scopedWrite,
	"POST /api/v1/fix-groups/{id}/applied": scopedWrite,
	// Anyone who can see the issues may ask; the request is narrowed too.
	"POST /api/v1/ignore-requests": scopedWrite,
	// Security on every issue's asset; a rule for every asset needs an
	// organisation-wide security or admin role (Server.everywhere).
	"POST /api/v1/ignore-requests/{id}/decision": scopedWrite,
	"DELETE /api/v1/ignore-rules/{id}":           scopedWrite,
}

// ProjectScopeOf returns how a route ("METHOD pattern") treats project
// access: org, account, global, scoped or scoped-write. For tests.
func ProjectScopeOf(route string) string { return projectScopeNames[projectRoutes[route]] }

type scopeKey struct{}

func routeScope(r *http.Request) projectScope {
	sc, _ := r.Context().Value(scopeKey{}).(projectScope)
	return sc
}

// projectGate runs on every authenticated route, after routing. It refuses
// organisation routes to members with project access only, and narrows
// project-scoped routes to the project the caller chose.
func (s *Server) projectGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		route := r.Method + " "
		if rc := chi.RouteContext(r.Context()); rc != nil {
			route += rc.RoutePattern()
		}
		sc := projectRoutes[route]
		if p.Restricted && sc == orgOnly {
			writeError(w, 403, "forbidden", "this needs an organisation-wide role; you have access to some projects only")
			return
		}
		if p.Ask {
			// Ask Stackurity's tools read what the person may read, and
			// nothing else: no changes, no account settings, no assistant.
			if r.Method != http.MethodGet {
				writeError(w, 403, "forbidden", "Ask Stackurity only reads")
				return
			}
			if sc == accountScope && route != "GET /api/v1/auth/me" {
				writeError(w, 403, "forbidden", "Ask Stackurity cannot read account settings")
				return
			}
		}
		if a := p.Assistant; a != nil {
			// An assistant reaches only what its tools use: no account
			// settings, and with a connection to one project, nothing
			// outside it.
			if sc == accountScope && route != "GET /api/v1/auth/me" {
				writeError(w, 403, "forbidden", "an assistant cannot change account settings")
				return
			}
			if !a.AllowWrites && r.Method != http.MethodGet {
				writeError(w, 403, "forbidden", "this assistant is read-only: allow changes for it under Settings → AI assistants")
				return
			}
			if a.ProjectID != nil {
				if sc == orgOnly {
					writeError(w, 403, "forbidden", "this assistant is connected to one project only; this needs a connection to the whole organisation")
					return
				}
				if p.Project != 0 && p.Project != *a.ProjectID {
					writeError(w, 403, "forbidden", "this assistant is connected to another project")
					return
				}
				p.Project = *a.ProjectID
			}
		}
		ctx := context.WithValue(r.Context(), scopeKey{}, sc)
		scoped := sc == scopedRead || sc == scopedWrite
		if p.Project < 0 && scoped {
			writeError(w, 400, "bad_request", "project_id must be a project id, or 0 for all projects")
			return
		}
		if p.Project > 0 && scoped && p.Workspace > 0 {
			ok, err := s.Store.ProjectVisible(ctx, p.Project)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if !ok {
				writeError(w, 404, "not_found", "no such project")
				return
			}
			if p.boundToProject() {
				// Nothing on this request may widen it to the workspace.
				ctx = tenant.WithBoundProject(ctx, p.Project)
			} else {
				ctx = tenant.WithProject(ctx, p.Project)
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestedProject reads the project chosen in the switcher: the
// X-Stackurity-Project header (the dashboard) or the project_id query
// parameter (API clients). 0: all projects; -1: not a valid id.
func requestedProject(r *http.Request) int64 {
	v := strings.TrimSpace(r.Header.Get("X-Stackurity-Project"))
	if v == "" {
		v = strings.TrimSpace(r.URL.Query().Get("project_id"))
	}
	if v == "" || v == "0" || v == "all" {
		return 0
	}
	id, err := strconv.ParseInt(v, 10, 64)
	if err != nil || id <= 0 {
		return -1
	}
	return id
}

// allowedOn reports whether the caller may act with at least min on every
// one of the assets: through their organisation-wide role, or through
// project and asset grants (capped by the token's role).
func (s *Server) allowedOn(r *http.Request, min auth.Role, assetIDs []int64) (bool, error) {
	p := principal(r)
	if p.Role.AtLeast(min) {
		return true, nil
	}
	if p.User == nil || !p.ProjectRole.AtLeast(min) || len(assetIDs) == 0 {
		return false, nil
	}
	role, err := s.Store.GrantRoleOn(r.Context(), p.User.ID, assetIDs)
	if err != nil {
		return false, err
	}
	if p.Token != nil {
		role = auth.Lower(role, p.Token.Role)
	}
	return role.AtLeast(min), nil
}

// requireOn writes 403 and returns false unless allowedOn.
func (s *Server) requireOn(w http.ResponseWriter, r *http.Request, min auth.Role, assetIDs ...int64) bool {
	ok, err := s.allowedOn(r, min, assetIDs)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if !ok {
		writeError(w, 403, "forbidden", "requires role "+string(min)+" on this asset")
	}
	return ok
}

// --- projects

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	archived := r.URL.Query().Get("archived") == "true" && principal(r).Role.AtLeast(auth.RoleAdmin)
	ps, err := s.Store.ListProjects(r.Context(), archived)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ps = boundProjects(principal(r), ps)
	out := map[string]any{"items": ps, "total": len(ps)}
	if p := principal(r); !p.Restricted && !p.boundToProject() {
		n, err := s.Store.UnfiledAssetCount(tenant.WithoutProject(r.Context()))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out["unfiled_assets"] = n
	}
	if ps == nil {
		out["items"] = []store.Project{}
	}
	writeJSON(w, 200, out)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// An assistant connected to one project sees only that one.
	if p := principal(r); p.boundToProject() && id != *p.Assistant.ProjectID {
		writeError(w, 404, "not_found", "not found")
		return
	}
	pr, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// An archived project gives its members nothing, not even its name.
	if pr.ArchivedAt != nil && principal(r).Restricted {
		writeError(w, 404, "not_found", "not found")
		return
	}
	out := map[string]any{"project": pr}
	if principal(r).Role.AtLeast(auth.RoleAdmin) {
		gs, err := s.Store.ListGrants(r.Context(), store.GrantFilter{ProjectID: id})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out["grants"] = all(gs)
	}
	writeJSON(w, 200, out)
}

type projectRequest struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	AssetIDs    []int64 `json:"asset_ids"`
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var req projectRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.AssetIDs) > 5000 {
		s.fail(w, r, badRequest("add at most 5000 assets at a time"))
		return
	}
	pr, err := s.Store.CreateProject(r.Context(), req.Name, req.Description)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.AssetIDs) > 0 {
		if _, err := s.Store.AddProjectAssets(r.Context(), pr.ID, req.AssetIDs); err != nil {
			s.fail(w, r, err)
			return
		}
		if pr, err = s.Store.GetProject(r.Context(), pr.ID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "project.create", "project", itoa(pr.ID),
		map[string]any{"name": pr.Name, "assets": len(req.AssetIDs)})
	writeJSON(w, 201, pr)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var u store.ProjectUpdate
	if err := decode(r, &u); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.UpdateProject(r.Context(), id, u); err != nil {
		s.fail(w, r, err)
		return
	}
	action := "project.update"
	if u.Archived != nil {
		action = map[bool]string{true: "project.archive", false: "project.restore"}[*u.Archived]
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), action, "project", itoa(id), u)
	pr, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, pr)
}

type projectAssetsRequest struct {
	AssetIDs []int64 `json:"asset_ids"`
}

func (s *Server) changeProjectAssets(add bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := idParam(r, "id")
		if err != nil {
			s.fail(w, r, err)
			return
		}
		var req projectAssetsRequest
		if err := decode(r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
		if len(req.AssetIDs) == 0 || len(req.AssetIDs) > 5000 {
			s.fail(w, r, badRequest("asset_ids must list 1 to 5000 assets"))
			return
		}
		var n int64
		action := "project.assets_add"
		if add {
			n, err = s.Store.AddProjectAssets(r.Context(), id, req.AssetIDs)
		} else {
			action = "project.assets_remove"
			n, err = s.Store.RemoveProjectAssets(r.Context(), id, req.AssetIDs)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		_ = s.Store.Audit(r.Context(), principal(r).Actor(r), action, "project", itoa(id),
			map[string]any{"asset_ids": firstIDs(req.AssetIDs, 50), "requested": len(req.AssetIDs), "changed": n})
		writeJSON(w, 200, map[string]int64{"changed": n})
	}
}

// boundToProject: an assistant connected to one project only.
func (p *Principal) boundToProject() bool {
	return p.Assistant != nil && p.Assistant.ProjectID != nil
}

// boundProjects keeps only the project an assistant is connected to.
func boundProjects(p *Principal, ps []store.Project) []store.Project {
	if !p.boundToProject() {
		return ps
	}
	out := []store.Project{}
	for _, pr := range ps {
		if pr.ID == *p.Assistant.ProjectID {
			out = append(out, pr)
		}
	}
	return out
}

func firstIDs(ids []int64, n int) []int64 {
	if len(ids) > n {
		return ids[:n]
	}
	return ids
}

// --- access grants

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request) {
	f := store.GrantFilter{ProjectID: qInt(r, "project_id"), AssetID: qInt(r, "asset_id"), UserID: qInt(r, "user_id"), TeamID: qInt(r, "team_id")}
	gs, err := s.Store.ListGrants(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(gs))
}

type grantRequest struct {
	store.GrantInput
	// Email adds the person to the organisation with project access only
	// when they are not a member yet (creating their account with
	// Password when they have none).
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request) {
	var req grantRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	in := req.GrantInput
	created := false
	if email := strings.TrimSpace(req.Email); email != "" {
		if in.UserID != nil || in.TeamID != nil {
			s.fail(w, r, badRequest("name the person by email or by user_id, not both"))
			return
		}
		if !strings.Contains(email, "@") {
			s.fail(w, r, badRequest("a valid email is required"))
			return
		}
		uid, newAccount, err := s.Store.EnsureMember(r.Context(), email, req.Name, req.Password)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		in.UserID, created = &uid, newAccount
		if newAccount {
			_ = s.Store.Audit(r.Context(), p.Actor(r), "user.create", "user", itoa(uid), map[string]any{"email": strings.ToLower(email), "role": "none"})
		}
	}
	g, isNew, err := s.Store.SaveGrant(r.Context(), in, actorUserID(p))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "access.grant", "access_grant", itoa(g.ID), g)
	status := 200
	if isNew {
		status = 201
	}
	writeJSON(w, status, map[string]any{"grant": g, "account_created": created})
}

type grantUpdate struct {
	Role auth.Role `json:"role"`
}

func (s *Server) updateGrant(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req grantUpdate
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := s.Store.GetGrant(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in := store.GrantInput{ProjectID: g.ProjectID, AssetID: g.AssetID, UserID: g.UserID, TeamID: g.TeamID, Role: req.Role}
	g, _, err = s.Store.SaveGrant(r.Context(), in, actorUserID(principal(r)))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "access.change", "access_grant", itoa(g.ID), g)
	writeJSON(w, 200, g)
}

func (s *Server) deleteGrant(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := s.Store.GetGrant(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteGrant(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "access.revoke", "access_grant", itoa(g.ID), g)
	w.WriteHeader(204)
}

// Grants are audited as object type access_grant, which narrowed
// connections never see (stackurity_audit_visible): the details name the
// person or team, which members of other projects must not learn.

func actorUserID(p *Principal) int64 {
	if p != nil && p.User != nil {
		return p.User.ID
	}
	return 0
}

// --- suggestions

func (s *Server) projectSuggestions(w http.ResponseWriter, r *http.Request) {
	sg, err := s.Store.ProjectSuggestions(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(sg))
}

type dismissRequest struct {
	Key string `json:"key"`
}

func (s *Server) dismissSuggestion(w http.ResponseWriter, r *http.Request) {
	var req dismissRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DismissSuggestion(r.Context(), req.Key); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "project.suggestion_dismiss", "settings", "projects", req)
	w.WriteHeader(204)
}

// --- the switcher's remembered choice

type defaultProjectRequest struct {
	ProjectID int64 `json:"project_id"`
}

func (s *Server) setDefaultProject(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User == nil || !p.Session || p.Workspace == 0 {
		writeError(w, 403, "forbidden", "sign in to choose a project")
		return
	}
	var req defaultProjectRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ProjectID < 0 {
		s.fail(w, r, badRequest("project_id must be a project, or 0 for all projects"))
		return
	}
	if req.ProjectID > 0 {
		ok, err := s.Store.ProjectVisible(r.Context(), req.ProjectID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !ok {
			writeError(w, 404, "not_found", "no such project")
			return
		}
	}
	if err := s.Store.SetDefaultProject(r.Context(), p.User.ID, req.ProjectID); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

// everywhere checks that the caller may ignore an issue on every asset of
// the organisation, which only an organisation-wide security or admin role
// may: such a rule applies to assets of every project, and to those found
// later. It returns the context to apply it in, without the project chosen
// in the switcher, so the rule covers every asset at once.
func (s *Server) everywhere(w http.ResponseWriter, r *http.Request) (context.Context, bool) {
	if p := principal(r); p.boundToProject() || tenant.Bound(r.Context()) {
		writeError(w, 403, "forbidden", "this assistant is connected to one project only; ignore the issue on its assets instead")
		return nil, false
	}
	if !principal(r).Role.AtLeast(auth.RoleSecurity) {
		writeError(w, 403, "forbidden", "ignoring an issue on every asset needs an organisation-wide security or admin role; ignore it on this asset instead")
		return nil, false
	}
	return tenant.WithoutProject(r.Context()), true
}
