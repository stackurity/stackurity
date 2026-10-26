package api

import (
	"crypto/subtle"
	"github.com/stackurity/stackurity/internal/license"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	n, err := s.Store.CountUsers(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	meta := map[string]any{"name": "stackurity", "version": s.Version, "api": "v1", "setup_required": n == 0}
	if sso := s.ssoMeta(r); sso != nil {
		meta["sso"] = sso
	}
	writeJSON(w, 200, meta)
}

type setupRequest struct {
	SetupToken string `json:"setup_token"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	Password   string `json:"password"`
}

// setup creates the first admin. It requires the one-time setup token from
// the server log so whoever reaches a fresh install first cannot claim it.
func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts", limitHit{"setup", clientIP(r), limitPerAddress},
		limitHit{"setup-total", "", limitSetupTotal}) {
		return
	}
	var req setupRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.SetupToken == "" || subtle.ConstantTimeCompare([]byte(req.SetupToken), []byte(s.SetupToken)) != 1 {
		writeError(w, 403, "forbidden", "invalid setup token")
		return
	}
	if !strings.Contains(req.Email, "@") {
		s.fail(w, r, badRequest("a valid email is required"))
		return
	}
	u, err := s.Store.CreateFirstAdmin(r.Context(), req.Email, req.Name, req.Password)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), store.Actor{Type: "system", Name: "setup", RemoteAddr: clientIP(r)}, "setup.admin_created", "user", itoa(u.ID), nil)
	s.startSession(w, r, u)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many login attempts; wait a minute", limitHit{"login", clientIP(r), limitPerAddress}) {
		return
	}
	var req loginRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	// Guessing one account's password from many addresses is limited per
	// account, whether or not the account exists.
	account := strings.ToLower(strings.TrimSpace(req.Email))
	if s.limited(w, r, "too many login attempts for this account; wait a few minutes", limitHit{"login-account", account, limitPerAccount}) {
		return
	}
	u, err := s.Store.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		if err == store.ErrNotFound {
			// People type their password into the email field; record what
			// was typed only when it names an existing account.
			name := "(no such account)"
			if ok, _ := s.Store.UserExists(r.Context(), account); ok {
				name = account
			}
			_ = s.Store.Audit(r.Context(), store.Actor{Type: "anonymous", Name: name, RemoteAddr: clientIP(r)}, "auth.login_failed", "user", "", nil)
			writeError(w, 401, "unauthorized", "invalid email or password")
			return
		}
		s.fail(w, r, err)
		return
	}
	s.startSession(w, r, u)
}

// startSession signs u in, working in their first workspace.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *store.User) {
	ms, err := s.Store.Memberships(r.Context(), u.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var ws int64
	if len(ms) > 0 {
		ws = ms[0].WorkspaceID
	}
	secret, err := s.Store.CreateSession(r.Context(), u.ID, ws)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if u, err = s.Store.GetUser(tenant.WithWorkspace(r.Context(), ws), u.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: secret, Path: "/", HttpOnly: true, Secure: s.CookieSecure,
		SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(store.SessionTTL),
	})
	_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), ws), store.Actor{Type: "user", ID: u.ID, Name: u.Email, RemoteAddr: clientIP(r)}, "auth.login", "user", itoa(u.ID), nil)
	writeJSON(w, 200, u)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		_ = s.Store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: s.CookieSecure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(204)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	ed := s.Gate.Edition(r.Context())
	features := ed.Features()
	if features == nil {
		features = []license.Feature{}
	}
	out := map[string]any{"user": p.User, "role": p.Role, "token": p.Token, "workspace": nil, "workspaces": []store.Membership{},
		"edition": ed, "features": features, "feedback_enabled": s.FeedbackURL != "" && p.User != nil,
		"access": "organisation", "project_role": p.ProjectRole, "projects": []store.Project{}, "default_project_id": 0}
	if p.Restricted {
		out["access"] = "projects"
	}
	if p.Workspace > 0 {
		ws, err := s.Store.GetWorkspace(r.Context(), p.Workspace)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out["workspace"] = map[string]any{"id": ws.ID, "name": ws.Name, "slug": ws.Slug}
		// The projects for the switcher, and the one chosen last.
		ps, err := s.Store.ListProjects(r.Context(), false)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if ps != nil {
			out["projects"] = ps
		}
		if p.User != nil {
			def, err := s.Store.DefaultProject(r.Context(), p.User.ID)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			out["default_project_id"] = def
		}
	}
	if p.User != nil && p.Session {
		ms, err := s.Store.Memberships(r.Context(), p.User.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if ms != nil {
			out["workspaces"] = ms
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	var uid int64
	if !p.Role.AtLeast(auth.RoleAdmin) {
		if p.User == nil {
			writeError(w, 403, "forbidden", "not a user token")
			return
		}
		uid = p.User.ID
	}
	ts, err := s.Store.ListTokens(r.Context(), uid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(ts))
}

type tokenRequest struct {
	Name     string    `json:"name"`
	Role     auth.Role `json:"role"`
	TTLHours int       `json:"ttl_hours"`
}

// createToken issues a personal token (role at most the caller's), or,
// for admins, a collector token not tied to a user.
func (s *Server) createToken(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	// Collector tokens cannot mint tokens, and user tokens only can when
	// they carry admin rights.
	if p.User == nil || (p.Token != nil && !p.Role.AtLeast(auth.RoleAdmin)) {
		writeError(w, 403, "forbidden", "sign in to create tokens")
		return
	}
	var req tokenRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		s.fail(w, r, badRequest("name is required (max 100 characters)"))
		return
	}
	if req.TTLHours < 0 || req.TTLHours > 24*366 {
		s.fail(w, r, badRequest("ttl_hours must be between 0 (no expiry) and 8784"))
		return
	}
	var userID *int64
	switch {
	case req.Role == auth.RoleCollector:
		if !p.Role.AtLeast(auth.RoleAdmin) {
			writeError(w, 403, "forbidden", "only admins can create collector tokens")
			return
		}
	case req.Role.ValidUser():
		// A token never acts above its user; one of a member with project
		// access only is narrowed like their sessions.
		if !auth.Higher(p.Role, p.ProjectRole).AtLeast(req.Role) {
			writeError(w, 403, "forbidden", "cannot create a token above your own role")
			return
		}
		userID = &p.User.ID
	default:
		s.fail(w, r, badRequest("role must be one of viewer, engineer, security, admin, collector"))
		return
	}
	t, secret, err := s.Store.CreateToken(r.Context(), req.Name, req.Role, userID, p.User.ID, time.Duration(req.TTLHours)*time.Hour)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "token.create", "token", itoa(t.ID), map[string]any{"name": t.Name, "role": t.Role})
	writeJSON(w, 201, map[string]any{"token": t, "secret": secret})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	t, err := s.Store.GetToken(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	own := p.User != nil && t.UserID != nil && *t.UserID == p.User.ID
	if !own && !p.Role.AtLeast(auth.RoleAdmin) {
		writeError(w, 404, "not_found", "not found")
		return
	}
	if err := s.Store.RevokeToken(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "token.revoke", "token", itoa(id), nil)
	w.WriteHeader(204)
}

func itoa(i int64) string { return strconv.FormatInt(i, 10) }

// changePassword lets a signed-in user change their own password. Other
// sessions are signed out; API tokens are unaffected.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User == nil || !p.Session {
		writeError(w, 403, "forbidden", "sign in with a session to change your password")
		return
	}
	if s.limited(w, r, "too many attempts", limitHit{"password", clientIP(r), limitPerAddress},
		limitHit{"password-user", itoa(p.User.ID), limitPerAccount}) {
		return
	}
	var req struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	c, _ := r.Cookie(sessionCookie)
	if err := s.Store.ChangeOwnPassword(r.Context(), p.User.ID, req.Current, req.New, c.Value); err != nil {
		if err == store.ErrNotFound {
			_ = s.Store.Audit(r.Context(), p.Actor(r), "auth.password_change_failed", "user", itoa(p.User.ID), nil)
			writeError(w, 400, "bad_request", "current password is incorrect")
			return
		}
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "auth.password_changed", "user", itoa(p.User.ID), nil)
	w.WriteHeader(204)
}
