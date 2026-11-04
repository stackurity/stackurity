package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Your account → Active sessions: the caller's own browser sessions, and
// signing them out (docs/install.md, "Sessions"). Only a browser session may
// use these routes: an API token is not a session, and listing would show it
// where the person signs in. A session pinned by an organisation's single
// sign-on sees and ends only the sessions pinned to that organisation
// (store.ListSessions). Every query names the caller's user ID; there is no
// cache, so a session signed out here fails its very next request.

// sessionClient records the request's browser for any session started while
// handling it (store.WithSessionClient). It runs after realIP, so the
// address is the one clientIP reports.
func sessionClient(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := store.SessionClient{UserAgent: r.Header.Get("User-Agent"), IP: clientIP(r)}
		next.ServeHTTP(w, r.WithContext(store.WithSessionClient(r.Context(), c)))
	})
}

func (s *Server) accountSessionRoutes(r chi.Router) {
	r.Get("/auth/sessions", s.listMySessions)
	r.Delete("/auth/sessions/{id}", s.revokeMySession)
	r.Post("/auth/sessions/revoke-others", s.revokeMyOtherSessions)
}

func init() {
	for _, r := range []string{"GET /api/v1/auth/sessions", "DELETE /api/v1/auth/sessions/{id}", "POST /api/v1/auth/sessions/revoke-others"} {
		projectRoutes[r] = accountScope
	}
}

// browserSession answers 403 unless the request was made with a browser
// session of the person's own (not an API token, an assistant or Ask
// Stackurity), and returns its secret.
func browserSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	p := principal(r)
	secret := sessionSecret(r)
	if p == nil || p.User == nil || !p.Session || p.Ask || p.Token != nil || secret == "" {
		writeError(w, 403, "forbidden", "sessions are managed from a signed-in browser; API tokens are under Integrations → API tokens")
		return "", false
	}
	return secret, true
}

func (s *Server) listMySessions(w http.ResponseWriter, r *http.Request) {
	secret, ok := browserSession(w, r)
	if !ok {
		return
	}
	p := principal(r)
	list, err := s.Store.ListSessions(r.Context(), p.User.ID, secret, p.SSOWorkspace)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": list, "pinned": p.SSOWorkspace > 0})
}

func (s *Server) revokeMySession(w http.ResponseWriter, r *http.Request) {
	secret, ok := browserSession(w, r)
	if !ok {
		return
	}
	p := principal(r)
	ended, err := s.Store.RevokeSession(r.Context(), p.User.ID, chi.URLParam(r, "id"), secret, p.SSOWorkspace)
	switch {
	case errors.Is(err, store.ErrCurrentSession):
		writeError(w, 409, "current_session", "this is the session you are using; sign out instead")
		return
	case errors.Is(err, store.ErrNotFound):
		writeError(w, 404, "not_found", "no such session; it may have ended already")
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	detail := map[string]any{"session_id": ended.ID, "login_method": ended.LoginMethod}
	// Recorded where the request works and, when it differs, where the
	// ended session was working (as its own sign-out would be).
	s.auditSessions(r, "auth.session_revoked", detail, ended.Workspace)
	w.WriteHeader(204)
}

func (s *Server) revokeMyOtherSessions(w http.ResponseWriter, r *http.Request) {
	secret, ok := browserSession(w, r)
	if !ok {
		return
	}
	p := principal(r)
	n, err := s.Store.RevokeOtherSessions(r.Context(), p.User.ID, secret, p.SSOWorkspace)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	detail := map[string]any{"sessions_ended": n}
	if p.SSOWorkspace > 0 {
		s.auditSessions(r, "auth.other_sessions_revoked", detail, 0)
	} else {
		// Sessions in any of the person's organisations ended: each one
		// sees it, as with a second factor changed.
		s.auditAccount(r, p.User, "auth.other_sessions_revoked", detail)
	}
	writeJSON(w, 200, map[string]any{"sessions_ended": n})
}

// auditSessions records action in the request's workspace and in also (when
// it is another workspace), or as a system event when there is neither.
func (s *Server) auditSessions(r *http.Request, action string, detail map[string]any, also int64) {
	p := principal(r)
	actor := p.Actor(r)
	id := itoa(p.User.ID)
	if p.Workspace == 0 && also == 0 {
		_ = s.Store.Audit(tenant.System(r.Context()), actor, action, "user", id, detail)
		return
	}
	if p.Workspace > 0 {
		_ = s.Store.Audit(r.Context(), actor, action, "user", id, detail)
	}
	if also > 0 && also != p.Workspace {
		_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), also), actor, action, "user", id, detail)
	}
}
