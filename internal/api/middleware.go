package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const sessionCookie = "stackurity_session"

// Principal is the authenticated caller. Role is the caller's
// organisation-wide role in Workspace, the workspace the request is scoped
// to (0: the user belongs to none, so only account endpoints work).
type Principal struct {
	User      *store.User  // nil for collector tokens without a user
	Token     *store.Token // nil for browser sessions
	Role      auth.Role    // organisation-wide role; empty with project access only
	Session   bool
	Workspace int64
	// ProjectRole is the highest role the caller holds through project
	// and asset grants. It opens project-scoped routes; handlers that
	// change something check the role on each asset (allowedOn).
	ProjectRole auth.Role
	// Restricted: a member with project access only. Their requests are
	// narrowed to their projects' assets and asset grants by row-level
	// security, and organisation routes refuse them.
	Restricted bool
	// Project is the project chosen in the switcher (0: all, -1: invalid);
	// projectGate applies it to project-scoped routes.
	Project int64
	// Assistant is the connection of an AI assistant signed in with OAuth
	// (assistants.go). Its requests come only from the tools behind /mcp;
	// Token then describes it, so it is capped like an API token.
	Assistant *store.AssistantGrant
	// PasswordSession: a browser session signed in with a local password.
	PasswordSession bool
	// NeedsMFAEnrolment: such a session without a second factor in a
	// workspace that requires one (mfa.go); it may only set one up.
	NeedsMFAEnrolment bool
	// PasswordChangeRequired: an administrator set a temporary password
	// (password_reset.go); the session may only change it.
	PasswordChangeRequired bool
}

func (p *Principal) Actor(r *http.Request) store.Actor {
	a := store.Actor{RemoteAddr: clientIP(r)}
	switch {
	case p == nil:
		a.Type = "anonymous"
	case p.Assistant != nil:
		a.Type, a.ID, a.Name = "assistant", p.Assistant.ID, p.User.Email+" (assistant "+p.Assistant.ClientName+")"
	case p.Token != nil:
		a.Type, a.ID, a.Name = "token", p.Token.ID, p.Token.Name
		if p.User != nil {
			a.Name = p.User.Email + " (token " + p.Token.Prefix + ")"
		}
	default:
		a.Type, a.ID, a.Name = "user", p.User.ID, p.User.Email
	}
	return a
}

type ctxKey struct{}

func principal(r *http.Request) *Principal {
	p, _ := r.Context().Value(ctxKey{}).(*Principal)
	return p
}

// authenticate resolves a bearer token or session cookie and scopes the
// request to the caller's workspace, which row-level security then enforces.
// Requests with no credentials continue unauthenticated and unscoped; invalid
// credentials are rejected.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p *Principal
		if h := r.Header.Get("Authorization"); h != "" {
			secret, ok := strings.CutPrefix(h, "Bearer ")
			if !ok {
				writeError(w, 401, "unauthorized", "use a Bearer token")
				return
			}
			var err error
			p, err = s.bearerPrincipal(r.Context(), strings.TrimSpace(secret))
			if errors.Is(err, errAssistantToken) {
				writeError(w, 401, "unauthorized", "an assistant's token works only through /mcp")
				return
			}
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, 401, "unauthorized", "invalid or expired token")
				return
			}
			if err != nil {
				s.credentialsUnavailable(w, r, err)
				return
			}
		} else if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			sess, err := s.Store.SessionInfo(r.Context(), c.Value)
			switch {
			case err == nil:
				p = &Principal{User: sess.User, Role: sess.User.Role, Session: true, Workspace: sess.Workspace,
					PasswordSession: sess.PasswordLogin, NeedsMFAEnrolment: sess.NeedsMFAEnrolment,
					PasswordChangeRequired: sess.PasswordChangeRequired}
				if sessionGate(w, r, p) {
					return
				}
			case !errors.Is(err, store.ErrNotFound):
				s.credentialsUnavailable(w, r, err)
				return
			default:
				s.sessionEnded(r, err)
			}
		}
		if p != nil {
			ctx := context.WithValue(r.Context(), ctxKey{}, p)
			if p.Workspace > 0 {
				ctx = tenant.WithWorkspace(ctx, p.Workspace)
				if p.User != nil {
					access, err := s.Store.UserAccess(r.Context(), p.Workspace, p.User.ID)
					if err != nil {
						s.credentialsUnavailable(w, r, err)
						return
					}
					if p.Token != nil {
						// TokenPrincipal capped the token at the user's
						// highest role; it never acts above either.
						p.Role = auth.Lower(p.Token.Role, access.OrgRole)
						p.ProjectRole = auth.Lower(p.Token.Role, access.ProjectRole)
					} else {
						p.Role, p.ProjectRole = access.OrgRole, access.ProjectRole
					}
					if access.Restricted() {
						p.Restricted = true
						ctx = tenant.WithMember(ctx, p.User.ID)
					}
				}
				p.Project = requestedProject(r)
			}
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

// errAssistantToken is an assistant's access token sent to the API directly:
// it is for /mcp only (the audience it was issued for).
var errAssistantToken = errors.New("assistant token outside /mcp")

// bearerPrincipal resolves an API token, or an assistant's access token on
// a request the /mcp endpoint makes in process (viaMCP). Invalid tokens are
// store.ErrNotFound.
func (s *Server) bearerPrincipal(ctx context.Context, secret string) (*Principal, error) {
	if strings.HasPrefix(secret, assistantTokenPrefix) {
		if !viaMCP(ctx) {
			return nil, errAssistantToken
		}
		g, user, err := s.Store.AssistantPrincipal(ctx, secret)
		if err != nil {
			return nil, err
		}
		tok := &store.Token{WorkspaceID: g.WorkspaceID, Name: "assistant: " + g.ClientName, Prefix: secret[:len(assistantTokenPrefix)+8],
			UserID: &user.ID, Role: g.Role, UserEmail: user.Email, ProjectID: g.ProjectID}
		return &Principal{User: user, Token: tok, Role: g.Role, Workspace: g.WorkspaceID, Assistant: g}, nil
	}
	tok, user, err := s.Store.TokenPrincipal(ctx, secret)
	if err != nil {
		return nil, err
	}
	return &Principal{User: user, Token: tok, Role: tok.Role, Workspace: tok.WorkspaceID}, nil
}

// credentialsUnavailable answers a request whose credentials could not be
// checked, usually because the database is unreachable. It is a 503, never a
// 401: agents and CI do not retry a 401, and the dashboard would sign the
// person out, although nothing is wrong with their credentials.
func (s *Server) credentialsUnavailable(w http.ResponseWriter, r *http.Request, err error) {
	s.Log.Warn("could not check credentials", "path", r.URL.Path, "err", err, "request_id", middleware.GetReqID(r.Context()))
	writeError(w, 503, "unavailable", "credentials cannot be checked right now; try again shortly")
}

// csrfGuard requires a custom header on state-changing requests made with
// cookies. Browsers cannot send custom headers cross-site without a CORS
// preflight, which this server never grants.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			if r.Header.Get("Authorization") == "" && r.Header.Get("X-Stackurity-CSRF") != "1" {
				writeError(w, 403, "csrf", "missing X-Stackurity-CSRF header")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal(r) == nil {
			writeError(w, 401, "unauthorized", "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireInstanceAdmin allows only operators of the installation, signed in
// with a session or an admin token of theirs.
func requireInstanceAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if p == nil || p.User == nil || !p.User.InstanceAdmin || (p.Token != nil && p.Role != auth.RoleAdmin) || p.Assistant != nil {
			writeError(w, 403, "forbidden", "requires an instance administrator")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireRole checks the organisation-wide role. On project-scoped and
// account routes a role from project grants also opens the route; the
// handler then checks the role on the objects it changes.
func requireRole(min auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := principal(r)
			if p == nil {
				writeError(w, 403, "forbidden", "requires role "+string(min))
				return
			}
			role := p.Role
			if routeScope(r) != orgOnly {
				role = auth.Higher(p.Role, p.ProjectRole)
			}
			if !role.AtLeast(min) {
				writeError(w, 403, "forbidden", "requires role "+string(min))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireWritable refuses, with 402 read_only, what would collect
// something new or send a notification while the organisation is
// read-only (docs/asset-limits.md). Uploads are refused in the store
// (Ingest), whatever route they come by.
func (s *Server) requireWritable(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.Store.CheckWritable(r.Context()); err != nil {
			s.fail(w, r, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireIngest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := principal(r); p == nil || !p.Role.CanIngest() {
			writeError(w, 403, "forbidden", "token cannot submit observations")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	csp := "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
	if len(s.WidgetOrigins) > 0 {
		o := strings.Join(s.WidgetOrigins, " ")
		csp += "; script-src 'self' " + o + "; frame-src " + o
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", csp)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil && v != http.ErrAbortHandler {
				s.Log.Error("panic", "path", r.URL.Path, "panic", v, "request_id", middleware.GetReqID(r.Context()))
				writeError(w, 500, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// instrument records each request in HTTPMetrics under its route pattern
// (known only once routing is done), so raw paths never become labels.
func (s *Server) instrument(next http.Handler) http.Handler {
	if s.HTTPMetrics == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		route := ""
		if rc := chi.RouteContext(r.Context()); rc != nil {
			route = rc.RoutePattern()
		}
		s.HTTPMetrics.Observe(r.Method, route, ww.Status(), time.Since(start))
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return
		}
		// Query strings are not logged: they can carry search terms but
		// never secrets, and paths alone are enough for operations.
		s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", ww.Status(),
			"bytes", ww.BytesWritten(), "took", time.Since(start).Round(time.Millisecond),
			"request_id", middleware.GetReqID(r.Context()))
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
