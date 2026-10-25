package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const sessionCookie = "stackurity_session"

// Principal is the authenticated caller. Role is the caller's role in
// Workspace, the workspace the request is scoped to (0: the user belongs to
// none, so only account endpoints work).
type Principal struct {
	User      *store.User  // nil for collector tokens without a user
	Token     *store.Token // nil for browser sessions
	Role      auth.Role
	Session   bool
	Workspace int64
}

func (p *Principal) Actor(r *http.Request) store.Actor {
	a := store.Actor{RemoteAddr: clientIP(r)}
	switch {
	case p == nil:
		a.Type = "anonymous"
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
			tok, user, err := s.Store.TokenPrincipal(r.Context(), strings.TrimSpace(secret))
			if err != nil {
				writeError(w, 401, "unauthorized", "invalid or expired token")
				return
			}
			p = &Principal{User: user, Token: tok, Role: tok.Role, Workspace: tok.WorkspaceID}
		} else if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
			user, ws, err := s.Store.SessionUser(r.Context(), c.Value)
			if err == nil {
				p = &Principal{User: user, Role: user.Role, Session: true, Workspace: ws}
			}
		}
		if p != nil {
			ctx := context.WithValue(r.Context(), ctxKey{}, p)
			if p.Workspace > 0 {
				ctx = tenant.WithWorkspace(ctx, p.Workspace)
			}
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
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
		if p == nil || p.User == nil || !p.User.InstanceAdmin || (p.Token != nil && p.Role != auth.RoleAdmin) {
			writeError(w, 403, "forbidden", "requires an instance administrator")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireRole(min auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := principal(r); p == nil || !p.Role.AtLeast(min) {
				writeError(w, 403, "forbidden", "requires role "+string(min))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
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

// rateLimiter is a small fixed-window limiter keyed by client IP, used for
// login and setup.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*window
}

type window struct {
	start time.Time
	n     int
}

func newRateLimiter(limit int, w time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: w, hits: map[string]*window{}}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 10_000 {
		for k, v := range l.hits {
			if now.Sub(v.start) > l.window {
				delete(l.hits, k)
			}
		}
	}
	w := l.hits[key]
	if w == nil || now.Sub(w.start) > l.window {
		l.hits[key] = &window{start: now, n: 1}
		return true
	}
	w.n++
	return w.n <= l.limit
}
