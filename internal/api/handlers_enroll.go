package api

import (
	_ "embed"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

//go:embed install/agent.sh
var agentInstallScript string

type enrollmentRequest struct {
	Label        string   `json:"label"`
	Environment  string   `json:"environment"`
	AppDirs      []string `json:"app_dirs"`
	DiscoverApps bool     `json:"discover_apps"`
	Uses         int      `json:"uses"`      // default 1
	TTLHours     int      `json:"ttl_hours"` // default 24
}

var envLabel = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var req enrollmentRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Uses == 0 {
		req.Uses = 1
	}
	if req.TTLHours == 0 {
		req.TTLHours = 24
	}
	switch {
	case req.Uses < 1 || req.Uses > 500:
		s.fail(w, r, badRequest("uses must be between 1 and 500"))
		return
	case req.TTLHours < 1 || req.TTLHours > 24*30:
		s.fail(w, r, badRequest("ttl_hours must be between 1 and 720"))
		return
	case len(req.Label) > 200 || !envLabel.MatchString(req.Environment):
		s.fail(w, r, badRequest("label is limited to 200 characters; environment to letters, digits, dot, dash and underscore"))
		return
	case len(req.AppDirs) > 32:
		s.fail(w, r, badRequest("at most 32 application directories"))
		return
	}
	for i, d := range req.AppDirs {
		d = strings.TrimSpace(d)
		// The directories end up in a systemd EnvironmentFile and the
		// agent's flags: absolute paths without separators or quoting.
		if !path.IsAbs(d) || path.Clean(d) != d || strings.ContainsAny(d, ",\"'\\$`\n\r\t ") {
			s.fail(w, r, badRequest("application directories must be absolute paths without spaces, commas or quotes"))
			return
		}
		req.AppDirs[i] = d
	}
	p := principal(r)
	var by int64
	if p.User != nil {
		by = p.User.ID
	}
	e, code, err := s.Store.CreateEnrollment(r.Context(), store.Enrollment{Label: strings.TrimSpace(req.Label), Environment: req.Environment,
		AppDirs: req.AppDirs, DiscoverApps: req.DiscoverApps, UsesLeft: req.Uses}, time.Duration(req.TTLHours)*time.Hour, by)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "enrollment.create", "enrollment", itoa(e.ID), map[string]any{
		"label": e.Label, "environment": e.Environment, "uses": e.UsesLeft, "expires_at": e.ExpiresAt})
	writeJSON(w, 201, map[string]any{"enrollment": e, "code": code})
}

func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListEnrollments(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items})
}

func (s *Server) revokeEnrollment(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.RevokeEnrollment(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "enrollment.revoke", "enrollment", itoa(id), nil)
	w.WriteHeader(204)
}

// enroll exchanges a one-time code for a collector token. It needs no
// session or token, so it is rate limited and says nothing about why a code
// was refused.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("enroll:" + clientIP(r)) {
		writeError(w, 429, "rate_limited", "too many attempts; wait a minute")
		return
	}
	var req struct {
		Code     string `json:"code"`
		Hostname string `json:"hostname"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	host := strings.TrimSpace(req.Hostname)
	if len(host) > 253 {
		host = host[:253]
	}
	e, token, err := s.Store.RedeemEnrollment(r.Context(), strings.TrimSpace(req.Code), host)
	if errors.Is(err, store.ErrEnrollmentInvalid) {
		writeError(w, 403, "forbidden", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), e.WorkspaceID), store.Actor{Type: "enrollment", Name: e.Prefix, RemoteAddr: clientIP(r)},
		"enrollment.redeem", "enrollment", itoa(e.ID), map[string]any{"hostname": host})
	writeJSON(w, 200, map[string]any{"token": token, "environment": e.Environment, "app_dirs": e.AppDirs,
		"discover_apps": e.DiscoverApps})
}

// installScript serves the agent installer with this server's URL filled in.
func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(agentInstallScript, "__SERVER__", s.publicURL(r))))
}

// publicURL is the configured base URL, or the URL this request came in on.
func (s *Server) publicURL(r *http.Request) string {
	if s.BaseURL != "" {
		return strings.TrimRight(s.BaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil || (s.TrustProxy && r.Header.Get("X-Forwarded-Proto") == "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

var agentPlatform = regexp.MustCompile(`^linux-(amd64|arm64)(\.sha256)?$`)

// downloadAgent serves the agent binaries bundled with the server.
func (s *Server) downloadAgent(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "platform")
	if !agentPlatform.MatchString(name) || s.AgentDir == "" {
		writeError(w, 404, "not_found", "no agent build for this platform on this server")
		return
	}
	file := filepath.Join(s.AgentDir, "stackurity-"+name)
	f, err := os.Open(file)
	if err != nil {
		writeError(w, 404, "not_found", "no agent build for this platform on this server")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if strings.HasSuffix(name, ".sha256") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="stackurity"`)
	}
	http.ServeContent(w, r, "", st.ModTime(), f)
}
