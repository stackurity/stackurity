package api

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

//go:embed install/agent.sh
var agentInstallScript string

//go:embed install/agent.ps1
var agentInstallPowerShell string

type enrollmentRequest struct {
	Label        string   `json:"label"`
	Environment  string   `json:"environment"`
	AppDirs      []string `json:"app_dirs"`
	DiscoverApps bool     `json:"discover_apps"`
	Uses         int      `json:"uses"`      // default 1; required for a fleet code
	TTLHours     int      `json:"ttl_hours"` // default 24; required for a fleet code
	// ProjectID: hosts enrolled with the code land in this project.
	ProjectID int64 `json:"project_id"`
	// Fleet makes a fleet code: up to store.MaxFleetUses servers and
	// store.MaxFleetTTL, with uses and ttl_hours given explicitly.
	Fleet bool `json:"fleet"`
}

var envLabel = regexp.MustCompile(`^[A-Za-z0-9._-]{0,64}$`)

func (s *Server) createEnrollment(w http.ResponseWriter, r *http.Request) {
	var req enrollmentRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	maxUses, maxHours := store.MaxCodeUses, int(store.MaxCodeTTL/time.Hour)
	if req.Fleet {
		// A code that can add a thousand servers for three months is made
		// on purpose: no defaults.
		maxUses, maxHours = store.MaxFleetUses, int(store.MaxFleetTTL/time.Hour)
		if req.Uses == 0 || req.TTLHours == 0 {
			s.fail(w, r, badRequest("a fleet code needs uses (how many servers) and ttl_hours (how long it is valid)"))
			return
		}
	}
	if req.Uses == 0 {
		req.Uses = 1
	}
	if req.TTLHours == 0 {
		req.TTLHours = 24
	}
	switch {
	case req.Uses < 1 || req.Uses > maxUses:
		msg := fmt.Sprintf("uses must be between 1 and %d", maxUses)
		if !req.Fleet && req.Uses > maxUses {
			msg += fmt.Sprintf("; for up to %d servers create a fleet code (fleet: true)", store.MaxFleetUses)
		}
		s.fail(w, r, badRequest(msg))
		return
	case req.TTLHours < 1 || req.TTLHours > maxHours:
		s.fail(w, r, badRequest(fmt.Sprintf("ttl_hours must be between 1 and %d", maxHours)))
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
	// A code exists to add hosts; at the limit none could be added.
	if err := s.Store.AssetLimitReached(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	var by int64
	if p.User != nil {
		by = p.User.ID
	}
	var project *int64
	if req.ProjectID > 0 {
		project = &req.ProjectID
	} else if req.ProjectID < 0 {
		s.fail(w, r, badRequest("project_id must be a project"))
		return
	}
	e, code, err := s.Store.CreateEnrollment(r.Context(), store.Enrollment{Label: strings.TrimSpace(req.Label), Environment: req.Environment,
		AppDirs: req.AppDirs, DiscoverApps: req.DiscoverApps, UsesLeft: req.Uses, ProjectID: project, Fleet: req.Fleet}, time.Duration(req.TTLHours)*time.Hour, by)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "enrollment.create", "enrollment", itoa(e.ID), map[string]any{
		"label": e.Label, "environment": e.Environment, "uses": e.UsesLeft, "expires_at": e.ExpiresAt, "project_id": e.ProjectID, "fleet": e.Fleet})
	writeJSON(w, 201, map[string]any{"enrollment": e, "code": code})
}

// listEnrollments lists the codes that can still be used; with ?fleet=1,
// fleet codes in every state (so a finished rollout's usage stays visible).
func (s *Server) listEnrollments(w http.ResponseWriter, r *http.Request) {
	list := s.Store.ListEnrollments
	if r.URL.Query().Get("fleet") == "1" {
		list = s.Store.ListFleetEnrollments
	}
	items, err := list(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": nonNil(items)})
}

// enrollmentUses lists which hosts used a code, when and from where.
func (s *Server) enrollmentUses(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.Store.EnrollmentUses(r.Context(), id, store.MaxFleetUses)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": nonNil(items)})
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

// enroll exchanges a code for a collector token. It needs no session or
// token, so it is rate limited and says nothing about why a code was
// refused. Three limits apply (ratelimit.go): failed attempts per address
// (what stops guessing), all attempts per address (looser, so a fleet behind
// one NAT address can enroll), and redemptions per code (so a leaked fleet
// code cannot mint its thousand tokens in a burst before someone revokes
// it). A refused host is told when to retry (Retry-After), and `stackurity
// enroll` does.
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"enroll", ip, limitEnrollPerAddress}) {
		return
	}
	failures, err := s.Store.RateLimitCount(r.Context(), "enroll-fail", ip, limitEnrollFailures.window)
	if err != nil {
		s.Log.Error("rate limit unavailable; refusing the request", "bucket", "enroll-fail", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the server cannot check rate limits right now; try again shortly")
		return
	}
	if failures >= limitEnrollFailures.n {
		setRetryAfter(w, limitEnrollFailures)
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many attempts; wait a minute")
		return
	}
	var req struct {
		Code     string `json:"code"`
		Hostname string `json:"hostname"`
		// ProjectID (stackurity enroll --project) is a check, not a
		// choice: the code must add hosts to this project, or nothing is
		// redeemed (403).
		ProjectID int64 `json:"project_id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ProjectID < 0 {
		s.fail(w, r, badRequest("project_id must be a project id"))
		return
	}
	host := strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return -1
		}
		return c
	}, strings.TrimSpace(req.Hostname))
	if len(host) > 253 {
		host = strings.ToValidUTF8(host[:253], "")
	}
	code := strings.TrimSpace(req.Code)
	if s.limited(w, r, "many hosts are enrolling with this code at once; wait a minute", limitHit{"enroll-code", hex.EncodeToString(auth.HashToken(code)), limitEnrollPerCode}) {
		return
	}
	e, token, err := s.Store.Redeem(r.Context(), store.Redemption{Code: code, Hostname: host, Project: req.ProjectID, RemoteAddr: ip})
	if errors.Is(err, store.ErrEnrollmentInvalid) || errors.Is(err, store.ErrEnrollmentProject) {
		if _, herr := s.Store.RateLimitHit(r.Context(), "enroll-fail", ip, limitEnrollFailures.window); herr != nil {
			s.Log.Error("counting a failed enrollment", "err", herr)
		}
		writeError(w, 403, "forbidden", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), e.WorkspaceID), store.Actor{Type: "enrollment", Name: e.Prefix, RemoteAddr: clientIP(r)},
		"enrollment.redeem", "enrollment", itoa(e.ID), map[string]any{"hostname": host, "fleet": e.Fleet, "uses_left": e.UsesLeft})
	writeJSON(w, 200, map[string]any{"token": token, "environment": e.Environment, "app_dirs": e.AppDirs,
		"discover_apps": e.DiscoverApps, "project_id": e.ProjectID})
}

// installScript serves the agent installer with this server's URL filled in.
// Without STACKURITY_BASE_URL the URL comes from the request's Host header,
// which the client chooses: publicURL accepts only a hostname or IP address
// with an optional port, and the script receives it single-quoted as well,
// so nothing in it can run as shell code. The response depends on Host, so
// caches must neither share nor keep it.
func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", "Host")
	base, err := s.publicURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !scriptSafeURL.MatchString(base) {
		// Only STACKURITY_BASE_URL can get here: a Host-derived URL is
		// already narrower than this.
		writeError(w, 500, "misconfigured", "STACKURITY_BASE_URL must be an http(s) URL without spaces, quotes or shell characters")
		return
	}
	script := strings.ReplaceAll(agentInstallScript, "'__SERVER__'", shSingleQuoted(base))
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(script, "__SERVER__", base)))
}

// scriptSafeURL is what the installer will put in a script: an http(s) URL
// of unreserved characters plus the delimiters a host, port and path need.
// No quotes, whitespace, $, `, \, ;, &, |, parentheses or redirections.
var scriptSafeURL = regexp.MustCompile(`^https?://[A-Za-z0-9._~:/\[\]%@+,=-]+$`)

// shSingleQuoted quotes v for a POSIX shell: inside single quotes nothing is
// special, and a quote is written as quote, backslash, quote, quote.
func shSingleQuoted(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// installPowerShell serves the Windows agent installer with this server's URL
// filled in. The URL goes into a single-quoted PowerShell string, so quotes
// in it (from a Host header, when no base URL is configured) cannot end the
// string and run as code. The script never contains an enrollment code: the
// person running it sets STACKURITY_ENROLL_CODE.
func (s *Server) installPowerShell(w http.ResponseWriter, r *http.Request) {
	base, err := s.publicURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !scriptSafeURL.MatchString(base) {
		writeError(w, 500, "misconfigured", "STACKURITY_BASE_URL must be an http(s) URL without spaces, quotes or shell characters")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(strings.ReplaceAll(agentInstallPowerShell, "__SERVER__", psSingleQuoted(base))))
}

// psSingleQuoted escapes text for the inside of a PowerShell single-quoted
// string: PowerShell ends one at an ASCII apostrophe or any of the
// typographic single quotes, and reads each doubled as one literal quote.
func psSingleQuoted(v string) string {
	var b strings.Builder
	for _, c := range v {
		switch c {
		case '\'', '\u2018', '\u2019', '\u201a', '\u201b':
			b.WriteRune(c)
		}
		b.WriteRune(c)
	}
	return b.String()
}

// publicURL is the configured base URL, or the URL this request came in on.
// The second is built from the Host header, so it is refused (400) unless
// the header is a hostname or IP address with an optional port.
func (s *Server) publicURL(r *http.Request) (string, error) {
	if s.BaseURL != "" {
		return strings.TrimRight(s.BaseURL, "/"), nil
	}
	if !validHostHeader(r.Host) {
		return "", badRequest("the Host header is not a hostname or IP address; set STACKURITY_BASE_URL on the server")
	}
	scheme := "http"
	if r.TLS != nil || (s.TrustProxy && viaTrustedProxy(r) && r.Header.Get("X-Forwarded-Proto") == "https") {
		scheme = "https"
	}
	return scheme + "://" + r.Host, nil
}

// hostLabel is one DNS label. Underscores are allowed (container and
// compose service names have them); they mean nothing to a shell.
var hostLabel = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

// validHostHeader reports whether h is host[:port]: a DNS name, an IPv4
// address, or a bracketed IPv6 address (no zone), with a numeric port.
func validHostHeader(h string) bool {
	if h == "" || len(h) > 262 {
		return false
	}
	host, port := h, ""
	if strings.HasPrefix(h, "[") {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return false
		}
		host, port = h[1:end], h[end+1:]
		a, err := netip.ParseAddr(host)
		if err != nil || !a.Is6() || a.Zone() != "" {
			return false
		}
		if port == "" {
			return true
		}
		if port[0] != ':' {
			return false
		}
		port = port[1:]
		return validPort(port)
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		host, port = h[:i], h[i+1:]
		if !validPort(port) {
			return false
		}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return !strings.Contains(host, ":") // IPv6 must be bracketed
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253 {
		return false
	}
	for _, l := range strings.Split(host, ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

func validPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && len(p) <= 5 && strings.Trim(p, "0123456789") == "" && n >= 1 && n <= 65535
}

var agentPlatform = regexp.MustCompile(`^(linux-(amd64|arm64)|windows-amd64)(\.sha256)?$`)

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
		file := "stackurity"
		if strings.HasPrefix(name, "windows-") {
			file = "stackurity.exe"
		}
		w.Header().Set("Content-Disposition", `attachment; filename="`+file+`"`)
	}
	http.ServeContent(w, r, "", st.ModTime(), f)
}
