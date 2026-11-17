package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Signing in a command-line tool from the browser (docs/device-login.md):
// the OAuth 2.0 Device Authorization Grant, RFC 8628.
//
//  1. The tool asks for a code: POST /api/v1/device/code (no credentials).
//  2. It shows the person the user code and the address of /device, and
//     polls POST /api/v1/device/token every few seconds.
//  3. The person opens /device in a browser, signs in (or signs up), checks
//     the request and clicks Approve: POST /api/v1/device/preview and
//     /api/v1/device/decision, with their session.
//  4. The next poll returns an API token, once.
//
// The token is an ordinary API token of the person (Settings > API tokens,
// revocable there) with the collector role: it may upload scans (POST
// /ingest, POST /sbom/import) and read their results, nothing else, and only
// while its person may upload themselves (authenticate, uploadTokenRequest).
//
// CI jobs keep using keyless CI tokens (POST /ci/token, ci_oidc.go): the
// device flow is for people at a terminal.

// FeatureDeviceLogin, in GET /meta's features, says that this server signs
// command-line tools in from the browser (POST /device/code and /device/token).
// It is offered only with STACKURITY_BASE_URL set: the tool shows the person
// the address of /device.
const FeatureDeviceLogin = "device_login"

// DeviceGrantType is the grant_type of the token request (RFC 8628 section 3.4).
const DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

// DevicePath is the dashboard page where people enter and approve codes.
const DevicePath = "/device"

// deviceClients are the tools that may sign in this way, by client_id, with
// the name the approval page shows. The name never comes from the tool, so a
// request cannot pass itself off as something else.
var deviceClients = map[string]string{
	"stackurity-scan": "Stackurity scan (stackurity-scan)",
	"stackurity":      "Stackurity CLI (stackurity)",
}

// deviceHostLabel is what a tool may say about the machine it runs on: a host
// name, shown on the approval page and in the token's name.
var deviceHostLabel = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

var (
	// limitDeviceCode caps new sign-in requests per address.
	limitDeviceCode     = rateLimit{10, time.Minute}
	limitDeviceCodeHour = rateLimit{60, time.Hour}
	// limitDevicePoll caps polls per address: a tool polls every five
	// seconds, so this leaves room for several behind one NAT address.
	limitDevicePoll = rateLimit{120, time.Minute}
	// limitDeviceEntry caps codes looked up or decided per person and per
	// address. A code is one of 20^8 and lives ten minutes, so guessing
	// someone else's is hopeless at this rate; it also stops a script.
	limitDeviceEntry     = rateLimit{20, 15 * time.Minute}
	limitDeviceEntryAddr = rateLimit{40, 15 * time.Minute}
)

// deviceTokenTTLDays is how long the token works, for the approval page.
var deviceTokenTTLDays = int(store.DeviceTokenTTL / (24 * time.Hour))

// uploadToken is a person's upload token: a collector token with a user,
// made by device sign-in.
func (p *Principal) uploadToken() bool {
	return p != nil && p.Token != nil && p.User != nil && p.Token.Role == auth.RoleCollector && p.Assistant == nil
}

// uploadTokenRequest reports whether an upload token may make r: uploads,
// their results, and what describes the server.
func uploadTokenRequest(r *http.Request) bool {
	path := strings.TrimSuffix(r.URL.Path, "/")
	switch r.Method {
	case http.MethodPost:
		return path == "/api/v1/ingest" || path == "/api/v1/sbom/import"
	case http.MethodGet, http.MethodHead:
		if path == "/api/v1/meta" || path == "/api/v1/openapi.json" {
			return true
		}
		id, ok := strings.CutPrefix(path, "/api/v1/collections/")
		if !ok {
			return false
		}
		id, ok = strings.CutSuffix(id, "/result")
		return ok && id != "" && !strings.Contains(id, "/")
	}
	return false
}

// deviceRootRoutes are the tool's two endpoints. They take no credentials
// and are registered outside /api/v1's session and CSRF checks, so a
// standard RFC 8628 client (form-encoded, no custom headers) works as is.
func (s *Server) deviceRootRoutes(r chi.Router) {
	r.Post("/api/v1/device/code", s.deviceCode)
	r.Post("/api/v1/device/token", s.deviceToken)
}

// deviceAccountRoutes are the approval page's, for a signed-in session.
func (s *Server) deviceAccountRoutes(r chi.Router) {
	r.Post("/device/preview", s.devicePreview)
	r.Post("/device/decision", s.deviceDecision)
}

func init() {
	for _, r := range []string{"POST /api/v1/device/preview", "POST /api/v1/device/decision"} {
		projectRoutes[r] = accountScope
	}
}

// deviceOff answers while the server has no public address (the tool could
// not tell the person where to go), and reports whether it did.
func (s *Server) deviceOff(w http.ResponseWriter) bool {
	if s.BaseURL != "" {
		return false
	}
	writeError(w, 404, "not_configured", "signing in from a terminal is off on this server: an administrator has to set STACKURITY_BASE_URL to its public address")
	return true
}

// deviceParams reads a request of the tool: form-encoded, as RFC 8628 and
// RFC 6749 send it, or a JSON object of strings.
func deviceParams(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "application/json" {
		var m map[string]any
		b, err := io.ReadAll(r.Body)
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			err = json.Unmarshal(b, &m)
		}
		if err != nil {
			oauthError(w, 400, "invalid_request", "send the parameters form-encoded or as a JSON object")
			return nil, false
		}
		v := url.Values{}
		for k, x := range m {
			str, ok := x.(string)
			if !ok {
				oauthError(w, 400, "invalid_request", "parameter "+k+" must be a string")
				return nil, false
			}
			v.Set(k, str)
		}
		return v, true
	}
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "send the parameters form-encoded or as a JSON object")
		return nil, false
	}
	return r.PostForm, true
}

// deviceCode starts a sign-in (RFC 8628 section 3.1-3.2).
func (s *Server) deviceCode(w http.ResponseWriter, r *http.Request) {
	if s.deviceOff(w) {
		return
	}
	if s.limited(w, r, "too many sign-in requests from this address; wait a minute",
		limitHit{"device-code", addressKey(r), limitDeviceCode}, limitHit{"device-code-hour", addressKey(r), limitDeviceCodeHour}) {
		return
	}
	v, ok := deviceParams(w, r)
	if !ok {
		return
	}
	clientID := v.Get("client_id")
	if _, known := deviceClients[clientID]; !known {
		oauthError(w, 401, "invalid_client", "unknown client_id; this server signs in stackurity-scan and stackurity")
		return
	}
	if sc := v.Get("scope"); sc != "" && sc != "upload" {
		oauthError(w, 400, "invalid_scope", "the only scope is upload")
		return
	}
	host := strings.TrimSpace(v.Get("host"))
	if host != "" && !deviceHostLabel.MatchString(host) {
		oauthError(w, 400, "invalid_request", "host must be a host name: letters, digits, dots, hyphens and underscores, at most 63 characters")
		return
	}
	deviceCode, userCode, d, err := s.Store.CreateDeviceAuthorization(r.Context(), clientID, host, clientIP(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	verify := strings.TrimRight(s.BaseURL, "/") + DevicePath
	shown := store.FormatUserCode(userCode)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 shown,
		"verification_uri":          verify,
		"verification_uri_complete": verify + "?user_code=" + url.QueryEscape(shown),
		"expires_in":                int(time.Until(d.ExpiresAt).Round(time.Second).Seconds()),
		"interval":                  int(store.DeviceInterval / time.Second),
	})
}

// deviceToken is the tool's poll (RFC 8628 section 3.4-3.5). Errors are
// RFC 6749 section 5.2 answers: authorization_pending, slow_down,
// access_denied, expired_token, invalid_grant, invalid_client,
// unsupported_grant_type, invalid_request.
func (s *Server) deviceToken(w http.ResponseWriter, r *http.Request) {
	if s.deviceOff(w) {
		return
	}
	// Over the per-address limit the tool is told to slow down, which every
	// RFC 8628 client understands, rather than a 429 it would give up on.
	if ok, err := s.limiter.check(r.Context(), limitHit{"device-token", addressKey(r), limitDevicePoll}); err != nil {
		s.Log.Error("rate limit unavailable; refusing the request", "bucket", "device-token", "err", err)
		writeError(w, http.StatusServiceUnavailable, "unavailable", "the server cannot check rate limits right now; try again shortly")
		return
	} else if !ok {
		oauthError(w, 400, "slow_down", "too many requests from this address; poll less often")
		return
	}
	v, ok := deviceParams(w, r)
	if !ok {
		return
	}
	if v.Get("grant_type") != DeviceGrantType {
		oauthError(w, 400, "unsupported_grant_type", "grant_type must be "+DeviceGrantType)
		return
	}
	clientID := v.Get("client_id")
	if _, known := deviceClients[clientID]; !known {
		oauthError(w, 401, "invalid_client", "unknown client_id")
		return
	}
	code := v.Get("device_code")
	if code == "" {
		oauthError(w, 400, "invalid_request", "device_code is required")
		return
	}
	poll, err := s.Store.PollDeviceAuthorization(r.Context(), code, clientID)
	if errors.Is(err, store.ErrDeviceInvalidGrant) {
		oauthError(w, 400, "invalid_grant", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	switch poll.Outcome {
	case store.DevicePending:
		oauthError(w, 400, "authorization_pending", "waiting for the person to approve the code in the browser")
		return
	case store.DevicePollSlowDown:
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 400, map[string]any{"error": "slow_down", "error_description": "polling too often; wait longer between requests",
			"interval": poll.Interval})
		return
	case store.DeviceDenied:
		oauthError(w, 400, "access_denied", "the request was denied in the browser, or its token was revoked before it was collected")
		return
	case store.DevicePollExpired:
		oauthError(w, 400, "expired_token", "the code expired before it was approved and collected; start signing in again")
		return
	}
	d, tok := poll.Authorization, poll.Token
	ctx := tenant.WithWorkspace(r.Context(), tok.WorkspaceID)
	ws, err := s.Store.GetWorkspace(ctx, tok.WorkspaceID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var project any
	if tok.ProjectID != nil {
		if pr, err := s.Store.GetProject(tenant.WithoutProject(ctx), *tok.ProjectID); err == nil {
			project = map[string]any{"id": pr.ID, "name": pr.Name}
		}
	}
	_ = s.Store.Audit(ctx, store.Actor{Type: "token", ID: tok.ID, Name: tok.UserEmail + " (token " + tok.Prefix + ")", RemoteAddr: clientIP(r)},
		"device.token_collected", "token", itoa(tok.ID), map[string]any{"client_id": d.ClientID, "host": d.HostLabel, "device_authorization": d.ID})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, 200, map[string]any{
		"access_token": poll.Secret,
		"token_type":   "Bearer",
		"scope":        "upload",
		"expires_in":   expiresIn(tok.ExpiresAt),
		"token":        map[string]any{"id": tok.ID, "name": tok.Name, "prefix": tok.Prefix, "expires_at": tok.ExpiresAt},
		"workspace":    map[string]any{"id": ws.ID, "name": ws.Name, "slug": ws.Slug},
		"project":      project,
		"user":         map[string]any{"email": tok.UserEmail},
		"server_url":   strings.TrimRight(s.BaseURL, "/"),
	})
}

func expiresIn(t *time.Time) int {
	if t == nil {
		return 0
	}
	return int(time.Until(*t).Seconds())
}

// deviceApprover is the signed-in person on the approval page: a browser
// session of their own (never a token, an assistant or Ask Stackurity),
// whose browser says the request came from this site.
func deviceApprover(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	p := principal(r)
	if p == nil || p.User == nil || !p.Session || p.Token != nil || p.Ask || p.ViaAsk {
		writeError(w, 403, "forbidden", "approving a sign-in needs a signed-in browser session")
		return nil, false
	}
	// csrfGuard already requires X-Stackurity-CSRF; a browser that says
	// the request came from another site is refused as well.
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		writeError(w, 403, "csrf", "this request did not come from the Stackurity page")
		return nil, false
	}
	return p, true
}

// deviceRequest is what the approval page sends.
type deviceRequest struct {
	UserCode string `json:"user_code"`
	// For a decision: approve or deny, the organisation the page showed
	// (the session may have switched since, in another tab) and the project
	// the token's new assets go to (0: none).
	Decision    string `json:"decision"`
	WorkspaceID int64  `json:"workspace_id"`
	ProjectID   int64  `json:"project_id"`
}

// deviceLookup reads the request body and finds the pending request its
// code names, counting the attempt against the person's and the address's
// limits. On a refusal it has answered.
func (s *Server) deviceLookup(w http.ResponseWriter, r *http.Request, p *Principal) (*deviceRequest, *store.DeviceAuthorization, string, bool) {
	if s.deviceOff(w) {
		return nil, nil, "", false
	}
	if s.limited(w, r, "too many codes tried; wait a few minutes and try again",
		limitHit{"device-entry", itoa(p.User.ID), limitDeviceEntry}, limitHit{"device-entry-addr", addressKey(r), limitDeviceEntryAddr}) {
		return nil, nil, "", false
	}
	var req deviceRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return nil, nil, "", false
	}
	code := store.NormalizeUserCode(req.UserCode)
	if code == "" {
		writeError(w, 400, "bad_request", "a code is eight letters, like BCDF-GHJK; copy it from your terminal")
		return nil, nil, "", false
	}
	d, err := s.Store.DeviceAuthorizationByUserCode(r.Context(), code)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 404, "not_found", "no sign-in request has this code: check it against your terminal, or start signing in again there")
		return nil, nil, "", false
	}
	if err != nil {
		s.fail(w, r, err)
		return nil, nil, "", false
	}
	switch {
	case d.Status != store.DevicePending:
		writeError(w, 410, "code_used", "this code was already approved or denied; start signing in again from your terminal if you need to")
		return nil, nil, "", false
	case d.Expired:
		writeError(w, 410, "code_expired", "this code has expired (codes last 10 minutes); start signing in again from your terminal")
		return nil, nil, "", false
	}
	return &req, d, code, true
}

// deviceCannot says why the person cannot approve in their organisation,
// or "" when they can.
func deviceCannot(p *Principal) string {
	switch {
	case p.Workspace <= 0:
		return "You are not a member of an organisation yet. Create one, or ask to be invited, then open this page again."
	case p.Restricted:
		return "You have access to some projects only. Uploading needs the Engineer role (or above) for the whole organisation: ask an administrator."
	case !p.Role.CanIngest():
		return "Uploading needs the Engineer role or above in this organisation; you are " + string(p.Role) + ". Ask an administrator."
	}
	return ""
}

func deviceTokenName(d *store.DeviceAuthorization) string {
	name := d.ClientID + " (signed in from a terminal)"
	if d.HostLabel != "" {
		name = d.ClientID + " on " + d.HostLabel
	}
	return name
}

// devicePreview tells the approval page what is asking and what approving
// would allow.
func (s *Server) devicePreview(w http.ResponseWriter, r *http.Request) {
	p, ok := deviceApprover(w, r)
	if !ok {
		return
	}
	_, d, code, ok := s.deviceLookup(w, r, p)
	if !ok {
		return
	}
	out := map[string]any{
		"user_code":    store.FormatUserCode(code),
		"client":       map[string]any{"id": d.ClientID, "name": deviceClients[d.ClientID]},
		"host":         d.HostLabel,
		"request_ip":   d.RequestIP,
		"same_network": d.RequestIP == "" || sameNetwork(d.RequestIP, clientIP(r)),
		"requested_at": d.CreatedAt,
		"expires_at":   d.ExpiresAt,
		"signed_in_as": p.User.Email,
		"workspace":    nil,
		"your_role":    p.Role,
		"can_approve":  false,
		"projects":     []store.Project{},
		"token_name":   deviceTokenName(d),
		"token_days":   deviceTokenTTLDays,
	}
	if why := deviceCannot(p); why != "" {
		out["cannot_approve"] = why
	} else {
		out["can_approve"] = true
	}
	if p.Workspace > 0 {
		ctx := tenant.WithoutProject(r.Context())
		ws, err := s.Store.GetWorkspace(ctx, p.Workspace)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out["workspace"] = map[string]any{"id": ws.ID, "name": ws.Name}
		// Filing new assets in a project is for organisation admins, as
		// with any upload (uploadProject).
		if p.Role.AtLeast(auth.RoleAdmin) {
			ps, err := s.Store.ListProjects(ctx, false)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			if ps != nil {
				out["projects"] = ps
			}
		}
	}
	writeJSON(w, 200, out)
}

// deviceDecision records the person's answer. Approving makes the token
// (store.ApproveDeviceAuthorization); the tool collects it with its next
// poll.
func (s *Server) deviceDecision(w http.ResponseWriter, r *http.Request) {
	p, ok := deviceApprover(w, r)
	if !ok {
		return
	}
	req, d, code, ok := s.deviceLookup(w, r, p)
	if !ok {
		return
	}
	if p.Workspace <= 0 {
		writeError(w, 403, "forbidden", deviceCannot(p))
		return
	}
	if req.WorkspaceID != p.Workspace {
		writeError(w, 409, "conflict", "this session now works in another organisation; reload the page and check what you approve")
		return
	}
	detail := map[string]any{"client_id": d.ClientID, "host": d.HostLabel, "request_ip": d.RequestIP, "device_authorization": d.ID}
	switch req.Decision {
	case "deny":
		if _, err := s.Store.DenyDeviceAuthorization(r.Context(), code, p.User.ID, p.Workspace); err != nil {
			s.deviceFail(w, r, err)
			return
		}
		_ = s.Store.Audit(r.Context(), p.Actor(r), "device.deny", "device_authorization", itoa(d.ID), detail)
		writeJSON(w, 200, map[string]any{"status": store.DeviceDenied})
		return
	case "approve":
	default:
		s.fail(w, r, badRequest("decision must be approve or deny"))
		return
	}
	if why := deviceCannot(p); why != "" {
		writeError(w, 403, "forbidden", why)
		return
	}
	var project *int64
	switch {
	case req.ProjectID < 0:
		s.fail(w, r, badRequest("project_id must be a project, or 0 for none"))
		return
	case req.ProjectID > 0:
		if !p.Role.AtLeast(auth.RoleAdmin) {
			writeError(w, 403, "forbidden", "adding new assets to a project needs the admin role; approve without a project")
			return
		}
		if active, err := s.Store.ActiveProject(tenant.WithoutProject(r.Context()), req.ProjectID); err != nil {
			s.fail(w, r, err)
			return
		} else if !active {
			writeError(w, 404, "not_found", "no such project")
			return
		}
		project = &req.ProjectID
	}
	d, tok, err := s.Store.ApproveDeviceAuthorization(r.Context(), code, store.DeviceApproval{UserID: p.User.ID, WorkspaceID: p.Workspace,
		ProjectID: project, TokenName: deviceTokenName(d)})
	if err != nil {
		s.deviceFail(w, r, err)
		return
	}
	detail["project_id"] = project
	detail["token_id"] = tok.ID
	_ = s.Store.Audit(r.Context(), p.Actor(r), "device.approve", "device_authorization", itoa(d.ID), detail)
	_ = s.Store.Audit(r.Context(), p.Actor(r), "token.create", "token", itoa(tok.ID), map[string]any{"name": tok.Name, "role": tok.Role,
		"project_id": tok.ProjectID, "via": "device_login"})
	s.notifyDeviceToken(r, p, tok.Name, d.RequestIP)
	writeJSON(w, 200, map[string]any{"status": store.DeviceApproved,
		"token": map[string]any{"id": tok.ID, "name": tok.Name, "expires_at": tok.ExpiresAt, "project_id": tok.ProjectID}})
}

// notifyDeviceToken emails the approver, after the response, that a token
// was made in their name and where to revoke it.
func (s *Server) notifyDeviceToken(r *http.Request, p *Principal, tokenName, requestIP string) {
	if s.AccountMail == nil || p.User == nil || p.User.Email == "" {
		return
	}
	workspace := "your organisation"
	if ws, err := s.Store.GetWorkspace(tenant.WithoutProject(r.Context()), p.Workspace); err == nil && ws.Name != "" {
		workspace = ws.Name
	}
	m := notify.DeviceTokenEmail(s.BaseURL, p.User.Email, tokenName, workspace, requestIP, clientIP(r), deviceTokenTTLDays, time.Now().UTC())
	to := p.User.Email
	ctx := context.WithoutCancel(r.Context())
	go func() {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if err := s.AccountMail.SendMail(ctx, []string{to}, m); err != nil {
			s.Log.Error("device sign-in token notice not sent", "err", err)
		}
	}()
}

// sameNetwork reports whether two addresses look like one network: the
// same IPv4 /24 or IPv6 /48. A sign-in started elsewhere than the browser
// that approves it is the shape of a phished code, so the page says so.
func sameNetwork(a, b string) bool {
	x, y := net.ParseIP(a), net.ParseIP(b)
	if x == nil || y == nil {
		return a == b
	}
	if x4, y4 := x.To4(), y.To4(); x4 != nil || y4 != nil {
		return x4 != nil && y4 != nil && x4.Mask(net.CIDRMask(24, 32)).Equal(y4.Mask(net.CIDRMask(24, 32)))
	}
	return x.Mask(net.CIDRMask(48, 128)).Equal(y.Mask(net.CIDRMask(48, 128)))
}

func (s *Server) deviceFail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, store.ErrDeviceNotPending) {
		writeError(w, 410, "code_used", err.Error())
		return
	}
	s.fail(w, r, err)
}
