package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/mcp"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// AI assistants connect to /mcp, the remote MCP endpoint (Streamable HTTP),
// and sign in with OAuth 2.1 as the MCP authorization specification asks:
//
//   - discovery: protected resource metadata (RFC 9728) names this server
//     as the authorization server, whose metadata (RFC 8414) lists the
//     endpoints below;
//   - client registration: dynamic (RFC 7591, POST /oauth/register) or a
//     client ID metadata document (the client_id is an HTTPS URL, fetched
//     with the outbound address guard);
//   - the authorization code flow with PKCE (S256 only) and exact redirect
//     URIs; the person signs in to the dashboard and allows the connection
//     on its consent page (/oauth/authorize), choosing the organisation (the
//     active one), optionally one project, and a role no higher than their
//     own;
//   - one-hour access tokens and rotating refresh tokens (a replayed one
//     ends the connection), revocation (RFC 7009), and Settings, Connected
//     assistants to disconnect.
//
// An access token works only through /mcp: the tools call the API in
// process with it, so every rule of the API (roles, project access,
// row-level security, audit) applies, and the API refuses it from outside.
// /mcp also takes personal API tokens, for clients configured with one.

const (
	assistantTokenPrefix = "stka_"
	// assistantScope is the one scope tokens carry; what an assistant may
	// do is the role and project chosen on the consent page.
	assistantScope = "stackurity"
)

var (
	// limitMCP caps the messages one credential sends to /mcp.
	limitMCP = rateLimit{300, time.Minute}
	// limitOAuthToken caps token and revocation requests per address.
	limitOAuthToken = rateLimit{60, time.Minute}
	// limitOAuthRegister caps client registrations per address.
	limitOAuthRegister = rateLimit{20, time.Hour}
)

type viaMCPKey struct{}

// viaMCP reports whether the request is a tool of /mcp calling the API.
// Only the in-process API sets it; nothing from outside can.
func viaMCP(ctx context.Context) bool {
	v, _ := ctx.Value(viaMCPKey{}).(bool)
	return v
}

// assistantRoutes registers the MCP endpoint and the OAuth endpoints, which
// sit outside /api/v1: they take no session cookie, so the CSRF rule for
// cookie requests does not apply, and they allow cross-origin calls from
// browser-based MCP clients (no credentials are ever implied).
func (s *Server) assistantRoutes(r chi.Router) {
	r.Get("/.well-known/oauth-protected-resource", s.protectedResourceMetadata)
	r.Get("/.well-known/oauth-protected-resource/mcp", s.protectedResourceMetadata)
	r.Get("/.well-known/oauth-authorization-server", s.authorizationServerMetadata)
	r.With(s.limitAddress("oauth-register", limitOAuthRegister, "too many client registrations from this address; wait an hour")).
		Post("/oauth/register", s.registerClient)
	r.With(s.limitAddress("oauth-token", limitOAuthToken, "too many token requests; wait a minute")).Post("/oauth/token", s.oauthToken)
	r.With(s.limitAddress("oauth-token", limitOAuthToken, "too many token requests; wait a minute")).Post("/oauth/revoke", s.oauthRevoke)
	r.Post("/mcp", s.mcpEndpoint)
	r.Get("/mcp", s.mcpEndpoint)
	r.Delete("/mcp", s.mcpEndpoint)
}

var corsPaths = map[string]bool{
	"/.well-known/oauth-protected-resource": true, "/.well-known/oauth-protected-resource/mcp": true,
	"/.well-known/oauth-authorization-server": true, "/oauth/register": true, "/oauth/token": true, "/oauth/revoke": true, "/mcp": true,
}

// assistantCORS lets browser-based MCP clients reach the discovery, OAuth
// and MCP endpoints. They read no cookie, so allowing any origin lends a
// web page nothing it does not already hold.
func assistantCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !corsPaths[r.URL.Path] || r.Header.Get("Origin") == "" {
			next.ServeHTTP(w, r)
			return
		}
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Mcp-Session-Id, Last-Event-ID, X-Stackurity-Project")
			h.Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- discovery

func (s *Server) mcpResource(r *http.Request) string { return s.publicURL(r) + "/mcp" }

func (s *Server) resourceMetadataURL(r *http.Request) string {
	return s.publicURL(r) + "/.well-known/oauth-protected-resource/mcp"
}

func (s *Server) protectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"resource":                 s.mcpResource(r),
		"authorization_servers":    []string{s.publicURL(r)},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{assistantScope},
		"resource_name":            "Stackurity",
		"resource_documentation":   "https://github.com/stackurity/stackurity/blob/main/docs/ai-assistants.md",
	})
}

func (s *Server) authorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	base := s.publicURL(r)
	writeJSON(w, 200, map[string]any{
		"issuer":                                         base,
		"authorization_endpoint":                         base + "/oauth/authorize",
		"token_endpoint":                                 base + "/oauth/token",
		"registration_endpoint":                          base + "/oauth/register",
		"revocation_endpoint":                            base + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                               []string{assistantScope},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
		"service_documentation":                          "https://github.com/stackurity/stackurity/blob/main/docs/ai-assistants.md",
	})
}

// --- clients

// oauthError is an error of the token, registration and revocation
// endpoints (RFC 6749 section 5.2).
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

var privateScheme = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// Schemes a browser or the OS may treat as content or code rather than as
// an application to return to.
var badSchemes = map[string]bool{"javascript": true, "data": true, "file": true, "vbscript": true, "about": true, "blob": true,
	"ftp": true, "ws": true, "wss": true, "mailto": true, "filesystem": true, "view-source": true, "chrome": true, "resource": true}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkRedirectURI accepts an HTTPS URL, an HTTP URL on the loopback
// interface (a native app's local listener), or a native app's own scheme
// (RFC 8252). No fragments, user names or schemes that run content.
func checkRedirectURI(raw string) error {
	if raw == "" || len(raw) > 2048 {
		return errors.New("redirect URIs must be 1 to 2048 characters")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("%q has a fragment", raw)
	}
	if u.User != nil {
		return fmt.Errorf("%q has a user name", raw)
	}
	switch u.Scheme {
	case "https":
		if u.Hostname() == "" {
			return fmt.Errorf("%q has no host", raw)
		}
	case "http":
		if !isLoopback(u.Hostname()) {
			return fmt.Errorf("%q: plain http is only for localhost, 127.0.0.1 or [::1]", raw)
		}
	default:
		if !privateScheme.MatchString(u.Scheme) || badSchemes[u.Scheme] {
			return fmt.Errorf("%q: the scheme %s is not allowed", raw, u.Scheme)
		}
	}
	return nil
}

// redirectAllowed: the URI is one the client registered, compared exactly,
// except that on the loopback interface the port may differ (RFC 8252
// section 7.3: native apps pick a free port).
func redirectAllowed(c *store.OAuthClient, uri string) bool {
	for _, r := range c.RedirectURIs {
		if r == uri {
			return true
		}
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || !isLoopback(u.Hostname()) {
		return false
	}
	for _, r := range c.RedirectURIs {
		ru, err := url.Parse(r)
		if err == nil && ru.Scheme == "http" && ru.Hostname() == u.Hostname() && ru.Path == u.Path && ru.RawQuery == u.RawQuery {
			return true
		}
	}
	return false
}

type registrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

// registerClient implements dynamic client registration (RFC 7591).
// Registration needs no credentials, so it is rate limited per address and
// unused registrations are removed after 30 days. Other metadata (logo,
// contacts, software id) is accepted and ignored.
func (s *Server) registerClient(w http.ResponseWriter, r *http.Request) {
	var req registrationRequest
	if err := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(&req); err != nil {
		oauthError(w, 400, "invalid_client_metadata", "the body must be a JSON object of client metadata")
		return
	}
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > 10 {
		oauthError(w, 400, "invalid_redirect_uri", "register 1 to 10 redirect_uris")
		return
	}
	for _, u := range req.RedirectURIs {
		if err := checkRedirectURI(u); err != nil {
			oauthError(w, 400, "invalid_redirect_uri", err.Error())
			return
		}
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic" // RFC 7591's default
	}
	if method != "none" && method != "client_secret_post" && method != "client_secret_basic" {
		oauthError(w, 400, "invalid_client_metadata", "token_endpoint_auth_method must be none, client_secret_post or client_secret_basic")
		return
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	for _, g := range req.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, 400, "invalid_client_metadata", "grant_types may be authorization_code and refresh_token")
			return
		}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if len(req.ResponseTypes) != 1 || req.ResponseTypes[0] != "code" {
		oauthError(w, 400, "invalid_client_metadata", "response_types must be code")
		return
	}
	name := strings.TrimSpace(req.ClientName)
	if len(name) > 200 {
		name = name[:200]
	}
	cu := strings.TrimSpace(req.ClientURI)
	if u, err := url.Parse(cu); cu != "" && (err != nil || u.Scheme != "https" || len(cu) > 2048) {
		cu = ""
	}
	c, secret, err := s.Store.RegisterOAuthClient(r.Context(), store.OAuthClient{Name: name, ClientURI: cu, RedirectURIs: req.RedirectURIs, AuthMethod: method})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"client_id": c.ID, "client_id_issued_at": time.Now().Unix(), "client_name": c.Name, "redirect_uris": c.RedirectURIs,
		"grant_types": req.GrantTypes, "response_types": req.ResponseTypes, "token_endpoint_auth_method": method, "scope": assistantScope}
	if c.ClientURI != "" {
		out["client_uri"] = c.ClientURI
	}
	if secret != "" {
		out["client_secret"], out["client_secret_expires_at"] = secret, 0
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, out)
}

// metadataClientID reports whether a client_id is a client ID metadata
// document URL: HTTPS, with a path, no fragment, user name or query.
func metadataClientID(id string) bool {
	u, err := url.Parse(id)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Path != "" && u.Path != "/" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && !strings.Contains(id, "#") && len(id) <= 2048
}

// clientMetadataTTL is how long a fetched metadata document is used.
const clientMetadataTTL = time.Hour

// oauthClient finds a registered client, or fetches the metadata document
// a URL client_id names (cached for an hour).
func (s *Server) oauthClient(ctx context.Context, id string) (*store.OAuthClient, error) {
	c, err := s.Store.GetOAuthClient(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if !metadataClientID(id) {
		if err != nil {
			return nil, errors.New("unknown client_id: the assistant has to register again")
		}
		return c, nil
	}
	if c != nil && c.FetchedAt != nil && time.Since(*c.FetchedAt) < clientMetadataTTL {
		return c, nil
	}
	doc, ferr := s.fetchClientMetadata(ctx, id)
	if ferr != nil {
		return nil, fmt.Errorf("could not read the client's metadata document %s: %w", id, ferr)
	}
	if err := s.Store.SaveMetadataClient(ctx, *doc); err != nil {
		return nil, err
	}
	return s.Store.GetOAuthClient(ctx, id)
}

// fetchClientMetadata reads a client ID metadata document. The request goes
// through the outbound address guard (no private, loopback or metadata
// addresses), follows no redirects, and reads at most 64 KiB in 5 seconds.
func (s *Server) fetchClientMetadata(ctx context.Context, id string) (*store.OAuthClient, error) {
	hc := s.ClientMetadataHTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: netguard.DialContext, ResponseHeaderTimeout: 5 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("answered %d", resp.StatusCode)
	}
	var doc struct {
		ClientID                string   `json:"client_id"`
		ClientName              string   `json:"client_name"`
		ClientURI               string   `json:"client_uri"`
		RedirectURIs            []string `json:"redirect_uris"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc); err != nil {
		return nil, errors.New("not a JSON document")
	}
	if doc.ClientID != id {
		return nil, errors.New("its client_id is not its own URL")
	}
	if doc.TokenEndpointAuthMethod != "" && doc.TokenEndpointAuthMethod != "none" {
		return nil, errors.New("only public clients (token_endpoint_auth_method none) are supported")
	}
	if len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > 10 {
		return nil, errors.New("it must list 1 to 10 redirect_uris")
	}
	for _, u := range doc.RedirectURIs {
		if err := checkRedirectURI(u); err != nil {
			return nil, err
		}
	}
	name := strings.TrimSpace(doc.ClientName)
	if name == "" {
		return nil, errors.New("it has no client_name")
	}
	if len(name) > 200 {
		name = name[:200]
	}
	cu := doc.ClientURI
	if len(cu) > 2048 {
		cu = ""
	}
	return &store.OAuthClient{ID: id, Name: name, ClientURI: cu, RedirectURIs: doc.RedirectURIs, AuthMethod: "none"}, nil
}

// --- the authorization request and the consent page

// authorizeParams are the query parameters of the authorization request,
// which the consent page passes on.
type authorizeParams struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	Resource            string `json:"resource"`
}

// authorizeProblem is an authorization request that cannot go on. With
// redirect set the client gets the error at its redirect URI; without, the
// client or redirect URI could not be trusted, and the page only shows it.
type authorizeProblem struct {
	code, desc string
	redirect   string
}

var challengeFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// checkAuthorize validates an authorization request: first the client and
// its redirect URI, then the rest, whose errors may go back to the client.
func (s *Server) checkAuthorize(r *http.Request, ap *authorizeParams) (*store.OAuthClient, *authorizeProblem) {
	if ap.ClientID == "" {
		return nil, &authorizeProblem{code: "invalid_request", desc: "client_id is missing"}
	}
	c, err := s.oauthClient(r.Context(), ap.ClientID)
	if err != nil {
		return nil, &authorizeProblem{code: "invalid_client", desc: err.Error()}
	}
	if ap.RedirectURI == "" && len(c.RedirectURIs) == 1 {
		ap.RedirectURI = c.RedirectURIs[0]
	}
	if !redirectAllowed(c, ap.RedirectURI) {
		return nil, &authorizeProblem{code: "invalid_request", desc: "redirect_uri is not one this client registered"}
	}
	back := func(code, desc string) *authorizeProblem {
		return &authorizeProblem{code: code, desc: desc, redirect: s.redirectWith(r, ap.RedirectURI, ap.State, url.Values{"error": {code}, "error_description": {desc}})}
	}
	switch {
	case ap.ResponseType != "code":
		return c, back("unsupported_response_type", "response_type must be code")
	case ap.CodeChallenge == "" || ap.CodeChallengeMethod != "S256":
		return c, back("invalid_request", "PKCE is required: send code_challenge with code_challenge_method S256")
	case !challengeFormat.MatchString(ap.CodeChallenge):
		return c, back("invalid_request", "code_challenge must be the base64url SHA-256 of the code verifier")
	case ap.Resource != "" && !s.ourResource(r, ap.Resource):
		return c, back("invalid_target", "resource must be this server's MCP endpoint, "+s.mcpResource(r))
	}
	return c, nil
}

// ourResource accepts this server's MCP endpoint or its base URL as an RFC
// 8707 resource indicator (scheme and host compared without case).
func (s *Server) ourResource(r *http.Request, res string) bool {
	norm := func(v string) string {
		u, err := url.Parse(strings.TrimRight(v, "/"))
		if err != nil {
			return v
		}
		u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
		return u.String()
	}
	n := norm(res)
	return n == norm(s.mcpResource(r)) || n == norm(s.publicURL(r))
}

// redirectWith adds the answer, state and issuer (RFC 9207) to the client's
// redirect URI.
func (s *Server) redirectWith(r *http.Request, redirect, state string, v url.Values) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return ""
	}
	q := u.Query()
	for k, vs := range v {
		q[k] = vs
	}
	if state != "" {
		q.Set("state", state)
	}
	q.Set("iss", s.publicURL(r))
	u.RawQuery = q.Encode()
	return u.String()
}

func writeAuthorizeProblem(w http.ResponseWriter, p *authorizeProblem) {
	writeJSON(w, 400, map[string]any{"error": map[string]any{"code": p.code, "message": p.desc, "redirect": p.redirect}})
}

// consenter is the signed-in person on the consent page: a browser session
// in an organisation. Tokens (and assistants) cannot authorize assistants.
func consenter(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	p := principal(r)
	if p == nil || p.User == nil || !p.Session {
		writeError(w, 403, "forbidden", "connecting an assistant needs a signed-in session in the dashboard")
		return nil, false
	}
	if p.Workspace <= 0 {
		writeError(w, 403, "forbidden", "you are not a member of any organisation")
		return nil, false
	}
	return p, true
}

var assistantRoles = []auth.Role{auth.RoleViewer, auth.RoleEngineer, auth.RoleSecurity, auth.RoleAdmin}

// previewAuthorize tells the consent page who is asking and what the person
// may allow: the client's name and redirect host, the organisation, the
// projects they can choose and the roles up to their own.
func (s *Server) previewAuthorize(w http.ResponseWriter, r *http.Request) {
	p, ok := consenter(w, r)
	if !ok {
		return
	}
	var ap authorizeParams
	if err := decode(r, &ap); err != nil {
		s.fail(w, r, err)
		return
	}
	c, prob := s.checkAuthorize(r, &ap)
	if prob != nil {
		writeAuthorizeProblem(w, prob)
		return
	}
	ctx := tenant.WithoutProject(r.Context())
	ws, err := s.Store.GetWorkspace(ctx, p.Workspace)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ps, err := s.Store.ListProjects(ctx, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ps == nil {
		ps = []store.Project{}
	}
	most := auth.Higher(p.Role, p.ProjectRole)
	roles := []auth.Role{}
	for _, role := range assistantRoles {
		if most.AtLeast(role) {
			roles = append(roles, role)
		}
	}
	host := ""
	if u, err := url.Parse(ap.RedirectURI); err == nil {
		host = u.Host
		if host == "" {
			host = u.Scheme + ":"
		}
	}
	writeJSON(w, 200, map[string]any{
		"client": map[string]any{"id": c.ID, "name": c.Name, "client_uri": c.ClientURI, "metadata_document": c.MetadataURL,
			"redirect_host": host},
		"signed_in_as": p.User.Email, "workspace": map[string]any{"id": ws.ID, "name": ws.Name},
		"projects": ps, "roles": roles, "your_role": most, "access": map[bool]string{true: "projects", false: "organisation"}[p.Restricted],
		"access_token_minutes": int(store.OAuthAccessTTL.Minutes()), "idle_days": int(store.OAuthRefreshTTL.Hours() / 24),
	})
}

type authorizeDecision struct {
	authorizeParams
	Decision  string    `json:"decision"`
	ProjectID int64     `json:"project_id"`
	Role      auth.Role `json:"role"`
}

// decideAuthorize records the person's answer and returns where the browser
// goes next: the client's redirect URI with a code, or with access_denied.
func (s *Server) decideAuthorize(w http.ResponseWriter, r *http.Request) {
	p, ok := consenter(w, r)
	if !ok {
		return
	}
	var d authorizeDecision
	if err := decode(r, &d); err != nil {
		s.fail(w, r, err)
		return
	}
	c, prob := s.checkAuthorize(r, &d.authorizeParams)
	if prob != nil {
		writeAuthorizeProblem(w, prob)
		return
	}
	if d.Decision != "allow" {
		writeJSON(w, 200, map[string]string{"redirect": s.redirectWith(r, d.RedirectURI, d.State,
			url.Values{"error": {"access_denied"}, "error_description": {"the person declined"}})})
		return
	}
	most := auth.Higher(p.Role, p.ProjectRole)
	if !d.Role.ValidUser() {
		s.fail(w, r, badRequest("role must be viewer, engineer, security or admin"))
		return
	}
	if !most.AtLeast(d.Role) {
		writeError(w, 403, "forbidden", "an assistant cannot get a role above your own ("+string(most)+")")
		return
	}
	ctx := tenant.WithoutProject(r.Context())
	var project *int64
	if d.ProjectID < 0 {
		s.fail(w, r, badRequest("project_id must be a project, or 0 for the whole organisation"))
		return
	} else if d.ProjectID > 0 {
		ok, err := s.Store.ProjectVisible(ctx, d.ProjectID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !ok {
			writeError(w, 404, "not_found", "no such project")
			return
		}
		project = &d.ProjectID
	}
	code, err := s.Store.CreateOAuthCode(ctx, store.OAuthCode{ClientID: c.ID, UserID: p.User.ID, ProjectID: project, Role: d.Role,
		RedirectURI: d.RedirectURI, CodeChallenge: d.CodeChallenge, Resource: d.Resource})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "assistant.authorize", "assistant", "", map[string]any{"client_id": c.ID,
		"client_name": c.Name, "redirect_uri": d.RedirectURI, "role": d.Role, "project_id": project})
	writeJSON(w, 200, map[string]string{"redirect": s.redirectWith(r, d.RedirectURI, d.State, url.Values{"code": {code}})})
}

// --- the token endpoint

// tokenClient authenticates the client of a token or revocation request:
// public clients by client_id, confidential ones by their secret in the
// body or with HTTP Basic.
func (s *Server) tokenClient(r *http.Request) (*store.OAuthClient, bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id == "" {
		return nil, false
	}
	c, err := s.oauthClient(r.Context(), id)
	if err != nil {
		return nil, false
	}
	if c.AuthMethod == "none" {
		return c, secret == ""
	}
	if secret == "" || (c.AuthMethod == "client_secret_basic") != basic {
		return nil, false
	}
	return c, subtle.ConstantTimeCompare(auth.HashToken(secret), c.SecretHash) == 1
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		oauthError(w, 400, "invalid_request", "send the parameters form-encoded (application/x-www-form-urlencoded)")
		return
	}
	c, ok := s.tokenClient(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="stackurity"`)
		oauthError(w, 401, "invalid_client", "unknown client, or wrong client credentials")
		return
	}
	f := r.PostForm
	if res := f.Get("resource"); res != "" && !s.ourResource(r, res) {
		oauthError(w, 400, "invalid_target", "resource must be this server's MCP endpoint, "+s.mcpResource(r))
		return
	}
	var t *store.OAuthTokens
	var err error
	switch f.Get("grant_type") {
	case "authorization_code":
		verifier := f.Get("code_verifier")
		if len(verifier) < 43 || len(verifier) > 128 || strings.Trim(verifier, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") != "" {
			oauthError(w, 400, "invalid_request", "code_verifier (43 to 128 characters) is required")
			return
		}
		redirect := f.Get("redirect_uri")
		t, err = s.Store.RedeemOAuthCode(r.Context(), f.Get("code"), func(code store.OAuthCode) error {
			sum := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(sum[:])
			if code.ClientID != c.ID || (redirect != "" && code.RedirectURI != redirect) ||
				subtle.ConstantTimeCompare([]byte(challenge), []byte(code.CodeChallenge)) != 1 {
				return store.ErrOAuthInvalidGrant
			}
			return nil
		})
		if err == nil {
			_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), t.Grant.WorkspaceID), assistantActor(r, t.Grant), "assistant.connect", "assistant",
				itoa(t.Grant.ID), map[string]any{"client_id": c.ID, "client_name": t.Grant.ClientName, "role": t.Grant.Role, "project_id": t.Grant.ProjectID})
		}
	case "refresh_token":
		t, err = s.Store.RefreshOAuthGrant(r.Context(), f.Get("refresh_token"), c.ID)
	default:
		oauthError(w, 400, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		return
	}
	if errors.Is(err, store.ErrOAuthInvalidGrant) {
		oauthError(w, 400, "invalid_grant", err.Error())
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, 200, map[string]any{"access_token": t.Access, "token_type": "Bearer", "expires_in": int(store.OAuthAccessTTL.Seconds()),
		"refresh_token": t.Refresh, "scope": assistantScope})
}

// oauthRevoke implements token revocation (RFC 7009): always 200, whether
// or not the token was known.
func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, 400, "invalid_request", "send the parameters form-encoded")
		return
	}
	c, ok := s.tokenClient(r)
	if !ok {
		oauthError(w, 401, "invalid_client", "unknown client, or wrong client credentials")
		return
	}
	g, err := s.Store.RevokeOAuthToken(r.Context(), r.PostForm.Get("token"), c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if g != nil {
		_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), g.WorkspaceID), assistantActor(r, g), "assistant.revoke", "assistant", itoa(g.ID),
			map[string]any{"client_name": g.ClientName, "by": "assistant"})
	}
	w.WriteHeader(200)
}

func assistantActor(r *http.Request, g *store.AssistantGrant) store.Actor {
	return store.Actor{Type: "assistant", ID: g.ID, Name: "assistant " + g.ClientName, RemoteAddr: clientIP(r)}
}

// --- connected assistants (Settings)

func (s *Server) listAssistants(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User == nil || !p.Session {
		writeError(w, 403, "forbidden", "sign in to see your connected assistants")
		return
	}
	gs, err := s.Store.ListAssistantGrants(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(gs))
}

func (s *Server) disconnectAssistant(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User == nil || !p.Session {
		writeError(w, 403, "forbidden", "sign in to disconnect an assistant")
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := s.Store.RevokeAssistantGrant(r.Context(), id, p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.WithWorkspace(r.Context(), g.WorkspaceID), p.Actor(r), "assistant.revoke", "assistant", itoa(g.ID),
		map[string]any{"client_name": g.ClientName, "by": "user"})
	w.WriteHeader(204)
}

// --- the MCP endpoint

// mcpEndpoint serves MCP over Streamable HTTP. It needs a bearer token (an
// assistant's access token or a personal API token); without one it
// answers 401 with the protected resource metadata, which starts the
// sign-in. Cookies are never read, so a web page cannot use a signed-in
// browser to call it.
func (s *Server) mcpEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// No server-initiated stream and no sessions (2026-07-28; earlier
		// revisions allow 405 here as well).
		w.Header().Set("Allow", "POST")
		writeError(w, 405, "method_not_allowed", "send MCP messages with POST")
		return
	}
	if o := r.Header.Get("Origin"); o != "" && !s.allowedOrigin(r, o) {
		writeError(w, 403, "forbidden", "origin not allowed")
		return
	}
	challenge := `Bearer resource_metadata="` + s.resourceMetadataURL(r) + `", scope="` + assistantScope + `"`
	h := r.Header.Get("Authorization")
	secret, ok := strings.CutPrefix(h, "Bearer ")
	secret = strings.TrimSpace(secret)
	if !ok || secret == "" {
		w.Header().Set("WWW-Authenticate", challenge)
		writeError(w, 401, "unauthorized", "sign in: connect this server in your assistant, or send a personal API token")
		return
	}
	ctx := context.WithValue(r.Context(), viaMCPKey{}, true)
	p, err := s.bearerPrincipal(ctx, secret)
	if errors.Is(err, store.ErrNotFound) {
		w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token", error_description="the token is invalid, expired or revoked"`)
		writeError(w, 401, "unauthorized", "invalid or expired token")
		return
	}
	if err != nil {
		s.credentialsUnavailable(w, r, err)
		return
	}
	if p.User == nil {
		writeError(w, 403, "forbidden", "collector and agent tokens cannot use the MCP endpoint; use a personal token")
		return
	}
	subject := "token:" + strconv.FormatInt(p.Token.ID, 10)
	if p.Assistant != nil {
		subject = "assistant:" + strconv.FormatInt(p.Assistant.ID, 10)
	}
	if s.limited(w, r, "too many requests from this assistant; wait a minute", limitHit{"mcp", subject, limitMCP}) {
		return
	}
	api := &inProcessAPI{s: s, auth: "Bearer " + secret, remote: r.RemoteAddr, project: r.Header.Get("X-Stackurity-Project")}
	srv := &mcp.Server{API: api, Version: s.Version, BaseURL: s.publicURL(r)}
	srv.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, nil)))
}

// allowedOrigin: the MCP specification asks servers to check Origin
// against DNS rebinding. /mcp reads no cookies, so a page gains nothing
// from the browser; origins are accepted when they are well-formed HTTPS
// (or loopback HTTP) web origins, and "null" and others are refused.
func (s *Server) allowedOrigin(r *http.Request, origin string) bool {
	if origin == s.publicURL(r) {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Path != "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && isLoopback(u.Hostname()))
}

// inProcessAPI is the API as the MCP tools see it: each call goes through
// the server's own router with the caller's credentials, as if sent over
// HTTP, marked as coming from /mcp.
type inProcessAPI struct {
	s       *Server
	auth    string
	remote  string
	project string
}

func (a *inProcessAPI) Do(ctx context.Context, method, path string, body io.Reader, headers map[string]string, out any) error {
	// A fresh routing context: the router must not see /mcp's.
	ctx = context.WithValue(context.WithValue(ctx, chi.RouteCtxKey, nil), viaMCPKey{}, true)
	req, err := http.NewRequestWithContext(ctx, method, path, body)
	if err != nil {
		return err
	}
	req.RemoteAddr = a.remote
	req.Header.Set("Authorization", a.auth)
	req.Header.Set("User-Agent", "stackurity-mcp")
	if a.project != "" {
		req.Header.Set("X-Stackurity-Project", a.project)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := &recorder{header: http.Header{}, status: 200}
	a.s.router.ServeHTTP(rec, req)
	if rec.status >= 300 {
		var e struct {
			Error client.APIError `json:"error"`
		}
		_ = json.Unmarshal(rec.body.Bytes(), &e)
		e.Error.Status = rec.status
		return &e.Error
	}
	if out == nil || rec.body.Len() == 0 {
		return nil
	}
	return json.NewDecoder(bytes.NewReader(rec.body.Bytes())).Decode(out)
}
