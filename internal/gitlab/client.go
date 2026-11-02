// Package gitlab is "Connect GitLab": an organisation connects a GitLab
// group once and every project in it (subgroups included) is scanned, as
// the Stackurity GitHub App does for GitHub. See docs/gitlab.md.
//
// The operator registers one OAuth application on their GitLab (GitLab.com
// or self-managed; instance-wide or group-owned). An admin authorises it
// with the api scope, picks a group, and Stackurity uses that token once,
// in that request, to create:
//
//   - a group access token with read_api and read_repository, the Reporter
//     role and an expiry under a year, stored sealed: the credential every
//     scan and listing uses;
//   - a group webhook for push events, with a random secret token of which
//     only the SHA-256 is stored.
//
// The admin's token is then revoked at GitLab. Where GitLab does not allow
// a group access token (the admin is not the group's Owner, or GitLab.com's
// Free tier), the admin authorises a second time with read_api and
// read_repository only, and that OAuth credential is stored sealed and
// refreshed; GitLab rotates the refresh token on every use. Where the
// webhook is not allowed, the group is scanned on the schedule only.
package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
)

// Scopes asked for. SetupScopes is used once, at connect and at cleanup,
// and revoked in the same request; ReadScopes is what is kept.
var (
	SetupScopes = []string{"api"}
	ReadScopes  = []string{"read_api", "read_repository"}
)

// Access levels (GitLab's numbers).
const (
	AccessReporter = 20
	AccessOwner    = 50
)

// MaxProjects bounds how many projects of one group are read.
const MaxProjects = 5000

// TokenLifetime is how long a group access token Stackurity creates lives
// (GitLab allows at most a year, or 400 days on recent versions).
const TokenLifetime = 364 * 24 * time.Hour

// Client is the GitLab OAuth application and API.
type Client struct {
	// Base is GitLab's address: https://gitlab.com or a self-managed
	// instance. The API is Base + "/api/v4".
	Base         string
	ClientID     string
	ClientSecret string
	// HTTP makes the calls; tests point it at a fake. The default dials
	// through netguard, keeps no connection alive and follows no redirects.
	HTTP *http.Client
}

// FromEnv reads STACKURITY_GITLAB_CLIENT_ID and
// STACKURITY_GITLAB_CLIENT_SECRET (each also as _FILE) and the optional
// STACKURITY_GITLAB_URL (https://gitlab.com when unset). With neither
// credential set Connect GitLab is off (nil); with one it is a
// configuration error.
func FromEnv() (*Client, error) {
	read := func(name string) (string, error) {
		v := strings.TrimSpace(os.Getenv(name))
		if f := os.Getenv(name + "_FILE"); f != "" {
			b, err := os.ReadFile(f)
			if err != nil {
				return "", fmt.Errorf("%s_FILE: %w", name, err)
			}
			v = strings.TrimSpace(string(b))
		}
		return v, nil
	}
	id, err1 := read("STACKURITY_GITLAB_CLIENT_ID")
	secret, err2 := read("STACKURITY_GITLAB_CLIENT_SECRET")
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	if id == "" && secret == "" {
		return nil, nil
	}
	if id == "" || secret == "" {
		return nil, errors.New("Connect GitLab needs both STACKURITY_GITLAB_CLIENT_ID and STACKURITY_GITLAB_CLIENT_SECRET (or neither)")
	}
	base, err := ParseBase(os.Getenv("STACKURITY_GITLAB_URL"))
	if err != nil {
		return nil, err
	}
	return &Client{Base: base, ClientID: id, ClientSecret: secret}, nil
}

// ParseBase checks a GitLab address: https, a host, no credentials, query
// or fragment; a path is allowed (GitLab under a relative URL).
func ParseBase(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "https://gitlab.com", nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return "", errors.New("STACKURITY_GITLAB_URL must be your GitLab's https address, such as https://gitlab.example.com")
	}
	return "https://" + strings.ToLower(u.Host) + strings.TrimRight(u.Path, "/"), nil
}

// IsGitLabCom reports whether this is GitLab.com.
func (c *Client) IsGitLabCom() bool { return c.Base == "https://gitlab.com" }

func (c *Client) api(path string) string { return c.Base + "/api/v4" + path }

// AuthorizeURL is GitLab's consent page for scopes; GitLab sends the
// browser back to redirect with a code and the state.
func (c *Client) AuthorizeURL(state, redirect string, scopes []string) string {
	return c.Base + "/oauth/authorize?" + url.Values{"client_id": {c.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"state": {state}, "scope": {strings.Join(scopes, " ")}}.Encode()
}

// --- errors

var (
	// ErrNotFound: GitLab answered 404 (it does not exist, or the token
	// cannot see it).
	ErrNotFound = errors.New("GitLab does not know it, or the token cannot see it")
	// ErrForbidden: GitLab answered 403 (the role or the tier does not
	// allow it).
	ErrForbidden = errors.New("GitLab does not allow it")
	// ErrUnauthorized: the token is not valid (any more).
	ErrUnauthorized = errors.New("GitLab did not accept the token")
	// ErrInvalidGrant: the OAuth code or refresh token is not valid (used,
	// expired or revoked).
	ErrInvalidGrant = errors.New("GitLab did not accept the authorisation")
	// ErrRefused: GitLab answered, but not with what was asked.
	ErrRefused = errors.New("GitLab refused the request")
)

// RateLimited is GitLab's rate limit: try again after Wait.
type RateLimited struct{ Wait time.Duration }

func (e *RateLimited) Error() string {
	return fmt.Sprintf("GitLab's rate limit: try again in %s", e.Wait.Round(time.Second))
}

// APIError is another unexpected answer.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("GitLab answered HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("GitLab answered HTTP %d", e.Status)
}

// --- transport

// defaultClient dials through netguard with the organisation's context.
// Connections are not kept for reuse: netguard checks an address when it is
// dialled, so a connection opened for one organisation must not serve
// another whose policy differs.
var defaultClient = &http.Client{
	Timeout:       20 * time.Second,
	Transport:     &http.Transport{DialContext: netguard.DialContext, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (c *Client) client() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return defaultClient
}

// do sends req and reads at most 4 MiB of the answer. Transport errors are
// shortened (url.Error repeats the address).
func (c *Client) do(req *http.Request) (*http.Response, []byte, error) {
	req.Header.Set("User-Agent", "stackurity-gitlab")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, nil, fmt.Errorf("gitlab: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("gitlab: %w", err)
	}
	return resp, raw, nil
}

// call makes one API request with token (Authorization: Bearer, which
// GitLab accepts for OAuth and access tokens alike). out may be nil.
func (c *Client) call(ctx context.Context, method, rawURL, token string, body, out any) (http.Header, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, raw, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if wait, limited := rateLimit(resp); limited {
		return nil, &RateLimited{Wait: wait}
	}
	switch resp.StatusCode {
	case 401:
		return nil, ErrUnauthorized
	case 403:
		return nil, fmt.Errorf("%w: %s", ErrForbidden, message(raw))
	case 404:
		return nil, ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{Status: resp.StatusCode, Message: message(raw)}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fmt.Errorf("%w: unexpected answer", ErrRefused)
		}
	}
	return resp.Header, nil
}

// message is GitLab's error message, short. GitLab answers {"message":
// "..."} or {"message": {"field": ["..."]}} or {"error": "..."}.
func message(raw []byte) string {
	var m struct {
		Message any    `json:"message"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(raw, &m)
	s := m.Error
	switch v := m.Message.(type) {
	case string:
		s = v
	case map[string]any:
		b, _ := json.Marshal(v)
		s = string(b)
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// rateLimit reads GitLab's 429 (Retry-After, or RateLimit-Reset).
func rateLimit(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != 429 {
		return 0, false
	}
	if s := resp.Header.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return min(max(time.Duration(n)*time.Second, time.Second), time.Hour), true
		}
	}
	if n, err := strconv.ParseInt(resp.Header.Get("RateLimit-Reset"), 10, 64); err == nil {
		return min(max(time.Until(time.Unix(n, 0)), time.Second), time.Hour), true
	}
	return time.Minute, true
}

// --- OAuth

// Token is an OAuth token GitLab issued.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scope        string    `json:"scope"`
	ExpiresAt    time.Time `json:"-"`
}

// HasScopes reports whether the token's scopes are exactly want (in any
// order): a token with more is not kept.
func (t *Token) HasScopes(want []string) bool {
	got := strings.Fields(t.Scope)
	if len(got) != len(want) {
		return false
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			found = found || g == w
		}
		if !found {
			return false
		}
	}
	return true
}

func (c *Client) tokenRequest(ctx context.Context, form url.Values) (*Token, error) {
	form.Set("client_id", c.ClientID)
	form.Set("client_secret", c.ClientSecret)
	req, err := http.NewRequestWithContext(ctx, "POST", c.Base+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, raw, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if wait, limited := rateLimit(resp); limited {
		return nil, &RateLimited{Wait: wait}
	}
	var out struct {
		Token
		ExpiresIn int64  `json:"expires_in"`
		CreatedAt int64  `json:"created_at"`
		Error     string `json:"error"`
	}
	_ = json.Unmarshal(raw, &out)
	if out.Error == "invalid_grant" {
		return nil, ErrInvalidGrant
	}
	if resp.StatusCode != 200 || out.AccessToken == "" {
		reason := out.Error
		if reason == "" {
			reason = "HTTP " + strconv.Itoa(resp.StatusCode)
		}
		return nil, fmt.Errorf("%w: %s", ErrRefused, clip(reason, 100))
	}
	t := out.Token
	if out.ExpiresIn > 0 {
		t.ExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second)
	} else {
		// GitLab's access tokens live two hours; assume no more.
		t.ExpiresAt = time.Now().Add(2 * time.Hour)
	}
	return &t, nil
}

// Exchange trades the code GitLab sent back for a token.
func (c *Client) Exchange(ctx context.Context, code, redirect string) (*Token, error) {
	return c.tokenRequest(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect}})
}

// Refresh trades a refresh token for a new access token and a new refresh
// token: GitLab revokes the old one, so the new one must be stored before
// it is used again.
func (c *Client) Refresh(ctx context.Context, refreshToken, redirect string) (*Token, error) {
	return c.tokenRequest(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "redirect_uri": {redirect}})
}

// Revoke revokes an OAuth token (access or refresh: GitLab revokes the
// grant both belong to).
func (c *Client) Revoke(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	form := url.Values{"client_id": {c.ClientID}, "client_secret": {c.ClientSecret}, "token": {token}}
	req, err := http.NewRequestWithContext(ctx, "POST", c.Base+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _, err := c.do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return &APIError{Status: resp.StatusCode}
	}
	return nil
}

// --- the REST API

// User is the person a token belongs to.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// CurrentUser is GET /user.
func (c *Client) CurrentUser(ctx context.Context, token string) (*User, error) {
	var u User
	if _, err := c.call(ctx, "GET", c.api("/user"), token, nil, &u); err != nil {
		return nil, err
	}
	if u.ID <= 0 {
		return nil, fmt.Errorf("%w: no user", ErrRefused)
	}
	return &u, nil
}

// Group is a GitLab group.
type Group struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	FullPath string `json:"full_path"`
	WebURL   string `json:"web_url"`
}

// Groups lists the groups the token's user is a member of with at least
// minAccess (at most 1,000), following GitLab's pagination.
func (c *Client) Groups(ctx context.Context, token string, minAccess int) ([]Group, error) {
	var all []Group
	next := "1"
	for pages := 0; next != "" && pages < 10; pages++ {
		var out []Group
		u := c.api("/groups?" + url.Values{"min_access_level": {strconv.Itoa(minAccess)}, "per_page": {"100"}, "page": {next},
			"order_by": {"path"}, "sort": {"asc"}}.Encode())
		h, err := c.call(ctx, "GET", u, token, nil, &out)
		if err != nil {
			return nil, err
		}
		for _, g := range out {
			if g.ID > 0 && ValidPath(g.FullPath) {
				all = append(all, g)
			}
		}
		if next, err = nextPage(h); err != nil {
			return nil, err
		}
		if len(out) == 0 {
			break
		}
	}
	return all, nil
}

// nextPage is GitLab's X-Next-Page: "" on the last page.
func nextPage(h http.Header) (string, error) {
	next := h.Get("X-Next-Page")
	if n, err := strconv.Atoi(next); next != "" && (err != nil || n <= 0 || n > 100000) {
		return "", fmt.Errorf("%w: unexpected page %q", ErrRefused, clip(next, 20))
	}
	return next, nil
}

// Group reads a group.
func (c *Client) Group(ctx context.Context, token string, id int64) (*Group, error) {
	var g Group
	if _, err := c.call(ctx, "GET", c.api("/groups/"+strconv.FormatInt(id, 10)+"?with_projects=false"), token, nil, &g); err != nil {
		return nil, err
	}
	if g.ID != id || !ValidPath(g.FullPath) {
		return nil, fmt.Errorf("%w: unexpected group", ErrRefused)
	}
	return &g, nil
}

// MemberAccess is user's access level in a group, inherited membership
// included; 0 when they are not a member.
func (c *Client) MemberAccess(ctx context.Context, token string, groupID, userID int64) (int, error) {
	var m struct {
		ID          int64 `json:"id"`
		AccessLevel int   `json:"access_level"`
		State       string
	}
	_, err := c.call(ctx, "GET", c.api("/groups/"+strconv.FormatInt(groupID, 10)+"/members/all/"+strconv.FormatInt(userID, 10)), token, nil, &m)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if m.ID != userID || m.State != "" && m.State != "active" {
		return 0, nil
	}
	return m.AccessLevel, nil
}

// GroupToken is a group access token Stackurity created.
type GroupToken struct {
	ID        int64    `json:"id"`
	Token     string   `json:"token"`
	Scopes    []string `json:"scopes"`
	Access    int      `json:"access_level"`
	ExpiresAt string   `json:"expires_at"`
}

// CreateGroupToken creates a group access token with ReadScopes and the
// Reporter role, expiring after TokenLifetime. GitLab refuses it
// (ErrForbidden, or ErrNotFound) when the user is not the group's Owner or
// the tier has no group access tokens.
func (c *Client) CreateGroupToken(ctx context.Context, token string, groupID int64, now time.Time) (*GroupToken, time.Time, error) {
	expires := now.Add(TokenLifetime).UTC()
	body := map[string]any{"name": "Stackurity", "scopes": ReadScopes, "access_level": AccessReporter,
		"expires_at": expires.Format("2006-01-02"), "description": "Created by Connect GitLab in Stackurity: reads the group's projects and repositories."}
	var out GroupToken
	if _, err := c.call(ctx, "POST", c.api("/groups/"+strconv.FormatInt(groupID, 10)+"/access_tokens"), token, body, &out); err != nil {
		return nil, time.Time{}, err
	}
	if out.Token == "" || out.ID <= 0 {
		return nil, time.Time{}, fmt.Errorf("%w: no token", ErrRefused)
	}
	// GitLab never grants more than asked; check anyway, so a token with
	// write access is never kept.
	if out.Access > AccessReporter {
		return &out, time.Time{}, fmt.Errorf("%w: the token has access level %d, more than Reporter", ErrRefused, out.Access)
	}
	for _, s := range out.Scopes {
		if s != "read_api" && s != "read_repository" {
			return &out, time.Time{}, fmt.Errorf("%w: the token has the %s scope", ErrRefused, clip(s, 40))
		}
	}
	if t, err := time.Parse("2006-01-02", out.ExpiresAt); err == nil {
		expires = t
	}
	return &out, expires, nil
}

// RevokeGroupToken revokes a group access token (needs an Owner's api
// token). Already gone counts as done.
func (c *Client) RevokeGroupToken(ctx context.Context, token string, groupID, tokenID int64) error {
	_, err := c.call(ctx, "DELETE", c.api("/groups/"+strconv.FormatInt(groupID, 10)+"/access_tokens/"+strconv.FormatInt(tokenID, 10)), token, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// RevokeSelf revokes the access token it is called with (DELETE
// /personal_access_tokens/self, which "any token can use"; a group access
// token is a personal access token of the group's bot user).
func (c *Client) RevokeSelf(ctx context.Context, token string) error {
	_, err := c.call(ctx, "DELETE", c.api("/personal_access_tokens/self"), token, nil, nil)
	if errors.Is(err, ErrUnauthorized) {
		return nil // already revoked or expired
	}
	return err
}

// CreateGroupHook creates a group webhook for push and project events
// (a project created or deleted in the group) with secret as
// its secret token (X-Gitlab-Token). GitLab refuses it (ErrForbidden or
// ErrNotFound) without the group's Owner role or on a tier without group
// webhooks.
func (c *Client) CreateGroupHook(ctx context.Context, token string, groupID int64, hookURL, secret string) (int64, error) {
	body := map[string]any{"url": hookURL, "token": secret, "push_events": true, "project_events": true, "enable_ssl_verification": true,
		"tag_push_events": false, "merge_requests_events": false, "issues_events": false, "note_events": false,
		"pipeline_events": false, "job_events": false, "wiki_page_events": false, "releases_events": false,
		"name": "Stackurity", "description": "Rescans a project in Stackurity when its lockfiles change."}
	var out struct {
		ID int64 `json:"id"`
	}
	if _, err := c.call(ctx, "POST", c.api("/groups/"+strconv.FormatInt(groupID, 10)+"/hooks"), token, body, &out); err != nil {
		return 0, err
	}
	if out.ID <= 0 {
		return 0, fmt.Errorf("%w: no hook", ErrRefused)
	}
	return out.ID, nil
}

// DeleteGroupHook deletes a group webhook. Already gone counts as done.
func (c *Client) DeleteGroupHook(ctx context.Context, token string, groupID, hookID int64) error {
	_, err := c.call(ctx, "DELETE", c.api("/groups/"+strconv.FormatInt(groupID, 10)+"/hooks/"+strconv.FormatInt(hookID, 10)), token, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// Project is a project in a connected group.
type Project struct {
	ID                int64  `json:"id"`
	PathWithNamespace string `json:"path_with_namespace"`
	DefaultBranch     string `json:"default_branch"`
	Archived          bool   `json:"archived"`
	EmptyRepo         bool   `json:"empty_repo"`
}

// Projects lists a group's projects, subgroups included (at most
// MaxProjects), following GitLab's pagination.
func (c *Client) Projects(ctx context.Context, token string, groupID int64) ([]Project, error) {
	var all []Project
	next := "1"
	for next != "" && len(all) < MaxProjects {
		var out []Project
		u := c.api("/groups/" + strconv.FormatInt(groupID, 10) + "/projects?" + url.Values{"include_subgroups": {"true"}, "with_shared": {"false"},
			"per_page": {"100"}, "page": {next}, "order_by": {"id"}, "sort": {"asc"}, "simple": {"true"}}.Encode())
		h, err := c.call(ctx, "GET", u, token, nil, &out)
		if err != nil {
			return nil, err
		}
		all = append(all, out...)
		if next, err = nextPage(h); err != nil {
			return nil, err
		}
		if len(out) == 0 {
			break
		}
	}
	if len(all) > MaxProjects {
		all = all[:MaxProjects]
	}
	return all, nil
}

// --- paths and clone addresses

// segmentRE is one part of a GitLab path: letters, digits, '_', '-' and
// '.', starting with a letter, digit or '_'.
var segmentRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$`)

// ValidPath reports whether p is a GitLab group or project path
// ("group/subgroup/project"): at most 21 parts, none "." or "..", none
// ending in .git or .atom.
func ValidPath(p string) bool {
	if p == "" || len(p) > 255 {
		return false
	}
	parts := strings.Split(p, "/")
	if len(parts) > 21 {
		return false
	}
	for _, s := range parts {
		if !segmentRE.MatchString(s) || strings.HasSuffix(s, ".git") || strings.HasSuffix(s, ".atom") || strings.Contains(s, "..") {
			return false
		}
	}
	return true
}

// InGroup reports whether project path p is inside group path g.
func InGroup(p, g string) bool {
	return ValidPath(p) && ValidPath(g) && len(p) > len(g)+1 && strings.EqualFold(p[:len(g)+1], g+"/")
}

// CloneURL is a project's HTTPS address, built from the configured GitLab
// address and its validated path: the token is never sent to an address
// taken from an API answer or a webhook.
func (c *Client) CloneURL(path string) (string, error) {
	if !ValidPath(path) || !strings.Contains(path, "/") {
		return "", fmt.Errorf("unexpected project path %q", clip(path, 100))
	}
	return c.Base + "/" + path + ".git", nil
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
