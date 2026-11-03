// Package githubapp is the Stackurity GitHub App ("Install on GitHub"). One
// GitHub App, configured on the server, is installed by each customer on
// their GitHub account or organisation, where they pick the repositories on
// GitHub's own screen. Stackurity then clones each granted repository with a
// short-lived installation token, scoped to that one repository and to
// contents:read, minted for the scan and never stored. See
// docs/github-app.md.
//
// The app's private key signs a JWT (RS256) that authenticates the app
// itself; its webhook secret verifies GitHub's deliveries; its OAuth client
// proves, at install time, that the person who comes back from GitHub can
// see the installation they claim (the installation_id in the redirect is
// not trusted on its own: anyone can type another number into it).
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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

// Permissions the app asks for, and the only ones its tokens carry.
const (
	PermContents = "read"
	PermMetadata = "read"
)

// MaxRepositories bounds how many repositories of one installation are
// read (GitHub lists 100 per page).
const MaxRepositories = 5000

// App is the GitHub App's configuration.
type App struct {
	ID            int64
	ClientID      string
	ClientSecret  string
	Slug          string
	WebhookSecret string
	Key           *rsa.PrivateKey
	// Web is GitHub's site (https://github.com, or a GitHub Enterprise
	// Server's address): the install page, OAuth and clones. API is its
	// REST API (https://api.github.com, or <server>/api/v3).
	Web string
	API string
	// HTTP makes the API calls; tests point it at a fake. The default
	// dials through netguard and follows no redirects.
	HTTP *http.Client
	// Now is the clock for the app's JWT; time.Now when nil.
	Now func() time.Time
}

// FromEnv reads the app from STACKURITY_GITHUB_APP_ID,
// STACKURITY_GITHUB_APP_SLUG, STACKURITY_GITHUB_APP_CLIENT_ID,
// STACKURITY_GITHUB_APP_CLIENT_SECRET, STACKURITY_GITHUB_APP_PRIVATE_KEY and
// STACKURITY_GITHUB_APP_WEBHOOK_SECRET (each also as _FILE, a file holding
// it), and the optional STACKURITY_GITHUB_URL (a GitHub Enterprise Server).
// With none the app is off (nil); with some but not all it is a
// configuration error.
func FromEnv() (*App, error) {
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
	names := []string{"STACKURITY_GITHUB_APP_ID", "STACKURITY_GITHUB_APP_SLUG", "STACKURITY_GITHUB_APP_CLIENT_ID",
		"STACKURITY_GITHUB_APP_CLIENT_SECRET", "STACKURITY_GITHUB_APP_PRIVATE_KEY", "STACKURITY_GITHUB_APP_WEBHOOK_SECRET"}
	vals := make([]string, len(names))
	var errs []error
	for i, v := range []func() (string, error){
		func() (string, error) { return read("STACKURITY_GITHUB_APP_ID") },
		func() (string, error) { return read("STACKURITY_GITHUB_APP_SLUG") },
		func() (string, error) { return read("STACKURITY_GITHUB_APP_CLIENT_ID") },
		func() (string, error) { return read("STACKURITY_GITHUB_APP_CLIENT_SECRET") },
		func() (string, error) { return read("STACKURITY_GITHUB_APP_PRIVATE_KEY") },
		func() (string, error) { return read("STACKURITY_GITHUB_APP_WEBHOOK_SECRET") },
	} {
		var err error
		vals[i], err = v()
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	set := 0
	for _, v := range vals {
		if v != "" {
			set++
		}
	}
	if set == 0 {
		return nil, nil
	}
	if set != len(names) {
		var missing []string
		for i, n := range names {
			if vals[i] == "" {
				missing = append(missing, n)
			}
		}
		return nil, fmt.Errorf("the GitHub App needs all of %s (or none of them); missing %s",
			strings.Join(names, ", "), strings.Join(missing, ", "))
	}
	id, err := strconv.ParseInt(vals[0], 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("STACKURITY_GITHUB_APP_ID must be the app's numeric ID")
	}
	if !slugRE.MatchString(vals[1]) {
		return nil, errors.New("STACKURITY_GITHUB_APP_SLUG must be the app's slug, as in github.com/apps/<slug>")
	}
	key, err := ParsePrivateKey([]byte(vals[4]))
	if err != nil {
		return nil, fmt.Errorf("STACKURITY_GITHUB_APP_PRIVATE_KEY: %w", err)
	}
	a := &App{ID: id, Slug: vals[1], ClientID: vals[2], ClientSecret: vals[3], Key: key, WebhookSecret: vals[5],
		Web: "https://github.com", API: "https://api.github.com"}
	if ghes := strings.TrimSpace(os.Getenv("STACKURITY_GITHUB_URL")); ghes != "" {
		u, err := url.Parse(ghes)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" {
			return nil, errors.New("STACKURITY_GITHUB_URL must be your GitHub Enterprise Server's https address, such as https://github.example.com")
		}
		a.Web = "https://" + u.Host
		a.API = a.Web + "/api/v3"
	}
	return a, nil
}

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,99}$`)

// ParsePrivateKey reads the app's private key, the PEM file GitHub gives
// (PKCS#1, or PKCS#8).
func ParsePrivateKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("not a PEM private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("not an RSA private key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return rk, nil
}

// IsGHES reports whether the app is on a GitHub Enterprise Server.
func (a *App) IsGHES() bool { return a.Web != "" && a.Web != "https://github.com" }

// InstallURL is GitHub's page where the person picks the account and the
// repositories; GitHub sends them back to the app's callback URL with the
// state, a code and the installation.
func (a *App) InstallURL(state string) string {
	path := "/apps/"
	if a.IsGHES() {
		path = "/github-apps/"
	}
	u := strings.TrimSuffix(a.Web, "/") + path + url.PathEscape(a.Slug) + "/installations/new"
	if state != "" {
		u += "?" + url.Values{"state": {state}}.Encode()
	}
	return u
}

// VerifySignature checks GitHub's X-Hub-Signature-256 over the exact body,
// in constant time.
func (a *App) VerifySignature(body []byte, header string) bool {
	if a.WebhookSecret == "" || !strings.HasPrefix(header, "sha256=") {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil || len(got) != sha256.Size {
		return false
	}
	return hmac.Equal(got, Sign(a.WebhookSecret, body))
}

// Sign is the HMAC-SHA256 GitHub sends (hex-encoded after "sha256=").
func Sign(secret string, body []byte) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write(body)
	return m.Sum(nil)
}

// JWT is the app's own credential: RS256, issued a minute in the past for
// clock drift, valid 9 minutes (GitHub allows at most 10).
func (a *App) JWT() (string, error) {
	if a.Key == nil {
		return "", errors.New("the GitHub App has no private key")
	}
	now := time.Now()
	if a.Now != nil {
		now = a.Now()
	}
	enc := base64.RawURLEncoding
	head, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iat": now.Add(-60 * time.Second).Unix(), "exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(a.ID, 10)})
	signing := enc.EncodeToString(head) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// fullNameRE is "owner/repository" as GitHub allows them.
var fullNameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$`)

// ValidFullName reports whether name is a repository's "owner/name".
func ValidFullName(name string) bool {
	if !fullNameRE.MatchString(name) {
		return false
	}
	repo := name[strings.IndexByte(name, '/')+1:]
	return repo != "." && repo != ".."
}

// CloneURL is the HTTPS address of a repository, built from the app's own
// GitHub address and the repository's name: the token is never sent to an
// address taken from an API answer or a webhook.
func (a *App) CloneURL(fullName string) (string, error) {
	if !ValidFullName(fullName) {
		return "", fmt.Errorf("unexpected repository name %q", fullName)
	}
	return strings.TrimSuffix(a.Web, "/") + "/" + fullName + ".git", nil
}

// --- the REST API

// Installation is what GitHub says about an installation of the app.
type Installation struct {
	ID      int64 `json:"id"`
	AppID   int64 `json:"app_id"`
	Account struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Type  string `json:"type"`
	} `json:"account"`
	TargetType          string     `json:"target_type"`
	RepositorySelection string     `json:"repository_selection"`
	SuspendedAt         *time.Time `json:"suspended_at"`
}

// Repository is a repository an installation grants.
type Repository struct {
	ID            int64  `json:"id"`
	FullName      string `json:"full_name"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Archived      bool   `json:"archived"`
}

var (
	// ErrNotFound: GitHub does not know the installation (or it is not
	// this app's).
	ErrNotFound = errors.New("GitHub does not know this installation of the app")
	// ErrRefused: GitHub answered, but not with what was asked.
	ErrRefused = errors.New("GitHub refused the request")
)

// RateLimited is GitHub's rate limit: try again after Wait.
type RateLimited struct{ Wait time.Duration }

func (e *RateLimited) Error() string {
	return fmt.Sprintf("GitHub's rate limit: try again in %s", e.Wait.Round(time.Second))
}

// APIError is an unexpected answer from GitHub.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("GitHub answered HTTP %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("GitHub answered HTTP %d", e.Status)
}

// defaultClient dials through netguard with the organisation's context.
// Connections are not kept for reuse: netguard checks an address when it is
// dialled, so a connection opened for one organisation must not serve
// another whose policy differs. The app makes a few requests per scan.
var defaultClient = &http.Client{
	Timeout:       20 * time.Second,
	Transport:     &http.Transport{DialContext: netguard.DialContext, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func (a *App) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return defaultClient
}

// call makes one request. auth is the Authorization header's value.
func (a *App) call(ctx context.Context, method, rawURL, auth string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "stackurity-github-app")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := a.client().Do(req)
	if err != nil {
		// url.Error repeats the address; addresses carry no credential
		// here, but keep the message short.
		var ue *url.Error
		if errors.As(err, &ue) {
			return fmt.Errorf("github: %w", ue.Err)
		}
		return fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if wait, limited := rateLimit(resp); limited {
		return &RateLimited{Wait: wait}
	}
	if resp.StatusCode == 404 {
		return ErrNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var m struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &m)
		msg := m.Message
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: unexpected answer", ErrRefused)
	}
	return nil
}

// rateLimit reads GitHub's rate-limit answer (403 or 429 with Retry-After
// or no requests remaining).
func rateLimit(resp *http.Response) (time.Duration, bool) {
	if resp.StatusCode != 403 && resp.StatusCode != 429 {
		return 0, false
	}
	if s := resp.Header.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			return min(time.Duration(n)*time.Second, time.Hour), true
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") == "0" {
		if n, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
			wait := time.Until(time.Unix(n, 0))
			return min(max(wait, time.Second), time.Hour), true
		}
		return time.Minute, true
	}
	if resp.StatusCode == 429 {
		return time.Minute, true
	}
	return 0, false
}

func (a *App) api(path string) string { return strings.TrimSuffix(a.API, "/") + path }

func (a *App) bearerJWT() (string, error) {
	j, err := a.JWT()
	if err != nil {
		return "", err
	}
	return "Bearer " + j, nil
}

// Installation reads an installation with the app's JWT. ErrNotFound when
// it does not exist or is not this app's.
func (a *App) Installation(ctx context.Context, id int64) (*Installation, error) {
	if id <= 0 {
		return nil, ErrNotFound
	}
	auth, err := a.bearerJWT()
	if err != nil {
		return nil, err
	}
	var in Installation
	if err := a.call(ctx, "GET", a.api("/app/installations/"+strconv.FormatInt(id, 10)), auth, nil, &in); err != nil {
		return nil, err
	}
	if in.ID != id || in.AppID != a.ID {
		return nil, ErrNotFound
	}
	return &in, nil
}

// DeleteInstallation uninstalls the app from that account (Disconnect in
// Stackurity: the app keeps no access it no longer needs).
func (a *App) DeleteInstallation(ctx context.Context, id int64) error {
	auth, err := a.bearerJWT()
	if err != nil {
		return err
	}
	err = a.call(ctx, "DELETE", a.api("/app/installations/"+strconv.FormatInt(id, 10)), auth, nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// Token mints an installation token for the given repositories (all the
// installation grants when none), with only perms (contents:read,
// metadata:read when nil). It lives an hour at GitHub; the caller uses it
// at once and never stores it.
func (a *App) Token(ctx context.Context, installation int64, repoIDs []int64, perms map[string]string) (string, error) {
	auth, err := a.bearerJWT()
	if err != nil {
		return "", err
	}
	if perms == nil {
		perms = map[string]string{"contents": PermContents, "metadata": PermMetadata}
	}
	body := map[string]any{"permissions": perms}
	if len(repoIDs) > 0 {
		body["repository_ids"] = repoIDs
	}
	var out struct {
		Token       string            `json:"token"`
		Permissions map[string]string `json:"permissions"`
	}
	if err := a.call(ctx, "POST", a.api("/app/installations/"+strconv.FormatInt(installation, 10)+"/access_tokens"), auth, body, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("%w: no token", ErrRefused)
	}
	// GitHub never grants more than asked; check anyway, so a token with
	// write access is never used.
	for k, v := range out.Permissions {
		if v != "read" {
			return "", fmt.Errorf("%w: the token has %s:%s, more than read access", ErrRefused, k, v)
		}
	}
	return out.Token, nil
}

// Repositories lists what an installation grants, with an installation
// token (at most MaxRepositories).
func (a *App) Repositories(ctx context.Context, token string) ([]Repository, error) {
	var all []Repository
	for page := 1; ; page++ {
		var out struct {
			TotalCount   int          `json:"total_count"`
			Repositories []Repository `json:"repositories"`
		}
		u := a.api("/installation/repositories?" + url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}.Encode())
		if err := a.call(ctx, "GET", u, "token "+token, nil, &out); err != nil {
			return nil, err
		}
		all = append(all, out.Repositories...)
		if len(out.Repositories) < 100 || len(all) >= out.TotalCount || len(all) >= MaxRepositories {
			break
		}
	}
	if len(all) > MaxRepositories {
		all = all[:MaxRepositories]
	}
	return all, nil
}

// ExchangeCode trades the OAuth code GitHub sent back with the install for
// the person's user token. The token is used once, to check which
// installations they can see, and then revoked.
func (a *App) ExchangeCode(ctx context.Context, code string) (string, error) {
	form := url.Values{"client_id": {a.ClientID}, "client_secret": {a.ClientSecret}, "code": {code}}
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimSuffix(a.Web, "/")+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity-github-app")
	resp, err := a.client().Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return "", fmt.Errorf("github: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(raw, &out) != nil || out.AccessToken == "" {
		reason := out.Error
		if reason == "" {
			reason = "HTTP " + strconv.Itoa(resp.StatusCode)
		}
		if len(reason) > 100 {
			reason = reason[:100]
		}
		return "", fmt.Errorf("%w: %s", ErrRefused, reason)
	}
	return out.AccessToken, nil
}

// UserCanSee reports whether the person whose user token this is can see
// installation id of this app on GitHub (GET /user/installations lists the
// app's installations they have access to).
func (a *App) UserCanSee(ctx context.Context, userToken string, id int64) (bool, error) {
	seen := 0
	for page := 1; page <= 50; page++ {
		var out struct {
			TotalCount    int            `json:"total_count"`
			Installations []Installation `json:"installations"`
		}
		u := a.api("/user/installations?" + url.Values{"per_page": {"100"}, "page": {strconv.Itoa(page)}}.Encode())
		if err := a.call(ctx, "GET", u, "Bearer "+userToken, nil, &out); err != nil {
			return false, err
		}
		for _, in := range out.Installations {
			if in.ID == id && in.AppID == a.ID {
				return true, nil
			}
		}
		seen += len(out.Installations)
		if len(out.Installations) < 100 || seen >= out.TotalCount {
			break
		}
	}
	return false, nil
}

// RevokeUserToken revokes a user token (DELETE /applications/{client_id}/token).
func (a *App) RevokeUserToken(ctx context.Context, token string) error {
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(a.ClientID+":"+a.ClientSecret))
	err := a.call(ctx, "DELETE", a.api("/applications/"+url.PathEscape(a.ClientID)+"/token"), auth, map[string]string{"access_token": token}, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
