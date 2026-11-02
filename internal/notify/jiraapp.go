package notify

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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// Connect Jira: the Stackurity Atlassian app. The operator registers one
// OAuth 2.0 (3LO) app at developer.atlassian.com; an administrator of an
// organisation clicks Connect Jira, approves on Atlassian's consent page and
// picks a site, project, issue type and done status from lists Stackurity
// reads with the grant. Calls then go to
// https://api.atlassian.com/ex/jira/{cloudid}/rest/api/3 with a bearer
// token that is refreshed (and its refresh token rotated) as it expires.
// Jira Data Center and Server have no 3LO: they keep the API-token mode.
// See docs/jira-app.md.

// JiraAppScopes are the scopes Connect Jira asks for: read projects, issue
// types, statuses, priorities, issues and transitions (read:jira-work);
// create, comment on, edit and transition issues (write:jira-work); and a
// refresh token (offline_access).
const JiraAppScopes = "read:jira-work write:jira-work offline_access"

// JiraAuthOAuth is the auth of a Jira channel that uses a connection.
const JiraAuthOAuth = "oauth"

// JiraApp is the app's configuration.
type JiraApp struct {
	ClientID     string
	ClientSecret string
	// Auth is Atlassian's authorisation server (https://auth.atlassian.com)
	// and API its API gateway (https://api.atlassian.com); tests point
	// them at a fake.
	Auth string
	API  string
	// HTTP makes the requests; the server passes the notification
	// sender's, which checks every connection against the network policy
	// (internal/netguard) and never follows redirects.
	HTTP *http.Client
}

// JiraAppFromEnv reads STACKURITY_JIRA_CLIENT_ID (or _FILE) and
// STACKURITY_JIRA_CLIENT_SECRET (or _FILE). With neither the app is off
// (nil); with one only it is a configuration error.
func JiraAppFromEnv() (*JiraApp, error) {
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
	id, err := read("STACKURITY_JIRA_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	secret, err := read("STACKURITY_JIRA_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	switch {
	case id == "" && secret == "":
		return nil, nil
	case id == "" || secret == "":
		return nil, errors.New("Connect Jira needs STACKURITY_JIRA_CLIENT_ID and STACKURITY_JIRA_CLIENT_SECRET together (or neither)")
	}
	return &JiraApp{ClientID: id, ClientSecret: secret}, nil
}

func (a *JiraApp) auth() string {
	if a.Auth != "" {
		return strings.TrimSuffix(a.Auth, "/")
	}
	return "https://auth.atlassian.com"
}

func (a *JiraApp) api() string {
	if a.API != "" {
		return strings.TrimSuffix(a.API, "/")
	}
	return "https://api.atlassian.com"
}

var (
	jiraAppClientOnce sync.Once
	jiraAppClient     *http.Client
)

func (a *JiraApp) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	jiraAppClientOnce.Do(func() { jiraAppClient = NewSender(false).HTTP })
	return jiraAppClient
}

// SiteBase is the REST base of a Jira Cloud site through the API gateway.
func (a *JiraApp) SiteBase(cloudID string) string {
	return a.api() + "/ex/jira/" + url.PathEscape(cloudID)
}

// AuthorizeURL is Atlassian's consent page for one Connect Jira.
func (a *JiraApp) AuthorizeURL(state, redirect string) string {
	q := url.Values{
		"audience":      {"api.atlassian.com"},
		"client_id":     {a.ClientID},
		"scope":         {JiraAppScopes},
		"redirect_uri":  {redirect},
		"state":         {state},
		"response_type": {"code"},
		"prompt":        {"consent"},
	}
	return a.auth() + "/authorize?" + q.Encode()
}

// ErrJiraRefused: Atlassian answered, but not with a usable grant.
var ErrJiraRefused = errors.New("Atlassian did not complete the connection")

// Exchange trades the code Atlassian sent back for tokens.
func (a *JiraApp) Exchange(ctx context.Context, code, redirect string) (store.JiraTokens, string, error) {
	tok, scope, err := a.token(ctx, map[string]string{"grant_type": "authorization_code", "code": code, "redirect_uri": redirect})
	if err != nil {
		return tok, "", err
	}
	if tok.Refresh == "" {
		return tok, "", fmt.Errorf("%w: no refresh token (is offline_access among the app's scopes?)", ErrJiraRefused)
	}
	return tok, scope, nil
}

// Refresh trades a refresh token for new tokens. Atlassian rotates the
// refresh token: the one returned replaces the one used. A refusal of the
// refresh token itself (invalid_grant) wraps store.ErrJiraGrantRevoked.
func (a *JiraApp) Refresh(ctx context.Context, refresh string) (store.JiraTokens, error) {
	tok, _, err := a.token(ctx, map[string]string{"grant_type": "refresh_token", "refresh_token": refresh})
	return tok, err
}

func (a *JiraApp) token(ctx context.Context, body map[string]string) (store.JiraTokens, string, error) {
	body["client_id"], body["client_secret"] = a.ClientID, a.ClientSecret
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, "POST", a.auth()+"/oauth/token", bytes.NewReader(raw))
	if err != nil {
		return store.JiraTokens{}, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return store.JiraTokens{}, "", fmt.Errorf("atlassian token: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return store.JiraTokens{}, "", err
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		Description  string `json:"error_description"`
	}
	_ = json.Unmarshal(data, &out)
	if resp.StatusCode != 200 {
		// Only Atlassian's error code and description: never the body.
		why := clip(strings.TrimSpace(out.Error+": "+out.Description), 200)
		if out.Error == "" {
			why = "no error code"
		}
		err := fmt.Errorf("atlassian token: HTTP %d (%s)", resp.StatusCode, why)
		if out.Error == "invalid_grant" {
			return store.JiraTokens{}, "", fmt.Errorf("%w (%s)", store.ErrJiraGrantRevoked, why)
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return store.JiraTokens{}, "", err
		}
		return store.JiraTokens{}, "", fmt.Errorf("%w: %w", ErrJiraRefused, err)
	}
	if out.AccessToken == "" {
		return store.JiraTokens{}, "", fmt.Errorf("%w: no access token in the answer", ErrJiraRefused)
	}
	exp := time.Duration(out.ExpiresIn) * time.Second
	if exp <= 0 || exp > 24*time.Hour {
		exp = time.Hour
	}
	return store.JiraTokens{Access: out.AccessToken, Refresh: out.RefreshToken, ExpiresAt: time.Now().Add(exp)}, clip(out.Scope, 1000), nil
}

var jiraCloudIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// AccessibleSites lists the Jira sites the grant reaches (Atlassian's
// accessible-resources), leaving out other products' and anything that
// does not look like a site.
func (a *JiraApp) AccessibleSites(ctx context.Context, access string) ([]store.JiraSite, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", a.api()+"/oauth/token/accessible-resources", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+access)
	req.Header.Set("Accept", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("atlassian accessible-resources: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("atlassian accessible-resources: HTTP %d", resp.StatusCode)
	}
	var list []struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		URL    string   `json:"url"`
		Scopes []string `json:"scopes"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&list); err != nil {
		return nil, fmt.Errorf("atlassian accessible-resources: %w", err)
	}
	out := []store.JiraSite{}
	for _, r := range list {
		jira := slices.ContainsFunc(r.Scopes, func(s string) bool { return strings.Contains(s, "jira") })
		u, err := url.Parse(r.URL)
		if !jira || !jiraCloudIDRe.MatchString(r.ID) || err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			continue
		}
		if slices.ContainsFunc(out, func(s store.JiraSite) bool { return s.ID == r.ID }) {
			continue
		}
		out = append(out, store.JiraSite{ID: r.ID, Name: clip(r.Name, 200), URL: "https://" + u.Host})
		if len(out) == 50 {
			break
		}
	}
	return out, nil
}
