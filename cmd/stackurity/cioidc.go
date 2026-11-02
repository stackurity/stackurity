package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/client"
)

// Keyless CI scans: with no STACKURITY_TOKEN, stackurity scan in a CI job
// asks the CI provider for an OpenID Connect ID token and exchanges it for
// a short-lived collector token (POST /api/v1/ci/token), which may report
// only the repository the job runs for.
//
//   - GitHub Actions: the job has `permissions: id-token: write`, which sets
//     ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN; the
//     token is requested with the server's audience (GET /meta ci_audience,
//     or STACKURITY_CI_AUDIENCE).
//   - GitLab CI (or any CI that can put an ID token in a variable): the
//     job's id_tokens: names STACKURITY_ID_TOKEN with the server's audience.
//
// STACKURITY_CI_TRUST chooses the trust when several accept the job.

// errNoCredentials is the error when neither a token nor a CI identity is
// available.
var errNoCredentials = errors.New(`no token: set STACKURITY_TOKEN or --token-file, or run in CI without a stored secret: ` +
	`in GitHub Actions give the job "permissions: id-token: write"; in GitLab CI add "id_tokens: STACKURITY_ID_TOKEN: aud: <server URL>" ` +
	`(an administrator first adds a CI trust for the repository under Settings > Integrations > CI pipeline)`)

// ciIdentity is how this process can prove which CI job it is.
type ciIdentity struct {
	provider string // "GitHub Actions", "STACKURITY_ID_TOKEN"
	// idToken returns the job's ID token for audience.
	idToken func(ctx context.Context, audience string) (string, error)
	// needsAudience: the token is requested with an audience here (GitHub)
	// rather than fixed in the pipeline's configuration (GitLab).
	needsAudience bool
}

// detectCI finds a CI identity in the environment, or explains why none
// can be used.
func detectCI(getenv func(string) string, hc *http.Client) (*ciIdentity, error) {
	if tok := strings.TrimSpace(getenv("STACKURITY_ID_TOKEN")); tok != "" {
		return &ciIdentity{provider: "STACKURITY_ID_TOKEN", idToken: func(context.Context, string) (string, error) { return tok, nil }}, nil
	}
	reqURL, reqTok := getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if reqURL != "" && reqTok != "" {
		return &ciIdentity{provider: "GitHub Actions", needsAudience: true, idToken: func(ctx context.Context, aud string) (string, error) {
			return githubIDToken(ctx, hc, reqURL, reqTok, aud)
		}}, nil
	}
	switch {
	case getenv("GITHUB_ACTIONS") == "true":
		return nil, errors.New(`no token: this GitHub Actions job cannot request an ID token. Give the job "permissions: id-token: write" ` +
			`(and keep "contents: read"), or set STACKURITY_TOKEN from a secret`)
	case getenv("GITLAB_CI") == "true":
		return nil, errors.New(`no token: in GitLab CI add to the job "id_tokens: STACKURITY_ID_TOKEN: aud: <the server's URL>", ` +
			`or set STACKURITY_TOKEN from a masked CI/CD variable`)
	}
	return nil, errNoCredentials
}

// githubIDToken asks the Actions runtime for the job's ID token.
func githubIDToken(ctx context.Context, hc *http.Client, reqURL, reqTok, aud string) (string, error) {
	u, err := url.Parse(reqURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL")
	}
	q := u.Query()
	q.Set("audience", aud)
	u.RawQuery = q.Encode()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+reqTok)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("request the GitHub Actions ID token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", fmt.Errorf("request the GitHub Actions ID token: %d %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil || out.Value == "" {
		return "", errors.New("request the GitHub Actions ID token: the answer has no token")
	}
	return out.Value, nil
}

// ciExchange trades the job's ID token for a collector token on server.
func ciExchange(ctx context.Context, server string, id *ciIdentity, getenv func(string) string) (*client.CIToken, error) {
	anon, err := client.New(server, "", version)
	if err != nil {
		return nil, err
	}
	var trust int64
	if v := strings.TrimSpace(getenv("STACKURITY_CI_TRUST")); v != "" {
		if trust, err = strconv.ParseInt(v, 10, 64); err != nil || trust <= 0 {
			return nil, fmt.Errorf("STACKURITY_CI_TRUST must be a CI trust id, not %q", v)
		}
	}
	aud := strings.TrimSpace(getenv("STACKURITY_CI_AUDIENCE"))
	if id.needsAudience && aud == "" {
		m, err := anon.Meta(ctx)
		if err != nil {
			return nil, fmt.Errorf("ask the server for its CI audience: %w", err)
		}
		if aud = m.CIAudience; aud == "" {
			return nil, fmt.Errorf("the server (version %s) does not exchange CI ID tokens: it is older than keyless CI scans, or STACKURITY_BASE_URL is not set on it; set STACKURITY_TOKEN instead", m.Version)
		}
	}
	idTok, err := id.idToken(ctx, aud)
	if err != nil {
		return nil, err
	}
	out, err := anon.ExchangeCIToken(ctx, idTok, trust)
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			return nil, errors.New("the server is too old to exchange CI ID tokens; upgrade it or set STACKURITY_TOKEN")
		}
		return nil, fmt.Errorf("exchange the %s ID token: %w", id.provider, err)
	}
	return out, nil
}
