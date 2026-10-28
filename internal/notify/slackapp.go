package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// The Stackurity Slack app ("Add to Slack"). One Slack app, configured on
// the server, is installed into each organisation's Slack workspace with
// Slack's OAuth v2 flow: the person picks a channel on Slack's consent page
// (the incoming-webhook scope), and Stackurity gets that channel's webhook
// and a bot token. The app's signing secret verifies interactivity (Assign
// to me, Snooze) and events (uninstalled, tokens revoked) for every
// organisation; the team id of the install ties a Slack workspace to the
// organisations that added it. See docs/slack-app.md.

// SlackAppScopes are the scopes the app asks for: a channel's incoming
// webhook. Interactivity and the uninstall events need no scope.
const SlackAppScopes = "incoming-webhook"

// SlackApp is the app's configuration.
type SlackApp struct {
	ClientID      string
	ClientSecret  string
	SigningSecret string
	// API is Slack's Web API (https://slack.com/api); tests point it at a
	// fake. Authorize is the consent page.
	API       string
	Authorize string
	HTTP      *http.Client
}

// SlackAppFromEnv reads STACKURITY_SLACK_CLIENT_ID (or _FILE),
// STACKURITY_SLACK_CLIENT_SECRET (or _FILE) and
// STACKURITY_SLACK_SIGNING_SECRET (or _FILE). With none the app is off
// (nil); with some but not all it is a configuration error.
func SlackAppFromEnv() (*SlackApp, error) {
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
	id, err := read("STACKURITY_SLACK_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	secret, err := read("STACKURITY_SLACK_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	signing, err := read("STACKURITY_SLACK_SIGNING_SECRET")
	if err != nil {
		return nil, err
	}
	switch n := btoi(id != "") + btoi(secret != "") + btoi(signing != ""); n {
	case 0:
		return nil, nil
	case 3:
	default:
		return nil, errors.New("the Slack app needs STACKURITY_SLACK_CLIENT_ID, STACKURITY_SLACK_CLIENT_SECRET and STACKURITY_SLACK_SIGNING_SECRET together (or none of them)")
	}
	return &SlackApp{ClientID: id, ClientSecret: secret, SigningSecret: signing}, nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (a *SlackApp) api() string {
	if a.API != "" {
		return strings.TrimSuffix(a.API, "/")
	}
	return "https://slack.com/api"
}

func (a *SlackApp) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// AuthorizeURL is Slack's consent page for one install.
func (a *SlackApp) AuthorizeURL(state, redirect string) string {
	base := a.Authorize
	if base == "" {
		base = "https://slack.com/oauth/v2/authorize"
	}
	q := url.Values{"client_id": {a.ClientID}, "scope": {SlackAppScopes}, "redirect_uri": {redirect}}
	// Without a state (the Direct install URL, signed out) Slack's consent
	// page still works; the callback then starts a proper install.
	if state != "" {
		q.Set("state", state)
	}
	return base + "?" + q.Encode()
}

// SlackInstall is what an install returns (oauth.v2.access).
type SlackInstall struct {
	AppID       string `json:"app_id"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
	BotUserID   string `json:"bot_user_id"`
	Team        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"team"`
	Enterprise *struct {
		ID string `json:"id"`
	} `json:"enterprise"`
	IncomingWebhook struct {
		Channel          string `json:"channel"`
		ChannelID        string `json:"channel_id"`
		ConfigurationURL string `json:"configuration_url"`
		URL              string `json:"url"`
	} `json:"incoming_webhook"`
}

var slackTeamRE = regexp.MustCompile(`^T[A-Z0-9]{1,31}$`)

// ErrSlackRefused: Slack answered, but not with a usable install.
var ErrSlackRefused = errors.New("Slack did not complete the install")

// Exchange trades the code Slack sent back for the install.
func (a *SlackApp) Exchange(ctx context.Context, code, redirect string) (*SlackInstall, error) {
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		SlackInstall
	}
	form := url.Values{"code": {code}, "redirect_uri": {redirect}}
	if err := a.call(ctx, "oauth.v2.access", form, true, &out); err != nil {
		return nil, err
	}
	if !out.OK {
		return nil, fmt.Errorf("%w: %s", ErrSlackRefused, out.Error)
	}
	in := out.SlackInstall
	hook := in.IncomingWebhook.URL
	if !slackTeamRE.MatchString(in.Team.ID) || hook == "" {
		return nil, fmt.Errorf("%w: no channel webhook in the answer", ErrSlackRefused)
	}
	if u, err := url.Parse(hook); err != nil || u.Scheme != "https" || (u.Host != "hooks.slack.com" && u.Host != "hooks.slack-gov.com") {
		return nil, fmt.Errorf("%w: unexpected webhook address", ErrSlackRefused)
	}
	return &in, nil
}

// Uninstall removes the app from a Slack workspace (apps.uninstall), when
// no organisation uses it there any more.
func (a *SlackApp) Uninstall(ctx context.Context, token string) error {
	var out struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	form := url.Values{"client_id": {a.ClientID}, "client_secret": {a.ClientSecret}}
	if err := a.callToken(ctx, "apps.uninstall", form, token, &out); err != nil {
		return err
	}
	if !out.OK && out.Error != "invalid_auth" && out.Error != "account_inactive" && out.Error != "token_revoked" {
		return fmt.Errorf("slack apps.uninstall: %s", out.Error)
	}
	return nil
}

func (a *SlackApp) call(ctx context.Context, method string, form url.Values, basic bool, out any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", a.api()+"/"+method, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(a.ClientID, a.ClientSecret)
	}
	return a.do(req, out)
}

func (a *SlackApp) callToken(ctx context.Context, method string, form url.Values, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, "POST", a.api()+"/"+method, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	return a.do(req, out)
}

func (a *SlackApp) do(req *http.Request, out any) error {
	resp, err := a.client().Do(req)
	if err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("slack: HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}
