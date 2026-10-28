package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The Stackurity Slack app ("Add to Slack", notify_setup.go): OAuth state,
// installs, interactivity verified with the app's signing secret, uninstall
// events and token storage.

const (
	appSigning  = "app-signing-secret-1f2e"
	appBotToken = "xoxb-app-bot-token-9a8b7c"
	appHookURL  = "https://hooks.slack.com/services/T0APP/B0HOOK/s3cr3tPath"
)

// fakeSlack answers oauth.v2.access and apps.uninstall like Slack's Web API.
type fakeSlack struct {
	mu          sync.Mutex
	uninstalled []string
	codes       int
}

func (f *fakeSlack) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = r.ParseForm()
	switch r.URL.Path {
	case "/oauth.v2.access":
		id, secret, ok := r.BasicAuth()
		code := r.PostForm.Get("code")
		if !ok || id != "client-1" || secret != "client-secret-1" || code != "good-code" && code != "ops-code" ||
			r.PostForm.Get("redirect_uri") != "https://stk.example/integrations/slack/oauth/callback" {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "invalid_code"})
			return
		}
		f.codes++
		channel, channelID, hook := "#security", "C0SEC", appHookURL
		if code == "ops-code" {
			channel, channelID, hook = "#ops", "C0OPS", "https://hooks.slack.com/services/T0APP/B0OPS/opsPath"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "app_id": "A0APP", "access_token": appBotToken, "token_type": "bot",
			"scope": "incoming-webhook", "bot_user_id": "U0BOT", "team": map[string]string{"id": "T0APP", "name": "Acme"},
			"incoming_webhook": map[string]string{"channel": channel, "channel_id": channelID, "configuration_url": "https://acme.slack.com/services/B0HOOK",
				"url": hook}})
	case "/apps.uninstall":
		if r.Header.Get("Authorization") == "Bearer "+appBotToken && r.PostForm.Get("client_id") == "client-1" {
			f.uninstalled = append(f.uninstalled, appBotToken)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
	default:
		http.NotFound(w, r)
	}
}

type slackAppFx struct {
	e     *env
	slack *fakeSlack
}

func slackAppSetup(t *testing.T) *slackAppFx {
	t.Helper()
	fake := &fakeSlack{}
	ss := httptest.NewServer(fake)
	t.Cleanup(ss.Close)
	box, err := secrets.NewBox(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var st *store.Store
	e := newEnvWith(t, func(s *api.Server) {
		st = s.Store
		res := secrets.Resolver{Stored: func(ctx context.Context, name string) (string, error) { return st.SecretValue(ctx, box, name) }}
		s.SecretBox, s.Secrets, s.BaseURL = box, res, "https://stk.example"
		s.Dispatcher = &notify.Dispatcher{Store: s.Store, Sender: notify.NewSender(false), Secrets: res, BaseURL: "https://stk.example",
			Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
			SlackApp: &notify.SlackApp{ClientID: "client-1", ClientSecret: "client-secret-1", SigningSecret: appSigning, API: ss.URL}}
		s.SlackRespond = func(context.Context, string, []byte) error { return nil }
	})
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("other-admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	return &slackAppFx{e: e, slack: fake}
}

// start begins Add to Slack as s and returns the state Slack would send back.
func (f *slackAppFx) start(t *testing.T, s *session) string {
	t.Helper()
	var out struct{ URL string }
	if code := s.do("POST", "/api/v1/integrations/slack/install", map[string]string{"return_to": "/settings/integrations"}, &out); code != 200 {
		t.Fatalf("install: %d", code)
	}
	u, err := url.Parse(out.URL)
	if err != nil || u.Host != "slack.com" || u.Path != "/oauth/v2/authorize" {
		t.Fatalf("authorize url %q", out.URL)
	}
	q := u.Query()
	if q.Get("client_id") != "client-1" || q.Get("scope") != "incoming-webhook" ||
		q.Get("redirect_uri") != "https://stk.example/integrations/slack/oauth/callback" || len(q.Get("state")) < 40 {
		t.Fatalf("authorize query %v", q)
	}
	return q.Get("state")
}

type installAnswer struct {
	Channel      store.Channel `json:"channel"`
	ReturnTo     string        `json:"return_to"`
	SlackChannel string        `json:"slack_channel"`
	TeamName     string        `json:"team_name"`
}

func TestSlackAppOAuthState(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	admin, other := e.login("admin@x.io"), e.login("other-admin@x.io")

	// Only admins start an install.
	if code := e.login("viewer@x.io").do("POST", "/api/v1/integrations/slack/install", map[string]string{}, nil); code != 403 {
		t.Errorf("viewer install: %d", code)
	}
	state := f.start(t, admin)

	// The state is bound to the person who started it: another admin of the
	// same organisation cannot use it (and that does not use it up).
	if code := other.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 400 {
		t.Errorf("another person's state: %d", code)
	}
	// A guessed state is refused, without calling Slack.
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": "guessed"}, nil); code != 400 {
		t.Errorf("guessed state: %d", code)
	}
	// Another organisation's admin cannot use it either.
	ctx := context.Background()
	if _, _, err := e.st.CreateWorkspace(ctx, "Beta", "", "beta@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	if code := e.login("beta@x.io").do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 400 {
		t.Errorf("another organisation's state: %d", code)
	}
	if f.slack.codes != 0 {
		t.Fatalf("Slack was asked %d times for refused states", f.slack.codes)
	}

	// The person who started it finishes it once.
	var got installAnswer
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, &got); code != 201 {
		t.Fatalf("finish: %d", code)
	}
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(got.Channel.Config, &cfg)
	if got.Channel.Kind != "slack" || !cfg.SlackApp || cfg.TeamID != "T0APP" || cfg.SlackChannel != "#security" || got.ReturnTo != "/settings/integrations" ||
		got.Channel.SecretRef != "secret:slack-app-channel-"+itoa(got.Channel.ID) || cfg.SlackChannelID != "C0SEC" || got.Channel.Name != "Slack #security (Acme)" {
		t.Fatalf("install = %+v %+v", got, cfg)
	}
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 400 {
		t.Errorf("a state worked twice: %d", code)
	}
	// An expired state is refused.
	late := f.start(t, admin)
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE slack_oauth_states SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": late}, nil); code != 400 {
		t.Errorf("expired state: %d", code)
	}
	// A code Slack refuses is a 502, and creates nothing.
	bad := f.start(t, admin)
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "wrong", "state": bad}, nil); code != 502 {
		t.Errorf("refused code: %d", code)
	}
	// A return path to another site is not kept.
	var out struct{ URL string }
	admin.do("POST", "/api/v1/integrations/slack/install", map[string]string{"return_to": "//evil.example/x"}, &out)
	u, _ := url.Parse(out.URL)
	var back installAnswer
	// (The same Slack channel again: the integration is reused.)
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": u.Query().Get("state")}, &back); code != 200 ||
		back.ReturnTo != "/settings/integrations" || back.Channel.ID != got.Channel.ID {
		t.Errorf("return_to = %q (%d)", back.ReturnTo, code)
	}
	// App channels are made only by the install, and keep their webhook.
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "slack", "name": "fake", "secret_ref": "secret:X",
		"config": map[string]any{"slack_app": true, "team_id": "T0APP"}}, nil); code != 400 {
		t.Errorf("hand-made app channel: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/channels/"+itoa(got.Channel.ID), map[string]any{"secret_ref": "secret:OTHER"}, nil); code != 400 {
		t.Errorf("changing an app channel's webhook: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/channels/"+itoa(got.Channel.ID), map[string]any{"name": "security alerts"}, nil); code != 200 {
		t.Errorf("renaming an app channel: %d", code)
	}
}

// Tokens and webhooks are stored sealed, never in clear.
func TestSlackAppTokenEncryption(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	admin := e.login("admin@x.io")
	state := f.start(t, admin)
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 201 {
		t.Fatalf("finish: %d", code)
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var sealedToken, sealedHook []byte
	if err := e.st.Pool.QueryRow(ctx, `SELECT bot_token FROM slack_installations WHERE team_id = 'T0APP'`).Scan(&sealedToken); err != nil {
		t.Fatal(err)
	}
	if err := e.st.Pool.QueryRow(ctx, `SELECT sealed FROM workspace_secrets WHERE name LIKE 'slack-app-channel-%'`).Scan(&sealedHook); err != nil {
		t.Fatal(err)
	}
	if len(sealedToken) == 0 || bytes.Contains(sealedToken, []byte(appBotToken)) || bytes.Contains(sealedToken, []byte("xoxb")) {
		t.Error("the bot token is stored in clear")
	}
	if bytes.Contains(sealedHook, []byte("s3cr3tPath")) {
		t.Error("the webhook is stored in clear")
	}
	var dump string
	if err := e.st.Pool.QueryRow(ctx, `SELECT string_agg(config::text || secret_ref, ' ') FROM channels`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, "s3cr3tPath") || strings.Contains(dump, appBotToken) {
		t.Error("a credential is in the channel row")
	}
	if tok, err := e.st.SlackBotToken(ctx, e.api.SecretBox, "T0APP"); err != nil || tok != appBotToken {
		t.Errorf("token opens to %q (%v)", tok, err)
	}
	// Sealed for this organisation: another workspace id does not open it.
	if _, err := e.api.SecretBox.Open(tenant.DefaultWorkspace+1, "slack-app-bot:T0APP", sealedToken); err == nil {
		t.Error("the token opens for another workspace")
	}
}

// Clicks on an app channel are verified with the app's signing secret and
// accepted only from the Slack workspace the app was installed into.
func TestSlackAppWrongTeam(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	admin := e.login("admin@x.io")
	state := f.start(t, admin)
	var got installAnswer
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, &got); code != 201 {
		t.Fatalf("finish: %d", code)
	}
	sf := &slackFx{e: e, answers: make(chan slackAnswer, 8), secret: appSigning}
	ch := got.Channel.ID
	if code, _ := sf.send(t, click{channel: ch, kind: "open", fix: "1:x", team: "T0OTHER", user: "U1"}); code != 401 {
		t.Errorf("click from another Slack workspace: %d", code)
	}
	if code, _ := sf.send(t, click{channel: ch, kind: "open", fix: "1:x", team: "T0APP", user: "U1", secret: "not-the-app-secret"}); code != 401 {
		t.Errorf("click with another secret: %d", code)
	}
	if code, _ := sf.send(t, click{channel: ch, kind: "open", fix: "1:x", team: "T0APP", user: "U1"}); code != 200 {
		t.Errorf("click from the install's workspace: %d", code)
	}
	// Slack Connect: a person of the install's workspace in a channel
	// shared from another; someone of the other workspace is refused.
	if code, _ := sf.send(t, click{channel: ch, kind: "open", fix: "1:x", team: "T0SHARED", userTeam: "T0APP", user: "U2"}); code != 200 {
		t.Errorf("Slack Connect click by the install's person: %d", code)
	}
	if code, _ := sf.send(t, click{channel: ch, kind: "open", fix: "1:x", team: "T0SHARED", userTeam: "T0SHARED", user: "U3"}); code != 401 {
		t.Errorf("Slack Connect click by another workspace's person: %d", code)
	}
	// A channel with its own signing secret is not verified with the app's.
	t.Setenv("STACKURITY_SECRET_SLACK_SIGNING", "own-secret")
	t.Setenv("STACKURITY_SECRET_SLACK_HOOK", "https://hooks.slack.com/services/T0APP/B02/xyz")
	own := slackChannel(t, e, tenant.DefaultWorkspace, "own-app", `{"signing_secret_ref":"env:STACKURITY_SECRET_SLACK_SIGNING"}`)
	if code, _ := sf.send(t, click{channel: own, kind: "open", fix: "1:x", team: "T0APP", user: "U1"}); code != 401 {
		t.Errorf("app secret on a channel with its own: %d", code)
	}
}

func signedEvent(t *testing.T, e *env, secret string, body any, ts time.Time) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	stamp := fmt.Sprint(ts.Unix())
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/integrations/slack/events", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Slack-Request-Timestamp", stamp)
	req.Header.Set("X-Slack-Signature", api.SlackSignature(secret, stamp, raw))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// Removing the app from Slack disables its channels in every organisation
// that added it and deletes their webhooks and tokens; deleting the last
// app channel removes the app from Slack.
func TestSlackAppUninstall(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	admin := e.login("admin@x.io")
	var got installAnswer
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": f.start(t, admin)}, &got); code != 201 {
		t.Fatalf("finish: %d", code)
	}
	// Slack's URL check, and the signature on every event.
	if code, out := signedEvent(t, e, appSigning, map[string]string{"type": "url_verification", "challenge": "abc"}, time.Now()); code != 200 || out["challenge"] != "abc" {
		t.Errorf("url_verification: %d %v", code, out)
	}
	uninstall := map[string]any{"type": "event_callback", "team_id": "T0APP", "event": map[string]string{"type": "app_uninstalled"}}
	if code, _ := signedEvent(t, e, "wrong-secret", uninstall, time.Now()); code != 401 {
		t.Errorf("unsigned uninstall: %d", code)
	}
	if code, _ := signedEvent(t, e, appSigning, uninstall, time.Now().Add(-10*time.Minute)); code != 401 {
		t.Errorf("old uninstall: %d", code)
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if ch, _ := e.st.GetChannel(ctx, got.Channel.ID); ch == nil || !ch.Enabled {
		t.Fatal("refused events changed the channel")
	}
	// Another Slack workspace's uninstall changes nothing here.
	other := map[string]any{"type": "event_callback", "team_id": "T0ELSE", "event": map[string]string{"type": "app_uninstalled"}}
	if code, _ := signedEvent(t, e, appSigning, other, time.Now()); code != 200 {
		t.Errorf("other team: %d", code)
	}
	if ch, _ := e.st.GetChannel(ctx, got.Channel.ID); !ch.Enabled {
		t.Fatal("another team's uninstall disabled the channel")
	}
	stamp := time.Now()
	if code, _ := signedEvent(t, e, appSigning, uninstall, stamp); code != 200 {
		t.Fatalf("uninstall: %d", code)
	}
	ch, _ := e.st.GetChannel(ctx, got.Channel.ID)
	if ch.Enabled || !strings.Contains(ch.LastError, "removed from this Slack workspace") {
		t.Errorf("after uninstall: %+v", ch)
	}
	var n int
	_ = e.st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM slack_installations) + (SELECT count(*) FROM workspace_secrets WHERE name LIKE 'slack-app-%')`).Scan(&n)
	if n != 0 {
		t.Errorf("%d tokens or webhooks kept after uninstall", n)
	}

	// Installed again, then the channel deleted in Stackurity: the app is
	// removed from Slack, since no organisation uses it there.
	var again installAnswer
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": f.start(t, admin)}, &again); code != 200 ||
		again.Channel.ID != got.Channel.ID || !again.Channel.Enabled || again.Channel.LastError != "" {
		t.Fatalf("install again: %d %+v", code, again.Channel)
	}
	// The same signed uninstall sent again (a replay) changes nothing.
	if code, _ := signedEvent(t, e, appSigning, uninstall, stamp); code != 200 {
		t.Fatalf("replay: %d", code)
	}
	if ch, _ := e.st.GetChannel(ctx, again.Channel.ID); !ch.Enabled {
		t.Fatal("a replayed uninstall disabled the reinstalled channel")
	}
	// A read-only organisation cannot finish Add to Slack.
	state := f.start(t, admin)
	now := time.Now()
	if err := e.st.SetReadOnly(context.Background(), tenant.DefaultWorkspace, &now, "test"); err != nil {
		t.Fatal(err)
	}
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 402 {
		t.Errorf("read-only finish: %d", code)
	}
	if err := e.st.SetReadOnly(context.Background(), tenant.DefaultWorkspace, nil, ""); err != nil {
		t.Fatal(err)
	}
	if code := admin.do("DELETE", "/api/v1/channels/"+itoa(again.Channel.ID), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	f.slack.mu.Lock()
	removed := len(f.slack.uninstalled)
	f.slack.mu.Unlock()
	if removed != 1 {
		t.Errorf("apps.uninstall called %d times", removed)
	}
	_ = e.st.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM slack_installations) + (SELECT count(*) FROM workspace_secrets WHERE name LIKE 'slack-app-%')`).Scan(&n)
	if n != 0 {
		t.Errorf("%d tokens or webhooks kept after delete", n)
	}
}

// Without the app configured, Add to Slack and its events are not there and
// the options say so.
func TestSlackAppOff(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	if code := admin.do("POST", "/api/v1/integrations/slack/install", map[string]string{}, nil); code != 404 {
		t.Errorf("install without the app: %d", code)
	}
	var opts map[string]any
	if code := admin.do("GET", "/api/v1/notification-options", nil, &opts); code != 200 || opts["slack_app"] != false ||
		opts["platform_email"].(map[string]any)["enabled"] != false {
		t.Errorf("options = %d %v", code, opts)
	}
	if code, _ := signedEvent(t, e, appSigning, map[string]string{"type": "url_verification"}, time.Now()); code != 404 {
		t.Errorf("events without the app: %d", code)
	}
}

// Two Slack channels of one Slack workspace: deleting one keeps the other
// working (its own webhook) and keeps the app installed.
func TestSlackAppTwoChannels(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	admin := e.login("admin@x.io")
	var sec, ops installAnswer
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": f.start(t, admin)}, &sec); code != 201 {
		t.Fatalf("security: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "ops-code", "state": f.start(t, admin)}, &ops); code != 201 ||
		ops.Channel.ID == sec.Channel.ID || ops.Channel.SecretRef == sec.Channel.SecretRef {
		t.Fatalf("ops: %d %+v", code, ops.Channel)
	}
	if code := admin.do("DELETE", "/api/v1/channels/"+itoa(sec.Channel.ID), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	hook, err := e.api.Secrets.Resolve(ctx, ops.Channel.SecretRef)
	if err != nil || !strings.Contains(hook, "opsPath") {
		t.Errorf("the other channel's webhook: %q %v", hook, err)
	}
	var installs int
	_ = e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM slack_installations`).Scan(&installs)
	f.slack.mu.Lock()
	removed := len(f.slack.uninstalled)
	f.slack.mu.Unlock()
	if installs != 1 || removed != 0 {
		t.Errorf("install kept %d, apps.uninstall called %d", installs, removed)
	}
}

// Installs started from Slack's side (the Direct install URL, Slack's own
// install page or shareable link): Slack sends the person back with a code
// but without a state of ours. The code is never exchanged then; the person
// starts a proper install from the dashboard instead.
func TestSlackAppInstallFromSlack(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	noFollow := func(s *session) *session {
		s.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return s
	}

	// Signed out, the Direct install URL is a 302 to Slack's consent page,
	// as Slack requires, without a state (nobody to bind it to yet).
	resp := noFollow(e.anon()).req("GET", "/integrations/slack/install", nil, nil)
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != 302 || loc == nil || loc.Host != "slack.com" || loc.Path != "/oauth/v2/authorize" {
		t.Fatalf("signed out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if q := loc.Query(); q.Get("client_id") != "client-1" || q.Get("scope") != "incoming-webhook" ||
		q.Get("redirect_uri") != "https://stk.example/integrations/slack/oauth/callback" || q.Has("state") {
		t.Errorf("direct install query %v", q)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control %q", cc)
	}
	// Signed in, it is the dashboard page that picks the organisation.
	admin := noFollow(e.login("admin@x.io"))
	resp = admin.req("GET", "/integrations/slack/install", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Location") != "" || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("signed in: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Back from Slack with a code and no state (or an empty one): refused
	// before Slack is called, so a crafted link cannot add someone else's
	// Slack channel to this organisation.
	for _, body := range []map[string]string{{"code": "good-code"}, {"code": "good-code", "state": ""}} {
		if code := admin.do("POST", "/api/v1/integrations/slack/oauth", body, nil); code != 400 {
			t.Errorf("no state %v: %d", body, code)
		}
	}
	if f.slack.codes != 0 {
		t.Fatalf("Slack was asked %d times for a code without our state", f.slack.codes)
	}
	var chans struct{ Items []store.Channel }
	admin.do("GET", "/api/v1/channels", nil, &chans)
	if len(chans.Items) != 0 {
		t.Fatalf("channels after refused installs: %+v", chans.Items)
	}
}

// The start page acts in the organisation the person picked (an
// organisation where they are an admin); the state is bound to it.
func TestSlackAppInstallChoosesOrganisation(t *testing.T) {
	f := slackAppSetup(t)
	e := f.e
	ctx := context.Background()
	beta, _, err := e.st.CreateWorkspace(ctx, "Beta", "", "beta@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	gamma, _, err := e.st.CreateWorkspace(ctx, "Gamma", "", "gamma@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddMember(tenant.WithWorkspace(ctx, beta.ID), "admin@x.io", "", auth.RoleViewer, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.AddMember(tenant.WithWorkspace(ctx, gamma.ID), "admin@x.io", "", auth.RoleAdmin, ""); err != nil {
		t.Fatal(err)
	}
	s := e.login("admin@x.io")
	var me struct {
		Workspaces []struct {
			WorkspaceID int64  `json:"workspace_id"`
			Role        string `json:"role"`
		}
	}
	s.do("GET", "/api/v1/auth/me", nil, &me)
	roles := map[int64]string{}
	for _, m := range me.Workspaces {
		roles[m.WorkspaceID] = m.Role
	}
	if roles[tenant.DefaultWorkspace] != "admin" || roles[beta.ID] != "viewer" || roles[gamma.ID] != "admin" {
		t.Fatalf("memberships %v", roles)
	}

	// Not an admin in Beta: no install there.
	if code := s.do("POST", "/api/v1/workspaces/"+itoa(beta.ID)+"/activate", nil, nil); code != 200 && code != 204 {
		t.Fatalf("activate beta: %d", code)
	}
	if code := s.do("POST", "/api/v1/integrations/slack/install", map[string]string{}, nil); code != 403 {
		t.Errorf("install as a viewer: %d", code)
	}
	// An admin in Gamma: the install lands in Gamma, not in the first
	// organisation, and the state does not work from another one.
	if code := s.do("POST", "/api/v1/workspaces/"+itoa(gamma.ID)+"/activate", nil, nil); code != 200 && code != 204 {
		t.Fatalf("activate gamma: %d", code)
	}
	state := f.start(t, s)
	if code := s.do("POST", "/api/v1/workspaces/"+itoa(tenant.DefaultWorkspace)+"/activate", nil, nil); code != 200 && code != 204 {
		t.Fatal("activate default")
	}
	if code := s.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 400 {
		t.Errorf("Gamma's state finished from the default organisation: %d", code)
	}
	s.do("POST", "/api/v1/workspaces/"+itoa(gamma.ID)+"/activate", nil, nil)
	var got installAnswer
	if code := s.do("POST", "/api/v1/integrations/slack/oauth", map[string]string{"code": "good-code", "state": state}, &got); code != 201 {
		t.Fatalf("finish in gamma: %d", code)
	}
	var chans struct{ Items []store.Channel }
	s.do("GET", "/api/v1/channels", nil, &chans)
	if len(chans.Items) != 1 || chans.Items[0].ID != got.Channel.ID {
		t.Errorf("gamma channels %+v", chans.Items)
	}
	s.do("POST", "/api/v1/workspaces/"+itoa(tenant.DefaultWorkspace)+"/activate", nil, nil)
	chans.Items = nil
	s.do("GET", "/api/v1/channels", nil, &chans)
	if len(chans.Items) != 0 {
		t.Errorf("the install leaked into the default organisation: %+v", chans.Items)
	}
}
