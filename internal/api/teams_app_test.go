package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/notify/teamstest"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The Stackurity Teams app ("Add to Teams", teams_app.go) against a fake
// Bot Framework: binding a Teams channel with a code, every request to the
// messaging endpoint verified, replies and messages only to allowed Bot
// Connector hosts, and removal from Teams shown on the integration.

const (
	tmTenant  = "72f988bf-86f1-41af-91ab-2d7cd011db47"
	tmTeam    = "19:team-sec@thread.tacv2"
	tmChannel = "19:chan-alerts@thread.tacv2"
)

type teamsFx struct {
	e    *env
	ms   *teamstest.Fake
	seq  atomic.Int64
	path string
}

func teamsSetup(t *testing.T) *teamsFx {
	t.Helper()
	ms := teamstest.New(t)
	e := newEnvWith(t, func(s *api.Server) {
		s.BaseURL = "https://stk.example"
		s.Dispatcher = &notify.Dispatcher{Store: s.Store, Sender: notify.NewSender(false), Secrets: secrets.Resolver{}, BaseURL: "https://stk.example",
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)), TeamsApp: ms.App()}
	})
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("other-admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	return &teamsFx{e: e, ms: ms, path: e.srv.URL + "/api/v1/integrations/teams/messages"}
}

// activity is a Teams activity in the team channel, as Microsoft sends it.
func (f *teamsFx) activity(typ string, edit func(map[string]any)) map[string]any {
	a := map[string]any{
		"type": typ, "id": fmt.Sprintf("act-%d", f.seq.Add(1)), "channelId": "msteams", "serviceUrl": f.ms.ServiceURL(),
		"from":      map[string]any{"id": "29:user", "name": "Nirmal"},
		"recipient": map[string]any{"id": "28:" + teamstest.AppID, "name": "Stackurity"},
		"conversation": map[string]any{"id": tmChannel + ";messageid=1700000000000", "conversationType": "channel", "tenantId": tmTenant,
			"isGroup": true},
		"channelData": map[string]any{"tenant": map[string]any{"id": tmTenant}, "team": map[string]any{"id": tmTeam, "name": "Security"},
			"channel": map[string]any{"id": tmChannel, "name": "alerts"}},
	}
	if edit != nil {
		edit(a)
	}
	return a
}

func (f *teamsFx) message(text string) map[string]any {
	return f.activity("message", func(a map[string]any) { a["text"] = "<at>Stackurity</at> " + text })
}

// send posts an activity with a valid token for its serviceUrl.
func (f *teamsFx) send(t *testing.T, a map[string]any) int {
	t.Helper()
	return f.sendAuth(t, a, "Bearer "+f.ms.Mint("k1", teamstest.Good(a["serviceUrl"].(string))))
}

func (f *teamsFx) sendAuth(t *testing.T, a map[string]any, auth string) int {
	t.Helper()
	b, _ := json.Marshal(a)
	req, _ := http.NewRequest("POST", f.path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// replies are the bot's answers in the channel thread, newest last.
func (f *teamsFx) replies() []string {
	var out []string
	for _, p := range f.ms.PostsTo("/v3/conversations/") {
		if s, _ := p.Body["text"].(string); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (f *teamsFx) lastReply(t *testing.T) string {
	t.Helper()
	r := f.replies()
	if len(r) == 0 {
		t.Fatal("no reply")
	}
	return r[len(r)-1]
}

type teamsStart struct {
	ID         int64  `json:"id"`
	Code       string `json:"code"`
	InstallURL string `json:"install_url"`
}

func (f *teamsFx) start(t *testing.T, s *session) teamsStart {
	t.Helper()
	var out teamsStart
	if code := s.do("POST", "/api/v1/integrations/teams/install", map[string]any{}, &out); code != 200 {
		t.Fatalf("start: %d", code)
	}
	if len(out.Code) != 11 || out.Code[5] != '-' || out.InstallURL != "https://teams.microsoft.com/l/app/"+teamstest.AppID {
		t.Fatalf("start = %+v", out)
	}
	return out
}

type teamsStatus struct {
	Status  string         `json:"status"`
	Channel *store.Channel `json:"channel"`
}

func (f *teamsFx) status(t *testing.T, s *session, id int64) (teamsStatus, int) {
	t.Helper()
	var out teamsStatus
	code := s.do("GET", fmt.Sprintf("/api/v1/integrations/teams/install/%d", id), nil, &out)
	return out, code
}

func (f *teamsFx) channels(t *testing.T, ctx context.Context) []store.Channel {
	t.Helper()
	cs, err := f.e.st.ListChannels(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// bind connects the team channel with a fresh code and returns it.
func (f *teamsFx) bind(t *testing.T, s *session) store.Channel {
	t.Helper()
	st := f.start(t, s)
	if code := f.send(t, f.message(st.Code)); code != 200 {
		t.Fatalf("bind: %d", code)
	}
	got, _ := f.status(t, s, st.ID)
	if got.Status != "connected" || got.Channel == nil {
		t.Fatalf("bind status = %+v (reply %q)", got, f.lastReply(t))
	}
	return *got.Channel
}

func TestTeamsAppBinding(t *testing.T) {
	f := teamsSetup(t)
	e := f.e
	admin := e.login("admin@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	var opts map[string]any
	admin.do("GET", "/api/v1/notification-options", nil, &opts)
	if opts["teams_app"] != true {
		t.Fatalf("options = %v", opts)
	}
	if code := e.login("viewer@x.io").do("POST", "/api/v1/integrations/teams/install", map[string]any{}, nil); code != 403 {
		t.Errorf("viewer start: %d", code)
	}
	st := f.start(t, admin)
	if got, _ := f.status(t, admin, st.ID); got.Status != "pending" {
		t.Fatalf("status = %+v", got)
	}
	// Another admin cannot read someone else's code.
	if _, code := f.status(t, e.login("other-admin@x.io"), st.ID); code != 404 {
		t.Errorf("other admin's status: %d", code)
	}

	// Requests that are not from the Bot Framework for this app change
	// nothing and get no reply.
	msg := f.message(st.Code)
	good := teamstest.Good(f.ms.ServiceURL())
	other := good
	other.Audience = "11111111-2222-3333-4444-555555555555"
	for name, authz := range map[string]string{
		"no token":       "",
		"wrong audience": "Bearer " + f.ms.Mint("k1", other),
		"alg none":       "Bearer " + teamstest.None(good),
	} {
		if code := f.sendAuth(t, msg, authz); code != 401 {
			t.Errorf("%s: %d", name, code)
		}
	}
	// A forged serviceUrl in the activity, with a real token (for the real
	// serviceUrl): refused, nothing sent anywhere.
	forged := f.message(st.Code)
	forged["serviceUrl"] = "https://evil.example/amer/"
	if code := f.sendAuth(t, forged, "Bearer "+f.ms.Mint("k1", good)); code != 401 {
		t.Errorf("forged serviceUrl: %d", code)
	}
	// A token for that serviceUrl (signed, but not a Bot Connector host).
	if code := f.send(t, forged); code != 403 {
		t.Errorf("serviceUrl off the allow-list: %d", code)
	}
	if got, _ := f.status(t, admin, st.ID); got.Status != "pending" || len(f.ms.Posts) != 0 || len(f.channels(t, ctx)) != 0 {
		t.Fatalf("refused requests changed something: %+v, %d posts", got, len(f.ms.Posts))
	}

	// In a chat, not a channel: explained, the code stays usable.
	chat := f.message(st.Code)
	chat["conversation"].(map[string]any)["conversationType"] = "personal"
	chat["channelData"] = map[string]any{"tenant": map[string]any{"id": tmTenant}}
	if code := f.send(t, chat); code != 200 || !strings.Contains(f.lastReply(t), "team channel") {
		t.Fatalf("chat: %d %q", code, f.lastReply(t))
	}
	// A mistyped code.
	if f.send(t, f.message("ABCDE-FGHJK")); !strings.Contains(f.lastReply(t), "not valid") {
		t.Fatalf("wrong code reply %q", f.lastReply(t))
	}
	// No code: how to connect.
	if f.send(t, f.message("hello")); !strings.Contains(f.lastReply(t), "Add to Teams") {
		t.Fatalf("hello reply %q", f.lastReply(t))
	}

	// The admin's code, typed in lower case with a space.
	bindMsg := f.message("please connect " + strings.ToLower(strings.Replace(st.Code, "-", " ", 1)))
	if code := f.send(t, bindMsg); code != 200 {
		t.Fatalf("bind: %d", code)
	}
	if r := f.lastReply(t); !strings.Contains(r, "Connected") || !strings.Contains(r, "Default") {
		t.Fatalf("bind reply %q", r)
	}
	got, _ := f.status(t, admin, st.ID)
	if got.Status != "connected" || got.Channel == nil {
		t.Fatalf("status = %+v", got)
	}
	ch := got.Channel
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(ch.Config, &cfg)
	if ch.Kind != "teams" || ch.SecretRef != "" || !ch.Enabled || ch.Name != "Teams alerts (Security)" || !cfg.TeamsApp || cfg.TenantID != tmTenant ||
		cfg.TeamsTeamID != tmTeam || cfg.TeamsChannelID != tmChannel || cfg.ServiceURL != f.ms.ServiceURL() {
		t.Fatalf("channel = %+v %+v", ch, cfg)
	}
	// Replies went to the conversation the message came from, with the
	// app's token, only to the fake Bot Connector.
	for _, p := range f.ms.Posts {
		if !strings.HasPrefix(p.Auth, "Bearer bf-token-") {
			t.Fatalf("post without the app token: %+v", p)
		}
	}

	// The same activity again (Microsoft retrying): handled once.
	n := len(f.replies())
	if code := f.send(t, bindMsg); code != 200 || len(f.replies()) != n {
		t.Fatalf("redelivery: %d, %d replies", code, len(f.replies())-n)
	}
	// The code again, in a new message (replayed): refused.
	if f.send(t, f.message(st.Code)); !strings.Contains(f.lastReply(t), "not valid") {
		t.Fatalf("replayed code reply %q", f.lastReply(t))
	}
	// In another team of another tenant: refused too, nothing bound there.
	elsewhere := f.message(st.Code)
	elsewhere["channelData"].(map[string]any)["tenant"] = map[string]any{"id": "99999999-0000-0000-0000-000000000000"}
	f.send(t, elsewhere)
	if cs := f.channels(t, ctx); len(cs) != 1 {
		t.Fatalf("%d channels after replays, want 1", len(cs))
	}

	// An expired code.
	late := f.start(t, admin)
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE teams_install_codes SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if f.send(t, f.message(late.Code)); !strings.Contains(f.lastReply(t), "not valid") {
		t.Fatalf("expired code reply %q", f.lastReply(t))
	}
	if got, _ := f.status(t, admin, late.ID); got.Status != "expired" {
		t.Fatalf("expired status = %+v", got)
	}

	// A code binds to the organisation that made it, not another one.
	if _, _, err := e.st.CreateWorkspace(context.Background(), "Beta", "", "beta@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	beta := e.login("beta@x.io")
	bst := f.start(t, beta)
	betaMsg := f.message(bst.Code)
	betaMsg["channelData"].(map[string]any)["channel"] = map[string]any{"id": "19:beta@thread.tacv2", "name": "beta"}
	f.send(t, betaMsg)
	if r := f.lastReply(t); !strings.Contains(r, "Beta") {
		t.Fatalf("beta reply %q", r)
	}
	if cs := f.channels(t, ctx); len(cs) != 1 {
		t.Fatalf("Beta's code added a channel to the default organisation")
	}
	var betaList struct{ Items []store.Channel }
	beta.do("GET", "/api/v1/channels", nil, &betaList)
	if len(betaList.Items) != 1 || !strings.Contains(string(betaList.Items[0].Config), "19:beta@thread.tacv2") {
		t.Fatalf("beta channels = %+v", betaList.Items)
	}

	// App channels are made only by Add to Teams, and keep their binding.
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "teams", "name": "x",
		"config": map[string]any{"teams_app": true, "tenant_id": tmTenant, "teams_channel_id": "19:x@thread.tacv2", "service_url": "https://smba.trafficmanager.net/amer/"}}, nil); code != 400 {
		t.Errorf("hand-made app channel: %d", code)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/channels/%d", ch.ID), map[string]any{"config": map[string]any{"teams_app": true,
		"service_url": "https://smba.trafficmanager.net/amer/", "teams_channel_id": "19:other@thread.tacv2"}}, nil); code != 400 {
		t.Errorf("changing an app channel's binding: %d", code)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/channels/%d", ch.ID), map[string]any{"secret_ref": "env:STACKURITY_SECRET_X"}, nil); code != 400 {
		t.Errorf("adding a secret to an app channel: %d", code)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/channels/%d", ch.ID), map[string]any{"name": "Security alerts"}, nil); code != 200 {
		t.Errorf("rename: %d", code)
	}
}

func TestTeamsAppSendAndRemoval(t *testing.T) {
	f := teamsSetup(t)
	admin := f.e.login("admin@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	ch := f.bind(t, admin)
	get := func() *store.Channel {
		c, err := f.e.st.GetChannel(ctx, ch.ID)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	test := func() (bool, string) {
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		if code := admin.do("POST", fmt.Sprintf("/api/v1/channels/%d/test", ch.ID), nil, &out); code != 200 {
			t.Fatalf("test: %d", code)
		}
		return out.OK, out.Error
	}

	// Send test: a new post in the bound channel, as an Adaptive Card.
	if ok, msg := test(); !ok {
		t.Fatalf("send test: %s", msg)
	}
	posts := f.ms.PostsTo("/v3/conversations")
	last := posts[len(posts)-1]
	cd, _ := last.Body["channelData"].(map[string]any)
	if last.Path != "/v3/conversations" || cd["channel"].(map[string]any)["id"] != tmChannel ||
		!strings.Contains(toJSONString(last.Body), "This channel is configured correctly.") || !strings.Contains(toJSONString(last.Body), "AdaptiveCard") {
		t.Fatalf("post = %+v", last)
	}
	if c := get(); c.LastOKAt == nil || c.LastError != "" {
		t.Fatalf("after a good send: %+v", c)
	}

	// A busy Bot Connector: the error shows, the integration stays on.
	f.ms.Answer = func(string) int { return 503 }
	if ok, msg := test(); ok || !strings.Contains(msg, "503") {
		t.Fatalf("503: %v %s", ok, msg)
	}
	if c := get(); !c.Enabled || !strings.Contains(c.LastError, "503") {
		t.Fatalf("after 503: %+v", c)
	}
	// Teams says the bot is gone: the integration is switched off and says
	// why (never a silent failure).
	f.ms.Answer = func(string) int { return 403 }
	if ok, msg := test(); ok || !strings.Contains(msg, "Add to Teams again") {
		t.Fatalf("403: %v %s", ok, msg)
	}
	if c := get(); c.Enabled || !strings.Contains(c.LastError, "no longer in this Teams channel") {
		t.Fatalf("after 403: %+v", c)
	}
	f.ms.Answer = nil

	// Adding it again revives the same integration.
	if again := f.bind(t, admin); again.ID != ch.ID || !again.Enabled {
		t.Fatalf("rebind = %+v", again)
	}
	if ok, msg := test(); !ok {
		t.Fatalf("after rebind: %s", msg)
	}

	// A forged removal (no valid token) changes nothing.
	removed := f.activity("conversationUpdate", func(a map[string]any) {
		a["membersRemoved"] = []map[string]any{{"id": "28:" + teamstest.AppID}}
		a["conversation"] = map[string]any{"id": tmTeam, "conversationType": "channel", "tenantId": tmTenant}
	})
	if code := f.sendAuth(t, removed, "Bearer "+teamstest.MintWith(t, mustKey(t), "k1", teamstest.Good(f.ms.ServiceURL()))); code != 401 {
		t.Fatalf("forged removal: %d", code)
	}
	// Removal for the same team id in another tenant changes nothing either.
	otherTenant := f.activity("conversationUpdate", func(a map[string]any) {
		a["membersRemoved"] = []map[string]any{{"id": "28:" + teamstest.AppID}}
		a["channelData"].(map[string]any)["tenant"] = map[string]any{"id": "99999999-0000-0000-0000-000000000000"}
	})
	f.send(t, otherTenant)
	// Another channel of the team deleted: not ours.
	f.send(t, f.activity("conversationUpdate", func(a map[string]any) {
		a["channelData"].(map[string]any)["eventType"] = "channelDeleted"
		a["channelData"].(map[string]any)["channel"] = map[string]any{"id": "19:other@thread.tacv2"}
	}))
	if c := get(); !c.Enabled {
		t.Fatalf("switched off by someone else's event: %+v", c)
	}
	// Someone else's member leaving the team is not the app's removal.
	f.send(t, f.activity("conversationUpdate", func(a map[string]any) {
		a["membersRemoved"] = []map[string]any{{"id": "29:someone"}}
	}))
	if c := get(); !c.Enabled {
		t.Fatalf("a person leaving switched it off: %+v", c)
	}

	// The app removed from the team (signed): disconnected, with the reason.
	if code := f.send(t, removed); code != 200 {
		t.Fatalf("removal: %d", code)
	}
	if c := get(); c.Enabled || !strings.Contains(c.LastError, "removed from this Teams channel") {
		t.Fatalf("after removal: %+v", c)
	}
	// installationUpdate remove and channelDeleted work the same way.
	f.bind(t, admin)
	f.send(t, f.activity("installationUpdate", func(a map[string]any) { a["action"] = "remove" }))
	if c := get(); c.Enabled {
		t.Fatalf("after installationUpdate remove: %+v", c)
	}
	f.bind(t, admin)
	f.send(t, f.activity("conversationUpdate", func(a map[string]any) { a["channelData"].(map[string]any)["eventType"] = "channelDeleted" }))
	if c := get(); c.Enabled {
		t.Fatalf("after channelDeleted: %+v", c)
	}

	// The app installed in a team: a welcome in the channel.
	f.send(t, f.activity("conversationUpdate", func(a map[string]any) {
		a["membersAdded"] = []map[string]any{{"id": "28:" + teamstest.AppID}}
	}))
	if !strings.Contains(f.lastReply(t), "Add to Teams") {
		t.Fatalf("welcome %q", f.lastReply(t))
	}

	// Without the app on the server any more, its channels say so.
	f.e.api.Dispatcher.TeamsApp = nil
	f.bindDirect(t, ctx, ch.ID)
	if ok, msg := test(); ok || !strings.Contains(msg, "not set up on this server") {
		t.Fatalf("no app: %v %s", ok, msg)
	}
	if code := f.send(t, f.message("hello")); code != 404 {
		t.Fatalf("messaging endpoint without the app: %d", code)
	}
}

// bindDirect switches a channel on again without Teams.
func (f *teamsFx) bindDirect(t *testing.T, ctx context.Context, id int64) {
	t.Helper()
	if err := f.e.st.ReviveChannel(ctx, id, nil); err != nil {
		t.Fatal(err)
	}
}

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func toJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
