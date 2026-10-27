package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Acting from Slack (slack.go): signed clicks on interactive buttons, account
// linking, and actions with the linked user's permissions.

const slackResponseURL = "https://hooks.slack.com/actions/T0SLACK/1/abc"

type slackAnswer struct {
	URL  string
	Body map[string]any
}

type slackFx struct {
	e       *env
	answers chan slackAnswer
	channel int64 // the default workspace's Slack channel with a signing secret
	secret  string
}

// slackSetup gives the server a base URL and captures what it posts to
// response URLs, and adds a Slack channel with a signing secret to the
// default workspace. Secrets come from the environment (env: references).
func slackSetup(t *testing.T, e *env) *slackFx {
	t.Helper()
	t.Setenv("STACKURITY_SECRET_SLACK_SIGNING", "sign-default-6f1d2a")
	t.Setenv("STACKURITY_SECRET_SLACK_HOOK", "https://hooks.slack.com/services/T0SLACK/B01/xyz")
	f := &slackFx{e: e, answers: make(chan slackAnswer, 64), secret: "sign-default-6f1d2a"}
	e.api.BaseURL = "https://stk.example"
	e.api.SlackRespond = func(_ context.Context, u string, body []byte) error {
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		f.answers <- slackAnswer{u, m}
		return nil
	}
	f.channel = slackChannel(t, e, tenant.DefaultWorkspace, "slack-app", `{"signing_secret_ref":"env:STACKURITY_SECRET_SLACK_SIGNING"}`)
	return f
}

func slackChannel(t *testing.T, e *env, ws int64, name, cfg string) int64 {
	t.Helper()
	ch, err := e.st.CreateChannel(tenant.WithWorkspace(context.Background(), ws), "slack", name, json.RawMessage(cfg), "env:STACKURITY_SECRET_SLACK_HOOK")
	if err != nil {
		t.Fatal(err)
	}
	return ch.ID
}

type click struct {
	channel     int64
	kind, fix   string
	team, user  string
	secret      string
	ts          time.Time
	responseURL string
	value       string // overrides the button value
}

// send posts a click as Slack would, signed with c.secret.
func (f *slackFx) send(t *testing.T, c click) (int, string) {
	t.Helper()
	body := f.body(c)
	return f.post(t, c, body)
}

func (f *slackFx) body(c click) string {
	if c.team == "" {
		c.team = "T0SLACK"
	}
	if c.responseURL == "" {
		c.responseURL = slackResponseURL
	}
	if c.value == "" {
		c.value = notify.SlackActionValue(c.channel, c.kind, c.fix)
	}
	p := map[string]any{
		"type":         "block_actions",
		"team":         map[string]string{"id": c.team, "domain": "acme"},
		"user":         map[string]string{"id": c.user, "username": strings.ToLower(c.user), "name": "Slack " + c.user, "team_id": c.team},
		"response_url": c.responseURL,
		// As in Slack's payloads, each click has its own trigger and time.
		"trigger_id": fmt.Sprint(time.Now().UnixNano()),
		"actions": []map[string]string{{"action_id": "stk-0-" + c.kind, "block_id": "stk-0", "value": c.value,
			"action_ts": fmt.Sprint(time.Now().UnixNano())}},
		"message": map[string]any{"text": "1 urgent fix", "blocks": []map[string]any{
			{"type": "header", "text": map[string]any{"type": "plain_text", "text": "1 urgent fix"}},
			{"type": "section", "block_id": "s0", "text": map[string]any{"type": "mrkdwn", "text": "• fix"}},
			{"type": "actions", "block_id": "stk-0", "elements": []any{}},
			{"type": "section", "block_id": "s1", "text": map[string]any{"type": "mrkdwn", "text": "• other fix"}},
			{"type": "actions", "block_id": "stk-1", "elements": []any{}},
		}},
	}
	raw, _ := json.Marshal(p)
	return "payload=" + url.QueryEscape(string(raw))
}

func (f *slackFx) post(t *testing.T, c click, body string) (int, string) {
	t.Helper()
	if c.ts.IsZero() {
		c.ts = time.Now()
	}
	if c.secret == "" {
		c.secret = f.secret
	}
	ts := fmt.Sprint(c.ts.Unix())
	req, _ := http.NewRequest("POST", f.e.srv.URL+"/api/v1/integrations/slack/actions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", api.SlackSignature(c.secret, ts, []byte(body)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

func (f *slackFx) answer(t *testing.T) slackAnswer {
	t.Helper()
	select {
	case a := <-f.answers:
		return a
	case <-time.After(15 * time.Second):
		t.Fatal("no answer through response_url")
	}
	return slackAnswer{}
}

func (f *slackFx) noAnswer(t *testing.T) {
	t.Helper()
	select {
	case a := <-f.answers:
		t.Errorf("unexpected answer: %+v", a)
	case <-time.After(300 * time.Millisecond):
	}
}

// ephemeral reads an ephemeral answer's text.
func ephemeral(t *testing.T, a slackAnswer) string {
	t.Helper()
	if a.Body["response_type"] != "ephemeral" || a.Body["replace_original"] != false {
		t.Errorf("not ephemeral: %v", a.Body)
	}
	if a.URL != slackResponseURL {
		t.Errorf("answered to %q", a.URL)
	}
	s, _ := a.Body["text"].(string)
	return s
}

var linkToken = regexp.MustCompile(`https://stk\.example/slack/link#(slk_[a-z0-9]+)\|`)

// linkOffer reads the one-time link from the answer to an unlinked user.
func linkOffer(t *testing.T, a slackAnswer) string {
	t.Helper()
	m := linkToken.FindStringSubmatch(ephemeral(t, a))
	if m == nil {
		t.Fatalf("no link offered: %v", a.Body)
	}
	return m[1]
}

// TestSlackSignatureVerification: only requests signed with the signing
// secret of the channel the click names are acted on, once, within 5
// minutes; everything else is refused before anything is done.
func TestSlackSignatureVerification(t *testing.T) {
	e := newEnv(t)
	f := slackSetup(t, e)
	ctx := context.Background()
	ok := click{channel: f.channel, kind: "assign", fix: "1:package_upgrade:0", user: "U1"}

	// A valid click from someone not linked yet: acknowledged at once, then
	// a link offer only they see.
	if code, _ := f.send(t, ok); code != 200 {
		t.Fatalf("valid click: %d", code)
	}
	if tok := linkOffer(t, f.answer(t)); !strings.HasPrefix(tok, "slk_") {
		t.Fatal(tok)
	}

	// Another channel of the same workspace with its own secret, and a
	// channel in another workspace.
	t.Setenv("STACKURITY_SECRET_SLACK_SIGNING_2", "sign-second-9c0b")
	other := slackChannel(t, e, tenant.DefaultWorkspace, "slack-other", `{"signing_secret_ref":"env:STACKURITY_SECRET_SLACK_SIGNING_2"}`)
	ws2, _, err := e.st.CreateWorkspace(ctx, "Second Org", "", "admin-second@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_SECRET_SLACK_SIGNING_3", "sign-third-77aa")
	foreign := slackChannel(t, e, ws2.ID, "slack-ws2", `{"signing_secret_ref":"env:STACKURITY_SECRET_SLACK_SIGNING_3"}`)
	plain := slackChannel(t, e, tenant.DefaultWorkspace, "slack-plain", `{}`)
	off := slackChannel(t, e, tenant.DefaultWorkspace, "slack-off", `{"signing_secret_ref":"env:STACKURITY_SECRET_SLACK_SIGNING"}`)
	enabled := false
	if err := e.st.UpdateChannel(tenant.WithWorkspace(ctx, tenant.DefaultWorkspace), off, nil, nil, nil, &enabled); err != nil {
		t.Fatal(err)
	}

	with := func(mod func(*click)) click {
		c := ok
		c.user = "U2"
		mod(&c)
		return c
	}
	for name, c := range map[string]click{
		"bad signature":                    with(func(c *click) { c.secret = "not-the-secret" }),
		"old timestamp":                    with(func(c *click) { c.ts = time.Now().Add(-6 * time.Minute) }),
		"timestamp ahead":                  with(func(c *click) { c.ts = time.Now().Add(6 * time.Minute) }),
		"another channel's secret":         with(func(c *click) { c.secret = "sign-second-9c0b" }),
		"names another channel":            with(func(c *click) { c.channel = other }),
		"another workspace's channel":      with(func(c *click) { c.channel = foreign }),
		"another workspace's secret":       with(func(c *click) { c.secret = "sign-third-77aa" }),
		"channel without a signing secret": with(func(c *click) { c.channel = plain; c.secret = "" }),
		"disabled channel":                 with(func(c *click) { c.channel = off }),
		"no such channel":                  with(func(c *click) { c.channel = 999999 }),
		"not a button of ours":             with(func(c *click) { c.value = "something-else" }),
		"another Slack workspace":          with(func(c *click) { c.team = "TOTHER" }),
	} {
		if code, body := f.send(t, c); code != 401 {
			t.Errorf("%s: %d %s, want 401", name, code, body)
		}
	}
	f.noAnswer(t)

	// The signing secret of the named channel verifies, whatever workspace
	// it is in; the link offer is stored in that channel's workspace.
	if code, _ := f.send(t, with(func(c *click) { c.channel = other; c.secret = "sign-second-9c0b" })); code != 200 {
		t.Errorf("other channel with its own secret: %d", code)
	}
	linkOffer(t, f.answer(t))
	if code, _ := f.send(t, with(func(c *click) { c.channel = foreign; c.secret = "sign-third-77aa"; c.user = "U3" })); code != 200 {
		t.Errorf("second workspace's channel with its secret: %d", code)
	}
	linkOffer(t, f.answer(t))
	var ws int64
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT workspace_id FROM slack_link_requests WHERE slack_user_id = 'U3'`).Scan(&ws); err != nil || ws != ws2.ID {
		t.Errorf("link request of the second workspace's channel in workspace %d (%v), want %d", ws, err, ws2.ID)
	}

	// Replay: the same signed request is accepted once.
	c := with(func(c *click) { c.user = "U4" })
	body := f.body(c)
	c.ts = time.Now()
	if code, _ := f.post(t, c, body); code != 200 {
		t.Fatalf("first: %d", code)
	}
	f.answer(t)
	if code, _ := f.post(t, c, body); code != 401 {
		t.Errorf("replay: %d, want 401", code)
	}
	f.noAnswer(t)

	// Verified, but the response URL is not Slack's: refused, and nothing
	// is posted anywhere.
	if code, _ := f.send(t, with(func(c *click) { c.responseURL = "https://evil.example/hook"; c.user = "U5" })); code != 400 {
		t.Errorf("foreign response_url: %d", code)
	}
	if code, _ := f.send(t, with(func(c *click) { c.responseURL = "https://hooks.slack.com.evil.example/x"; c.user = "U5" })); code != 400 {
		t.Errorf("look-alike response_url: %d", code)
	}
	f.noAnswer(t)

	// The Open button is a URL button: acknowledged, nothing else.
	if code, _ := f.send(t, with(func(c *click) { c.kind = "open"; c.user = "U6" })); code != 200 {
		t.Errorf("open: %d", code)
	}
	f.noAnswer(t)

	// No headers, and an oversized body.
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/integrations/slack/actions", strings.NewReader(f.body(ok)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Errorf("unsigned: %d", resp.StatusCode)
	}
	if code, _ := f.post(t, ok, "payload="+strings.Repeat("x", 70<<10)); code != 413 {
		t.Errorf("oversized: %d", code)
	}
}

// link links a Slack user to a Stackurity account through the dashboard.
func (f *slackFx) link(t *testing.T, email, slackUser string) {
	t.Helper()
	tok, _, err := f.e.st.CreateSlackLinkRequest(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), f.channel, "T0SLACK", "acme", slackUser, "Slack "+slackUser)
	if err != nil {
		t.Fatal(err)
	}
	if code := f.e.signIn(email).do("POST", "/api/v1/slack/links/confirm", map[string]string{"token": tok}, nil); code != 200 {
		t.Fatalf("link %s: %d", email, code)
	}
}

// TestSlackAccountLinking: the link offered in Slack works once, for 15
// minutes, only in the workspace of the channel, only for a signed-in
// person, and never takes over a Slack account linked to someone else.
func TestSlackAccountLinking(t *testing.T) {
	e := newEnv(t)
	f := slackSetup(t, e)
	ctx := context.Background()
	e.user("eng-link@x.io", auth.RoleEngineer)
	e.user("other-link@x.io", auth.RoleEngineer)
	eng, other := e.signIn("eng-link@x.io"), e.signIn("other-link@x.io")

	if code, _ := f.send(t, click{channel: f.channel, kind: "assign", fix: "x", user: "UENG"}); code != 200 {
		t.Fatal(code)
	}
	tok := linkOffer(t, f.answer(t))

	// The person sees what they are linking before confirming.
	var pv struct {
		Link       store.SlackLinkRequest
		SignedInAs string `json:"signed_in_as"`
	}
	if code := eng.do("POST", "/api/v1/slack/links/preview", map[string]string{"token": tok}, &pv); code != 200 ||
		pv.Link.SlackUserID != "UENG" || pv.Link.TeamID != "T0SLACK" || pv.Link.SlackUserName != "Slack UENG" || pv.SignedInAs != "eng-link@x.io" {
		t.Fatalf("preview: %d %+v", code, pv)
	}
	// API tokens cannot link.
	var at struct{ Secret string }
	if code := eng.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "engineer"}, &at); code != 201 {
		t.Fatal(code)
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	if code := bearer(e, at.Secret, "POST", "/api/v1/slack/links/confirm", body, nil); code != 403 {
		t.Errorf("confirm with an API token: %d", code)
	}
	// Single use.
	var l store.SlackLink
	if code := eng.do("POST", "/api/v1/slack/links/confirm", map[string]string{"token": tok}, &l); code != 200 || l.SlackUserID != "UENG" {
		t.Fatalf("confirm: %d %+v", code, l)
	}
	for _, s := range []*session{eng, other} {
		if code := s.do("POST", "/api/v1/slack/links/confirm", map[string]string{"token": tok}, nil); code != 410 {
			t.Errorf("second use: %d", code)
		}
		if code := s.do("POST", "/api/v1/slack/links/preview", map[string]string{"token": tok}, nil); code != 410 {
			t.Errorf("preview after use: %d", code)
		}
	}
	// Linked: the next click acts (here, on a fix that does not exist).
	if code, _ := f.send(t, click{channel: f.channel, kind: "assign", fix: "nope", user: "UENG"}); code != 200 {
		t.Fatal(code)
	}
	if msg := ephemeral(t, f.answer(t)); !strings.Contains(msg, "not open any more") {
		t.Errorf("linked click: %q", msg)
	}

	// Expiry.
	ws := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	old, _, err := e.st.CreateSlackLinkRequest(ws, f.channel, "T0SLACK", "acme", "UOLD", "old")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE slack_link_requests SET expires_at = now() - interval '1 minute' WHERE slack_user_id = 'UOLD'`); err != nil {
		t.Fatal(err)
	}
	if code := other.do("POST", "/api/v1/slack/links/preview", map[string]string{"token": old}, nil); code != 410 {
		t.Errorf("expired preview: %d", code)
	}
	if code := other.do("POST", "/api/v1/slack/links/confirm", map[string]string{"token": old}, nil); code != 410 {
		t.Errorf("expired confirm: %d", code)
	}
	if store.SlackLinkTTL != 15*time.Minute {
		t.Errorf("TTL %s", store.SlackLinkTTL)
	}

	// Another Stackurity user cannot take over a linked Slack account.
	again, _, err := e.st.CreateSlackLinkRequest(ws, f.channel, "T0SLACK", "acme", "UENG", "Slack UENG")
	if err != nil {
		t.Fatal(err)
	}
	var pv2 struct{ Link store.SlackLinkRequest }
	if code := other.do("POST", "/api/v1/slack/links/preview", map[string]string{"token": again}, &pv2); code != 200 || !pv2.Link.LinkedToOther {
		t.Errorf("preview of a linked account: %d %+v", code, pv2.Link)
	}
	if code := other.do("POST", "/api/v1/slack/links/confirm", map[string]string{"token": again}, nil); code != 409 {
		t.Errorf("take over: %d, want 409", code)
	}

	// A link from another workspace's channel is refused here, and works
	// for that workspace's people.
	ws2, _, err := e.st.CreateWorkspace(ctx, "Second Org", "", "admin-second@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_SECRET_SLACK_SIGNING_3", "sign-third-77aa")
	foreign := slackChannel(t, e, ws2.ID, "slack-ws2", `{"signing_secret_ref":"env:STACKURITY_SECRET_SLACK_SIGNING_3"}`)
	if code, _ := f.send(t, click{channel: foreign, kind: "assign", fix: "x", user: "UWS2", secret: "sign-third-77aa"}); code != 200 {
		t.Fatal(code)
	}
	tok2 := linkOffer(t, f.answer(t))
	if code := other.do("POST", "/api/v1/slack/links/preview", map[string]string{"token": tok2}, nil); code != 410 {
		t.Errorf("cross-workspace preview: %d", code)
	}
	if code := other.do("POST", "/api/v1/slack/links/confirm", map[string]string{"token": tok2}, nil); code != 410 {
		t.Errorf("cross-workspace confirm: %d", code)
	}
	if code := e.signIn("admin-second@x.io").do("POST", "/api/v1/slack/links/confirm", map[string]string{"token": tok2}, nil); code != 200 {
		t.Errorf("the second workspace's admin: %d", code)
	}

	// Each person lists and removes only their own links.
	var mine struct{ Items []store.SlackLink }
	if code := eng.do("GET", "/api/v1/slack/links", nil, &mine); code != 200 || len(mine.Items) != 1 || mine.Items[0].SlackUserID != "UENG" {
		t.Fatalf("list: %d %+v", code, mine)
	}
	var theirs struct{ Items []store.SlackLink }
	if code := other.do("GET", "/api/v1/slack/links", nil, &theirs); code != 200 || len(theirs.Items) != 0 {
		t.Errorf("another's list: %d %+v", code, theirs)
	}
	path := fmt.Sprintf("/api/v1/slack/links/%d", mine.Items[0].ID)
	if code := other.do("DELETE", path, nil, nil); code != 404 {
		t.Errorf("unlink another's: %d", code)
	}
	if code := eng.do("DELETE", path, nil, nil); code != 204 {
		t.Errorf("unlink: %d", code)
	}
	// Unlinked: clicking offers a link again.
	if code, _ := f.send(t, click{channel: f.channel, kind: "assign", fix: "x", user: "UENG"}); code != 200 {
		t.Fatal(code)
	}
	linkOffer(t, f.answer(t))
	var audits int
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT count(*) FROM audit_events WHERE workspace_id = 1 AND actor_name = 'eng-link@x.io'
		AND action IN ('slack_link.create', 'slack_link.delete')`).Scan(&audits); err != nil || audits != 2 {
		t.Errorf("audit: %d %v", audits, err)
	}
}

// TestSlackActionPermissions: a linked Slack user acts as their account:
// the dashboard's role and project rules, the dashboard's audit entries
// (source slack), and the message says what was done.
func TestSlackActionPermissions(t *testing.T) {
	o := newOrg(t)
	e := o.e
	f := slackSetup(t, e)
	ctx := context.Background()
	ws := tenant.WithWorkspace(ctx, tenant.DefaultWorkspace)
	groups, _, err := e.st.ListFixGroups(ws, store.FixGroupFilter{AssetID: o.id("alpha-asset")})
	if err != nil || len(groups) == 0 {
		t.Fatalf("alpha fix groups: %v", err)
	}
	var g struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(groups[0], &g)
	alphaFix, betaFix := g.ID, o.fixGroup

	e.user("slack-viewer@x.io", auth.RoleViewer)
	e.user("slack-security@x.io", auth.RoleSecurity)
	o.grant(t, "slack-pa-engineer@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	f.link(t, "slack-viewer@x.io", "UVIEW")
	f.link(t, "org-engineer@x.io", "UENG")
	f.link(t, "slack-security@x.io", "USEC")
	f.link(t, "slack-pa-engineer@x.io", "UPA")
	f.link(t, "beta-viewer@x.io", "UBV")

	state := func(fix string) string {
		var s string
		if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT string_agg(concat_ws(':', state, COALESCE(u.email, '-')), ',' ORDER BY f.id)
			FROM findings f LEFT JOIN users u ON u.id = f.assignee_user_id WHERE f.fix_group = $1 AND f.status = 'open'`, fix).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	act := func(user, kind, fix string) slackAnswer {
		t.Helper()
		if code, body := f.send(t, click{channel: f.channel, kind: kind, fix: fix, user: user}); code != 200 {
			t.Fatalf("%s %s: %d %s", user, kind, code, body)
		}
		return f.answer(t)
	}
	refused := func(user, kind, fix, want string) {
		t.Helper()
		before := state(fix)
		if msg := ephemeral(t, act(user, kind, fix)); !strings.Contains(msg, want) {
			t.Errorf("%s %s %s: %q, want %q", user, kind, fix, msg, want)
		}
		if after := state(fix); after != before {
			t.Errorf("%s %s %s changed the fix: %s -> %s", user, kind, fix, before, after)
		}
	}

	// Refused, with why, and nothing changes.
	refused("UVIEW", "assign", alphaFix, "needs the engineer role")
	refused("UVIEW", "snooze", alphaFix, "needs the security role")
	refused("UENG", "snooze", alphaFix, "needs the security role")
	refused("UPA", "snooze", alphaFix, "needs the security role")
	refused("UPA", "assign", betaFix, "cannot see it")
	refused("UBV", "assign", betaFix, "needs the engineer role")

	// A project-only engineer assigns a fix of their project.
	a := act("UPA", "assign", alphaFix)
	if a.Body["replace_original"] != true {
		t.Fatalf("not a message update: %v", a.Body)
	}
	if got := state(alphaFix); !strings.Contains(got, "slack-pa-engineer@x.io") || strings.Contains(got, ":-") {
		t.Errorf("alpha after assign: %s", got)
	}
	// The message: the line goes under the clicked buttons, the rest stays.
	blocks := a.Body["blocks"].([]any)
	ids := []string{}
	for _, b := range blocks {
		id, _ := b.(map[string]any)["block_id"].(string)
		ids = append(ids, id)
	}
	if strings.Join(ids, ",") != ",s0,stk-0,stk-0-status,s1,stk-1" || a.Body["text"] != "1 urgent fix" {
		t.Errorf("blocks %v", ids)
	}
	status := blocks[3].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(status, "Assigned to slack-pa-engineer@x.io (") {
		t.Errorf("status %q", status)
	}

	// Security snoozes it for a week.
	a = act("USEC", "snooze", alphaFix)
	until := time.Now().Add(7 * 24 * time.Hour).UTC().Format("2 Jan")
	blocks = a.Body["blocks"].([]any)
	status = blocks[3].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.HasPrefix(status, "Snoozed until "+until+" by slack-security@x.io (") {
		t.Errorf("status %q", status)
	}
	if got := state(alphaFix); strings.Contains(got, "new:") || !strings.Contains(got, "suppressed:") {
		t.Errorf("alpha after snooze: %s", got)
	}
	var snoozeUntil time.Time
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT min(suppressed_until) FROM findings WHERE fix_group = $1 AND status = 'open'`, alphaFix).Scan(&snoozeUntil); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(snoozeUntil); d < 6*24*time.Hour || d > 8*24*time.Hour {
		t.Errorf("snoozed until %s", snoozeUntil)
	}

	// An organisation engineer assigns Beta's fix.
	act("UENG", "assign", betaFix)
	if got := state(betaFix); !strings.Contains(got, "org-engineer@x.io") {
		t.Errorf("beta after assign: %s", got)
	}

	// Audited like the dashboard, with the source.
	rows, err := e.st.Pool.Query(tenant.System(ctx), `SELECT actor_type, actor_name, action, detail->>'source', detail->>'slack_user_id'
		FROM audit_events WHERE workspace_id = 1 AND action IN ('finding.assign', 'finding.suppress') AND detail->>'source' = 'slack' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var typ, name, action, source, slackUser string
		if err := rows.Scan(&typ, &name, &action, &source, &slackUser); err != nil {
			t.Fatal(err)
		}
		got = append(got, strings.Join([]string{typ, name, action, slackUser}, " "))
	}
	want := "user slack-pa-engineer@x.io finding.assign UPA|user slack-security@x.io finding.suppress USEC|user org-engineer@x.io finding.assign UENG"
	if strings.Join(got, "|") != want {
		t.Errorf("audit:\n%s\nwant\n%s", strings.Join(got, "|"), want)
	}
	// The finding's history names the person, as from the dashboard.
	var history int
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT count(*) FROM finding_events ev JOIN findings f ON f.id = ev.finding_id
		WHERE f.fix_group = $1 AND ev.actor_name = 'slack-security@x.io'`, alphaFix).Scan(&history); err != nil || history == 0 {
		t.Errorf("no finding history for the snooze: %v", err)
	}

	// A person removed from the organisation acts no more.
	var uid int64
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT id FROM users WHERE email = 'slack-viewer@x.io'`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	if code := o.admin.do("DELETE", fmt.Sprintf("/api/v1/users/%d", uid), nil, nil); code != 204 && code != 200 {
		t.Fatalf("remove member: %d", code)
	}
	if code, _ := f.send(t, click{channel: f.channel, kind: "assign", fix: alphaFix, user: "UVIEW"}); code != 200 {
		t.Fatal(code)
	}
	if msg := ephemeral(t, f.answer(t)); !strings.Contains(msg, "not a member") && !strings.Contains(msg, "To act from Slack") {
		t.Errorf("removed member: %q", msg)
	}
}

// A Slack channel's signing secret reference follows the rules of every
// secret reference: validated, and env: or file: for instance admins only.
func TestSlackChannelSigningSecretRef(t *testing.T) {
	e := newEnv(t)
	e.user("admin-sig@x.io", auth.RoleAdmin)
	s := e.signIn("admin-sig@x.io")
	ch := map[string]any{"kind": "slack", "name": "s1", "secret_ref": "secret:HOOK", "config": map[string]string{"signing_secret_ref": "env:STACKURITY_SECRET_SIGN"}}
	if code := s.do("POST", "/api/v1/channels", ch, nil); code != 403 {
		t.Errorf("env: signing secret by a workspace admin: %d", code)
	}
	ch["config"] = map[string]string{"signing_secret_ref": "plain-value"}
	if code := s.do("POST", "/api/v1/channels", ch, nil); code != 400 {
		t.Errorf("not a reference: %d", code)
	}
	ch["config"] = map[string]string{"signing_secret_ref": "secret:SLACK_SIGNING"}
	var c store.Channel
	if code := s.do("POST", "/api/v1/channels", ch, &c); code != 201 || !strings.Contains(string(c.Config), `"signing_secret_ref":"secret:SLACK_SIGNING"`) {
		t.Errorf("stored reference: %d %s", code, c.Config)
	}
	wh := map[string]any{"kind": "webhook", "name": "w1", "config": map[string]string{"url": "https://x.example", "signing_secret_ref": "secret:X"}}
	if code := s.do("POST", "/api/v1/channels", wh, nil); code != 400 {
		t.Errorf("signing secret on a webhook: %d", code)
	}
}
