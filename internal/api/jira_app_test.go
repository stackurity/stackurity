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

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Connect Jira (jira_app.go): OAuth state, the code exchange, the sites,
// the setup lists, token storage and disconnecting, against a fake
// Atlassian.

const jiraCloud = "aaaabbbb-1111-2222-3333-ccccddddeeee"

type fakeAtlassianAPI struct {
	mu        sync.Mutex
	exchanges int
	n         int
	access    map[string]bool
	refresh   string
}

func (f *fakeAtlassianAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	issue := func() {
		f.n++
		at, rt := fmt.Sprintf("atl-access-%d-SECRET", f.n), fmt.Sprintf("atl-refresh-%d-SECRET", f.n)
		f.access[at], f.refresh = true, rt
		reply(200, map[string]any{"access_token": at, "refresh_token": rt, "expires_in": 3600, "scope": notify.JiraAppScopes})
	}
	authed := func() bool {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		return f.access[tok]
	}
	switch p := r.URL.Path; {
	case p == "/oauth/token":
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["client_id"] != "jira-client" || b["client_secret"] != "jira-secret" {
			reply(401, map[string]string{"error": "access_denied"})
			return
		}
		switch {
		case b["grant_type"] == "authorization_code" && (b["code"] == "good-code" || b["code"] == "again-code") &&
			b["redirect_uri"] == "https://stk.example/integrations/jira/oauth/callback":
			f.exchanges++
			issue()
		case b["grant_type"] == "authorization_code":
			f.exchanges++
			reply(403, map[string]string{"error": "invalid_grant", "error_description": "bad code"})
		case b["grant_type"] == "refresh_token" && b["refresh_token"] == f.refresh:
			issue()
		default:
			reply(403, map[string]string{"error": "invalid_grant", "error_description": "Unknown or invalid refresh token."})
		}
	case p == "/oauth/token/accessible-resources":
		if !authed() {
			reply(401, nil)
			return
		}
		reply(200, []map[string]any{{"id": jiraCloud, "name": "acme", "url": "https://acme.atlassian.net", "scopes": []string{"read:jira-work", "write:jira-work"}}})
	case strings.HasPrefix(p, "/ex/jira/"+jiraCloud+"/rest/api/3/"):
		if !authed() {
			reply(401, map[string]any{"errorMessages": []string{"unauthorized"}})
			return
		}
		switch strings.TrimPrefix(p, "/ex/jira/"+jiraCloud+"/rest/api/3") {
		case "/project/search":
			reply(200, map[string]any{"values": []map[string]string{{"key": "SEC", "name": "Security"}}, "isLast": true})
		case "/project/SEC":
			reply(200, map[string]any{"key": "SEC", "name": "Security", "issueTypes": []map[string]any{{"name": "Task"}, {"name": "Sub-task", "subtask": true}}})
		case "/project/SEC/statuses":
			reply(200, []map[string]any{{"name": "Task", "statuses": []map[string]any{{"name": "Done", "statusCategory": map[string]string{"key": "done"}}}}})
		case "/priority":
			reply(200, []map[string]string{{"name": "High"}})
		default:
			reply(404, map[string]any{"errorMessages": []string{"no route"}})
		}
	default:
		reply(404, nil)
	}
}

type jiraAppFx struct {
	e   *env
	atl *fakeAtlassianAPI
}

func jiraAppSetup(t *testing.T, configured bool) *jiraAppFx {
	t.Helper()
	fake := &fakeAtlassianAPI{access: map[string]bool{}}
	fs := httptest.NewServer(fake)
	t.Cleanup(fs.Close)
	box, err := secrets.NewBox(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, func(s *api.Server) {
		st := s.Store
		res := secrets.Resolver{Stored: func(ctx context.Context, name string) (string, error) { return st.SecretValue(ctx, box, name) }}
		s.SecretBox, s.Secrets, s.BaseURL = box, res, "https://stk.example"
		s.Dispatcher = &notify.Dispatcher{Store: s.Store, Sender: notify.NewSender(false), Secrets: res, BaseURL: "https://stk.example",
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Box: box}
		if configured {
			s.Dispatcher.JiraApp = &notify.JiraApp{ClientID: "jira-client", ClientSecret: "jira-secret", Auth: fs.URL, API: fs.URL,
				HTTP: s.Dispatcher.Sender.HTTP}
		}
	})
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("other-admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	return &jiraAppFx{e: e, atl: fake}
}

// start begins Connect Jira as s and returns the state Atlassian would
// send back.
func (f *jiraAppFx) start(t *testing.T, s *session, body map[string]any) string {
	t.Helper()
	var out struct{ URL string }
	if body == nil {
		body = map[string]any{"return_to": "/settings/integrations/new/jira"}
	}
	if code := s.do("POST", "/api/v1/integrations/jira/install", body, &out); code != 200 {
		t.Fatalf("install: %d", code)
	}
	u, err := url.Parse(out.URL)
	if err != nil || u.Path != "/authorize" {
		t.Fatalf("authorize url %q", out.URL)
	}
	q := u.Query()
	if q.Get("client_id") != "jira-client" || q.Get("scope") != notify.JiraAppScopes || q.Get("audience") != "api.atlassian.com" ||
		q.Get("prompt") != "consent" || q.Get("redirect_uri") != "https://stk.example/integrations/jira/oauth/callback" || len(q.Get("state")) < 40 {
		t.Fatalf("authorize query %v", q)
	}
	return q.Get("state")
}

type jiraAnswer struct {
	Connection  store.JiraConnection `json:"connection"`
	ReturnTo    string               `json:"return_to"`
	Reconnected bool                 `json:"reconnected"`
}

func rawBody(t *testing.T, s *session, method, path string) string {
	t.Helper()
	resp := s.req(method, path, nil, map[string]string{"X-Stackurity-CSRF": "1"})
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestJiraAppOAuthState(t *testing.T) {
	f := jiraAppSetup(t, true)
	e := f.e
	admin, other := e.login("admin@x.io"), e.login("other-admin@x.io")

	var opts map[string]any
	admin.do("GET", "/api/v1/notification-options", nil, &opts)
	if opts["jira_app"] != true {
		t.Errorf("options: %v", opts)
	}
	// Only admins start it.
	if code := e.login("viewer@x.io").do("POST", "/api/v1/integrations/jira/install", map[string]any{}, nil); code != 403 {
		t.Errorf("viewer: %d", code)
	}
	state := f.start(t, admin, nil)

	// Bound to the person who started it (and a refusal does not use it up).
	if code := other.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 400 {
		t.Errorf("another person's state: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": "guessed"}, nil); code != 400 {
		t.Errorf("guessed state: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code"}, nil); code != 400 {
		t.Errorf("no state: %d", code)
	}
	ctx := context.Background()
	if _, _, err := e.st.CreateWorkspace(ctx, "Beta", "", "beta@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	beta := e.login("beta@x.io")
	if code := beta.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 400 {
		t.Errorf("another organisation's state: %d", code)
	}
	if f.atl.exchanges != 0 {
		t.Fatalf("Atlassian was asked %d times for refused states", f.atl.exchanges)
	}

	// The person who started it finishes it, once.
	var got jiraAnswer
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": state}, &got); code != 201 {
		t.Fatalf("finish: %d", code)
	}
	if len(got.Connection.Sites) != 1 || got.Connection.Sites[0].ID != jiraCloud || got.Connection.Status != "active" ||
		got.ReturnTo != "/settings/integrations/new/jira" || got.Reconnected {
		t.Fatalf("answer = %+v", got)
	}
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": state}, nil); code != 400 {
		t.Errorf("a state worked twice: %d", code)
	}
	// Expired.
	late := f.start(t, admin, nil)
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE jira_oauth_states SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": late}, nil); code != 400 {
		t.Errorf("expired state: %d", code)
	}
	// A code Atlassian refuses: 502, nothing saved.
	bad := f.start(t, admin, nil)
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "wrong", "state": bad}, nil); code != 502 {
		t.Errorf("refused code: %d", code)
	}
	var list struct{ Items []store.JiraConnection }
	admin.do("GET", "/api/v1/integrations/jira/connections", nil, &list)
	if len(list.Items) != 1 {
		t.Fatalf("connections = %+v", list.Items)
	}
	// A return path to another site is not kept.
	off := f.start(t, admin, map[string]any{"return_to": "//evil.example/x"})
	var back jiraAnswer
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "again-code", "state": off}, &back); code != 201 ||
		back.ReturnTo != "/integrations" {
		t.Errorf("return_to = %q (%d)", back.ReturnTo, code)
	}

	// Reconnect: bound to a connection of this organisation; the same
	// connection gets the new grant.
	if code := beta.do("POST", "/api/v1/integrations/jira/install", map[string]any{"connection_id": got.Connection.ID}, nil); code != 404 {
		t.Errorf("reconnecting another organisation's connection: %d", code)
	}
	re := f.start(t, admin, map[string]any{"connection_id": got.Connection.ID, "return_to": "/settings/integrations"})
	var again jiraAnswer
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": re}, &again); code != 200 ||
		!again.Reconnected || again.Connection.ID != got.Connection.ID {
		t.Errorf("reconnect: %d %+v", code, again)
	}
	// Another organisation sees none of them.
	var none struct{ Items []store.JiraConnection }
	beta.do("GET", "/api/v1/integrations/jira/connections", nil, &none)
	if len(none.Items) != 0 {
		t.Errorf("another organisation lists %+v", none.Items)
	}
	if code := beta.do("GET", "/api/v1/integrations/jira/connections/"+itoa(got.Connection.ID)+"/projects?site="+jiraCloud, nil, nil); code != 404 {
		t.Errorf("another organisation's projects: %d", code)
	}
}

// The tokens are sealed, never in the API's answers, never a stored secret
// another channel could reference; channels use the connection by id and
// site.
func TestJiraAppTokensAndChannels(t *testing.T) {
	f := jiraAppSetup(t, true)
	e := f.e
	admin := e.login("admin@x.io")
	state := f.start(t, admin, nil)
	var got jiraAnswer
	if code := admin.do("POST", "/api/v1/integrations/jira/oauth", map[string]string{"code": "good-code", "state": state}, &got); code != 201 {
		t.Fatalf("finish: %d", code)
	}
	conn := got.Connection.ID
	base := "/api/v1/integrations/jira/connections/" + itoa(conn)

	// The setup lists, from the site.
	var projects struct{ Items []notify.JiraProject }
	if code := admin.do("GET", base+"/projects?site="+jiraCloud, nil, &projects); code != 200 || len(projects.Items) != 1 || projects.Items[0].Key != "SEC" {
		t.Fatalf("projects: %d %+v", code, projects)
	}
	var meta notify.JiraProjectMeta
	if code := admin.do("GET", base+"/projects/SEC?site="+jiraCloud, nil, &meta); code != 200 || len(meta.IssueTypes) != 2 ||
		meta.Statuses["Task"][0].Category != "done" || len(meta.Priorities) != 1 {
		t.Fatalf("project: %d %+v", code, meta)
	}
	if code := admin.do("GET", base+"/projects?site=not-a-site", nil, nil); code != 502 && code != 404 {
		t.Errorf("unknown site: %d", code)
	}
	if code := e.login("viewer@x.io").do("GET", base+"/projects?site="+jiraCloud, nil, nil); code != 403 {
		t.Errorf("viewer lists projects: %d", code)
	}

	// A channel on the connection: the address comes from the site.
	cfg := map[string]any{"auth": "oauth", "connection_id": conn, "cloud_id": jiraCloud, "url": "https://evil.example", "project": "SEC", "issue_type": "Task",
		"resolve_transition": "Done"}
	var ch store.Channel
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "jira", "name": "jira", "config": cfg}, &ch); code != 201 {
		t.Fatalf("channel: %d", code)
	}
	var cc notify.ChannelConfig
	_ = json.Unmarshal(ch.Config, &cc)
	if cc.URL != "https://acme.atlassian.net" || cc.Deployment != "cloud" || ch.SecretRef != "" {
		t.Errorf("channel config = %+v", cc)
	}
	for name, bad := range map[string]map[string]any{
		"site of no connection": {"auth": "oauth", "connection_id": conn, "cloud_id": "other-site", "project": "SEC"},
		"unknown connection":    {"auth": "oauth", "connection_id": conn + 100, "cloud_id": jiraCloud, "project": "SEC"},
		"with a secret_ref":     {"auth": "oauth", "connection_id": conn, "cloud_id": jiraCloud, "project": "SEC", "secret": true},
	} {
		body := map[string]any{"kind": "jira", "name": "bad " + name, "config": bad}
		if bad["secret"] == true {
			delete(bad, "secret")
			body["secret_ref"] = "secret:X"
		}
		if code := admin.do("POST", "/api/v1/channels", body, nil); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code := admin.do("POST", "/api/v1/channels/"+itoa(ch.ID)+"/test", nil, nil); code != 200 {
		t.Errorf("send test: %d", code)
	}

	// No answer carries a token.
	for _, p := range []string{"/api/v1/integrations/jira/connections", "/api/v1/channels", "/api/v1/secrets",
		"/api/v1/audit", "/api/v1/notification-options"} {
		if body := rawBody(t, admin, "GET", p); strings.Contains(body, "SECRET") || strings.Contains(body, "atl-") {
			t.Errorf("%s returns a token: %s", p, body)
		}
	}
	// Sealed in the database, for this organisation and connection only.
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var access, refresh []byte
	if err := e.st.Pool.QueryRow(ctx, `SELECT access_token, refresh_token FROM jira_connections WHERE id = $1`, conn).Scan(&access, &refresh); err != nil {
		t.Fatal(err)
	}
	if len(access) == 0 || bytes.Contains(access, []byte("atl-")) || bytes.Contains(refresh, []byte("atl-")) {
		t.Error("a token is stored in clear")
	}
	if _, err := e.api.SecretBox.Open(tenant.DefaultWorkspace+1, fmt.Sprintf("jira-oauth-refresh:%d", conn), refresh); err == nil {
		t.Error("the refresh token opens for another workspace")
	}
	if _, err := e.api.SecretBox.Open(tenant.DefaultWorkspace, fmt.Sprintf("jira-oauth-refresh:%d", conn+1), refresh); err == nil {
		t.Error("the refresh token opens for another connection")
	}
	var n int
	if err := e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM workspace_secrets`).Scan(&n); err != nil || n != 0 {
		t.Errorf("stored secrets: %d %v", n, err)
	}

	// Disconnect: the tokens go, the channel is switched off and says why.
	var del struct {
		ChannelsDisabled int    `json:"channels_disabled"`
		RevokeURL        string `json:"revoke_url"`
	}
	if code := admin.do("DELETE", base, nil, &del); code != 200 || del.ChannelsDisabled != 1 || del.RevokeURL == "" {
		t.Fatalf("disconnect: %d %+v", code, del)
	}
	var chans struct{ Items []store.Channel }
	admin.do("GET", "/api/v1/channels", nil, &chans)
	var after store.Channel
	for _, c := range chans.Items {
		if c.ID == ch.ID {
			after = c
		}
	}
	if after.Enabled || !strings.Contains(after.LastError, "disconnected") {
		t.Errorf("channel after disconnect: %+v", after)
	}
	if err := e.st.Pool.QueryRow(tenant.System(ctx), `SELECT count(*) FROM jira_connections`).Scan(&n); err != nil || n != 0 {
		t.Errorf("connections after disconnect: %d %v", n, err)
	}
}

// Without the app, Connect Jira is off and API-token channels work as before.
func TestJiraAppOff(t *testing.T) {
	f := jiraAppSetup(t, false)
	admin := f.e.login("admin@x.io")
	var opts map[string]any
	admin.do("GET", "/api/v1/notification-options", nil, &opts)
	if opts["jira_app"] != false {
		t.Errorf("options: %v", opts)
	}
	if code := admin.do("POST", "/api/v1/integrations/jira/install", map[string]any{}, nil); code != 404 {
		t.Errorf("install without the app: %d", code)
	}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "jira", "name": "oauth",
		"config": map[string]any{"auth": "oauth", "connection_id": 1, "cloud_id": jiraCloud, "project": "SEC"}}, nil); code != 400 {
		t.Errorf("oauth channel without the app: %d", code)
	}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "jira", "name": "token", "secret_ref": "secret:JIRA",
		"config": map[string]any{"url": "https://acme.atlassian.net", "username": "bot@x.io", "project": "SEC"}}, nil); code != 201 {
		t.Errorf("API-token channel: %d", code)
	}
}
