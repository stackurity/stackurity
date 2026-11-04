package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// fakeAtlassian is Atlassian's authorisation server and API gateway for
// Connect Jira: the token endpoint (authorization code, and refresh with
// rotation: a refresh token works once, then it is disabled),
// accessible-resources, and /ex/jira/{cloudid}/... forwarded to a fakeJira
// that accepts only the current access token.
type fakeAtlassian struct {
	mu      sync.Mutex
	t       *testing.T
	jira    *fakeJira
	cloudID string
	site    string
	// codes are the authorization codes that work, once each.
	codes map[string]bool
	// access tokens that work, and the one refresh token that works.
	access  map[string]bool
	refresh string
	n       int // tokens issued
	// refreshes counts refresh grants answered; reused counts refresh
	// tokens presented after they were rotated away.
	refreshes, reused int
	// refreshDelay holds each refresh, so concurrent refreshes overlap.
	refreshDelay time.Duration
	// revoked: the grant was revoked; every refresh answers invalid_grant.
	revoked bool
	// failRefresh answers refreshes with 503 (an outage).
	failRefresh bool
	expiresIn   int
	// gotBodies keeps every request body sent to the token endpoint.
	gotBodies []map[string]string
}

const fakeCloudID = "11223344-a1b2-3b33-c444-def123456789"

func newFakeAtlassian(t *testing.T, fj *fakeJira) (*fakeAtlassian, *httptest.Server) {
	fa := &fakeAtlassian{t: t, jira: fj, cloudID: fakeCloudID, site: "https://acme.atlassian.net",
		codes: map[string]bool{"code-1": true}, access: map[string]bool{}, expiresIn: 3600}
	fj.bearer = fa.validAccess
	srv := httptest.NewServer(fa)
	t.Cleanup(srv.Close)
	return fa, srv
}

func (fa *fakeAtlassian) validAccess(tok string) bool {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return fa.access[tok]
}

// issue makes a new token pair; the previous refresh token stops working.
func (fa *fakeAtlassian) issue() map[string]any {
	fa.n++
	at, rt := fmt.Sprintf("at-%d", fa.n), fmt.Sprintf("rt-%d", fa.n)
	fa.access[at] = true
	fa.refresh = rt
	return map[string]any{"access_token": at, "refresh_token": rt, "expires_in": fa.expiresIn, "scope": JiraAppScopes, "token_type": "Bearer"}
}

func (fa *fakeAtlassian) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if rest, ok := strings.CutPrefix(r.URL.Path, "/ex/jira/"+fa.cloudID); ok {
		r2 := r.Clone(r.Context())
		r2.URL.Path = rest
		fa.jira.ServeHTTP(w, r2)
		return
	}
	reply := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.Method == "POST" && r.URL.Path == "/oauth/token":
		var body map[string]string
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			reply(400, map[string]string{"error": "invalid_request"})
			return
		}
		if body["client_id"] != "cid" || body["client_secret"] != "csecret" {
			reply(401, map[string]string{"error": "access_denied", "error_description": "Unauthorized"})
			return
		}
		switch body["grant_type"] {
		case "authorization_code":
			fa.mu.Lock()
			defer fa.mu.Unlock()
			fa.gotBodies = append(fa.gotBodies, body)
			if !fa.codes[body["code"]] || body["redirect_uri"] != "https://stk.example/integrations/jira/oauth/callback" {
				reply(403, map[string]string{"error": "invalid_grant", "error_description": "Invalid authorization code"})
				return
			}
			delete(fa.codes, body["code"])
			reply(200, fa.issue())
		case "refresh_token":
			if fa.refreshDelay > 0 {
				time.Sleep(fa.refreshDelay)
			}
			fa.mu.Lock()
			defer fa.mu.Unlock()
			fa.gotBodies = append(fa.gotBodies, body)
			if fa.failRefresh {
				reply(503, map[string]string{"error": "temporarily_unavailable"})
				return
			}
			if fa.revoked || body["refresh_token"] != fa.refresh {
				if !fa.revoked {
					fa.reused++
				}
				reply(403, map[string]string{"error": "invalid_grant", "error_description": "Unknown or invalid refresh token."})
				return
			}
			fa.refreshes++
			reply(200, fa.issue())
		default:
			reply(400, map[string]string{"error": "unsupported_grant_type"})
		}
	case r.Method == "GET" && r.URL.Path == "/oauth/token/accessible-resources":
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !fa.validAccess(tok) {
			reply(401, map[string]string{"message": "Unauthorized"})
			return
		}
		reply(200, []map[string]any{
			{"id": fa.cloudID, "name": "acme", "url": fa.site, "scopes": []string{"read:jira-work", "write:jira-work"}},
			// Another product's site, and junk: left out.
			{"id": "conf-1", "name": "wiki", "url": "https://acme.atlassian.net", "scopes": []string{"read:confluence-content.all"}},
			{"id": "../x", "name": "bad", "url": "https://evil.example", "scopes": []string{"read:jira-work"}},
			{"id": "plain", "name": "http", "url": "http://insecure.example", "scopes": []string{"read:jira-work"}},
		})
	default:
		reply(404, map[string]string{"message": "no route " + r.URL.Path})
	}
}

// expireAll makes every access token issued so far stop working (Jira
// refuses them before their expiry: revoked, or a clock skew).
func (fa *fakeAtlassian) expireAll() {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	fa.access = map[string]bool{}
}

func testBox(t *testing.T) *secrets.Box {
	t.Helper()
	box, err := secrets.NewBox([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return box
}

// connectJira gives the fixture's dispatcher the app and a connection made
// with code-1, whose access token expires in expiresIn.
func (f *fixture) connectJira(ctx context.Context, fa *fakeAtlassian, srvURL string) int64 {
	f.t.Helper()
	f.d.JiraApp = &JiraApp{ClientID: "cid", ClientSecret: "csecret", Auth: srvURL, API: srvURL, HTTP: f.d.Sender.HTTP}
	f.d.Box = testBox(f.t)
	tok, scopes, err := f.d.JiraApp.Exchange(ctx, "code-1", "https://stk.example/integrations/jira/oauth/callback")
	if err != nil {
		f.t.Fatal(err)
	}
	sites, err := f.d.JiraApp.AccessibleSites(ctx, tok.Access)
	if err != nil {
		f.t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].ID != fakeCloudID || sites[0].URL != "https://acme.atlassian.net" {
		f.t.Fatalf("sites = %+v", sites)
	}
	id, err := f.st.SaveJiraConnection(ctx, f.d.Box, 0, sites, scopes, tok, 0)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// addJiraOAuth adds a Connect Jira channel (and a P4-and-above route).
func (f *fixture) addJiraOAuth(ctx context.Context, conn int64, mutate func(*ChannelConfig)) *store.Channel {
	f.t.Helper()
	cfg := ChannelConfig{Auth: JiraAuthOAuth, ConnectionID: conn, CloudID: fakeCloudID, URL: "https://acme.atlassian.net", Project: "SEC",
		IssueType: "Task", Labels: []string{"security"},
		Priorities: map[string]string{"P1": "Highest", "P2": "High", "P3": "Medium", "P4": "Low"}, ResolveTransition: "Done"}
	if mutate != nil {
		mutate(&cfg)
	}
	if err := ValidateChannel(KindJira, cfg, false, true); err != nil {
		f.t.Fatal(err)
	}
	raw, _ := json.Marshal(cfg)
	ch, err := f.st.CreateChannel(ctx, KindJira, fmt.Sprintf("jira-oauth-%d", time.Now().UnixNano()), raw, "")
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.st.SaveRoute(ctx, store.Route{Name: "jira-" + ch.Name, ChannelID: ch.ID, Enabled: true, MinPriority: "P4",
		Timezone: "UTC", MaxPerHour: 1}); err != nil {
		f.t.Fatal(err)
	}
	return ch
}

// jiraMode sets up a Jira channel of the fixture in one of the modes the
// lifecycle tests run in, and returns the fake Jira, the channel and the
// site address issue links start with.
func (f *fixture) jiraMode(ctx context.Context, mode string) (*fakeJira, *fakeAtlassian, *store.Channel, string) {
	f.t.Helper()
	switch mode {
	case "oauth":
		fj, _ := newFakeJira(f.t, true)
		fa, srv := newFakeAtlassian(f.t, fj)
		conn := f.connectJira(ctx, fa, srv.URL)
		return fj, fa, f.addJiraOAuth(ctx, conn, nil), "https://acme.atlassian.net"
	case "cloud", "datacenter":
		fj, srv := newFakeJira(f.t, mode == "cloud")
		return fj, nil, f.addJira(ctx, srv.URL, mode == "cloud", nil), srv.URL
	}
	f.t.Fatalf("mode %s", mode)
	return nil, nil, nil, ""
}

func TestJiraAppFromEnv(t *testing.T) {
	t.Setenv("STACKURITY_JIRA_CLIENT_ID", "")
	t.Setenv("STACKURITY_JIRA_CLIENT_SECRET", "")
	if a, err := JiraAppFromEnv(); a != nil || err != nil {
		t.Fatalf("unset: %v %v", a, err)
	}
	t.Setenv("STACKURITY_JIRA_CLIENT_ID", "cid")
	if _, err := JiraAppFromEnv(); err == nil {
		t.Fatal("client id without secret accepted")
	}
	f := t.TempDir() + "/secret"
	if err := os.WriteFile(f, []byte("csecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_JIRA_CLIENT_SECRET_FILE", f)
	a, err := JiraAppFromEnv()
	if err != nil || a.ClientID != "cid" || a.ClientSecret != "csecret" {
		t.Fatalf("app = %+v, %v", a, err)
	}
	u := a.AuthorizeURL("st", "https://stk.example/integrations/jira/oauth/callback")
	for _, want := range []string{"https://auth.atlassian.com/authorize?", "audience=api.atlassian.com", "client_id=cid", "prompt=consent",
		"response_type=code", "state=st", "scope=read%3Ajira-work+write%3Ajira-work+offline_access",
		"redirect_uri=https%3A%2F%2Fstk.example%2Fintegrations%2Fjira%2Foauth%2Fcallback"} {
		if !strings.Contains(u, want) {
			t.Errorf("authorize URL lacks %s: %s", want, u)
		}
	}
	if a.SiteBase(fakeCloudID) != "https://api.atlassian.com/ex/jira/"+fakeCloudID {
		t.Errorf("site base = %s", a.SiteBase(fakeCloudID))
	}
}

// The issue lifecycle of TestJiraIssueLifecycle with Connect Jira: the
// same one issue per incident, comments, priority and transition, through
// the API gateway with bearer tokens that are refreshed and rotated as
// they expire.
func TestJiraOAuthIssueLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, fa, ch, site := f.jiraMode(ctx, "oauth")
	// Tokens that expire within the refresh margin: refreshed before use.
	fa.expiresIn = 60
	if _, err := f.st.Pool.Exec(ctx, `UPDATE jira_connections SET expires_at = now()`); err != nil {
		t.Fatal(err)
	}
	if err := f.d.SendTest(ctx, ch); err != nil {
		t.Fatalf("send test: %v", err)
	}
	if len(fj.snapshot()) != 0 {
		t.Fatal("send test created an issue")
	}
	f.addAsset("web-1", "production", true)
	f.addAsset("web-2", "production", false)
	f.setFindings("web-1", "web-2")
	f.tick()
	issues := fj.snapshot()
	if len(issues) != 1 || issues[0].Priority != "Highest" || issues[0].Summary != "[P1] CVE-2021-23337 in lodash on 2 assets" {
		t.Fatalf("issues = %+v", issues)
	}
	incs, _, _ := f.st.ListIncidents(ctx, store.IncidentFilter{})
	if len(incs[0].Issues) != 1 || incs[0].Issues[0].URL != site+"/browse/SEC-1" {
		t.Errorf("issue link = %+v (want the site's address, not the gateway's)", incs[0].Issues)
	}
	f.addAsset("web-3", "staging", false)
	f.setFindings("web-1", "web-2", "web-3")
	f.tick()
	f.setFindings()
	f.tick()
	f.tick()
	is := fj.snapshot()[0]
	if len(is.Comments) != 2 || is.Status != "Done" || fj.creates != 1 {
		t.Fatalf("lifecycle: status %s, %d created, comments %s", is.Status, fj.creates, is.Comments)
	}
	for _, d := range jiraDeliveries(t, f.st, ctx, ch.ID) {
		if d.Status != "sent" {
			t.Errorf("delivery %d %s: %s %s", d.ID, d.Event, d.Status, d.LastError)
		}
	}
	fa.mu.Lock()
	refreshes, reused := fa.refreshes, fa.reused
	fa.mu.Unlock()
	if refreshes == 0 || reused != 0 {
		t.Errorf("refreshes %d, rotated-away refresh tokens used %d", refreshes, reused)
	}
	// The rotated refresh token is what is stored: one more refresh works.
	if _, _, err := f.st.JiraAccessToken(ctx, f.d.Box, connOf(t, ch), true, -1, f.d.JiraApp.Refresh); err != nil {
		t.Fatalf("refresh with the stored token: %v", err)
	}
}

func connOf(t *testing.T, ch *store.Channel) int64 {
	var cfg ChannelConfig
	if err := json.Unmarshal(ch.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.ConnectionID
}

// Two workers refresh the same expired token at once. Atlassian disables a
// refresh token when it is used, so a second use would fail and lose the
// connection: the second worker must wait for the first and use its new
// token. Negative control: without the row lock (two refreshes from the
// same stored token), the second is refused as reuse.
func TestJiraOAuthConcurrentRefresh(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, _ := newFakeJira(t, true)
	fa, srv := newFakeAtlassian(t, fj)
	conn := f.connectJira(ctx, fa, srv.URL)
	if _, err := f.st.Pool.Exec(ctx, `UPDATE jira_connections SET expires_at = now() - interval '1 minute' WHERE id = $1`, conn); err != nil {
		t.Fatal(err)
	}
	fa.refreshDelay = 300 * time.Millisecond
	var wg sync.WaitGroup
	toks := make([]string, 4)
	errs := make([]error, 4)
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], _, errs[i] = f.st.JiraAccessToken(ctx, f.d.Box, conn, false, 0, f.d.JiraApp.Refresh)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d: %v", i, err)
		}
		if toks[i] != toks[0] || !fa.validAccess(toks[i]) {
			t.Errorf("worker %d got %q, worker 0 %q", i, toks[i], toks[0])
		}
	}
	if fa.refreshes != 1 || fa.reused != 0 {
		t.Fatalf("refreshes %d, reused %d: concurrent workers must refresh once", fa.refreshes, fa.reused)
	}
	c, _ := f.st.GetJiraConnection(ctx, conn)
	if c.Status != store.JiraStatusActive {
		t.Fatalf("status %s: %s", c.Status, c.StatusReason)
	}

	// Two forced refreshes for the same refused token (both workers saw
	// Jira answer 401 to version v): one refreshes, the other uses it.
	_, v, err := f.st.JiraAccessToken(ctx, f.d.Box, conn, false, 0, f.d.JiraApp.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	before := fa.refreshes
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], _, errs[i] = f.st.JiraAccessToken(ctx, f.d.Box, conn, true, v, f.d.JiraApp.Refresh)
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil || toks[i] != toks[0] {
			t.Fatalf("forced worker %d: %q %v", i, toks[i], err)
		}
	}
	if fa.refreshes != before+1 || fa.reused != 0 {
		t.Fatalf("forced refreshes: %d (want 1), reused %d", fa.refreshes-before, fa.reused)
	}

	// Negative control: the same refresh token used twice (what two
	// workers without the lock would do) is refused the second time.
	rt := fa.refresh
	if _, err := f.d.JiraApp.Refresh(ctx, rt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.JiraApp.Refresh(ctx, rt); !errors.Is(err, store.ErrJiraGrantRevoked) {
		t.Fatalf("reused refresh token: %v", err)
	}
}

// A connection whose refresh token Atlassian refuses (revoked by the
// person, expired after 90 days unused, password changed) is marked
// reconnect_needed, its channels say so, and the delivery fails at once
// with the reason: never a silent failure. An outage, by contrast, is
// retried and leaves the connection as it is. Reconnecting restores it.
func TestJiraOAuthRevokedNeedsReconnect(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, fa, ch, _ := f.jiraMode(ctx, "oauth")
	conn := connOf(t, ch)
	fa.expireAll()
	if _, err := f.st.Pool.Exec(ctx, `UPDATE jira_connections SET expires_at = now() WHERE id = $1`, conn); err != nil {
		t.Fatal(err)
	}

	// An outage at Atlassian: retried, the connection stays active.
	fa.failRefresh = true
	f.addAsset("web-1", "production", true)
	f.setFindings("web-1")
	f.tick()
	ds := jiraDeliveries(t, f.st, ctx, ch.ID)
	if len(ds) != 1 || ds[0].Status != "pending" || !strings.Contains(ds[0].LastError, "HTTP 503") {
		t.Fatalf("after an outage: %+v", ds)
	}
	if c, _ := f.st.GetJiraConnection(ctx, conn); c.Status != store.JiraStatusActive {
		t.Fatalf("an outage marked the connection %s", c.Status)
	}

	// Revoked: the delivery fails with the reason, the connection and the
	// channel say reconnect.
	fa.failRefresh, fa.revoked = false, true
	if _, err := f.st.Pool.Exec(ctx, `UPDATE deliveries SET next_attempt = now() WHERE id = $1`, ds[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.Deliver(ctx); err != nil {
		t.Fatal(err)
	}
	ds = jiraDeliveries(t, f.st, ctx, ch.ID)
	if ds[0].Status != "failed" || !strings.Contains(ds[0].LastError, "needs reconnecting") {
		t.Fatalf("after revocation: %s %s", ds[0].Status, ds[0].LastError)
	}
	c, _ := f.st.GetJiraConnection(ctx, conn)
	if c.Status != store.JiraStatusReconnect || !strings.Contains(c.StatusReason, "invalid_grant") {
		t.Fatalf("connection: %s %q", c.Status, c.StatusReason)
	}
	got, _ := f.st.GetChannel(ctx, ch.ID)
	if !strings.Contains(got.LastError, "needs reconnecting") {
		t.Errorf("channel last error: %q", got.LastError)
	}
	// Send test says so too, without calling Atlassian again.
	n := len(fa.gotBodies)
	if err := f.d.SendTest(ctx, ch); err == nil || !strings.Contains(err.Error(), "needs reconnecting") {
		t.Errorf("send test: %v", err)
	}
	if len(fa.gotBodies) != n {
		t.Errorf("a connection that needs reconnecting called Atlassian")
	}
	if len(fj.snapshot()) != 0 {
		t.Fatal("an issue was created")
	}

	// Reconnect (a new grant for the same connection): active again.
	fa.revoked = false
	fa.codes["code-2"] = true
	tok, scopes, err := f.d.JiraApp.Exchange(ctx, "code-2", "https://stk.example/integrations/jira/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.SaveJiraConnection(ctx, f.d.Box, conn, c.Sites, scopes, tok, 0); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.st.GetChannel(ctx, ch.ID); got.LastError != "" {
		t.Errorf("channel still says %q after reconnecting", got.LastError)
	}
	if err := f.d.SendTest(ctx, ch); err != nil {
		t.Fatalf("send test after reconnecting: %v", err)
	}
}

// A token Jira refuses before it expires is refreshed once and the
// request retried.
func TestJiraOAuthRefusedTokenRefreshed(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, fa, ch, _ := f.jiraMode(ctx, "oauth")
	fa.expireAll()
	if err := f.d.SendTest(ctx, ch); err != nil {
		t.Fatalf("send test: %v", err)
	}
	if fa.refreshes != 1 {
		t.Errorf("refreshes = %d", fa.refreshes)
	}
	_ = fj
}

// The setup lists come from the connection's site; another
// organisation's connection is not found.
func TestJiraOAuthSetupLists(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	fj, _ := newFakeJira(t, true)
	fa, srv := newFakeAtlassian(t, fj)
	conn := f.connectJira(ctx, fa, srv.URL)
	js, err := f.d.JiraSetup(ctx, conn, fakeCloudID)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := js.Projects(ctx, "")
	if err != nil || len(ps) != 2 || ps[0].Key != "OPS" || ps[1].Key != "SEC" {
		t.Fatalf("projects = %+v, %v", ps, err)
	}
	m, err := js.ProjectMeta(ctx, "SEC")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.IssueTypes) != 2 || m.IssueTypes[0].Name != "Task" || len(m.Statuses["Task"]) != 3 || m.Statuses["Task"][2].Category != "done" ||
		len(m.Priorities) != 4 {
		t.Fatalf("meta = %+v", m)
	}
	if _, err := js.ProjectMeta(ctx, "../x"); err == nil {
		t.Error("a path in the project key was accepted")
	}
	if _, err := f.d.JiraSetup(ctx, conn, "other-site"); err == nil {
		t.Error("a site the connection does not reach was accepted")
	}
	other, _, err := f.st.CreateWorkspace(context.Background(), "Other", "other", "o@x.io", "", "Correct horse battery 1!")
	if err != nil {
		t.Fatal(err)
	}
	octx := tenant.WithWorkspace(context.Background(), other.ID)
	if _, err := f.d.JiraSetup(octx, conn, fakeCloudID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another organisation's connection: %v", err)
	}
	if _, _, err := f.st.JiraAccessToken(octx, f.d.Box, conn, false, 0, f.d.JiraApp.Refresh); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("another organisation's token: %v", err)
	}
}

func TestJiraOAuthValidation(t *testing.T) {
	base := ChannelConfig{Auth: JiraAuthOAuth, ConnectionID: 1, CloudID: fakeCloudID, URL: "https://acme.atlassian.net", Project: "SEC"}
	if err := ValidateChannel(KindJira, base, false, false); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]func(*ChannelConfig){
		"secret":        nil,
		"datacenter":    func(c *ChannelConfig) { c.Deployment = JiraDataCenter },
		"no connection": func(c *ChannelConfig) { c.ConnectionID = 0 },
		"bad cloud id":  func(c *ChannelConfig) { c.CloudID = "../../x" },
		"username":      func(c *ChannelConfig) { c.Username = "a@b.c" },
		"other auth":    func(c *ChannelConfig) { c.Auth = "basic" },
	} {
		cfg := base
		hasSecret := name == "secret"
		if c != nil {
			c(&cfg)
		}
		if err := ValidateChannel(KindJira, cfg, hasSecret, false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// API-token channels cannot carry a connection.
	tokenCfg := ChannelConfig{URL: "https://acme.atlassian.net", Username: "a@b.c", Project: "SEC", ConnectionID: 1}
	if err := ValidateChannel(KindJira, tokenCfg, true, false); err == nil {
		t.Error("an API-token channel with a connection_id was accepted")
	}
}
