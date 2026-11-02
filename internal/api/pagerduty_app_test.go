package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
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

// "Connect PagerDuty" (pagerduty_app.go) against a fake PagerDuty: one
// identity service, and a REST API per region.

const (
	pdClientID     = "pd-client-1"
	pdClientSecret = "pd-client-secret-1"
	pdRedirect     = "https://stk.example/integrations/pagerduty/oauth/callback"
)

// pdRoutingKey is the routing key the fake gives the integration on a
// service: 32 alphanumerics.
func pdRoutingKey(region, service string) string {
	k := "R0" + strings.ToUpper(region) + service + "KEY"
	return k + strings.Repeat("0", 32-len(k))
}

type pdIntegration struct {
	Service, Name, Type, Region string
}

// fakePD is PagerDuty's identity service (token endpoint) and REST API.
type fakePD struct {
	mu         sync.Mutex
	challenges map[string]string // code -> PKCE challenge it was issued for
	tokenHits  int
	apiHits    map[string]int // region -> REST requests
	created    []pdIntegration
	deletes    int
	services   map[string]int // region -> number of services
}

func newFakePD() *fakePD {
	return &fakePD{challenges: map[string]string{}, apiHits: map[string]int{}, services: map[string]int{"us": 230, "eu": 3}}
}

// authorize is the person agreeing on PagerDuty's consent page: the code
// is issued for the challenge in the authorize URL.
func (f *fakePD) authorize(code, challenge string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.challenges[code] = challenge
}

func pdIDToken(aud string) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]string{"alg": "RS256"}) + "." + enc(map[string]any{"aud": []string{aud, pdClientID}, "sub": "x@example.com"}) + ".sig"
}

func (f *fakePD) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokenHits++
	_ = r.ParseForm()
	fm := r.PostForm
	code := fm.Get("code")
	challenge, ok := f.challenges[code]
	delete(f.challenges, code) // codes work once
	if r.Method != "POST" || !ok || fm.Get("grant_type") != "authorization_code" || fm.Get("client_id") != pdClientID ||
		fm.Get("client_secret") != pdClientSecret || fm.Get("redirect_uri") != pdRedirect || notify.PKCEChallenge(fm.Get("code_verifier")) != challenge {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "bad code or verifier"})
		return
	}
	region, scope := "us", "openid services.read services.write"
	switch {
	case strings.HasPrefix(code, "eu-"):
		region = "eu"
	case strings.HasPrefix(code, "readonly-"):
		scope = "openid services.read"
	}
	aud := "https://api.pagerduty.com"
	if region == "eu" {
		aud = "https://api.eu.pagerduty.com"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "pd-token-" + region, "refresh_token": "pd-refresh-" + region,
		"token_type": "bearer", "scope": scope, "expires_in": 86400, "id_token": pdIDToken(aud)})
}

func (f *fakePD) api(region string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.apiHits[region]++
		if r.Header.Get("Authorization") != "Bearer pd-token-"+region || r.Header.Get("Accept") != "application/vnd.pagerduty+json;version=2" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "Unauthorized", "code": 2006}})
			return
		}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		switch {
		case r.Method == "GET" && r.URL.Path == "/services":
			limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
			offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
			if limit > 100 || limit <= 0 {
				w.WriteHeader(400)
				return
			}
			var all []map[string]string
			for i := 0; i < f.services[region]; i++ {
				name := fmt.Sprintf("Service %03d", i)
				if q := r.URL.Query().Get("query"); q != "" && !strings.Contains(name, q) {
					continue
				}
				all = append(all, map[string]string{"id": fmt.Sprintf("PS%03d", i), "name": name, "type": "service",
					"html_url": "https://acme.pagerduty.com/service-directory/" + fmt.Sprintf("PS%03d", i)})
			}
			page := []map[string]string{}
			if offset < len(all) {
				page = all[offset:min(offset+limit, len(all))]
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"services": page, "limit": limit, "offset": offset, "more": offset+limit < len(all)})
		case r.Method == "POST" && len(parts) == 3 && parts[0] == "services" && parts[2] == "integrations":
			var body struct {
				Integration struct {
					Type    string `json:"type"`
					Name    string `json:"name"`
					Service struct{ ID, Type string }
				} `json:"integration"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			svc := parts[1]
			if svc == "PFORBID" {
				w.WriteHeader(403)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"message": "Access Denied", "code": 2010}})
				return
			}
			if body.Integration.Service.ID != svc || body.Integration.Service.Type != "service_reference" {
				w.WriteHeader(400)
				return
			}
			f.created = append(f.created, pdIntegration{Service: svc, Name: body.Integration.Name, Type: body.Integration.Type, Region: region})
			in := map[string]any{"id": "PI" + svc, "type": body.Integration.Type, "name": body.Integration.Name,
				"html_url": "https://acme.pagerduty.com/services/" + svc + "/integrations/PI" + svc,
				"service":  map[string]string{"id": svc, "type": "service_reference", "summary": "Payments " + svc}}
			// One service answers without the key: it is read back.
			if svc != "PNOKEY" {
				in["integration_key"] = pdRoutingKey(region, svc)
			}
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"integration": in})
		case r.Method == "GET" && len(parts) == 4 && parts[2] == "integrations":
			_ = json.NewEncoder(w).Encode(map[string]any{"integration": map[string]any{"id": parts[3], "type": "events_api_v2_inbound_integration",
				"integration_key": pdRoutingKey(region, parts[1])}})
		case r.Method == "DELETE":
			f.deletes++
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}
}

type pdFx struct {
	e      *env
	pd     *fakePD
	events chan map[string]any
}

func pagerDutyAppSetup(t *testing.T) *pdFx {
	t.Helper()
	fake := newFakePD()
	identity := httptest.NewServer(http.HandlerFunc(fake.token))
	us := httptest.NewServer(fake.api("us"))
	eu := httptest.NewServer(fake.api("eu"))
	events := make(chan map[string]any, 8)
	enqueue := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		_ = json.NewDecoder(r.Body).Decode(&ev)
		events <- ev
		w.WriteHeader(202)
		_, _ = io.WriteString(w, `{"status":"success","message":"Event processed","dedup_key":"x"}`)
	}))
	for _, s := range []*httptest.Server{identity, us, eu, enqueue} {
		t.Cleanup(s.Close)
	}
	box, err := secrets.NewBox(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var st *store.Store
	e := newEnvWith(t, func(s *api.Server) {
		st = s.Store
		res := secrets.Resolver{Stored: func(ctx context.Context, name string) (string, error) { return st.SecretValue(ctx, box, name) }}
		s.SecretBox, s.Secrets, s.BaseURL = box, res, "https://stk.example"
		sender := notify.NewSender(false)
		sender.PagerDutyURL = enqueue.URL + "/v2/enqueue"
		s.Dispatcher = &notify.Dispatcher{Store: s.Store, Sender: sender, Secrets: res, BaseURL: "https://stk.example",
			Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			// HTTP is left nil: the guarded client (netguard, no
			// keep-alives) is the one under test; the default workspace
			// may reach the loopback fakes.
			PagerDutyApp: &notify.PagerDutyApp{ClientID: pdClientID, ClientSecret: pdClientSecret,
				Identity: identity.URL, APIUS: us.URL, APIEU: eu.URL}}
	})
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("other-admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	return &pdFx{e: e, pd: fake, events: events}
}

// start begins Connect PagerDuty as s, checks the consent URL, and returns
// the state with the PKCE challenge PagerDuty would have seen.
func (f *pdFx) start(t *testing.T, s *session) (state, challenge string) {
	t.Helper()
	var out struct{ URL string }
	if code := s.do("POST", "/api/v1/integrations/pagerduty/connect", map[string]string{"return_to": "/settings/integrations"}, &out); code != 200 {
		t.Fatalf("connect: %d", code)
	}
	u, err := url.Parse(out.URL)
	if err != nil || u.Path != "/oauth/authorize" {
		t.Fatalf("authorize url %q", out.URL)
	}
	q := u.Query()
	if q.Get("client_id") != pdClientID || q.Get("scope") != "services.read services.write" || q.Get("response_type") != "code" ||
		q.Get("redirect_uri") != pdRedirect || q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 || len(q.Get("state")) < 40 {
		t.Fatalf("authorize query %v", q)
	}
	if q.Has("code_verifier") || q.Has("client_secret") {
		t.Fatalf("the verifier or client secret is in the authorize URL: %v", q)
	}
	return q.Get("state"), q.Get("code_challenge")
}

type pdOAuthAnswer struct {
	Session  string                    `json:"session"`
	Region   string                    `json:"region"`
	ReturnTo string                    `json:"return_to"`
	Services []notify.PagerDutyService `json:"services"`
	More     bool                      `json:"more"`
	Error    struct{ Code, Message string }
}

type pdFinishAnswer struct {
	Channel     store.Channel `json:"channel"`
	ReturnTo    string        `json:"return_to"`
	ServiceName string        `json:"service_name"`
	Reused      bool          `json:"reused"`
	Error       struct{ Code, Message string }
}

// connect runs the OAuth step for code and returns the answer.
func (f *pdFx) connect(t *testing.T, s *session, code string) pdOAuthAnswer {
	t.Helper()
	state, challenge := f.start(t, s)
	f.pd.authorize(code, challenge)
	var got pdOAuthAnswer
	if c := s.do("POST", "/api/v1/integrations/pagerduty/oauth", map[string]string{"code": code, "state": state}, &got); c != 200 {
		t.Fatalf("oauth: %d %+v", c, got.Error)
	}
	return got
}

func (f *pdFx) connectRows(t *testing.T) (rows int, tokens int) {
	t.Helper()
	if err := f.e.st.Pool.QueryRow(tenant.System(context.Background()),
		`SELECT count(*), count(access_token) FROM pagerduty_connects`).Scan(&rows, &tokens); err != nil {
		t.Fatal(err)
	}
	return rows, tokens
}

func TestPagerDutyConnect(t *testing.T) {
	f := pagerDutyAppSetup(t)
	e := f.e
	admin := e.login("admin@x.io")

	var opts map[string]any
	admin.do("GET", "/api/v1/notification-options", nil, &opts)
	if opts["pagerduty_app"] != true {
		t.Errorf("notification-options = %v", opts)
	}
	if code := e.login("viewer@x.io").do("POST", "/api/v1/integrations/pagerduty/connect", map[string]string{}, nil); code != 403 {
		t.Errorf("viewer connect: %d", code)
	}

	got := f.connect(t, admin, "good-1")
	// 230 services over three pages of at most 100.
	if got.Region != "us" || len(got.Services) != 230 || got.More || got.ReturnTo != "/settings/integrations" || len(got.Session) < 40 {
		t.Fatalf("oauth answer: region %q, %d services, more %v, return %q", got.Region, len(got.Services), got.More, got.ReturnTo)
	}
	if got.Services[229].ID != "PS229" || got.Services[0].Name != "Service 000" {
		t.Errorf("services %+v ... %+v", got.Services[0], got.Services[229])
	}
	if f.pd.apiHits["us"] != 3 || f.pd.apiHits["eu"] != 0 {
		t.Errorf("API requests: %v", f.pd.apiHits)
	}
	// While choosing, the token is in the database sealed only.
	var sealed []byte
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT access_token FROM pagerduty_connects`).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if len(sealed) == 0 || bytes.Contains(sealed, []byte("pd-token-us")) {
		t.Error("the access token is stored in clear")
	}
	var dump string
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT string_agg(t::text, ' ') FROM pagerduty_connects t`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, "pd-token") || strings.Contains(dump, "pd-refresh") || strings.Contains(dump, got.Session) {
		t.Error("a token, the refresh token or the session handle is in the connect row")
	}
	// A query narrows the list.
	var some struct {
		Services []notify.PagerDutyService
		More     bool
	}
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/services", map[string]string{"session": got.Session, "query": "Service 22"}, &some); code != 200 ||
		len(some.Services) != 10 {
		t.Errorf("query: %d, %d services", code, len(some.Services))
	}

	// Another admin cannot use the session.
	other := e.login("other-admin@x.io")
	if code := other.do("POST", "/api/v1/integrations/pagerduty/services", map[string]string{"session": got.Session}, nil); code != 400 {
		t.Errorf("another person's session (services): %d", code)
	}
	if code := other.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": got.Session, "service_id": "PS007"}, nil); code != 400 {
		t.Errorf("another person's session (finish): %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": got.Session, "service_id": "../x"}, nil); code != 400 {
		t.Errorf("a service id that is not one: %d", code)
	}

	var fin pdFinishAnswer
	raw := json.RawMessage{}
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": got.Session, "service_id": "PS007"}, &raw); code != 201 {
		t.Fatalf("finish: %d %s", code, raw)
	}
	key := pdRoutingKey("us", "PS007")
	if bytes.Contains(raw, []byte(key)) {
		t.Error("the routing key is in the finish answer")
	}
	_ = json.Unmarshal(raw, &fin)
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(fin.Channel.Config, &cfg)
	if fin.Channel.Kind != "pagerduty" || !cfg.PagerDutyApp || cfg.Region != "us" || cfg.PagerDutyServiceID != "PS007" || cfg.PagerDutyIntegrationID != "PIPS007" ||
		fin.Channel.SecretRef != "secret:pagerduty-app-channel-"+itoa(fin.Channel.ID) || fin.Channel.Name != "PagerDuty Payments PS007" ||
		cfg.PagerDutyManageURL != "https://acme.pagerduty.com/services/PS007/integrations/PIPS007" || fin.ReturnTo != "/settings/integrations" {
		t.Fatalf("finish = %+v %+v", fin, cfg)
	}
	if len(f.pd.created) != 1 || f.pd.created[0] != (pdIntegration{Service: "PS007", Name: "Stackurity", Type: "events_api_v2_inbound_integration", Region: "us"}) {
		t.Errorf("integrations made in PagerDuty: %+v", f.pd.created)
	}
	// The OAuth token is gone: no connect row is left at all.
	if rows, tokens := f.connectRows(t); rows != 0 || tokens != 0 {
		t.Errorf("after finishing: %d connect rows, %d tokens", rows, tokens)
	}
	// The session worked once.
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": got.Session, "service_id": "PS008"}, nil); code != 400 {
		t.Errorf("a session worked twice: %d", code)
	}

	// The routing key is a sealed secret, never in clear and never
	// returned by the API.
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	var sealedKey []byte
	if err := e.st.Pool.QueryRow(ctx, `SELECT sealed FROM workspace_secrets WHERE name = $1`, "pagerduty-app-channel-"+itoa(fin.Channel.ID)).Scan(&sealedKey); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealedKey, []byte(key)) {
		t.Error("the routing key is stored in clear")
	}
	if v, err := e.st.SecretValue(ctx, e.api.SecretBox, "pagerduty-app-channel-"+itoa(fin.Channel.ID)); err != nil || v != key {
		t.Errorf("secret opens to %q (%v)", v, err)
	}
	for _, path := range []string{"/api/v1/channels", "/api/v1/channels/" + itoa(fin.Channel.ID), "/api/v1/secrets", "/api/v1/audit"} {
		var body json.RawMessage
		admin.do("GET", path, nil, &body)
		if bytes.Contains(body, []byte(key)) || bytes.Contains(body, []byte("pd-token")) {
			t.Errorf("%s shows a credential", path)
		}
	}
	if err := e.st.Pool.QueryRow(ctx, `SELECT string_agg(config::text || secret_ref, ' ') FROM channels`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, key) {
		t.Error("the routing key is in the channel row")
	}

	// Events go out on the existing path with that key.
	var test struct {
		OK    bool
		Error string
	}
	if code := admin.do("POST", "/api/v1/channels/"+itoa(fin.Channel.ID)+"/test", nil, &test); code != 200 || !test.OK {
		t.Fatalf("test event: %d %+v", code, test)
	}
	if ev := <-f.events; ev["routing_key"] != key {
		t.Errorf("event routing key %v", ev["routing_key"])
	}

	// Connecting the same service again refreshes the channel instead of
	// adding a second one.
	again := f.connect(t, admin, "good-2")
	var re pdFinishAnswer
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": again.Session, "service_id": "PS007"}, &re); code != 200 ||
		!re.Reused || re.Channel.ID != fin.Channel.ID {
		t.Errorf("reconnect: %d %+v", code, re)
	}
}

// States are single use, bound to the person and the organisation, and
// checked before PagerDuty is called; the PKCE verifier must match.
func TestPagerDutyConnectState(t *testing.T) {
	f := pagerDutyAppSetup(t)
	e := f.e
	admin, other := e.login("admin@x.io"), e.login("other-admin@x.io")
	state, challenge := f.start(t, admin)
	f.pd.authorize("good-1", challenge)

	oauth := func(s *session, code, state string) (int, pdOAuthAnswer) {
		var out pdOAuthAnswer
		c := s.do("POST", "/api/v1/integrations/pagerduty/oauth", map[string]string{"code": code, "state": state}, &out)
		return c, out
	}
	if c, out := oauth(other, "good-1", state); c != 400 || out.Error.Code != "pagerduty_state" {
		t.Errorf("another person's state: %d %+v", c, out.Error)
	}
	if c, _ := oauth(admin, "good-1", "forged-state-forged-state-forged-state-forged"); c != 400 {
		t.Errorf("forged state: %d", c)
	}
	if c, _ := oauth(admin, "good-1", ""); c != 400 {
		t.Errorf("no state: %d", c)
	}
	ctx := context.Background()
	if _, _, err := e.st.CreateWorkspace(ctx, "Beta", "", "beta@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	if c, _ := oauth(e.login("beta@x.io"), "good-1", state); c != 400 {
		t.Errorf("another organisation's state: %d", c)
	}
	if f.pd.tokenHits != 0 {
		t.Fatalf("PagerDuty was asked %d times for refused states", f.pd.tokenHits)
	}
	if c, out := oauth(admin, "good-1", state); c != 200 || out.Session == "" {
		t.Fatalf("own state: %d %+v", c, out.Error)
	}
	if c, _ := oauth(admin, "good-1", state); c != 400 {
		t.Errorf("a state worked twice: %d", c)
	}

	// A code issued for another PKCE challenge (an intercepted code) is
	// refused by the token endpoint, and nothing is kept.
	state2, _ := f.start(t, admin)
	f.pd.authorize("stolen", notify.PKCEChallenge("the-attackers-verifier-the-attackers-verifier"))
	if c, out := oauth(admin, "stolen", state2); c != 502 || out.Error.Code != "pagerduty_refused" {
		t.Errorf("code for another verifier: %d %+v", c, out.Error)
	}
	// The failed state is gone; only the first connect's session is left.
	if rows, tokens := f.connectRows(t); rows != 1 || tokens != 1 {
		t.Errorf("connect rows %d, tokens %d", rows, tokens)
	}

	// An expired state is refused.
	late, ch := f.start(t, admin)
	f.pd.authorize("late", ch)
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE pagerduty_connects SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if c, _ := oauth(admin, "late", late); c != 400 {
		t.Errorf("expired state: %d", c)
	}
	// Expired sessions are purged with their tokens.
	if _, err := e.st.Pool.Exec(tenant.System(ctx), `UPDATE pagerduty_connects SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if err := e.st.PurgePagerDutyConnects(tenant.System(ctx)); err != nil {
		t.Fatal(err)
	}
	if rows, _ := f.connectRows(t); rows != 0 {
		t.Errorf("%d connect rows after the purge", rows)
	}
}

// EU accounts: the ID token names the EU API, which is used for every call.
func TestPagerDutyConnectEU(t *testing.T) {
	f := pagerDutyAppSetup(t)
	admin := f.e.login("admin@x.io")
	got := f.connect(t, admin, "eu-1")
	if got.Region != "eu" || len(got.Services) != 3 {
		t.Fatalf("eu: %q %d", got.Region, len(got.Services))
	}
	var fin pdFinishAnswer
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": got.Session, "service_id": "PNOKEY"}, &fin); code != 201 {
		t.Fatalf("finish: %d %+v", code, fin.Error)
	}
	var cfg notify.ChannelConfig
	_ = json.Unmarshal(fin.Channel.Config, &cfg)
	if cfg.Region != "eu" || f.pd.apiHits["us"] != 0 || len(f.pd.created) != 1 || f.pd.created[0].Region != "eu" {
		t.Errorf("eu channel %+v, hits %v, created %+v", cfg, f.pd.apiHits, f.pd.created)
	}
	// The key was not in the create answer: it was read back.
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if v, err := f.e.st.SecretValue(ctx, f.e.api.SecretBox, strings.TrimPrefix(fin.Channel.SecretRef, "secret:")); err != nil || v != pdRoutingKey("eu", "PNOKEY") {
		t.Errorf("key %q (%v)", v, err)
	}
}

// Errors: a missing scope is explained; a refusal by PagerDuty is shown;
// either way no token is left behind.
func TestPagerDutyConnectErrors(t *testing.T) {
	f := pagerDutyAppSetup(t)
	admin := f.e.login("admin@x.io")

	state, challenge := f.start(t, admin)
	f.pd.authorize("readonly-1", challenge)
	var out pdOAuthAnswer
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/oauth", map[string]string{"code": "readonly-1", "state": state}, &out); code != 502 ||
		out.Error.Code != "pagerduty_scope" || !strings.Contains(out.Error.Message, "services.write") {
		t.Errorf("missing scope: %d %+v", code, out.Error)
	}
	if f.pd.apiHits["us"] != 0 {
		t.Error("PagerDuty's API was called without the scopes")
	}
	if rows, _ := f.connectRows(t); rows != 0 {
		t.Errorf("%d connect rows after a refused scope", rows)
	}

	got := f.connect(t, admin, "good-1")
	var fin pdFinishAnswer
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": got.Session, "service_id": "PFORBID"}, &fin); code != 502 ||
		fin.Error.Code != "pagerduty_refused" || !strings.Contains(fin.Error.Message, "403") {
		t.Errorf("refused integration: %d %+v", code, fin.Error)
	}
	if rows, _ := f.connectRows(t); rows != 0 {
		t.Errorf("%d connect rows after a refusal", rows)
	}
	var chans []store.Channel
	admin.do("GET", "/api/v1/channels", nil, &chans)
	if len(chans) != 0 {
		t.Errorf("channels after a refusal: %d", len(chans))
	}

	// Cancel deletes the session and its token.
	got = f.connect(t, admin, "good-2")
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/cancel", map[string]string{"session": got.Session}, nil); code != 204 {
		t.Errorf("cancel: %d", code)
	}
	if rows, _ := f.connectRows(t); rows != 0 {
		t.Errorf("%d connect rows after cancel", rows)
	}
}

// App channels are made only by Connect PagerDuty and keep their key;
// deleting one deletes the key and leaves the integration in PagerDuty
// (the dashboard links to where it is removed).
func TestPagerDutyAppChannel(t *testing.T) {
	f := pagerDutyAppSetup(t)
	e := f.e
	admin := e.login("admin@x.io")
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "pagerduty", "name": "fake", "secret_ref": "secret:X",
		"config": map[string]any{"pagerduty_app": true, "pagerduty_service_id": "PS001"}}, nil); code != 400 {
		t.Errorf("hand-made app channel: %d", code)
	}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "slack", "name": "fake2", "secret_ref": "secret:X",
		"config": map[string]any{"pagerduty_service_id": "PS001"}}, nil); code != 400 {
		t.Errorf("PagerDuty app fields on a Slack channel: %d", code)
	}
	got := f.connect(t, admin, "good-1")
	var fin pdFinishAnswer
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/finish", map[string]string{"session": got.Session, "service_id": "PS001"}, &fin); code != 201 {
		t.Fatalf("finish: %d", code)
	}
	id := itoa(fin.Channel.ID)
	if code := admin.do("PATCH", "/api/v1/channels/"+id, map[string]any{"secret_ref": "secret:OTHER"}, nil); code != 400 {
		t.Errorf("changing the key: %d", code)
	}
	var cfg map[string]any
	_ = json.Unmarshal(fin.Channel.Config, &cfg)
	cfg["pagerduty_service_id"] = "PS002"
	if code := admin.do("PATCH", "/api/v1/channels/"+id, map[string]any{"config": cfg}, nil); code != 400 {
		t.Errorf("changing the service: %d", code)
	}
	cfg["pagerduty_service_id"] = "PS001"
	cfg["severities"] = map[string]string{"P1": "critical", "P2": "critical"}
	if code := admin.do("PATCH", "/api/v1/channels/"+id, map[string]any{"config": cfg, "name": "On-call"}, nil); code != 200 {
		t.Errorf("changing severities and name: %d", code)
	}
	// A pasted-key channel stays as it was.
	if code := admin.do("PUT", "/api/v1/secrets/PD_KEY", map[string]string{"value": "R0PASTEDKEY00000000000000000000X"}, nil); code != 204 && code != 200 {
		t.Fatalf("put secret: %d", code)
	}
	if code := admin.do("POST", "/api/v1/channels", map[string]any{"kind": "pagerduty", "name": "pasted", "secret_ref": "secret:PD_KEY",
		"config": map[string]any{"region": "eu"}}, nil); code != 201 {
		t.Errorf("pasted-key channel: %d", code)
	}

	if code := admin.do("DELETE", "/api/v1/channels/"+id, nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	var n int
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := e.st.Pool.QueryRow(ctx, `SELECT count(*) FROM workspace_secrets WHERE name LIKE 'pagerduty-app-%'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d routing keys left after the delete", n)
	}
	if f.pd.deletes != 0 || f.pd.tokenHits != 1 {
		t.Errorf("PagerDuty called on delete: %d deletes, %d token requests", f.pd.deletes, f.pd.tokenHits)
	}
}

// Not configured: the endpoints say so and nothing is offered.
func TestPagerDutyAppOff(t *testing.T) {
	e := newEnvWith(t, func(s *api.Server) {
		s.Dispatcher = &notify.Dispatcher{Store: s.Store, Sender: notify.NewSender(false), Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	})
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	var out struct{ Error struct{ Code string } }
	if code := admin.do("POST", "/api/v1/integrations/pagerduty/connect", map[string]string{}, &out); code != 404 || out.Error.Code != "not_configured" {
		t.Errorf("connect without the app: %d %+v", code, out)
	}
	var opts map[string]any
	admin.do("GET", "/api/v1/notification-options", nil, &opts)
	if opts["pagerduty_app"] != false {
		t.Errorf("pagerduty_app = %v", opts["pagerduty_app"])
	}
}
