package notify_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/notify/teamstest"
)

// The Teams app against a fake Bot Framework (teamstest): the JWT on every
// request to the messaging endpoint, the signing keys' cache and rotation,
// the Bot Connector addresses allowed, and proactive messages with the
// app's cached token.

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestTeamsVerifyRequest(t *testing.T) {
	f := teamstest.New(t)
	// Published from the start, so it is refused for its endorsements,
	// not as an unknown key.
	f.AddKey("skype-only", "skype")
	app := f.App()
	ctx := context.Background()
	svc := f.ServiceURL()
	good := teamstest.Good(svc)
	verify := func(auth, channel, service string) error { return app.VerifyRequest(ctx, auth, channel, service) }

	if err := verify("Bearer "+f.Mint("k1", good), "msteams", svc); err != nil {
		t.Fatalf("a valid token was refused: %v", err)
	}
	// A trailing slash difference is the same serviceUrl.
	if err := verify("Bearer "+f.Mint("k1", good), "msteams", strings.TrimSuffix(svc, "/")); err != nil {
		t.Fatalf("serviceUrl without the slash: %v", err)
	}

	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	k1 := f.Key("k1")
	mod := func(fn func(*teamstest.Claims)) teamstest.Claims { c := good; fn(&c); return c }
	cases := []struct {
		name, auth, channel, service string
	}{
		{"no header", "", "msteams", svc},
		{"not bearer", "Basic " + f.Mint("k1", good), "msteams", svc},
		{"bad signature (another key, published kid)", "Bearer " + teamstest.MintWith(t, other, "k1", good), "msteams", svc},
		{"tampered payload", "Bearer " + tamper(f.Mint("k1", good)), "msteams", svc},
		{"wrong audience", "Bearer " + f.Mint("k1", mod(func(c *teamstest.Claims) { c.Audience = "00000000-0000-0000-0000-000000000000" })), "msteams", svc},
		{"no audience", "Bearer " + f.Mint("k1", mod(func(c *teamstest.Claims) { c.Audience = "" })), "msteams", svc},
		{"wrong issuer", "Bearer " + f.Mint("k1", mod(func(c *teamstest.Claims) { c.Issuer = "https://sts.windows.net/evil/" })), "msteams", svc},
		{"expired", "Bearer " + f.Mint("k1", mod(func(c *teamstest.Claims) { c.Expiry = time.Now().Add(-10 * time.Minute) })), "msteams", svc},
		{"not yet valid", "Bearer " + f.Mint("k1", mod(func(c *teamstest.Claims) { c.NotBefore = time.Now().Add(10 * time.Minute) })), "msteams", svc},
		{"no serviceurl claim", "Bearer " + f.Mint("k1", mod(func(c *teamstest.Claims) { c.ServiceURL = "" })), "msteams", svc},
		{"serviceurl mismatch", "Bearer " + f.Mint("k1", good), "msteams", "https://evil.example/amer/"},
		{"token for another serviceurl", "Bearer " + f.Mint("k1", mod(func(c *teamstest.Claims) { c.ServiceURL = "https://evil.example/" })), "msteams", svc},
		{"not msteams", "Bearer " + f.Mint("k1", good), "webchat", svc},
		{"key not endorsed for msteams", "Bearer " + f.Mint("skype-only", good), "msteams", svc},
		{"unknown kid", "Bearer " + teamstest.MintWith(t, other, "nope", good), "msteams", svc},
		{"alg none", "Bearer " + teamstest.None(good), "msteams", svc},
		{"alg confusion: HS256 with the public key", "Bearer " + teamstest.HS256(t, k1.N.Bytes(), "k1", good), "msteams", svc},
		{"alg confusion: HS256 with the PEM public key", "Bearer " + teamstest.HS256(t, pemPublic(t, &k1.PublicKey), "k1", good), "msteams", svc},
	}
	for _, c := range cases {
		err := verify(c.auth, c.channel, c.service)
		if !errors.Is(err, notify.ErrTeamsUnauthorized) {
			t.Errorf("%s: accepted (%v)", c.name, err)
		}
	}
}

func tamper(tok string) string {
	parts := strings.Split(tok, ".")
	// Another payload (a different audience) with the original signature.
	payload, _ := json.Marshal(map[string]any{"iss": teamstest.Issuer, "aud": "someone-else", "exp": time.Now().Add(time.Hour).Unix()})
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + parts[2]
}

func pemPublic(t *testing.T, k *rsa.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

func TestTeamsSigningKeysCacheAndRotation(t *testing.T) {
	f := teamstest.New(t)
	app := f.App()
	c := &clock{t: time.Now()}
	app.Now = c.now
	ctx := context.Background()
	svc := f.ServiceURL()
	claims := func() teamstest.Claims {
		return teamstest.Claims{Issuer: teamstest.Issuer, Audience: teamstest.AppID, ServiceURL: svc, Expiry: c.now().Add(time.Hour), NotBefore: c.now().Add(-time.Minute)}
	}
	ok := func(kid string) error { return app.VerifyRequest(ctx, "Bearer "+f.Mint(kid, claims()), "msteams", svc) }

	if err := ok("k1"); err != nil {
		t.Fatal(err)
	}
	if err := ok("k1"); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Counts(); n != 1 {
		t.Fatalf("keys fetched %d times for two requests, want 1 (cached)", n)
	}
	// Microsoft rotates: a new kid fetches the keys again and works.
	c.add(2 * time.Minute)
	f.AddKey("k2", "msteams", "skype")
	if err := ok("k2"); err != nil {
		t.Fatalf("rotated key refused: %v", err)
	}
	if n, _ := f.Counts(); n != 2 {
		t.Fatalf("keys fetched %d times after rotation, want 2", n)
	}
	// Unknown kids right after do not fetch again (no hammering Microsoft).
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	for i := 0; i < 5; i++ {
		if err := app.VerifyRequest(ctx, "Bearer "+teamstest.MintWith(t, stranger, "made-up", claims()), "msteams", svc); err == nil {
			t.Fatal("unknown kid accepted")
		}
	}
	if n, _ := f.Counts(); n != 2 {
		t.Fatalf("keys fetched %d times for made-up kids, want still 2", n)
	}
	// A key published within that window is picked up after it.
	f.AddKey("k3", "msteams")
	if err := ok("k3"); err == nil {
		t.Fatal("k3 accepted before the keys could be fetched again (test assumption)")
	}
	c.add(2 * time.Minute)
	if err := ok("k3"); err != nil {
		t.Fatalf("k3 after the retry window: %v", err)
	}
	// After a day the cached keys are fetched again even for a known kid.
	n0, _ := f.Counts()
	c.add(25 * time.Hour)
	if err := ok("k1"); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.Counts(); n != n0+1 {
		t.Fatalf("keys not refreshed after a day: %d fetches, want %d", n, n0+1)
	}
}

func TestTeamsServiceURLAllowList(t *testing.T) {
	for u, want := range map[string]bool{
		"https://smba.trafficmanager.net/amer/":                 true,
		"https://smba.trafficmanager.net/emea/":                 true,
		"https://smba.trafficmanager.net/teams/":                true,
		"https://SMBA.trafficmanager.net/apac/":                 true,
		"https://smba.trafficmanager.net:443/amer/":             true,
		"https://smba.infra.gcc.teams.microsoft.com/":           true,
		"https://smba.infra.gov.teams.microsoft.us/":            true,
		"https://smba.infra.dod.teams.microsoft.us/":            true,
		"http://smba.trafficmanager.net/amer/":                  false,
		"https://smba.trafficmanager.net:8443/amer/":            false,
		"https://evil.example/amer/":                            false,
		"https://smba.trafficmanager.net.evil.example/amer/":    false,
		"https://evilsmba.trafficmanager.net/amer/":             false,
		"https://x.smba.trafficmanager.net/amer/":               false,
		"https://user:pw@smba.trafficmanager.net/amer/":         false,
		"https://smba.trafficmanager.net@evil.example/":         false,
		"https://smba.trafficmanager.net/amer/?x=https://evil/": false,
		"https://169.254.169.254/latest/":                       false,
		"https://127.0.0.1/amer/":                               false,
		"":                                                      false,
		"smba.trafficmanager.net/amer/":                         false,
	} {
		if got := notify.TeamsServiceURLAllowed(u); got != want {
			t.Errorf("%q: allowed = %v, want %v", u, got, want)
		}
	}
}

func TestTeamsProactiveSend(t *testing.T) {
	f := teamstest.New(t)
	app := f.App()
	c := &clock{t: time.Now()}
	app.Now = c.now
	ctx := context.Background()
	target := notify.TeamsTarget{ServiceURL: f.ServiceURL(), TenantID: "tenant-1", ChannelID: "19:abc@thread.tacv2"}
	msg := notify.Message{Event: "test", Title: "Stackurity test notification", Summary: []string{"This channel is configured correctly."}, Link: "https://stk.example/x"}

	for i := 0; i < 3; i++ {
		if err := app.PostToChannel(ctx, target, notify.TeamsActivity(msg)); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if _, tokens := f.Counts(); tokens != 1 {
		t.Fatalf("%d tokens for three messages, want 1 (cached)", tokens)
	}
	posts := f.PostsTo("/v3/conversations")
	if len(posts) != 3 || posts[0].Auth != "Bearer bf-token-1" {
		t.Fatalf("posts = %+v", posts)
	}
	b := posts[0].Body
	cd, _ := b["channelData"].(map[string]any)
	ch, _ := cd["channel"].(map[string]any)
	act, _ := b["activity"].(map[string]any)
	atts, _ := act["attachments"].([]any)
	if b["isGroup"] != true || ch["id"] != "19:abc@thread.tacv2" || len(atts) != 1 ||
		atts[0].(map[string]any)["contentType"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("body = %v", b)
	}
	card := atts[0].(map[string]any)["content"].(map[string]any)
	if !strings.Contains(toJSON(card), "This channel is configured correctly.") || !strings.Contains(toJSON(card), "Open in Stackurity") {
		t.Fatalf("card does not carry the message: %s", toJSON(card))
	}
	// The token is renewed before it expires.
	c.add(56 * time.Minute)
	if err := app.PostToChannel(ctx, target, notify.TeamsActivity(msg)); err != nil {
		t.Fatal(err)
	}
	if _, tokens := f.Counts(); tokens != 2 {
		t.Fatalf("%d tokens after expiry, want 2", tokens)
	}
	// A token the Bot Connector refuses is replaced once.
	f.RevokeTokens()
	if err := app.PostToChannel(ctx, target, notify.TeamsActivity(msg)); err != nil {
		t.Fatalf("after a revoked token: %v", err)
	}
	if _, tokens := f.Counts(); tokens != 3 {
		t.Fatalf("%d tokens after a 401, want 3", tokens)
	}
	// The app removed from the team: permanent, and says so.
	f.Answer = func(string) int { return 403 }
	err := app.PostToChannel(ctx, target, notify.TeamsActivity(msg))
	var pe *notify.PermanentError
	if !errors.Is(err, notify.ErrTeamsRemoved) || !errors.As(err, &pe) || !strings.Contains(err.Error(), "BotNotInConversationRoster") {
		t.Fatalf("removed app: %v", err)
	}
	f.Answer = func(string) int { return 404 }
	if err := app.PostToChannel(ctx, target, notify.TeamsActivity(msg)); !errors.Is(err, notify.ErrTeamsRemoved) {
		t.Fatalf("deleted channel: %v", err)
	}
	// A busy Bot Connector: retried later, not permanent.
	f.Answer = func(string) int { return 503 }
	if err := app.PostToChannel(ctx, target, notify.TeamsActivity(msg)); err == nil || errors.As(err, &pe) {
		t.Fatalf("503: %v", err)
	}
	f.Answer = nil

	// A serviceUrl off the allow-list gets nothing: no token, no request.
	before := len(f.PostsTo(""))
	_, tokensBefore := f.Counts()
	strict := f.App()
	strict.ServiceURLAllowed = nil
	err = strict.PostToChannel(ctx, notify.TeamsTarget{ServiceURL: f.ServiceURL(), ChannelID: "19:abc@thread.tacv2"}, notify.TeamsActivity(msg))
	if !errors.Is(err, notify.ErrTeamsServiceURL) || !errors.As(err, &pe) {
		t.Fatalf("serviceUrl off the allow-list: %v", err)
	}
	if err := strict.Reply(ctx, "https://evil.example/", "19:abc", "", notify.TeamsText("hi")); !errors.Is(err, notify.ErrTeamsServiceURL) {
		t.Fatalf("reply to a forged serviceUrl: %v", err)
	}
	if _, tokens := f.Counts(); len(f.PostsTo("")) != before || tokens != tokensBefore {
		t.Fatal("something was sent for a serviceUrl off the allow-list")
	}

	// Wrong credentials: permanent.
	bad := f.App()
	bad.Password = "wrong"
	if err := bad.PostToChannel(ctx, target, notify.TeamsActivity(msg)); !errors.As(err, &pe) {
		t.Fatalf("wrong secret: %v", err)
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestTeamsCertificateCredential(t *testing.T) {
	f := teamstest.New(t)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "stackurity-bot"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	pemFile := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	cert, k, err := notify.ParseTeamsCertificate(pemFile)
	if err != nil {
		t.Fatal(err)
	}
	app := f.App()
	app.Password, app.Certificate, app.Key = "", cert, k
	if err := app.PostToChannel(context.Background(), notify.TeamsTarget{ServiceURL: f.ServiceURL(), ChannelID: "19:a@thread.tacv2"}, notify.TeamsText("x")); err != nil {
		t.Fatal(err)
	}
	form := f.LastForm
	if form["client_secret"] != nil || form["client_assertion_type"][0] != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		t.Fatalf("form = %v", form)
	}
	tok, err := jwt.ParseSigned(form["client_assertion"][0], []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var cl jwt.Claims
	if err := tok.Claims(&key.PublicKey, &cl); err != nil {
		t.Fatalf("assertion not signed with the certificate's key: %v", err)
	}
	if cl.Issuer != teamstest.AppID || cl.Subject != teamstest.AppID || !cl.Audience.Contains(f.Srv.URL+"/botframework.com/oauth2/v2.0/token") || cl.ID == "" {
		t.Fatalf("claims = %+v", cl)
	}
	if tok.Headers[0].ExtraHeaders["x5t"] == nil {
		t.Fatal("no x5t header")
	}
	// A key that is not the certificate's is refused when read.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	if _, _, err := notify.ParseTeamsCertificate(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER})...)); err == nil {
		t.Fatal("mismatched key accepted")
	}
	// From the environment.
	dir := t.TempDir()
	p := filepath.Join(dir, "bot.pem")
	if err := os.WriteFile(p, pemFile, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_TEAMS_APP_ID", teamstest.AppID)
	t.Setenv("STACKURITY_TEAMS_APP_CERTIFICATE_FILE", p)
	got, err := notify.TeamsAppFromEnv()
	if err != nil || got == nil || got.Key == nil || got.Password != "" {
		t.Fatalf("from env: %v %+v", err, got)
	}
}

func TestTeamsAppFromEnv(t *testing.T) {
	for _, k := range []string{"STACKURITY_TEAMS_APP_ID", "STACKURITY_TEAMS_APP_PASSWORD", "STACKURITY_TEAMS_APP_CERTIFICATE_FILE", "STACKURITY_TEAMS_APP_TENANT", "STACKURITY_TEAMS_APP_INSTALL_URL"} {
		t.Setenv(k, "")
	}
	if app, err := notify.TeamsAppFromEnv(); app != nil || err != nil {
		t.Fatalf("nothing set: %v %v", app, err)
	}
	t.Setenv("STACKURITY_TEAMS_APP_PASSWORD", "x")
	if _, err := notify.TeamsAppFromEnv(); err == nil {
		t.Fatal("a secret without an app id was accepted")
	}
	t.Setenv("STACKURITY_TEAMS_APP_ID", "not-a-guid")
	if _, err := notify.TeamsAppFromEnv(); err == nil {
		t.Fatal("a bad app id was accepted")
	}
	t.Setenv("STACKURITY_TEAMS_APP_ID", strings.ToUpper(teamstest.AppID))
	t.Setenv("STACKURITY_TEAMS_APP_PASSWORD", "")
	if _, err := notify.TeamsAppFromEnv(); err == nil {
		t.Fatal("an app without a credential was accepted")
	}
	t.Setenv("STACKURITY_TEAMS_APP_PASSWORD", "s3cret")
	t.Setenv("STACKURITY_TEAMS_APP_INSTALL_URL", "http://teams.example/")
	if _, err := notify.TeamsAppFromEnv(); err == nil {
		t.Fatal("an http install link was accepted")
	}
	t.Setenv("STACKURITY_TEAMS_APP_INSTALL_URL", "")
	app, err := notify.TeamsAppFromEnv()
	if err != nil || app.AppID != teamstest.AppID || app.Password != "s3cret" || app.InstallLink() != "https://teams.microsoft.com/l/app/"+teamstest.AppID {
		t.Fatalf("%v %+v", err, app)
	}
}

// The Workflows webhook mode is unchanged: a secret webhook URL, the same
// Adaptive Card, no Bot Framework.
func TestTeamsWorkflowsWebhookStillWorks(t *testing.T) {
	var got map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(202)
	}))
	defer srv.Close()
	s := notify.NewSender(false)
	s.HTTP = srv.Client()
	msg := notify.Message{Event: "test", Title: "Stackurity test notification", Summary: []string{"ok"}}
	if err := s.Send(context.Background(), notify.KindTeams, notify.ChannelConfig{}, srv.URL+"/workflows/abc", 1, msg); err != nil {
		t.Fatal(err)
	}
	if got["type"] != "message" || !strings.Contains(toJSON(got), "AdaptiveCard") {
		t.Fatalf("payload = %v", got)
	}
	if err := notify.ValidateChannel(notify.KindTeams, notify.ChannelConfig{}, false, false); err == nil {
		t.Fatal("a webhook Teams channel without its URL was accepted")
	}
	if err := notify.ValidateChannel(notify.KindTeams, notify.ChannelConfig{}, true, false); err != nil {
		t.Fatal(err)
	}
	if err := notify.ValidateChannel(notify.KindTeams, notify.ChannelConfig{TeamsApp: true, TeamsChannelID: "19:a", ServiceURL: "https://smba.trafficmanager.net/amer/"}, true, false); err == nil {
		t.Fatal("an app channel with a secret was accepted")
	}
	if err := notify.ValidateChannel(notify.KindSlack, notify.ChannelConfig{TeamsApp: true}, true, false); err == nil {
		t.Fatal("teams_app on a Slack channel was accepted")
	}
}
