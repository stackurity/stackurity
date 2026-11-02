package notify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // x5t is defined as the SHA-1 thumbprint (RFC 7515 4.1.7)
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/netguard"
)

// The Stackurity Microsoft Teams app ("Add to Teams"). One bot (an Azure
// Bot with a Microsoft Entra app registration), configured on the server,
// is added to a team in each organisation's Microsoft 365 tenant. Teams
// sends the bot's activities (installed, removed, a message mentioning it)
// to the messaging endpoint, POST /api/v1/integrations/teams/messages,
// each with a JWT the Bot Framework signed; nothing in an activity is used
// before that token is verified (VerifyRequest). A channel is bound to an
// organisation by a short code shown in Stackurity to the admin who clicked
// Add to Teams and typed in that channel (internal/api/teams_app.go), never
// by the tenant alone. Messages are then posted to the channel with the
// Bot Connector API, with an access token for the app (client credentials
// against Microsoft Entra), only to Bot Connector hosts Microsoft
// documents. See docs/teams-app.md.

// Bot Framework constants (learn.microsoft.com: "Authenticate requests
// from the Bot Connector service to your bot", "Authenticate requests from
// your bot to the Bot Connector service").
const (
	teamsOpenIDURL  = "https://login.botframework.com/v1/.well-known/openidconfiguration"
	teamsIssuer     = "https://api.botframework.com"
	teamsTokenScope = "https://api.botframework.com/.default"
	teamsLoginURL   = "https://login.microsoftonline.com"
	// teamsMultiTenant is the token authority of a multi-tenant bot.
	teamsMultiTenant = "botframework.com"
	// teamsChannelID is the Bot Framework channel of Microsoft Teams.
	teamsChannelID = "msteams"
)

// teamsServiceHosts are the Bot Connector hosts Teams uses as serviceUrl:
// the commercial cloud (smba.trafficmanager.net, with a region path such
// as /amer/ or /emea/), GCC, GCC High and DoD. Messages and replies go to
// these hosts only, over HTTPS on port 443: a serviceUrl is part of the
// activity, and a forged one must not receive the app's access token.
var teamsServiceHosts = map[string]string{
	"smba.trafficmanager.net":            "https://smba.trafficmanager.net/",
	"smba.infra.gcc.teams.microsoft.com": "https://smba.infra.gcc.teams.microsoft.com/",
	"smba.infra.gov.teams.microsoft.us":  "https://smba.infra.gov.teams.microsoft.us/",
	"smba.infra.dod.teams.microsoft.us":  "https://smba.infra.dod.teams.microsoft.us/",
}

// TeamsServiceURLAllowed reports whether u is a Bot Connector address
// Microsoft documents for Teams: https, one of teamsServiceHosts, the
// default port, no credentials, query or fragment.
func TeamsServiceURLAllowed(raw string) bool {
	_, _, ok := serviceOrigin(raw, nil)
	return ok
}

// serviceOrigin splits an allowed serviceUrl into the origin it is sent to,
// taken from the allow-list (hosts: host -> "scheme://host/"; nil:
// teamsServiceHosts, https on port 443 only), and its path without the
// leading and trailing "/". Requests are built from that origin, never from
// the activity's text.
func serviceOrigin(raw string, hosts map[string]string) (origin, path string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", "", false
	}
	if hosts != nil {
		origin, ok = hosts[strings.ToLower(u.Host)]
	} else if p := u.Port(); u.Scheme == "https" && (p == "" || p == "443") {
		origin, ok = teamsServiceHosts[strings.ToLower(u.Hostname())]
	}
	if !ok || !strings.HasPrefix(origin, u.Scheme+"://") {
		return "", "", false
	}
	return origin, strings.Trim(u.EscapedPath(), "/"), true
}

// TeamsApp is the bot's configuration.
type TeamsApp struct {
	// AppID is the Microsoft App ID of the Azure Bot (its Entra app's
	// client ID). It is the audience of every token Teams sends.
	AppID string
	// Password is a client secret of the Entra app; or Certificate and Key
	// sign a client assertion instead (one of the two).
	Password    string
	Certificate *x509.Certificate
	Key         *rsa.PrivateKey
	// Tenant is the Entra tenant of a single-tenant bot; empty for a
	// multi-tenant bot (the botframework.com authority).
	Tenant string
	// InstallURL replaces the "Open in Teams" link (an app uploaded to an
	// organisation's catalogue gets its own id); empty uses AppID.
	InstallURL string

	// Tests: Microsoft's endpoints, the HTTP client, the clock and the
	// serviceUrl hosts allowed, as host[:port] -> "scheme://host[:port]/"
	// (nil: teamsServiceHosts).
	OpenIDURL    string
	LoginURL     string
	HTTP         *http.Client
	Now          func() time.Time
	ServiceHosts map[string]string

	mu       sync.Mutex
	keys     map[string]teamsKey
	keysAt   time.Time
	keysTry  time.Time
	token    string
	tokenExp time.Time
}

type teamsKey struct {
	pub          *rsa.PublicKey
	endorsements []string
}

var teamsAppIDRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// TeamsAppFromEnv reads STACKURITY_TEAMS_APP_ID (or _FILE), the client
// secret STACKURITY_TEAMS_APP_PASSWORD (or _FILE) or a certificate
// STACKURITY_TEAMS_APP_CERTIFICATE_FILE (PEM: certificate and private
// key), STACKURITY_TEAMS_APP_TENANT and STACKURITY_TEAMS_APP_INSTALL_URL.
// Without an app ID the app is off (nil).
func TeamsAppFromEnv() (*TeamsApp, error) {
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
	id, err := read("STACKURITY_TEAMS_APP_ID")
	if err != nil {
		return nil, err
	}
	password, err := read("STACKURITY_TEAMS_APP_PASSWORD")
	if err != nil {
		return nil, err
	}
	certFile := strings.TrimSpace(os.Getenv("STACKURITY_TEAMS_APP_CERTIFICATE_FILE"))
	tenant := strings.TrimSpace(os.Getenv("STACKURITY_TEAMS_APP_TENANT"))
	install := strings.TrimSpace(os.Getenv("STACKURITY_TEAMS_APP_INSTALL_URL"))
	if id == "" {
		if password != "" || certFile != "" || tenant != "" || install != "" {
			return nil, errors.New("the Teams app needs STACKURITY_TEAMS_APP_ID")
		}
		return nil, nil
	}
	if !teamsAppIDRE.MatchString(id) {
		return nil, errors.New("STACKURITY_TEAMS_APP_ID must be the bot's Microsoft App ID (a GUID)")
	}
	if (password == "") == (certFile == "") {
		return nil, errors.New("the Teams app needs one of STACKURITY_TEAMS_APP_PASSWORD (a client secret) or STACKURITY_TEAMS_APP_CERTIFICATE_FILE")
	}
	if tenant != "" && !teamsAppIDRE.MatchString(tenant) && !regexp.MustCompile(`^[a-zA-Z0-9.-]{1,253}$`).MatchString(tenant) {
		return nil, errors.New("STACKURITY_TEAMS_APP_TENANT must be a tenant ID or domain")
	}
	if install != "" {
		if u, err := url.Parse(install); err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, errors.New("STACKURITY_TEAMS_APP_INSTALL_URL must be an https URL")
		}
	}
	app := &TeamsApp{AppID: strings.ToLower(id), Password: password, Tenant: tenant, InstallURL: install}
	if certFile != "" {
		b, err := os.ReadFile(certFile)
		if err != nil {
			return nil, fmt.Errorf("STACKURITY_TEAMS_APP_CERTIFICATE_FILE: %w", err)
		}
		if app.Certificate, app.Key, err = ParseTeamsCertificate(b); err != nil {
			return nil, fmt.Errorf("STACKURITY_TEAMS_APP_CERTIFICATE_FILE: %w", err)
		}
	}
	return app, nil
}

// ParseTeamsCertificate reads a PEM file holding a certificate and its RSA
// private key (PKCS #8 or PKCS #1).
func ParseTeamsCertificate(b []byte) (*x509.Certificate, *rsa.PrivateKey, error) {
	var cert *x509.Certificate
	var key *rsa.PrivateKey
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		switch blk.Type {
		case "CERTIFICATE":
			if cert == nil {
				c, err := x509.ParseCertificate(blk.Bytes)
				if err != nil {
					return nil, nil, err
				}
				cert = c
			}
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, err
			}
			rk, ok := k.(*rsa.PrivateKey)
			if !ok {
				return nil, nil, errors.New("the private key must be RSA")
			}
			key = rk
		case "RSA PRIVATE KEY":
			k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
			if err != nil {
				return nil, nil, err
			}
			key = k
		}
	}
	if cert == nil || key == nil {
		return nil, nil, errors.New("needs a CERTIFICATE and a PRIVATE KEY block")
	}
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&key.PublicKey) {
		return nil, nil, errors.New("the private key does not match the certificate")
	}
	return cert, key, nil
}

func (a *TeamsApp) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// client makes every request to Microsoft: public addresses only (never
// private networks, loopback or metadata services, whatever the
// workspace's policy), no redirects, no environment proxy.
func (a *TeamsApp) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	return teamsHTTP
}

var teamsHTTP = &http.Client{
	Timeout:       20 * time.Second,
	Transport:     &http.Transport{DialContext: netguard.Policy{}.DialContext, TLSHandshakeTimeout: 10 * time.Second, MaxIdleConns: 10, IdleConnTimeout: 90 * time.Second},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// AllowsServiceURL reports whether replies and messages may go to u.
func (a *TeamsApp) AllowsServiceURL(u string) bool {
	_, _, ok := serviceOrigin(u, a.ServiceHosts)
	return ok
}

// InstallLink opens the app in Teams, where the person adds it to a team.
func (a *TeamsApp) InstallLink() string {
	if a.InstallURL != "" {
		return a.InstallURL
	}
	return "https://teams.microsoft.com/l/app/" + url.PathEscape(a.AppID)
}

// --- inbound: the Bot Framework's JWT

// ErrTeamsUnauthorized: a request to the messaging endpoint is not from
// the Bot Framework for this app.
var ErrTeamsUnauthorized = errors.New("not a verified Bot Framework request")

// teamsKeysTTL is how long the Bot Framework's signing keys are used;
// Microsoft rotates them and asks bots to fetch them at least daily. A
// token whose kid is not in the cached set fetches them again, at most
// once per teamsKeysRetry (Microsoft publishes new keys well before it
// signs with them).
const (
	teamsKeysTTL   = 24 * time.Hour
	teamsKeysRetry = time.Minute
	teamsSkew      = 5 * time.Minute
)

type teamsClaims struct {
	jwt.Claims
	ServiceURL string `json:"serviceurl"`
}

// VerifyRequest checks the Authorization header of an activity: a Bearer
// JWT signed with RS256 by a Bot Framework key endorsed for channelID
// (msteams only), issued by https://api.botframework.com for this app's ID,
// current (5 minutes' leeway), whose serviceurl claim is the activity's
// serviceUrl. Anything else is ErrTeamsUnauthorized.
func (a *TeamsApp) VerifyRequest(ctx context.Context, authorization, channelID, serviceURL string) error {
	fail := func(why string) error { return fmt.Errorf("%w: %s", ErrTeamsUnauthorized, why) }
	raw, ok := strings.CutPrefix(authorization, "Bearer ")
	if !ok || raw == "" || len(raw) > 16<<10 {
		return fail("no bearer token")
	}
	if channelID != teamsChannelID {
		return fail("not a Teams activity")
	}
	// Only RS256: a token naming none, HS256 (the public key as a shared
	// secret) or another algorithm is refused before any key is used.
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(tok.Headers) != 1 {
		return fail("not an RS256 JWT")
	}
	kid := tok.Headers[0].KeyID
	if kid == "" {
		return fail("no key id")
	}
	key, err := a.signingKey(ctx, kid)
	if err != nil {
		return fail(err.Error())
	}
	if !slices.Contains(key.endorsements, channelID) {
		return fail("key not endorsed for msteams")
	}
	var c teamsClaims
	if err := tok.Claims(key.pub, &c); err != nil {
		return fail("bad signature")
	}
	if c.Expiry == nil {
		return fail("no expiry")
	}
	if err := c.ValidateWithLeeway(jwt.Expected{Issuer: teamsIssuer, AnyAudience: jwt.Audience{a.AppID}, Time: a.now()}, teamsSkew); err != nil {
		return fail(err.Error())
	}
	if c.ServiceURL == "" || !sameServiceURL(c.ServiceURL, serviceURL) {
		return fail("serviceurl does not match the activity")
	}
	return nil
}

func sameServiceURL(a, b string) bool {
	return strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(b, "/"))
}

// signingKey returns the Bot Framework key kid: from the cache while it is
// fresh, otherwise (or when kid is unknown, keys having rotated) from the
// OpenID metadata's jwks_uri.
func (a *TeamsApp) signingKey(ctx context.Context, kid string) (teamsKey, error) {
	a.mu.Lock()
	k, ok := a.keys[kid]
	fresh := a.now().Sub(a.keysAt) < teamsKeysTTL
	recent := !a.keysTry.IsZero() && a.now().Sub(a.keysTry) < teamsKeysRetry
	a.mu.Unlock()
	if ok && fresh {
		return k, nil
	}
	// Stale keys, or a kid not in them (Microsoft rotated its keys): fetch
	// again, but not more than once per teamsKeysRetry, so tokens with
	// made-up kids cannot make the server hammer Microsoft.
	if recent {
		if ok {
			return k, nil
		}
		return teamsKey{}, errors.New("unknown key id")
	}
	keys, err := a.fetchKeys(ctx)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keysTry = a.now()
	if err != nil {
		// Keep using a cached key Microsoft still lists, rather than refuse
		// every request while its metadata cannot be read.
		if ok {
			return k, nil
		}
		return teamsKey{}, err
	}
	a.keys, a.keysAt = keys, a.now()
	if k, ok = keys[kid]; !ok {
		return teamsKey{}, errors.New("unknown key id")
	}
	return k, nil
}

func (a *TeamsApp) getJSON(ctx context.Context, u string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(out)
}

func (a *TeamsApp) fetchKeys(ctx context.Context) (map[string]teamsKey, error) {
	meta := a.OpenIDURL
	if meta == "" {
		meta = teamsOpenIDURL
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := a.getJSON(ctx, meta, &doc); err != nil {
		return nil, fmt.Errorf("bot framework metadata: %w", err)
	}
	if u, err := url.Parse(doc.JWKSURI); err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("bot framework metadata: jwks_uri is not an https URL")
	}
	var set struct {
		Keys []struct {
			Kty          string   `json:"kty"`
			Kid          string   `json:"kid"`
			Use          string   `json:"use"`
			N            string   `json:"n"`
			E            string   `json:"e"`
			Endorsements []string `json:"endorsements"`
		} `json:"keys"`
	}
	if err := a.getJSON(ctx, doc.JWKSURI, &set); err != nil {
		return nil, fmt.Errorf("bot framework keys: %w", err)
	}
	out := map[string]teamsKey{}
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		n, err1 := base64.RawURLEncoding.DecodeString(k.N)
		e, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			continue
		}
		exp := int(new(big.Int).SetBytes(e).Int64())
		if exp < 3 {
			continue
		}
		out[k.Kid] = teamsKey{pub: &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}, endorsements: k.Endorsements}
	}
	if len(out) == 0 {
		return nil, errors.New("bot framework keys: no RSA signing keys")
	}
	return out, nil
}

// --- outbound: the app's access token and the Bot Connector API

func (a *TeamsApp) tokenURL() string {
	base := a.LoginURL
	if base == "" {
		base = teamsLoginURL
	}
	tenant := a.Tenant
	if tenant == "" {
		tenant = teamsMultiTenant
	}
	return strings.TrimRight(base, "/") + "/" + url.PathEscape(tenant) + "/oauth2/v2.0/token"
}

// accessToken returns the app's token for the Bot Connector, cached until
// five minutes before it expires; fresh asks for a new one.
func (a *TeamsApp) accessToken(ctx context.Context, fresh bool) (string, error) {
	a.mu.Lock()
	if !fresh && a.token != "" && a.now().Before(a.tokenExp) {
		t := a.token
		a.mu.Unlock()
		return t, nil
	}
	a.mu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {a.AppID}, "scope": {teamsTokenScope}}
	if a.Key != nil {
		assertion, err := a.clientAssertion()
		if err != nil {
			return "", err
		}
		form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		form.Set("client_assertion", assertion)
	} else {
		form.Set("client_secret", a.Password)
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", a.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client().Do(req)
	if err != nil {
		return "", fmt.Errorf("teams app token: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		Error       string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out)
	if resp.StatusCode != 200 || out.AccessToken == "" {
		err := fmt.Errorf("teams app token: HTTP %d %s", resp.StatusCode, out.Error)
		if resp.StatusCode == 400 || resp.StatusCode == 401 {
			// Wrong app ID, secret or certificate: retrying cannot help.
			return "", &PermanentError{Err: fmt.Errorf("%w (check the Teams app's ID and client secret or certificate)", err)}
		}
		return "", err
	}
	life := time.Duration(out.ExpiresIn) * time.Second
	if life <= 0 || life > 24*time.Hour {
		life = time.Hour
	}
	a.mu.Lock()
	a.token, a.tokenExp = out.AccessToken, a.now().Add(life-5*time.Minute)
	a.mu.Unlock()
	return out.AccessToken, nil
}

// clientAssertion is the signed JWT that authenticates the app with its
// certificate (Microsoft identity platform certificate credentials).
func (a *TeamsApp) clientAssertion() (string, error) {
	thumb := sha1.Sum(a.Certificate.Raw) //nolint:gosec // see the import
	thumb256 := sha256.Sum256(a.Certificate.Raw)
	opts := (&jose.SignerOptions{}).WithType("JWT").
		WithHeader("x5t", base64.RawURLEncoding.EncodeToString(thumb[:])).
		WithHeader("x5t#S256", base64.RawURLEncoding.EncodeToString(thumb256[:]))
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: crypto.Signer(a.Key)}, opts)
	if err != nil {
		return "", err
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := a.now()
	return jwt.Signed(sig).Claims(jwt.Claims{Issuer: a.AppID, Subject: a.AppID, Audience: jwt.Audience{a.tokenURL()},
		ID: base64.RawURLEncoding.EncodeToString(jti), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now),
		Expiry: jwt.NewNumericDate(now.Add(10 * time.Minute))}).Serialize()
}

// ErrTeamsRemoved: Teams says the bot is no longer in that team or
// channel (removed, or the channel or team deleted). The integration is
// disconnected; adding the app again reconnects it.
var ErrTeamsRemoved = errors.New("the Stackurity app is no longer in this Teams channel; use Add to Teams again")

// ErrTeamsServiceURL: a serviceUrl that is not a Bot Connector host
// Microsoft documents for Teams. Nothing is sent to it.
var ErrTeamsServiceURL = errors.New("not a Microsoft Teams Bot Connector address")

// TeamsTarget is where a bound channel's messages go.
type TeamsTarget struct {
	ServiceURL string
	TenantID   string
	ChannelID  string // the Teams channel's conversation id (19:...@thread.tacv2)
}

// PostToChannel starts a new post in the channel (Bot Connector
// "create conversation" with the channel's id) and returns its id.
func (a *TeamsApp) PostToChannel(ctx context.Context, t TeamsTarget, activity map[string]any) error {
	body := map[string]any{
		"isGroup":     true,
		"channelData": map[string]any{"channel": map[string]string{"id": t.ChannelID}, "tenant": map[string]string{"id": t.TenantID}},
		"activity":    activity,
	}
	if t.TenantID != "" {
		body["tenantId"] = t.TenantID
	}
	return a.connector(ctx, t.ServiceURL, "/v3/conversations", body)
}

// Reply answers an activity in its conversation (the thread it came from).
func (a *TeamsApp) Reply(ctx context.Context, serviceURL, conversationID, replyTo string, activity map[string]any) error {
	if replyTo != "" {
		activity["replyToId"] = replyTo
	}
	return a.connector(ctx, serviceURL, "/v3/conversations/"+url.PathEscape(conversationID)+"/activities", activity)
}

func (a *TeamsApp) connector(ctx context.Context, serviceURL, path string, body any) error {
	origin, base, ok := serviceOrigin(serviceURL, a.ServiceHosts)
	if !ok {
		return &PermanentError{Err: ErrTeamsServiceURL}
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	u := origin + base + path
	if base == "" {
		u = origin + strings.TrimPrefix(path, "/")
	}
	for try := 0; ; try++ {
		token, err := a.accessToken(ctx, try > 0)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", "stackurity-notify")
		resp, err := a.client().Do(req)
		if err != nil {
			return fmt.Errorf("teams: %w", err)
		}
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		case resp.StatusCode == 401 && try == 0:
			// The cached token was revoked or expired early: once more
			// with a new one.
			continue
		case resp.StatusCode == 403 || resp.StatusCode == 404:
			// BotNotInConversationRoster, ConversationNotFound: the app was
			// removed from the team or the channel deleted.
			return &PermanentError{Err: fmt.Errorf("%w (HTTP %d %s)", ErrTeamsRemoved, resp.StatusCode, teamsErrorCode(msg))}
		case resp.StatusCode == 429:
			wait := time.Minute
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s < 3600 {
				wait = time.Duration(s) * time.Second
			}
			return &RetryAfterError{Wait: wait, Err: errors.New("teams: HTTP 429 (rate limited)")}
		default:
			return fmt.Errorf("teams: HTTP %d %s", resp.StatusCode, teamsErrorCode(msg))
		}
	}
}

// teamsErrorCode keeps the error code of a Bot Connector answer, not its
// whole body.
func teamsErrorCode(body []byte) string {
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error.Code != "" && len(e.Error.Code) < 80 {
		return e.Error.Code
	}
	return ""
}

// TeamsActivity is the message activity for m: the same Adaptive Card the
// Workflows webhook posts.
func TeamsActivity(m Message) map[string]any {
	p := teamsPayload(m)
	return map[string]any{"type": "message", "attachments": p["attachments"], "summary": m.Subject()}
}

// TeamsText is a plain message activity (replies to people in Teams).
func TeamsText(text string) map[string]any {
	return map[string]any{"type": "message", "textFormat": "markdown", "text": text}
}
