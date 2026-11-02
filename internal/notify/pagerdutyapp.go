package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
)

// The Stackurity PagerDuty app ("Connect PagerDuty"). One PagerDuty app
// with Scoped OAuth, registered by the operator, is authorised by a
// PagerDuty user of each customer with OAuth 2.0 and PKCE. With the token
// Stackurity lists the account's services, the admin picks one, and
// Stackurity adds an Events API v2 integration named "Stackurity" to it.
// The integration's routing key becomes the channel's secret, exactly as a
// pasted key would; the token is then thrown away (it is never needed to
// send events). See docs/install.md#pagerduty.

// PagerDutyAppScopes are the scopes asked for: services.read to list the
// services (and read an integration's key back), services.write to add the
// integration ("Create a new integration" requires it).
const PagerDutyAppScopes = "services.read services.write"

// PagerDutyIntegrationName is the name of the integration Stackurity adds.
const PagerDutyIntegrationName = "Stackurity"

// PagerDuty's identity service and REST API per service region. The
// identity service is the same for both regions; the token's ID token
// names the account's region.
const (
	PagerDutyIdentity = "https://identity.pagerduty.com"
	PagerDutyAPIUS    = "https://api.pagerduty.com"
	PagerDutyAPIEU    = "https://api.eu.pagerduty.com"
)

// PagerDutyApp is the app's configuration.
type PagerDutyApp struct {
	ClientID     string
	ClientSecret string
	// Identity, APIUS and APIEU replace PagerDuty's addresses (tests).
	Identity string
	APIUS    string
	APIEU    string
	// HTTP replaces the guarded client (tests).
	HTTP *http.Client

	once    sync.Once
	guarded *http.Client
}

// PagerDutyAppFromEnv reads STACKURITY_PAGERDUTY_CLIENT_ID (or _FILE) and
// STACKURITY_PAGERDUTY_CLIENT_SECRET (or _FILE). With neither the app is
// off (nil); with one only it is a configuration error.
func PagerDutyAppFromEnv() (*PagerDutyApp, error) {
	id, err := envOrFile("STACKURITY_PAGERDUTY_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	secret, err := envOrFile("STACKURITY_PAGERDUTY_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	switch {
	case id == "" && secret == "":
		return nil, nil
	case id == "" || secret == "":
		return nil, errors.New("the PagerDuty app needs STACKURITY_PAGERDUTY_CLIENT_ID and STACKURITY_PAGERDUTY_CLIENT_SECRET together (or neither)")
	}
	return &PagerDutyApp{ClientID: id, ClientSecret: secret}, nil
}

// envOrFile reads a setting from name or, when set, the file name_FILE.
func envOrFile(name string) (string, error) {
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

func (a *PagerDutyApp) identity() string {
	if a.Identity != "" {
		return strings.TrimSuffix(a.Identity, "/")
	}
	return PagerDutyIdentity
}

// API is the REST API address for a service region.
func (a *PagerDutyApp) API(region string) string {
	if region == "eu" {
		if a.APIEU != "" {
			return strings.TrimSuffix(a.APIEU, "/")
		}
		return PagerDutyAPIEU
	}
	if a.APIUS != "" {
		return strings.TrimSuffix(a.APIUS, "/")
	}
	return PagerDutyAPIUS
}

// client is the HTTP client for PagerDuty. Connections are checked by
// netguard when dialled; keep-alives are off so every request dials (a
// reused connection would skip that check), no proxy from the environment
// is used and redirects are not followed.
func (a *PagerDutyApp) client() *http.Client {
	if a.HTTP != nil {
		return a.HTTP
	}
	a.once.Do(func() { a.guarded = newPagerDutyClient() })
	return a.guarded
}

func newPagerDutyClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext:         netguard.DialContext,
			DisableKeepAlives:   true,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// NewPKCE returns a PKCE code verifier and its S256 challenge (RFC 7636).
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	return verifier, PKCEChallenge(verifier), nil
}

// PKCEChallenge is the S256 challenge of a verifier.
func PKCEChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthorizeURL is PagerDuty's consent page for one connect.
func (a *PagerDutyApp) AuthorizeURL(state, challenge, redirect string) string {
	q := url.Values{"client_id": {a.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"scope": {PagerDutyAppScopes}, "state": {state}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	return a.identity() + "/oauth/authorize?" + q.Encode()
}

// PagerDutyGrant is what a code exchange gives: the access token (kept only
// until the integration is made) and the account's service region. The
// refresh token PagerDuty also returns is dropped at once.
type PagerDutyGrant struct {
	AccessToken string
	Region      string // "us" or "eu"
	Scopes      []string
}

// ErrPagerDutyRefused: PagerDuty answered, but not with a usable token.
var ErrPagerDutyRefused = errors.New("PagerDuty did not complete the connection")

// ErrPagerDutyScope: the token lacks a scope Stackurity needs.
type ErrPagerDutyScope struct{ Missing []string }

func (e *ErrPagerDutyScope) Error() string {
	return "PagerDuty did not grant " + strings.Join(e.Missing, " and ") +
		": check that the Stackurity app in PagerDuty has the scopes services.read and services.write, then connect again"
}

// Exchange trades the code PagerDuty sent back, with the PKCE verifier,
// for an access token.
func (a *PagerDutyApp) Exchange(ctx context.Context, code, verifier, redirect string) (*PagerDutyGrant, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {a.ClientID}, "client_secret": {a.ClientSecret},
		"code": {code}, "redirect_uri": {redirect}, "code_verifier": {verifier}}
	req, err := http.NewRequestWithContext(ctx, "POST", a.identity()+"/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("pagerduty token: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		IDToken     string `json:"id_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil, fmt.Errorf("%w: HTTP %d", ErrPagerDutyRefused, resp.StatusCode)
	}
	if resp.StatusCode != 200 || out.AccessToken == "" {
		msg := out.Error
		if out.Description != "" {
			msg += ": " + out.Description
		}
		return nil, fmt.Errorf("%w: HTTP %d %s", ErrPagerDutyRefused, resp.StatusCode, clip(msg, 200))
	}
	if t := strings.ToLower(out.TokenType); t != "" && t != "bearer" {
		return nil, fmt.Errorf("%w: token type %q", ErrPagerDutyRefused, clip(out.TokenType, 20))
	}
	g := &PagerDutyGrant{AccessToken: out.AccessToken, Scopes: strings.Fields(out.Scope)}
	// PagerDuty does not refuse a scope it will not grant: the token comes
	// back with fewer scopes, so check them here, with a clear message.
	var missing []string
	for _, need := range strings.Fields(PagerDutyAppScopes) {
		if !hasScope(g.Scopes, need) {
			missing = append(missing, need)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrPagerDutyScope{Missing: missing}
	}
	g.Region = pagerDutyRegion(out.IDToken)
	return g, nil
}

func hasScope(have []string, want string) bool {
	for _, s := range have {
		if s == want {
			return true
		}
	}
	return false
}

// pagerDutyRegion reads the account's service region from the ID token's
// audience, which names the regional REST API (https://api.pagerduty.com or
// https://api.eu.pagerduty.com). The token came straight from PagerDuty's
// token endpoint over TLS, so its signature is not checked (OpenID Connect
// Core 3.1.3.7); only those two exact values are recognised, and anything
// else is the US region, PagerDuty's default.
func pagerDutyRegion(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "us"
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "us"
	}
	var claims struct {
		Aud    json.RawMessage `json:"aud"`
		Region string          `json:"region"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return "us"
	}
	var auds []string
	if json.Unmarshal(claims.Aud, &auds) != nil {
		var one string
		if json.Unmarshal(claims.Aud, &one) == nil {
			auds = []string{one}
		}
	}
	for _, a := range auds {
		if strings.TrimSuffix(a, "/") == PagerDutyAPIEU {
			return "eu"
		}
	}
	return "us"
}

// PagerDutyService is a service of the connected account.
type PagerDutyService struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Status      string `json:"status,omitempty"`
	HTMLURL     string `json:"html_url,omitempty"`
}

// PagerDutyMaxServices bounds how many services one listing reads (ten
// pages of 100); a query narrows it on larger accounts.
const PagerDutyMaxServices = 1000

var pagerDutyIDRE = regexp.MustCompile(`^[A-Z0-9]{1,32}$`)

// ValidPagerDutyID reports whether s looks like a PagerDuty object id.
func ValidPagerDutyID(s string) bool { return pagerDutyIDRE.MatchString(s) }

// ListServices reads the account's services, following PagerDuty's offset
// pagination; more is true when there were more than PagerDutyMaxServices.
func (a *PagerDutyApp) ListServices(ctx context.Context, g *PagerDutyGrant, query string) (services []PagerDutyService, more bool, err error) {
	const page = 100
	for offset := 0; offset < PagerDutyMaxServices; offset += page {
		q := url.Values{"limit": {strconv.Itoa(page)}, "offset": {strconv.Itoa(offset)}, "sort_by": {"name"}}
		if query = strings.TrimSpace(query); query != "" {
			q.Set("query", clip(query, 100))
		}
		var out struct {
			Services []PagerDutyService `json:"services"`
			More     bool               `json:"more"`
		}
		if err := a.rest(ctx, g, "GET", "/services?"+q.Encode(), nil, &out); err != nil {
			return nil, false, err
		}
		for _, s := range out.Services {
			if ValidPagerDutyID(s.ID) {
				s.Name, s.Description = clip(s.Name, 255), clip(s.Description, 300)
				s.HTMLURL = safePagerDutyURL(s.HTMLURL)
				services = append(services, s)
			}
		}
		if !out.More || len(out.Services) == 0 {
			return services, false, nil
		}
	}
	return services, true, nil
}

// PagerDutyIntegration is the Events API v2 integration Stackurity added.
type PagerDutyIntegration struct {
	ID          string
	ServiceID   string
	ServiceName string
	RoutingKey  string
	HTMLURL     string
}

var pagerDutyKeyRE = regexp.MustCompile(`^[A-Za-z0-9]{20,64}$`)

// CreateIntegration adds an Events API v2 integration named "Stackurity" to
// a service and returns its routing key (integration key).
func (a *PagerDutyApp) CreateIntegration(ctx context.Context, g *PagerDutyGrant, serviceID string) (*PagerDutyIntegration, error) {
	if !ValidPagerDutyID(serviceID) {
		return nil, errors.New("not a PagerDuty service id")
	}
	type ref struct {
		ID   string `json:"id"`
		Type string `json:"type"`
	}
	body := map[string]any{"integration": map[string]any{"type": "events_api_v2_inbound_integration",
		"name": PagerDutyIntegrationName, "service": ref{ID: serviceID, Type: "service_reference"}}}
	type integration struct {
		ID             string `json:"id"`
		Type           string `json:"type"`
		IntegrationKey string `json:"integration_key"`
		HTMLURL        string `json:"html_url"`
		Service        struct {
			ID      string `json:"id"`
			Summary string `json:"summary"`
		} `json:"service"`
	}
	var out struct {
		Integration integration `json:"integration"`
	}
	if err := a.rest(ctx, g, "POST", "/services/"+serviceID+"/integrations", body, &out); err != nil {
		return nil, err
	}
	in := out.Integration
	if !ValidPagerDutyID(in.ID) {
		return nil, fmt.Errorf("%w: no integration in the answer", ErrPagerDutyRefused)
	}
	// The key is normally in the answer; otherwise read the integration.
	if in.IntegrationKey == "" {
		var again struct {
			Integration integration `json:"integration"`
		}
		if err := a.rest(ctx, g, "GET", "/services/"+serviceID+"/integrations/"+in.ID, nil, &again); err != nil {
			return nil, err
		}
		in.IntegrationKey = again.Integration.IntegrationKey
	}
	if !pagerDutyKeyRE.MatchString(in.IntegrationKey) {
		return nil, fmt.Errorf("%w: PagerDuty returned no Events API v2 routing key", ErrPagerDutyRefused)
	}
	return &PagerDutyIntegration{ID: in.ID, ServiceID: serviceID, ServiceName: clip(in.Service.Summary, 255),
		RoutingKey: in.IntegrationKey, HTMLURL: safePagerDutyURL(in.HTMLURL)}, nil
}

// PagerDutyServiceURL is where a service's integrations are managed in
// PagerDuty's web app; app.pagerduty.com sends the person on to their own
// account.
func PagerDutyServiceURL(region, serviceID string) string {
	host := "app.pagerduty.com"
	if region == "eu" {
		host = "app.eu.pagerduty.com"
	}
	if !ValidPagerDutyID(serviceID) {
		return "https://" + host + "/service-directory"
	}
	return "https://" + host + "/service-directory/" + serviceID + "/integrations"
}

// safePagerDutyURL keeps an https address on pagerduty.com only.
func safePagerDutyURL(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || len(s) > 500 ||
		!(u.Hostname() == "pagerduty.com" || strings.HasSuffix(u.Hostname(), ".pagerduty.com")) {
		return ""
	}
	return s
}

// PagerDutyAPIError is an error answer of PagerDuty's REST API.
type PagerDutyAPIError struct {
	Status  int
	Message string
}

func (e *PagerDutyAPIError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized:
		return "PagerDuty no longer accepts this connection (HTTP 401): connect again"
	case http.StatusForbidden:
		return "PagerDuty refused (HTTP 403): the connection lacks the services.write scope, or your PagerDuty user may not add integrations to this service; " +
			"ask a PagerDuty admin or the service's manager to connect" + e.detail()
	case http.StatusNotFound:
		return "PagerDuty does not know that service (HTTP 404)" + e.detail()
	case http.StatusTooManyRequests:
		return "PagerDuty is rate limiting requests (HTTP 429): try again in a minute"
	}
	return "PagerDuty answered HTTP " + strconv.Itoa(e.Status) + e.detail()
}

func (e *PagerDutyAPIError) detail() string {
	if e.Message == "" {
		return ""
	}
	return " (" + e.Message + ")"
}

func (a *PagerDutyApp) rest(ctx context.Context, g *PagerDutyGrant, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.API(g.Region)+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+g.AccessToken)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
	req.Header.Set("User-Agent", "stackurity")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client().Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error struct {
				Message string   `json:"message"`
				Errors  []string `json:"errors"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Error.Message
		if len(e.Error.Errors) > 0 {
			msg += ": " + strings.Join(e.Error.Errors, "; ")
		}
		return &PagerDutyAPIError{Status: resp.StatusCode, Message: clip(msg, 300)}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: unreadable answer", ErrPagerDutyRefused)
	}
	return nil
}
