// Package teamstest is a fake of Microsoft's Bot Framework and Entra
// endpoints for tests of the Stackurity Teams app: the OpenID metadata and
// signing keys, the token endpoint and the Bot Connector API. Nothing here
// talks to Microsoft.
package teamstest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/notify"
)

const (
	AppID    = "6f1c7a52-3c1e-4f0e-9b2a-1d2e3f4a5b6c"
	Password = "teams-client-secret-7Q~x"
	Issuer   = "https://api.botframework.com"
)

// Post is one request the fake Bot Connector received.
type Post struct {
	Path string
	Auth string
	Body map[string]any
}

// Fake is the fake Microsoft.
type Fake struct {
	Srv *httptest.Server
	t   *testing.T

	mu         sync.Mutex
	keys       map[string]*rsa.PrivateKey
	endorse    map[string][]string
	KeyFetches int
	Tokens     int // tokens issued
	tokenSeq   int
	revoked    map[string]bool
	Posts      []Post
	// Answer, when set, answers Bot Connector POSTs (status code).
	Answer func(path string) int
	// LastForm is the last token request's form.
	LastForm map[string][]string
}

// New starts the fake with one signing key "k1" endorsed for msteams.
func New(t *testing.T) *Fake {
	t.Helper()
	f := &Fake{t: t, keys: map[string]*rsa.PrivateKey{}, endorse: map[string][]string{}, revoked: map[string]bool{}}
	f.AddKey("k1", "msteams")
	f.Srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Srv.Close)
	return f
}

// AddKey adds (or replaces) a signing key in the published set.
func (f *Fake) AddKey(kid string, endorsements ...string) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		f.t.Fatal(err)
	}
	f.mu.Lock()
	f.keys[kid], f.endorse[kid] = k, endorsements
	f.mu.Unlock()
	return k
}

// Key returns a published key.
func (f *Fake) Key(kid string) *rsa.PrivateKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[kid]
}

// RevokeTokens makes the Bot Connector refuse every token issued so far.
func (f *Fake) RevokeTokens() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := 1; i <= f.tokenSeq; i++ {
		f.revoked["bf-token-"+itoa(i)] = true
	}
}

// ServiceURL is the fake's Bot Connector address (a region path, like
// smba.trafficmanager.net/amer/).
func (f *Fake) ServiceURL() string { return f.Srv.URL + "/amer/" }

// App is a TeamsApp pointed at the fake.
func (f *Fake) App() *notify.TeamsApp {
	return &notify.TeamsApp{AppID: AppID, Password: Password, OpenIDURL: f.Srv.URL + "/v1/.well-known/openidconfiguration",
		LoginURL: f.Srv.URL, HTTP: f.Srv.Client(),
		ServiceHosts: map[string]string{f.Srv.Listener.Addr().String(): f.Srv.URL + "/"}}
}

// Claims of a token the fake mints.
type Claims struct {
	Issuer     string
	Audience   string
	ServiceURL string
	Expiry     time.Time
	NotBefore  time.Time
}

// Good are the claims of a valid token for serviceURL.
func Good(serviceURL string) Claims {
	return Claims{Issuer: Issuer, Audience: AppID, ServiceURL: serviceURL, Expiry: time.Now().Add(time.Hour), NotBefore: time.Now().Add(-time.Minute)}
}

// Mint signs claims with key kid (RS256), as the Bot Framework does.
func (f *Fake) Mint(kid string, c Claims) string {
	return MintWith(f.t, f.Key(kid), kid, c)
}

// MintWith signs claims with any RSA key.
func MintWith(t *testing.T, key *rsa.PrivateKey, kid string, c Claims) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	type claims struct {
		jwt.Claims
		ServiceURL string `json:"serviceurl,omitempty"`
	}
	cl := claims{Claims: jwt.Claims{Issuer: c.Issuer, Expiry: jwt.NewNumericDate(c.Expiry), NotBefore: jwt.NewNumericDate(c.NotBefore)}, ServiceURL: c.ServiceURL}
	if c.Audience != "" {
		cl.Audience = jwt.Audience{c.Audience}
	}
	s, err := jwt.Signed(sig).Claims(cl).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// HS256 forges a token "signed" with HMAC using the public key's modulus
// as the secret (algorithm confusion).
func HS256(t *testing.T, secret []byte, kid string, c Claims) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: secret}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(map[string]any{"iss": c.Issuer, "aud": c.Audience, "serviceurl": c.ServiceURL,
		"exp": c.Expiry.Unix(), "nbf": c.NotBefore.Unix()}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// None forges an unsigned token (alg none).
func None(c Claims) string {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	return enc(map[string]string{"alg": "none", "typ": "JWT", "kid": "k1"}) + "." +
		enc(map[string]any{"iss": c.Issuer, "aud": c.Audience, "serviceurl": c.ServiceURL, "exp": c.Expiry.Unix()}) + "."
}

func itoa(i int) string { return big.NewInt(int64(i)).String() }

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/.well-known/openidconfiguration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": Issuer, "jwks_uri": f.Srv.URL + "/v1/.well-known/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	case r.URL.Path == "/v1/.well-known/keys":
		f.KeyFetches++
		var keys []map[string]any
		for kid, k := range f.keys {
			keys = append(keys, map[string]any{"kty": "RSA", "use": "sig", "kid": kid,
				"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
				"endorsements": f.endorse[kid]})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		_ = r.ParseForm()
		f.LastForm = r.PostForm
		ok := r.PostForm.Get("grant_type") == "client_credentials" && r.PostForm.Get("client_id") == AppID &&
			r.PostForm.Get("scope") == "https://api.botframework.com/.default" &&
			(r.PostForm.Get("client_secret") == Password || r.PostForm.Get("client_assertion") != "")
		if !ok {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}
		f.Tokens++
		f.tokenSeq++
		_ = json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer", "expires_in": 3600, "access_token": "bf-token-" + itoa(f.tokenSeq)})
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/amer/v3/conversations"):
		auth := r.Header.Get("Authorization")
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.Posts = append(f.Posts, Post{Path: strings.TrimPrefix(r.URL.Path, "/amer"), Auth: auth, Body: body})
		tok := strings.TrimPrefix(auth, "Bearer ")
		if !strings.HasPrefix(tok, "bf-token-") || f.revoked[tok] {
			w.WriteHeader(401)
			return
		}
		if f.Answer != nil {
			if code := f.Answer(r.URL.Path); code != 0 && code != 200 && code != 201 {
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "BotNotInConversationRoster", "message": "The bot is not part of the conversation roster."}})
				return
			}
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "1:new", "activityId": "a1"})
	default:
		http.NotFound(w, r)
	}
}

// PostsTo returns the posts whose path starts with prefix.
func (f *Fake) PostsTo(prefix string) []Post {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Post
	for _, p := range f.Posts {
		if strings.HasPrefix(p.Path, prefix) {
			out = append(out, p)
		}
	}
	return out
}

// Counts returns KeyFetches and Tokens.
func (f *Fake) Counts() (keyFetches, tokens int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.KeyFetches, f.Tokens
}
