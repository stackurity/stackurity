package api_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
)

// A client whose metadata document declares private_key_jwt, as ChatGPT's
// (https://chatgpt.com/oauth/client.json) does: it connects by signing a
// client assertion with a key from its jwks_uri, and every malformed,
// misaddressed, foreign-signed or replayed assertion is refused.
func TestAssistantPrivateKeyJWT(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	meta := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		switch r.URL.Path {
		case "/oauth/client.json":
			_ = json.NewEncoder(w).Encode(map[string]any{"client_id": base + r.URL.Path, "client_name": "ChatGPT", "client_uri": base,
				"redirect_uris": []string{redirectURI}, "token_endpoint_auth_method": "private_key_jwt",
				"token_endpoint_auth_methods_supported": []string{"none", "private_key_jwt"}, "token_endpoint_auth_signing_alg": "RS256",
				"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "jwks_uri": base + "/oauth/jwks.json"})
		case "/oauth/jwks.json":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer meta.Close()
	e := newEnvWith(t, func(s *api.Server) { s.ClientMetadataHTTP = meta.Client() })
	withBaseURL(e)
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.signIn("admin@x.io")
	clientID := meta.URL + "/oauth/client.json"
	tokenURL := e.srv.URL + "/oauth/token"

	sign := func(signer any, alg jose.SignatureAlgorithm, kid string, c jwt.Claims) string {
		s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: signer}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
		if err != nil {
			t.Fatal(err)
		}
		out, err := jwt.Signed(s).Claims(c).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	n := 0
	claims := func() jwt.Claims {
		n++
		now := time.Now()
		return jwt.Claims{Issuer: clientID, Subject: clientID, Audience: jwt.Audience{tokenURL}, ID: "jti-" + string(rune('a'+n)),
			IssuedAt: jwt.NewNumericDate(now), Expiry: jwt.NewNumericDate(now.Add(5 * time.Minute))}
	}
	post := func(form url.Values) (int, map[string]any) {
		resp, err := http.Post(tokenURL, "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	md := &oauthFx{e: e, clientID: clientID}
	v, c := pkcePair("j")
	code := md.authorize(t, admin, c, auth.RoleViewer, 0)
	grant := func(assertion string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v}, "redirect_uri": {redirectURI},
			"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {assertion}}
	}

	// Refused: no assertion at all, the wrong audience, an expired one, a
	// key the client does not publish, another client named in iss.
	if status, _ := post(url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {v}, "redirect_uri": {redirectURI},
		"client_id": {clientID}}); status != 401 {
		t.Errorf("no assertion: %d", status)
	}
	wrongAud := claims()
	wrongAud.Audience = jwt.Audience{"https://elsewhere.example/oauth/token"}
	expired := claims()
	expired.Expiry = jwt.NewNumericDate(time.Now().Add(-5 * time.Minute))
	tooLong := claims()
	tooLong.Expiry = jwt.NewNumericDate(time.Now().Add(3 * time.Hour))
	otherIss := claims()
	otherIss.Issuer, otherIss.Subject = meta.URL+"/other.json", meta.URL+"/other.json"
	for name, a := range map[string]string{
		"wrong audience": sign(key, jose.RS256, "k1", wrongAud),
		"expired":        sign(key, jose.RS256, "k1", expired),
		"too long":       sign(key, jose.RS256, "k1", tooLong),
		"foreign key":    sign(other, jose.ES256, "k1", claims()),
		"unknown kid":    sign(other, jose.ES256, "k9", claims()),
		"other client":   sign(key, jose.RS256, "k1", otherIss),
		"not a JWT":      "abc.def.ghi",
	} {
		if status, out := post(grant(a)); status != 401 || out["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, status, out)
		}
	}
	// A secret alongside an assertion is refused too.
	f := grant(sign(key, jose.RS256, "k1", claims()))
	f.Set("client_secret", "x")
	if status, _ := post(f); status != 401 {
		t.Errorf("assertion and secret: %d", status)
	}

	// Accepted, once.
	good := sign(key, jose.RS256, "k1", claims())
	status, out := post(grant(good))
	if status != 200 || out["access_token"] == nil {
		t.Fatalf("good assertion: %d %v", status, out)
	}
	if code, _, _ := mcpPost(e, out["access_token"].(string), map[string]any{"id": 1, "method": "ping"}); code != 200 {
		t.Errorf("token from an assertion: %d", code)
	}
	refresh := out["refresh_token"].(string)
	if status, _ := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {good}}); status != 401 {
		t.Errorf("replayed assertion: %d", status)
	}
	// The issuer itself is an accepted audience; client_id may be given.
	issAud := claims()
	issAud.Audience = jwt.Audience{e.srv.URL}
	if status, out := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {clientID},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {sign(key, jose.RS256, "k1", issAud)}}); status != 200 {
		t.Errorf("refresh with an assertion: %d %v", status, out)
	}

	// The server says it supports the method.
	var asm map[string]any
	resp, err := http.Get(e.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	_ = json.NewDecoder(resp.Body).Decode(&asm)
	resp.Body.Close()
	if !strings.Contains(strings.Join(toStrings(asm["token_endpoint_auth_methods_supported"]), ","), "private_key_jwt") {
		t.Errorf("metadata: %v", asm["token_endpoint_auth_methods_supported"])
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
