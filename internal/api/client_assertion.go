package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/store"
)

// Client authentication with a signed JWT (private_key_jwt, RFC 7523
// section 2.2 and OpenID Connect Core section 9). ChatGPT's client ID
// metadata document (https://chatgpt.com/oauth/client.json) declares it,
// with its keys at jwks_uri. The client sends client_assertion_type
// urn:ietf:params:oauth:client-assertion-type:jwt-bearer and a JWT that it
// signed, whose iss and sub are its client_id, whose aud is this server's
// token endpoint (or its issuer), with exp and a jti used once.

const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// assertionAlgs are the signature algorithms accepted: asymmetric only.
var assertionAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384}

// maxAssertionLife bounds how far ahead an assertion's exp may be, so the
// list of used jti values stays short.
const maxAssertionLife = time.Hour

// jwksTTL is how long fetched keys are used; a kid not in the cached set
// fetches them again, at most once a minute.
const jwksTTL = time.Hour

type cachedKeys struct {
	keys    jose.JSONWebKeySet
	fetched time.Time
}

type jwksCache struct {
	mu   sync.Mutex
	sets map[string]cachedKeys
}

var clientKeys = &jwksCache{sets: map[string]cachedKeys{}}

// clientKeySet returns the client's public keys: inline from its metadata
// document, or fetched from its jwks_uri (through the outbound address
// guard, no redirects, 64 KiB, 5 seconds).
func (s *Server) clientKeySet(ctx context.Context, c *store.OAuthClient, kid string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	if len(c.JWKS) > 0 {
		if err := json.Unmarshal(c.JWKS, &set); err != nil {
			return set, errors.New("the client's jwks is not a key set")
		}
		return set, nil
	}
	if c.JWKSURI == "" {
		return set, errors.New("the client has no keys")
	}
	clientKeys.mu.Lock()
	cached, ok := clientKeys.sets[c.JWKSURI]
	clientKeys.mu.Unlock()
	fresh := ok && time.Since(cached.fetched) < jwksTTL
	if fresh && (kid == "" || len(cached.keys.Key(kid)) > 0 || time.Since(cached.fetched) < time.Minute) {
		return cached.keys, nil
	}
	hc := s.ClientMetadataHTTP
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: netguard.DialContext, ResponseHeaderTimeout: 5 * time.Second},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", c.JWKSURI, nil)
	if err != nil {
		return set, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return set, fmt.Errorf("could not fetch the client's keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return set, fmt.Errorf("the client's jwks_uri answered %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&set); err != nil {
		return set, errors.New("the client's jwks_uri is not a key set")
	}
	clientKeys.mu.Lock()
	clientKeys.sets[c.JWKSURI] = cachedKeys{keys: set, fetched: time.Now()}
	clientKeys.mu.Unlock()
	return set, nil
}

// assertionIssuer reads which client an assertion names, to find that
// client when the request does not send client_id (RFC 7523 allows it).
// It is only a lookup key: nothing is trusted until verifyClientAssertion
// has checked the signature against that client's own keys and iss, sub,
// aud, exp and jti.
func assertionIssuer(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || len(parts[1]) > 8<<10 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	return c.Issuer
}

// verifyClientAssertion checks a private_key_jwt client assertion for c.
func (s *Server) verifyClientAssertion(ctx context.Context, c *store.OAuthClient, assertion string) error {
	tok, err := jwt.ParseSigned(assertion, assertionAlgs)
	if err != nil {
		return errors.New("client_assertion is not a signed JWT with an accepted algorithm")
	}
	if len(tok.Headers) != 1 {
		return errors.New("client_assertion must have one signature")
	}
	h := tok.Headers[0]
	set, err := s.clientKeySet(ctx, c, h.KeyID)
	if err != nil {
		return err
	}
	keys := set.Keys
	if h.KeyID != "" {
		keys = set.Key(h.KeyID)
	}
	var claims jwt.Claims
	verified := false
	for _, k := range keys {
		if !k.Valid() || !k.IsPublic() || (k.Use != "" && k.Use != "sig") || (k.Algorithm != "" && k.Algorithm != h.Algorithm) {
			continue
		}
		if tok.Claims(k.Key, &claims) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return errors.New("client_assertion is not signed by a key of the client")
	}
	base := s.assistantBase()
	if claims.Issuer != c.ID || claims.Subject != c.ID {
		return errors.New("client_assertion iss and sub must be the client_id")
	}
	if !claims.Audience.Contains(base+"/oauth/token") && !claims.Audience.Contains(base) {
		return errors.New("client_assertion aud must be this server's token endpoint")
	}
	now := time.Now()
	if claims.Expiry == nil || claims.ID == "" {
		return errors.New("client_assertion needs exp and jti")
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Time: now}, time.Minute); err != nil {
		return fmt.Errorf("client_assertion: %w", err)
	}
	exp := claims.Expiry.Time()
	if exp.After(now.Add(maxAssertionLife)) {
		return errors.New("client_assertion expires too far ahead")
	}
	fresh, err := s.Store.UseClientAssertion(ctx, c.ID, claims.ID, exp.Add(time.Minute))
	if err != nil {
		return err
	}
	if !fresh {
		return errors.New("client_assertion was already used")
	}
	return nil
}

func algNames() []string {
	out := make([]string, len(assertionAlgs))
	for i, a := range assertionAlgs {
		out[i] = string(a)
	}
	return out
}
