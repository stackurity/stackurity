package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

const ciAud = "https://stk.test"

// fakeIssuer is a CI provider's OpenID Connect issuer: a discovery
// document and a key set over HTTPS, and tokens signed with test keys.
type fakeIssuer struct {
	t      *testing.T
	srv    *httptest.Server
	issuer string
	mu     sync.Mutex
	// published are the keys the JWKS serves; priv signs by key id.
	published []jose.JSONWebKey
	priv      map[string]*rsa.PrivateKey
	jwksHits  int
	// discIssuer, when set, is what the discovery document claims.
	discIssuer string
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newFakeIssuer serves on a TLS test server. issuer "" is the server's own
// URL; otherwise the server presents a certificate for issuer's host
// (reached through the client issuerClient returns).
func newFakeIssuer(t *testing.T, issuer string) *fakeIssuer {
	f := &fakeIssuer{t: t, priv: map[string]*rsa.PrivateKey{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		iss := f.issuer
		if f.discIssuer != "" {
			iss = f.discIssuer
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": f.issuer + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.jwksHits++
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: f.published})
	})
	f.srv = httptest.NewUnstartedServer(mux)
	if issuer != "" {
		host := strings.TrimPrefix(issuer, "https://")
		host = strings.SplitN(host, "/", 2)[0]
		f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t, host)}}
	}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	f.issuer = issuer
	if issuer == "" {
		f.issuer = f.srv.URL
	}
	f.addKey("k1")
	return f
}

func selfSigned(t *testing.T, host string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// pool trusts the fake issuer's certificate.
func (f *fakeIssuer) pool() *x509.CertPool {
	p := x509.NewCertPool()
	if f.srv.TLS != nil && len(f.srv.TLS.Certificates) > 0 {
		c, _ := x509.ParseCertificate(f.srv.TLS.Certificates[0].Certificate[0])
		p.AddCert(c)
	}
	p.AddCert(f.srv.Certificate())
	return p
}

// issuerClient reaches the fake issuer whatever host is asked for (for an
// issuer with a real provider's name).
func (f *fakeIssuer) issuerClient() *http.Client {
	addr := f.srv.Listener.Addr().String()
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: f.pool()},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
}

func (f *fakeIssuer) addKey(kid string) {
	k := rsaKey(f.t)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.priv[kid] = k
	f.published = append(f.published, jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
}

// addUnpublished makes a signing key the JWKS does not serve.
func (f *fakeIssuer) addUnpublished(kid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.priv[kid] = rsaKey(f.t)
}

func (f *fakeIssuer) publish(kid string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.published = append(f.published, jose.JSONWebKey{Key: &f.priv[kid].PublicKey, KeyID: kid, Algorithm: "RS256", Use: "sig"})
}

func (f *fakeIssuer) hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jwksHits
}

func (f *fakeIssuer) sign(kid string, claims map[string]any) string {
	f.mu.Lock()
	k := f.priv[kid]
	f.mu.Unlock()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k, KeyID: kid}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		f.t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// gitlabClaims are a GitLab CI job's ID token claims for project path.
func gitlabClaims(iss, path string, extra map[string]any) map[string]any {
	now := time.Now()
	ns := path[:strings.LastIndex(path, "/")]
	c := map[string]any{"iss": iss, "aud": ciAud, "sub": "project_path:" + path + ":ref_type:branch:ref:main",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(), "jti": "jti-" + path,
		"project_path": path, "namespace_path": ns, "namespace_id": "42", "ref": "main", "ref_type": "branch",
		"ref_path": "refs/heads/main", "pipeline_id": "777", "job_id": "888", "user_login": "dev",
		"ci_config_ref_uri": "gitlab.example/" + path + "//.gitlab-ci.yml@refs/heads/main"}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// ciEnv is a server whose CI audience is ciAud and that trusts f's
// certificate, with an admin signed in.
func ciEnv(t *testing.T, f *fakeIssuer) (*env, *session) {
	e := newEnvWith(t, func(s *api.Server) {
		s.BaseURL = ciAud + "/"
		s.CIOIDCRootCAs = f.pool()
	})
	e.user("admin@x.io", auth.RoleAdmin)
	return e, e.login("admin@x.io")
}

func exchange(e *env, idToken string, trust int64) (int, map[string]any) {
	var out map[string]any
	code := e.anon().do("POST", "/api/v1/ci/token", map[string]any{"token": idToken, "trust_id": trust}, &out)
	return code, out
}

func addTrust(t *testing.T, admin *session, body map[string]any) store.CITrust {
	t.Helper()
	var out store.CITrust
	if code := admin.do("POST", "/api/v1/ci-trusts", body, &out); code != 201 {
		t.Fatalf("create trust %v: %d", body, code)
	}
	return out
}

func repoBatch(name string, ids ...model.Identifier) []byte {
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetRepository, Name: name, Identifiers: ids})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.20", Confidence: model.ConfidenceConfirmed}}
	out, _ := json.Marshal(b)
	return out
}

func gitURL(v string) model.Identifier { return model.Identifier{Scheme: "git-url", Value: v} }

func ciAudit(t *testing.T, e *env, action string) []store.AuditEvent {
	t.Helper()
	items, _, err := e.st.ListAudit(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "ci_trust", "", store.Page{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []store.AuditEvent
	for _, a := range items {
		if a.Action == action {
			out = append(out, a)
		}
	}
	return out
}

// A GitLab job's token is exchanged through the real outbound path (the
// address guard of the trust's workspace) for a collector token that
// expires in 15 minutes, files its asset in the trust's project, can report
// only its own repository, and is audit-logged.
func TestCITokenExchange(t *testing.T) {
	f := newFakeIssuer(t, "")
	e, admin := ciEnv(t, f)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	proj, err := e.st.CreateProject(ctx, "payments", "")
	if err != nil {
		t.Fatal(err)
	}
	tr := addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer + "/", "repository": "group/app", "ref": "main", "project_id": proj.ID})
	if tr.Issuer != f.issuer || tr.Ref != "refs/heads/main" {
		t.Fatalf("trust not normalised: %+v", tr)
	}
	var list struct {
		Items    []store.CITrust `json:"items"`
		Audience string          `json:"audience"`
	}
	if admin.do("GET", "/api/v1/ci-trusts", nil, &list); len(list.Items) != 1 || list.Audience != ciAud {
		t.Fatalf("list: %+v", list)
	}
	var meta map[string]any
	e.anon().do("GET", "/api/v1/meta", nil, &meta)
	if meta["ci_audience"] != ciAud {
		t.Errorf("meta ci_audience = %v", meta["ci_audience"])
	}

	code, got := exchange(e, f.sign("k1", gitlabClaims(f.issuer, "group/app", nil)), 0)
	if code != 200 {
		t.Fatalf("exchange: %d %v", code, got)
	}
	repo := f.issuer + "/group/app"
	tok, _ := got["token"].(string)
	if got["repository_url"] != repo || !strings.HasPrefix(tok, "stk_") || got["trust_id"] != float64(tr.ID) {
		t.Fatalf("answer: %v", got)
	}
	exp, _ := time.Parse(time.RFC3339Nano, got["expires_at"].(string))
	if d := time.Until(exp); d < 14*time.Minute || d > 16*time.Minute {
		t.Errorf("token lives %v, want 15 minutes", d)
	}

	// Only its own repository.
	for name, b := range map[string][]byte{
		"another repository":            repoBatch("other", gitURL(f.issuer+"/group/other")),
		"a name instead of the git-url": repoBatch("app", model.Identifier{Scheme: "name:repository", Value: "app"}),
		"a host":                        sampleBatch(),
	} {
		if code := bearer(e, tok, "POST", "/api/v1/ingest", b, nil); code != 403 {
			t.Errorf("%s: %d, want 403", name, code)
		}
	}
	app := model.NewBatch(model.Collector{ID: "t", Method: "agent"}, model.AssetRef{Kind: model.AssetApplication, Name: "srv",
		Identifiers: []model.Identifier{{Scheme: model.AppPathScheme, Value: "/srv/app"}}})
	app.Relations = []model.RelationRef{{Kind: "runs_on", To: []model.Identifier{{Scheme: "machine-id", Value: "x"}}}}
	ab, _ := json.Marshal(app)
	if code := bearer(e, tok, "POST", "/api/v1/ingest", ab, nil); code != 403 {
		t.Errorf("application on a host: %d, want 403", code)
	}
	// Its repository, with an extra identifier that would claim another
	// asset: stored under the git-url alone, in the trust's project.
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/ingest", strings.NewReader(string(repoBatch("app",
		model.Identifier{Scheme: "name:repository", Value: "victim"}, gitURL(repo+".git")))))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var res store.IngestResult
	_ = json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("own repository: %d", resp.StatusCode)
	}
	ids, _ := e.st.AssetIdentifiers(ctx, res.AssetID)
	if len(ids) != 1 || ids[0].Scheme != "git-url" || ids[0].Value != repo {
		t.Errorf("identifiers stored: %+v", ids)
	}
	if in, _ := e.st.AssetInProject(ctx, proj.ID, res.AssetID); !in {
		t.Error("the asset is not in the trust's project")
	}
	if code := bearer(e, tok, "GET", "/api/v1/findings", nil, nil); code != 403 {
		t.Errorf("CI token read findings: %d", code)
	}

	// Audit: provider, repository, ref, run and jti.
	ev := ciAudit(t, e, "ci.token")
	if len(ev) != 1 {
		t.Fatalf("audit rows: %d", len(ev))
	}
	var d map[string]any
	_ = json.Unmarshal(ev[0].Detail, &d)
	for k, want := range map[string]any{"provider": "gitlab", "repository": "group/app", "ref": "refs/heads/main", "pipeline_id": "777",
		"job_id": "888", "jti": "jti-group/app", "issuer": f.issuer} {
		if d[k] != want {
			t.Errorf("audit %s = %v, want %v", k, d[k], want)
		}
	}
	if ev[0].ActorType != "ci" || ev[0].ActorName != "gitlab:group/app" {
		t.Errorf("audit actor %s %s", ev[0].ActorType, ev[0].ActorName)
	}

	// Not in the API token list; deleting the trust revokes its tokens.
	var toks struct {
		Items []store.Token `json:"items"`
	}
	admin.do("GET", "/api/v1/tokens", nil, &toks)
	for _, x := range toks.Items {
		if x.RepositoryURL != "" {
			t.Errorf("CI token listed: %+v", x)
		}
	}
	if code := admin.do("DELETE", "/api/v1/ci-trusts/"+itoa(tr.ID), nil, nil); code != 204 {
		t.Fatalf("delete trust: %d", code)
	}
	if code := bearer(e, tok, "POST", "/api/v1/ingest", repoBatch("app", gitURL(repo)), nil); code != 401 {
		t.Errorf("token of a deleted trust: %d, want 401", code)
	}
}

// Tokens that do not verify are refused, without a collector token.
func TestCITokenVerification(t *testing.T) {
	defer api.SetCITokenLimit(1000)()
	f := newFakeIssuer(t, "")
	e, admin := ciEnv(t, f)
	addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app"})
	now := time.Now()
	ok := func(extra map[string]any) string { return f.sign("k1", gitlabClaims(f.issuer, "group/app", extra)) }

	if code, got := exchange(e, ok(nil), 0); code != 200 {
		t.Fatalf("control: a valid token is accepted: %d %v", code, got)
	}

	hs := func() string {
		pub, _ := x509.MarshalPKIXPublicKey(&f.priv["k1"].PublicKey)
		sig, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: pub}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		s, _ := jwt.Signed(sig).Claims(gitlabClaims(f.issuer, "group/app", nil)).Serialize()
		return s
	}()
	none := func() string {
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		b, _ := json.Marshal(gitlabClaims(f.issuer, "group/app", nil))
		return h + "." + base64.RawURLEncoding.EncodeToString(b) + "."
	}()
	forged := func() string {
		// Signed with another key under the published key id.
		f.addUnpublished("forger")
		parts := strings.Split(f.sign("forger", gitlabClaims(f.issuer, "group/app", nil)), ".")
		h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`))
		good := strings.Split(ok(nil), ".")
		return h + "." + good[1] + "." + parts[2]
	}()
	tampered := func() string {
		parts := strings.Split(ok(nil), ".")
		b, _ := json.Marshal(gitlabClaims(f.issuer, "group/app", map[string]any{"project_path": "group/other"}))
		return parts[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + parts[2]
	}()
	f.addUnpublished("k9")

	for name, tok := range map[string]string{
		"wrong audience":           ok(map[string]any{"aud": "https://elsewhere.example"}),
		"two audiences":            ok(map[string]any{"aud": []string{ciAud, "https://elsewhere.example"}}),
		"no audience":              ok(map[string]any{"aud": nil}),
		"expired":                  ok(map[string]any{"exp": now.Add(-2 * time.Minute).Unix(), "iat": now.Add(-10 * time.Minute).Unix(), "nbf": now.Add(-10 * time.Minute).Unix()}),
		"not yet valid":            ok(map[string]any{"nbf": now.Add(5 * time.Minute).Unix()}),
		"issued in the future":     ok(map[string]any{"iat": now.Add(5 * time.Minute).Unix(), "nbf": nil}),
		"no exp":                   ok(map[string]any{"exp": nil}),
		"no iat":                   ok(map[string]any{"iat": nil}),
		"bad signature":            forged,
		"claims changed":           tampered,
		"unknown kid":              f.sign("k9", gitlabClaims(f.issuer, "group/app", nil)),
		"alg none":                 none,
		"HS256 with public key":    hs,
		"not a JWT":                "hello",
		"issuer with no trust":     ok(map[string]any{"iss": "https://gitlab.other.example"}),
		"http issuer":              ok(map[string]any{"iss": strings.Replace(f.issuer, "https://", "http://", 1)}),
		"issuer with a trailing /": ok(map[string]any{"iss": f.issuer + "/"}),
	} {
		code, got := exchange(e, tok, 0)
		if code != 401 && code != 403 {
			t.Errorf("%s: %d %v, want 401 or 403", name, code, got)
		}
		if got["token"] != nil {
			t.Errorf("%s: a token was issued", name)
		}
	}
	if n := len(ciAudit(t, e, "ci.token")); n != 1 {
		t.Errorf("tokens issued: %d, want only the control's", n)
	}

	// The discovery document must name the issuer exactly.
	f2 := newFakeIssuer(t, "")
	f2.discIssuer = "https://evil.example"
	e2, admin2 := ciEnv(t, f2)
	addTrust(t, admin2, map[string]any{"provider": "gitlab", "issuer": f2.issuer, "repository": "group/app"})
	if code, got := exchange(e2, f2.sign("k1", gitlabClaims(f2.issuer, "group/app", nil)), 0); code != 401 {
		t.Errorf("discovery naming another issuer: %d %v", code, got)
	}
}

// A rotated key is fetched when a token names a key id not in the cached
// set, and only after the refresh interval.
func TestCITokenKeyRotation(t *testing.T) {
	defer api.SetCITokenLimit(1000)()
	f := newFakeIssuer(t, "")
	e, admin := ciEnv(t, f)
	addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app"})
	tok := func(kid string) string { return f.sign(kid, gitlabClaims(f.issuer, "group/app", nil)) }
	if code, _ := exchange(e, tok("k1"), 0); code != 200 {
		t.Fatal(code)
	}
	if code, _ := exchange(e, tok("k1"), 0); code != 200 || f.hits() != 1 {
		t.Fatalf("cached keys: %d, %d fetches", code, f.hits())
	}
	// The issuer rotates to k2. Within the refresh interval a new key id
	// does not fetch again (made-up ids cannot make the server hammer the
	// issuer)...
	f.addUnpublished("k2")
	f.publish("k2")
	if code, _ := exchange(e, tok("k2"), 0); code != 401 || f.hits() != 1 {
		t.Errorf("within the refresh interval: %d, %d fetches", code, f.hits())
	}
	// ...after it, it does, and the rotated key verifies.
	defer api.SetCIKeysRefresh(0)()
	if code, got := exchange(e, tok("k2"), 0); code != 200 || f.hits() != 2 {
		t.Errorf("after rotation: %d %v, %d fetches", code, got, f.hits())
	}
	if code, _ := exchange(e, tok("k1"), 0); code != 200 || f.hits() != 2 {
		t.Errorf("old key still published: %d, %d fetches", code, f.hits())
	}
}

// Fetches go through the address guard of the trust's workspace: a policy
// that refuses private addresses refuses the (loopback) test issuer.
func TestCITokenFetchGuarded(t *testing.T) {
	f := newFakeIssuer(t, "")
	e, admin := ciEnv(t, f)
	addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app"})
	netguard.Set(netguard.Config{Mode: "none"})
	defer netguard.Set(netguard.FromEnv())
	code, got := exchange(e, f.sign("k1", gitlabClaims(f.issuer, "group/app", nil)), 0)
	if code != 401 || f.hits() != 0 || !strings.Contains(got["error"].(map[string]any)["message"].(string), "could not be fetched") {
		t.Errorf("private issuer under a guard that refuses it: %d %v, %d fetches", code, got, f.hits())
	}
	netguard.Set(netguard.Config{Mode: "default"})
	defer api.SetCIKeysRefresh(0)()
	if code, got := exchange(e, f.sign("k1", gitlabClaims(f.issuer, "group/app", nil)), 0); code != 200 {
		t.Errorf("control: allowed again: %d %v", code, got)
	}
}

// Trusts: the repository must match, constraints apply, an owner wildcard
// exists only when chosen, and the owner's id is pinned.
func TestCITrustMatching(t *testing.T) {
	defer api.SetCITokenLimit(1000)()
	f := newFakeIssuer(t, "")
	e, admin := ciEnv(t, f)
	e.user("eng@x.io", auth.RoleEngineer)
	if code := e.login("eng@x.io").do("POST", "/api/v1/ci-trusts", map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app"}, nil); code != 403 {
		t.Errorf("engineer created a trust: %d", code)
	}
	for _, bad := range []map[string]any{
		{"provider": "gitlab", "issuer": f.issuer, "repository": "group/*"},
		{"provider": "gitlab", "issuer": f.issuer, "repository": "*"},
		{"provider": "gitlab", "issuer": f.issuer, "repository": "*/*", "owner_wildcard": true},
		{"provider": "gitlab", "issuer": f.issuer, "repository": "group/ap*"},
		{"provider": "gitlab", "issuer": f.issuer, "repository": "app"},
		{"provider": "gitlab", "issuer": strings.Replace(f.issuer, "https", "http", 1), "repository": "group/app"},
		{"provider": "gitlab", "issuer": "https://user:pw@gitlab.example", "repository": "group/app"},
		{"provider": "github", "issuer": "https://evil.example", "repository": "acme/app"},
		{"provider": "github", "repository": "acme/app/sub"},
		{"provider": "jenkins", "repository": "acme/app"},
		{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app", "ref": "refs/heads/a b"},
	} {
		if code := admin.do("POST", "/api/v1/ci-trusts", bad, nil); code != 400 {
			t.Errorf("accepted %v: %d", bad, code)
		}
	}

	tr := addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app", "ref": "refs/heads/main", "environment": "production"})
	tok := func(path string, extra map[string]any) string {
		return f.sign("k1", gitlabClaims(f.issuer, path, extra))
	}
	if code, got := exchange(e, tok("group/other", map[string]any{"environment": "production"}), 0); code != 403 {
		t.Errorf("repository no trust names: %d %v", code, got)
	}
	code, got := exchange(e, tok("group/app", map[string]any{"environment": "production", "ref_path": "refs/heads/feature"}), 0)
	if code != 403 || !strings.Contains(got["error"].(map[string]any)["message"].(string), "refs/heads/main") {
		t.Errorf("other ref: %d %v", code, got)
	}
	if code, _ := exchange(e, tok("group/app", nil), 0); code != 403 {
		t.Errorf("no environment: %d", code)
	}
	if n := len(ciAudit(t, e, "ci.token_refused")); n != 2 {
		t.Errorf("refusals audited: %d, want 2", n)
	}
	if code, got := exchange(e, tok("GROUP/App", map[string]any{"environment": "production"}), 0); code != 200 {
		t.Errorf("control: matching job (name case differs): %d %v", code, got)
	}

	// No wildcard unless chosen: group/app's trust does not cover
	// group/other; an explicit owner wildcard covers the group's projects,
	// subgroups included, and not another group.
	wild := addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "team", "owner_wildcard": true})
	if wild.Repository != "team/*" || !wild.OwnerWildcard {
		t.Fatalf("wildcard trust: %+v", wild)
	}
	for path, want := range map[string]int{"team/api": 200, "team/sub/web": 200, "teamx/api": 403, "other/team": 403} {
		if code, got := exchange(e, tok(path, nil), 0); code != want {
			t.Errorf("owner wildcard, %s: %d %v, want %d", path, code, got, want)
		}
	}

	// The owner's id is pinned on first use: a group of the same name with
	// another id is refused.
	if code, got := exchange(e, tok("team/api", map[string]any{"namespace_id": "666"}), 0); code != 403 ||
		!strings.Contains(got["error"].(map[string]any)["message"].(string), "owner's id") {
		t.Errorf("owner re-registered: %d %v", code, got)
	}

	// Two trusts in one workspace and project: the most specific one is
	// used. In two projects: the job must choose (STACKURITY_CI_TRUST).
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	p2, _ := e.st.CreateProject(ctx, "two", "")
	other := addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "team/api", "project_id": p2.ID})
	if code, got := exchange(e, tok("team/api", nil), 0); code != 409 {
		t.Errorf("two projects accept the job: %d %v", code, got)
	}
	if code, got := exchange(e, tok("team/api", nil), other.ID); code != 200 || got["trust_id"] != float64(other.ID) {
		t.Errorf("chosen trust: %d %v", code, got)
	}
	if code, _ := exchange(e, tok("team/api", nil), tr.ID); code != 403 {
		t.Errorf("chosen trust that does not accept the job: %d", code)
	}
}

// GitHub Actions: the repository's identity is its github.com URL, and an
// organisation's id is pinned.
func TestCITokenGitHub(t *testing.T) {
	f := newFakeIssuer(t, api.GitHubIssuer)
	e := newEnvWith(t, func(s *api.Server) {
		s.BaseURL = ciAud
		s.CIOIDCHTTP = f.issuerClient()
	})
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	tr := addTrust(t, admin, map[string]any{"provider": "github", "repository": "acme/app",
		"workflow_ref": "acme/app/.github/workflows/scan.yml@refs/heads/main"})
	if tr.Issuer != api.GitHubIssuer {
		t.Fatalf("issuer: %s", tr.Issuer)
	}
	now := time.Now()
	claims := map[string]any{"iss": api.GitHubIssuer, "aud": ciAud, "sub": "repo:acme/app:ref:refs/heads/main", "exp": now.Add(5 * time.Minute).Unix(),
		"iat": now.Unix(), "nbf": now.Unix(), "jti": "gh-1", "repository": "acme/app", "repository_owner": "acme", "repository_owner_id": "1001",
		"ref": "refs/heads/main", "job_workflow_ref": "acme/app/.github/workflows/scan.yml@refs/heads/main", "run_id": "42", "run_attempt": "1",
		"sha": "abc", "actor": "octocat", "event_name": "push"}
	code, got := exchange(e, f.sign("k1", claims), 0)
	if code != 200 || got["repository_url"] != "https://github.com/acme/app" {
		t.Fatalf("exchange: %d %v", code, got)
	}
	tok := got["token"].(string)
	if code := bearer(e, tok, "POST", "/api/v1/ingest", repoBatch("app", gitURL("https://github.com/acme/app.git")), nil); code != 201 {
		t.Errorf("own repository: %d", code)
	}
	if code := bearer(e, tok, "POST", "/api/v1/ingest", repoBatch("lib", gitURL("https://github.com/acme/lib")), nil); code != 403 {
		t.Errorf("another repository of the owner: %d", code)
	}
	claims["job_workflow_ref"] = "acme/app/.github/workflows/other.yml@refs/heads/main"
	if code, _ := exchange(e, f.sign("k1", claims), 0); code != 403 {
		t.Errorf("another workflow: %d", code)
	}
	claims["job_workflow_ref"] = "acme/app/.github/workflows/scan.yml@refs/heads/main"
	claims["repository_owner_id"] = "2002"
	if code, _ := exchange(e, f.sign("k1", claims), 0); code != 403 {
		t.Errorf("owner id changed: %d", code)
	}
	ev := ciAudit(t, e, "ci.token")
	var d map[string]any
	if len(ev) != 1 || json.Unmarshal(ev[0].Detail, &d) != nil || d["run_id"] != "42" || d["jti"] != "gh-1" || d["sha"] != "abc" {
		t.Errorf("audit: %+v %v", ev, d)
	}
}

// The exchange is rate limited per address, before any work.
func TestCITokenRateLimit(t *testing.T) {
	defer api.SetCITokenLimit(3)()
	f := newFakeIssuer(t, "")
	e, admin := ciEnv(t, f)
	addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app"})
	tok := f.sign("k1", gitlabClaims(f.issuer, "group/app", nil))
	for i := 0; i < 3; i++ {
		if code, _ := exchange(e, tok, 0); code != 200 {
			t.Fatalf("exchange %d: %d", i, code)
		}
	}
	if code, _ := exchange(e, tok, 0); code != 429 {
		t.Errorf("over the limit: %d, want 429", code)
	}
}

// Without a public URL or audience the exchange is off.
func TestCITokenNeedsAudience(t *testing.T) {
	e := newEnv(t)
	if code, got := exchange(e, "x.y.z", 0); code != 503 {
		t.Errorf("no audience configured: %d %v", code, got)
	}
	var meta map[string]any
	e.anon().do("GET", "/api/v1/meta", nil, &meta)
	if _, ok := meta["ci_audience"]; ok {
		t.Errorf("meta offers a CI audience: %v", meta)
	}
}

// On a server with several organisations the job must name its trust, so
// a repository another organisation trusts by name never receives its
// scans by default.
func TestCITokenSeveralOrganisations(t *testing.T) {
	f := newFakeIssuer(t, "")
	e, admin := ciEnv(t, f)
	mine := addTrust(t, admin, map[string]any{"provider": "gitlab", "issuer": f.issuer, "repository": "group/app"})
	tok := f.sign("k1", gitlabClaims(f.issuer, "group/app", nil))
	if code, got := exchange(e, tok, 0); code != 200 {
		t.Fatalf("control: one organisation, no trust named: %d %v", code, got)
	}
	if _, _, err := e.st.CreateWorkspace(tenant.System(context.Background()), "Other", "other", "o@x.io", "O", pw); err != nil {
		t.Fatal(err)
	}
	if code, got := exchange(e, tok, 0); code != 400 || !strings.Contains(got["error"].(map[string]any)["message"].(string), "STACKURITY_CI_TRUST") {
		t.Errorf("several organisations, no trust named: %d %v", code, got)
	}
	if code, got := exchange(e, tok, mine.ID); code != 200 {
		t.Errorf("several organisations, trust named: %d %v", code, got)
	}
}
