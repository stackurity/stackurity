package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net"
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

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

// Which CI identity the environment offers, or why there is none.
func TestDetectCI(t *testing.T) {
	var gotAuth, gotAud string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotAud = r.Header.Get("Authorization"), r.URL.Query().Get("audience")
		if r.URL.Query().Get("api-version") != "2.0" {
			http.Error(w, "query lost", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "gh-id-token"})
	}))
	defer gh.Close()
	ctx := context.Background()

	id, err := detectCI(envOf(map[string]string{"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": gh.URL + "/token?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runtime-secret"}), gh.Client())
	if err != nil || !id.needsAudience {
		t.Fatalf("GitHub Actions with id-token: write: %v", err)
	}
	if tok, err := id.idToken(ctx, "https://stk.example"); err != nil || tok != "gh-id-token" || gotAuth != "Bearer runtime-secret" || gotAud != "https://stk.example" {
		t.Errorf("GitHub ID token: %q %v (auth %q, audience %q)", tok, err, gotAuth, gotAud)
	}

	id, err = detectCI(envOf(map[string]string{"GITLAB_CI": "true", "STACKURITY_ID_TOKEN": " gl-id-token\n"}), nil)
	if err != nil || id.needsAudience {
		t.Fatalf("GitLab id_tokens: %v", err)
	}
	if tok, _ := id.idToken(ctx, ""); tok != "gl-id-token" {
		t.Errorf("GitLab ID token: %q", tok)
	}

	for name, c := range map[string]struct {
		env  map[string]string
		want string
	}{
		"GitHub without id-token: write": {map[string]string{"GITHUB_ACTIONS": "true"}, "permissions: id-token: write"},
		"GitHub with half the variables": {map[string]string{"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": gh.URL}, "permissions: id-token: write"},
		"GitLab without id_tokens":       {map[string]string{"GITLAB_CI": "true"}, "id_tokens: STACKURITY_ID_TOKEN"},
		"no CI":                          {map[string]string{}, "set STACKURITY_TOKEN or --token-file"},
	} {
		if _, err := detectCI(envOf(c.env), nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// The token, when set, wins: no exchange is attempted.
func TestCITokenNotUsedWithToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s", r.URL.Path)
	}))
	defer srv.Close()
	c := conn{server: srv.URL, ci: true, getenv: envOf(map[string]string{"STACKURITY_TOKEN": "stk_x", "STACKURITY_ID_TOKEN": "id"})}
	cl, err := c.clientCtx(context.Background())
	if err != nil || cl.Token != "stk_x" || c.ciRepo != "" {
		t.Fatalf("%v %+v", err, c)
	}
	// A command that does not allow it (c.ci false) never exchanges.
	c = conn{server: srv.URL, getenv: envOf(map[string]string{"STACKURITY_ID_TOKEN": "id"})}
	if _, err := c.clientCtx(context.Background()); err == nil || !strings.Contains(err.Error(), "no token") {
		t.Errorf("exchange outside scan: %v", err)
	}
}

// --- end to end against the real server

type testIssuer struct {
	srv  *httptest.Server
	key  *rsa.PrivateKey
	iss  string
	mu   sync.Mutex
	pool *x509.CertPool
}

// newTestIssuer serves discovery and keys for iss over TLS with a
// certificate for iss's host.
func newTestIssuer(t *testing.T, iss string) *testIssuer {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	ti := &testIssuer{key: k, iss: iss}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": ti.iss, "jwks_uri": ti.iss + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &k.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	ti.srv = httptest.NewUnstartedServer(mux)
	host := strings.SplitN(strings.TrimPrefix(iss, "https://"), "/", 2)[0]
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ck.PublicKey, ck)
	ti.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: ck}}}
	ti.srv.StartTLS()
	t.Cleanup(ti.srv.Close)
	cert, _ := x509.ParseCertificate(der)
	ti.pool = x509.NewCertPool()
	ti.pool.AddCert(cert)
	return ti
}

// client reaches the issuer whatever host is asked for.
func (ti *testIssuer) client() *http.Client {
	addr := ti.srv.Listener.Addr().String()
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ti.pool},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}}}
}

func (ti *testIssuer) sign(t *testing.T, claims map[string]any) string {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: ti.key, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := jwt.Signed(sig).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// stackurity scan in a GitHub Actions job with id-token: write and no
// stored token: it asks the runner for an ID token with the server's
// audience, exchanges it, and the scan lands on the job's repository.
// With another --git-url the server refuses it.
func TestScanKeylessGitHubActions(t *testing.T) {
	const aud = "https://stk.test"
	iss := newTestIssuer(t, api.GitHubIssuer)
	st := store.New(testdb.New(t))
	holder := &license.Holder{}
	s := &api.Server{Store: st, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test", Licence: holder,
		Gate: &license.Gate{Licence: holder}, CIAudience: aud, CIOIDCHTTP: iss.client()}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if _, err := st.CreateCITrust(ctx, store.CITrust{Provider: "github", Issuer: api.GitHubIssuer, Repository: "acme/shop", Ref: "refs/heads/main"}); err != nil {
		t.Fatal(err)
	}

	// The Actions runtime's ID token endpoint.
	var asked []string
	runner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runtime-secret" {
			http.Error(w, "no", 401)
			return
		}
		a := r.URL.Query().Get("audience")
		asked = append(asked, a)
		now := time.Now()
		_ = json.NewEncoder(w).Encode(map[string]string{"value": iss.sign(t, map[string]any{"iss": api.GitHubIssuer, "aud": a,
			"sub": "repo:acme/shop:ref:refs/heads/main", "exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nbf": now.Unix(),
			"repository": "acme/shop", "repository_owner": "acme", "repository_owner_id": "7", "ref": "refs/heads/main", "run_id": "99",
			"job_workflow_ref": "acme/shop/.github/workflows/scan.yml@refs/heads/main"})})
	}))
	defer runner.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STACKURITY_SERVER", srv.URL)
	t.Setenv("STACKURITY_TOKEN", "")
	t.Setenv("STACKURITY_CI_AUDIENCE", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", runner.URL+"/token?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runtime-secret")
	run := func(args ...string) error {
		cmd := scanCmd()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		return cmd.Execute()
	}
	if err := run(dir, "--no-packs"); err != nil {
		t.Fatalf("keyless scan: %v", err)
	}
	if len(asked) != 1 || asked[0] != aud {
		t.Errorf("audiences requested: %v, want the server's %s", asked, aud)
	}
	id, err := st.AssetByIdentifier(ctx, "git-url", "https://github.com/acme/shop")
	if err != nil {
		t.Fatalf("the repository's asset: %v", err)
	}
	if a, _ := st.GetAsset(ctx, id); a == nil || a.Kind != "repository" {
		t.Errorf("asset: %+v", a)
	}
	if err := run(dir, "--no-packs", "--git-url", "https://github.com/acme/other"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("another repository's identity: %v", err)
	}

	// Without id-token: write the job is told what to add.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	if err := run(dir, "--no-packs"); err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Errorf("no ID token: %v", err)
	}
}
