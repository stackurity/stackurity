package api_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/githubapp"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/worker"
)

// The Stackurity GitHub App (github_app.go, internal/githubapp), on the real
// path: the API server, the store, the runner and gitrepo's hardened clone,
// against a fake GitHub (REST API, OAuth and git smart HTTP over TLS) that
// serves real bare repositories through git http-backend.

const (
	ghAppID         = 4242
	ghClientID      = "Iv1.testclient"
	ghClientSecret  = "gh-client-secret-5a6b7c"
	ghWebhookSecret = "gh-webhook-secret-1d2e3f"
	ghSlug          = "stackurity-test"
)

type ghRepo struct {
	id            int64
	fullName      string
	defaultBranch string
}

type ghInstall struct {
	id        int64
	appID     int64
	login     string
	repos     []int64
	suspended bool
}

type ghToken struct {
	installation int64
	repos        []int64 // nil: every repository of the installation
	perms        map[string]string
}

// fakeGitHub is GitHub for one app: installations, repositories, OAuth
// users, and git over HTTPS with installation tokens.
type fakeGitHub struct {
	t        *testing.T
	key      *rsa.PublicKey
	gitRoot  string
	backend  string
	mu       sync.Mutex
	repos    map[int64]*ghRepo
	installs map[int64]*ghInstall
	// codes maps an OAuth code to the GitHub user's token; users maps
	// that token to the installations the user can see.
	codes      map[string]string
	users      map[string][]int64
	tokens     map[string]ghToken
	issued     []string // every token handed out, installation and user
	tokenReqs  []ghToken
	exchanges  int
	revoked    []string
	deleted    []int64
	clones     map[string]int // full name -> successful upload-pack calls
	badGitAuth int
}

func newFakeGitHub(t *testing.T, key *rsa.PublicKey) *fakeGitHub {
	backend := filepath.Join(strings.TrimSpace(gitOut(t, "", "--exec-path")), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not available")
	}
	return &fakeGitHub{t: t, key: key, gitRoot: t.TempDir(), backend: backend, repos: map[int64]*ghRepo{}, installs: map[int64]*ghInstall{},
		codes: map[string]string{}, users: map[string][]int64{}, tokens: map[string]ghToken{}, clones: map[string]int{}}
}

func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

// addRepo creates a bare repository served at /<fullName>.git with files.
func (f *fakeGitHub) addRepo(id int64, fullName string, files map[string]string) {
	f.t.Helper()
	work := f.t.TempDir()
	gitOut(f.t, work, "init", "-q", "-b", "main")
	for name, body := range files {
		p := filepath.Join(work, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	gitOut(f.t, work, "add", ".")
	gitOut(f.t, work, "commit", "-qm", "init")
	gitOut(f.t, "", "clone", "-q", "--bare", work, filepath.Join(f.gitRoot, fullName+".git"))
	f.mu.Lock()
	f.repos[id] = &ghRepo{id: id, fullName: fullName, defaultBranch: "main"}
	f.mu.Unlock()
}

func (f *fakeGitHub) newToken(tk ghToken) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	tok := "ghs_" + hex.EncodeToString(b)
	f.tokens[tok] = tk
	f.issued = append(f.issued, tok)
	return tok
}

// user adds a GitHub user who can see installations, signing in with code.
func (f *fakeGitHub) user(code string, sees ...int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	tok := "ghu_" + hex.EncodeToString(b)
	f.codes[code] = tok
	f.users[tok] = sees
	f.issued = append(f.issued, tok)
}

func (f *fakeGitHub) appJWT(r *http.Request) bool {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(f.key, crypto.SHA256, sum[:], sig) != nil {
		return false
	}
	var head struct{ Alg string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	if json.Unmarshal(hb, &head) != nil || head.Alg != "RS256" {
		return false
	}
	var c struct {
		Iat, Exp int64
		Iss      string
	}
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if json.Unmarshal(cb, &c) != nil || c.Iss != strconv.Itoa(ghAppID) {
		return false
	}
	now := time.Now().Unix()
	return c.Iat <= now && c.Exp > now && c.Exp-c.Iat <= 600
}

func (f *fakeGitHub) installJSON(in *ghInstall) map[string]any {
	m := map[string]any{"id": in.id, "app_id": in.appID, "account": map[string]any{"login": in.login, "id": in.id * 10, "type": "Organization"},
		"target_type": "Organization", "repository_selection": "selected", "suspended_at": nil}
	if in.suspended {
		m["suspended_at"] = time.Now().UTC().Format(time.RFC3339)
	}
	return m
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	unlock := true
	defer func() {
		if unlock {
			f.mu.Unlock()
		}
	}()
	p := r.URL.Path
	writeJSON := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case r.Method == "POST" && p == "/login/oauth/access_token":
		_ = r.ParseForm()
		f.exchanges++
		tok, ok := f.codes[r.PostForm.Get("code")]
		if !ok || r.PostForm.Get("client_id") != ghClientID || r.PostForm.Get("client_secret") != ghClientSecret {
			writeJSON(200, map[string]string{"error": "bad_verification_code"})
			return
		}
		delete(f.codes, r.PostForm.Get("code")) // single use
		writeJSON(200, map[string]string{"access_token": tok, "token_type": "bearer"})
	case r.Method == "GET" && p == "/api/v3/user/installations":
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sees, ok := f.users[tok]
		if !ok {
			writeJSON(401, map[string]string{"message": "Bad credentials"})
			return
		}
		var list []map[string]any
		for _, id := range sees {
			if in, ok := f.installs[id]; ok {
				list = append(list, f.installJSON(in))
			}
		}
		writeJSON(200, map[string]any{"total_count": len(list), "installations": list})
	case r.Method == "DELETE" && p == "/api/v3/applications/"+ghClientID+"/token":
		id, secret, _ := r.BasicAuth()
		var body struct {
			AccessToken string `json:"access_token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if id == ghClientID && secret == ghClientSecret {
			f.revoked = append(f.revoked, body.AccessToken)
			delete(f.users, body.AccessToken)
		}
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/api/v3/app/installations/"):
		if !f.appJWT(r) {
			writeJSON(401, map[string]string{"message": "A JSON web token could not be decoded"})
			return
		}
		rest := strings.TrimPrefix(p, "/api/v3/app/installations/")
		idStr, tail, _ := strings.Cut(rest, "/")
		id, _ := strconv.ParseInt(idStr, 10, 64)
		in, ok := f.installs[id]
		if !ok || in.appID != ghAppID {
			writeJSON(404, map[string]string{"message": "Not Found"})
			return
		}
		switch {
		case r.Method == "GET" && tail == "":
			writeJSON(200, f.installJSON(in))
		case r.Method == "DELETE" && tail == "":
			f.deleted = append(f.deleted, id)
			delete(f.installs, id)
			w.WriteHeader(204)
		case r.Method == "POST" && tail == "access_tokens":
			if in.suspended {
				writeJSON(403, map[string]string{"message": "This installation has been suspended"})
				return
			}
			var body struct {
				RepositoryIDs []int64           `json:"repository_ids"`
				Permissions   map[string]string `json:"permissions"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, rid := range body.RepositoryIDs {
				if !contains(in.repos, rid) {
					writeJSON(422, map[string]string{"message": "There is at least one repository that does not exist or is not accessible"})
					return
				}
			}
			tk := ghToken{installation: id, repos: body.RepositoryIDs, perms: body.Permissions}
			f.tokenReqs = append(f.tokenReqs, tk)
			writeJSON(201, map[string]any{"token": f.newToken(tk), "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
				"permissions": body.Permissions})
		default:
			writeJSON(404, map[string]string{"message": "Not Found"})
		}
	case r.Method == "GET" && p == "/api/v3/installation/repositories":
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "token ")
		tk, ok := f.tokens[tok]
		if !ok {
			writeJSON(401, map[string]string{"message": "Bad credentials"})
			return
		}
		in := f.installs[tk.installation]
		var list []map[string]any
		if in != nil {
			for _, rid := range in.repos {
				rp := f.repos[rid]
				list = append(list, map[string]any{"id": rp.id, "full_name": rp.fullName, "default_branch": rp.defaultBranch, "private": true})
			}
		}
		writeJSON(200, map[string]any{"total_count": len(list), "repositories": list})
	case strings.Contains(p, ".git/"):
		// git smart HTTP: Basic x-access-token:<installation token> with
		// contents:read on this repository.
		full := strings.TrimPrefix(p[:strings.Index(p, ".git/")], "/")
		user, tok, _ := r.BasicAuth()
		tk, ok := f.tokens[tok]
		var repo *ghRepo
		for _, rp := range f.repos {
			if rp.fullName == full {
				repo = rp
			}
		}
		in := f.installs[tk.installation]
		if !ok || user != "x-access-token" || repo == nil || in == nil || !contains(in.repos, repo.id) || tk.perms["contents"] != "read" ||
			(tk.repos != nil && !contains(tk.repos, repo.id)) {
			f.badGitAuth++
			w.Header().Set("WWW-Authenticate", `Basic realm="GitHub"`)
			w.WriteHeader(401)
			return
		}
		if strings.HasSuffix(p, "/info/refs") {
			f.clones[full]++ // once per clone (then one or more POSTs)
		}
		f.mu.Unlock()
		unlock = false
		h := &cgi.Handler{Path: f.backend, Env: []string{"GIT_PROJECT_ROOT=" + f.gitRoot, "GIT_HTTP_EXPORT_ALL=1"}, InheritEnv: []string{"PATH"}}
		h.ServeHTTP(w, r)
	default:
		writeJSON(404, map[string]string{"message": "Not Found"})
	}
}

func contains(xs []int64, x int64) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

type ghFx struct {
	e      *env
	gh     *fakeGitHub
	srv    *httptest.Server
	app    *githubapp.App
	runner *githubapp.Runner
	pemKey string
}

const shopLock = `{"name":"shop","lockfileVersion":3,"packages":{"":{"name":"shop"},"node_modules/lodash":{"version":"4.17.20"}}}`
const blogLock = `{"name":"blog","lockfileVersion":3,"packages":{"":{"name":"blog"},"node_modules/minimist":{"version":"1.2.5"}}}`

func githubAppSetup(t *testing.T) *ghFx {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	gh := newFakeGitHub(t, &key.PublicKey)
	srv := httptest.NewTLSServer(gh)
	t.Cleanup(srv.Close)
	gh.addRepo(11, "acme/shop", map[string]string{"package-lock.json": shopLock, "README.md": "shop"})
	gh.addRepo(12, "acme/blog", map[string]string{"package-lock.json": blogLock})
	gh.addRepo(13, "acme/docs", map[string]string{"README.md": "docs"})
	gh.addRepo(21, "beta/api", map[string]string{"package-lock.json": shopLock})
	gh.installs[101] = &ghInstall{id: 101, appID: ghAppID, login: "acme", repos: []int64{11, 12}}
	gh.installs[202] = &ghInstall{id: 202, appID: ghAppID, login: "beta", repos: []int64{21}}
	gh.installs[303] = &ghInstall{id: 303, appID: 9999, login: "other-app", repos: []int64{13}}

	// The app's calls dial through netguard, as in production; the test
	// server's certificate is the only one trusted.
	// The fake GitHub is on 127.0.0.1, a private address: every
	// organisation may reach it here, as with STACKURITY_PRIVATE_CIDRS.
	restore := netguard.FromEnv()
	netguard.Set(netguard.Config{Mode: "default", Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	t.Cleanup(func() { netguard.Set(restore) })
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig
	client := &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{DialContext: netguard.DialContext, TLSClientConfig: tlsCfg, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	app := &githubapp.App{ID: ghAppID, ClientID: ghClientID, ClientSecret: ghClientSecret, Slug: ghSlug, WebhookSecret: ghWebhookSecret,
		Key: key, Web: srv.URL, API: srv.URL + "/api/v3", HTTP: client}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, func(s *api.Server) { s.GitHubApp = app; s.BaseURL = "https://stk.example" })
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("other-admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	runner := &githubapp.Runner{Store: e.st, App: app, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Spacing: -1,
		Scanner: &gitrepo.Scanner{WorkDir: t.TempDir(), Version: "test", CAFile: caFile, Timeout: time.Minute}}
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return &ghFx{e: e, gh: gh, srv: srv, app: app, runner: runner, pemKey: pemKey}
}

// start begins Install on GitHub as s and returns the state GitHub sends back.
func (f *ghFx) start(t *testing.T, s *session) string {
	t.Helper()
	var out struct{ URL string }
	if code := s.do("POST", "/api/v1/integrations/github/install", map[string]string{"return_to": "/settings/integrations"}, &out); code != 200 {
		t.Fatalf("install: %d", code)
	}
	u, err := url.Parse(out.URL)
	if err != nil || "https://"+u.Host != f.srv.URL || u.Path != "/github-apps/"+ghSlug+"/installations/new" {
		t.Fatalf("install url %q", out.URL)
	}
	state := u.Query().Get("state")
	if len(state) < 40 {
		t.Fatalf("state %q", state)
	}
	return state
}

type setupAnswer struct {
	Installation store.GitHubInstallation `json:"installation"`
	ReturnTo     string                   `json:"return_to"`
	Error        struct{ Code string }    `json:"error"`
}

func (f *ghFx) finish(s *session, state, code string, installation any) (int, setupAnswer) {
	var out setupAnswer
	st := s.do("POST", "/api/v1/integrations/github/setup", map[string]any{"state": state, "code": code, "installation_id": installation,
		"setup_action": "install"}, &out)
	return st, out
}

// install connects installation 101 to the default workspace as admin@x.io.
func (f *ghFx) install(t *testing.T) *session {
	t.Helper()
	admin := f.e.login("admin@x.io")
	f.gh.user("code-acme", 101)
	if code, out := f.finish(admin, f.start(t, admin), "code-acme", "101"); code != 201 || out.Installation.InstallationID != 101 {
		t.Fatalf("finish install: %d %+v", code, out)
	}
	return admin
}

// drain runs queued GitHub App jobs as the worker would: syncs and scans
// (others, such as evaluations, are completed without running). It returns
// the scans' errors by integration.
func (f *ghFx) drain(t *testing.T) map[int64]error {
	t.Helper()
	ctx := tenant.System(context.Background())
	errs := map[int64]error{}
	if _, err := f.e.st.Pool.Exec(ctx, `UPDATE jobs SET run_at = now() WHERE done_at IS NULL AND failed_at IS NULL AND kind IN ('integration.run', 'github_app.sync')`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		j, err := f.e.st.Claim(ctx, "test")
		if err != nil {
			t.Fatal(err)
		}
		if j == nil {
			return errs
		}
		jctx := context.Background()
		if j.WorkspaceID != nil {
			jctx = tenant.WithWorkspace(jctx, *j.WorkspaceID)
		}
		var p struct {
			InstallationID int64 `json:"installation_id"`
			IntegrationID  int64 `json:"integration_id"`
		}
		_ = json.Unmarshal(j.Payload, &p)
		var runErr error
		switch j.Kind {
		case "github_app.sync":
			runErr = f.runner.Sync(jctx, p.InstallationID)
		case "integration.run":
			in, err := f.e.st.GetIntegration(jctx, p.IntegrationID)
			if err != nil {
				t.Fatal(err)
			}
			jctx = store.WithReportSource(jctx, store.ReportSource{Source: store.SourceIntegration, IntegrationID: in.ID})
			runErr = f.runner.Run(jctx, in)
			errs[in.ID] = runErr
		}
		var d *worker.Deferred
		switch {
		case errors.As(runErr, &d):
			// Not run again in this drain.
			_ = f.e.st.DeferJob(ctx, j.ID, time.Hour)
		case runErr != nil:
			t.Fatalf("job %s: %v", j.Kind, runErr)
		default:
			_ = f.e.st.CompleteJob(ctx, j.ID)
		}
	}
	t.Fatal("jobs did not drain")
	return nil
}

// webhook delivers a signed event.
func (f *ghFx) webhook(t *testing.T, event, delivery string, payload any) (int, string) {
	t.Helper()
	body, _ := json.Marshal(payload)
	mac := hmac.New(sha256.New, []byte(ghWebhookSecret))
	mac.Write(body)
	return f.rawWebhook(t, body, map[string]string{"X-GitHub-Event": event, "X-GitHub-Delivery": delivery,
		"X-Hub-Signature-256": "sha256=" + hex.EncodeToString(mac.Sum(nil))})
}

func (f *ghFx) rawWebhook(t *testing.T, body []byte, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.e.srv.URL+"/api/v1/integrations/github/webhook", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Result string `json:"result"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.Result
}

// appIntegrations are the workspace's GitHub App integrations by name.
func appIntegrations(t *testing.T, e *env, ws int64) map[string]store.Integration {
	t.Helper()
	is, err := e.st.ListIntegrations(tenant.WithWorkspace(context.Background(), ws))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.Integration{}
	for _, in := range is {
		if in.Kind == store.KindGitHubApp {
			out[in.Name] = in
		}
	}
	return out
}

func dbScalar[T any](t *testing.T, e *env, q string, args ...any) T {
	t.Helper()
	var v T
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}

func TestGitHubAppInstallScansGrantedRepositories(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	// A CI scan already reported acme/shop: the app's scan lands on the same
	// asset (the same git-url identity).
	shopURL := gitrepo.NormalizeURL(f.srv.URL + "/acme/shop.git")
	ci := model.NewBatch(model.Collector{ID: "lockfile-scanner", Version: "1", Method: "lockfile"},
		model.AssetRef{Kind: model.AssetRepository, Name: "acme/shop", Identifiers: []model.Identifier{{Scheme: "git-url", Value: shopURL}}})
	ciRaw, _ := json.Marshal(ci)
	_, secret, err := e.st.CreateToken(ctx, "ci", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if code := bearer(e, secret, "POST", "/api/v1/ingest", ciRaw, nil); code != 201 {
		t.Fatalf("CI ingest: %d", code)
	}
	ciAsset := dbScalar[int64](t, e, `SELECT asset_id FROM asset_identifiers WHERE scheme = 'git-url' AND value = $1`, shopURL)

	// Without the app nothing is offered; engineers see the status, not the
	// install.
	var status struct {
		Configured    bool
		Installations []store.GitHubInstallation
	}
	if code := e.login("eng@x.io").do("GET", "/api/v1/integrations/github", nil, &status); code != 200 || !status.Configured || len(status.Installations) != 0 {
		t.Fatalf("status: %d %+v", code, status)
	}
	if code := e.login("eng@x.io").do("POST", "/api/v1/integrations/github/install", map[string]string{}, nil); code != 403 {
		t.Fatalf("engineer install: %d", code)
	}

	admin := f.install(t)
	// The user token was used to check the installation, then revoked.
	if len(f.gh.revoked) != 1 {
		t.Fatalf("user token revoked %d times", len(f.gh.revoked))
	}
	f.drain(t)

	ints := appIntegrations(t, e, tenant.DefaultWorkspace)
	if len(ints) != 2 || ints["acme/shop"].ID == 0 || ints["acme/blog"].ID == 0 {
		t.Fatalf("integrations: %+v", ints)
	}
	for name, in := range ints {
		got, _ := e.st.GetIntegration(ctx, in.ID)
		if got.LastError != "" || got.LastSuccess == nil || got.AssetID == nil || got.SecretRef != "" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	if got := *mustIntegration(t, e, ints["acme/shop"].ID).AssetID; got != ciAsset {
		t.Fatalf("the app's scan made asset %d, CI's is %d: one repository, two assets", got, ciAsset)
	}
	n := dbScalar[int64](t, e, `SELECT count(*) FROM inventory i JOIN components c ON c.id = i.component_id
		WHERE i.asset_id = $1 AND c.name = 'lodash' AND i.version = '4.17.20' AND i.removed_at IS NULL`, ciAsset)
	if n != 1 {
		t.Fatalf("lodash on the shop asset: %d", n)
	}
	if f.gh.clones["acme/shop"] != 1 || f.gh.clones["acme/blog"] != 1 || f.gh.clones["acme/docs"] != 0 {
		t.Fatalf("clones: %v", f.gh.clones)
	}

	// Every token: read-only; each scan's for its one repository.
	scoped := 0
	for _, tk := range f.gh.tokenReqs {
		for k, v := range tk.perms {
			if v != "read" {
				t.Fatalf("token asked for %s:%s", k, v)
			}
		}
		if tk.perms["contents"] == "read" {
			scoped++
			if len(tk.repos) != 1 {
				t.Fatalf("a scan's token covers %v", tk.repos)
			}
		} else if tk.perms["metadata"] != "read" || len(tk.perms) != 1 {
			t.Fatalf("listing token %+v", tk.perms)
		}
	}
	if scoped != 2 {
		t.Fatalf("scan tokens: %d", scoped)
	}

	// The installation is listed with its repositories.
	if code := admin.do("GET", "/api/v1/integrations/github", nil, &status); code != 200 || len(status.Installations) != 1 ||
		status.Installations[0].Repositories != 2 || status.Installations[0].AccountLogin != "acme" || status.Installations[0].Status != "active" {
		t.Fatalf("status after install: %+v", status)
	}

	// The integration is the app's: no config or name changes, no manual
	// github_app integrations; switching off and rescheduling work.
	id := ints["acme/shop"].ID
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(id), map[string]any{"config": map[string]any{"installation_id": 202}}, nil); code != 400 {
		t.Fatalf("config change: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(id), map[string]any{"secret_ref": "env:STACKURITY_SECRET_X"}, nil); code != 400 {
		t.Fatalf("secret change: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(id), map[string]any{"schedule_minutes": 720, "enabled": true}, nil); code != 200 {
		t.Fatalf("schedule change: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "github_app",
		"config": map[string]any{"installation_id": 202, "repository_id": 21, "full_name": "beta/api"}}, nil); code != 400 {
		t.Fatalf("manual github_app integration: %d", code)
	}

	assertNoTokenMaterial(t, f)
}

func mustIntegration(t *testing.T, e *env, id int64) *store.Integration {
	t.Helper()
	in, err := e.st.GetIntegration(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), id)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// assertNoTokenMaterial reads every row of every table as text: no GitHub
// token (installation or user), OAuth code, client secret, webhook secret
// or private key may be anywhere in the database.
func assertNoTokenMaterial(t *testing.T, f *ghFx) {
	t.Helper()
	ctx := tenant.System(context.Background())
	rows, err := f.e.st.Pool.Query(ctx, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	if len(tables) < 20 {
		t.Fatalf("only %d tables found", len(tables))
	}
	f.gh.mu.Lock()
	secrets := append([]string{ghClientSecret, ghWebhookSecret, "code-acme"}, f.gh.issued...)
	f.gh.mu.Unlock()
	keyLines := strings.Split(f.pemKey, "\n")
	secrets = append(secrets, keyLines[2], keyLines[len(keyLines)-3])
	if len(f.gh.issued) < 3 {
		t.Fatalf("only %d tokens issued: the check would prove little", len(f.gh.issued))
	}
	var dump strings.Builder
	for _, tb := range tables {
		rs, err := f.e.st.Pool.Query(ctx, `SELECT t::text FROM `+pgIdent(tb)+` t`)
		if err != nil {
			t.Fatalf("%s: %v", tb, err)
		}
		for rs.Next() {
			var s string
			_ = rs.Scan(&s)
			dump.WriteString(tb + ": " + s + "\n")
		}
		rs.Close()
	}
	all := dump.String()
	for _, s := range secrets {
		if s != "" && strings.Contains(all, s) {
			i := strings.Index(all, s)
			t.Fatalf("token material %q found in the database: %s", s[:min(8, len(s))]+"...", all[max(0, i-200):i])
		}
	}
}

func pgIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func TestGitHubAppStateIsBoundAndSingleUse(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	admin, other := e.login("admin@x.io"), e.login("other-admin@x.io")
	f.gh.user("code-1", 101)
	f.gh.user("code-2", 101)

	// Another admin of the same organisation cannot use admin's state.
	state := f.start(t, admin)
	if code, out := f.finish(other, state, "code-1", 101); code != 400 || out.Error.Code != "github_state" {
		t.Fatalf("someone else's state: %d %+v", code, out)
	}
	// Nor can a person of another organisation.
	ws2, _, err := e.st.CreateWorkspace(context.Background(), "Beta Corp", "", "beta-admin@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	beta := e.login("beta-admin@x.io")
	if code, _ := f.finish(beta, state, "code-1", 101); code != 400 {
		t.Fatalf("another organisation's state: %d", code)
	}
	// Missing, forged and expired states.
	for _, s := range []string{"", "forged-state-value-that-is-long-enough-xxxxxxxx"} {
		if code, _ := f.finish(admin, s, "code-1", 101); code != 400 {
			t.Fatalf("state %q: %d", s, code)
		}
	}
	old := f.start(t, admin)
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE github_app_states SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.finish(admin, old, "code-1", 101); code != 400 {
		t.Fatalf("expired state: %d", code)
	}
	// None of those reached GitHub: the state is checked first.
	if f.gh.exchanges != 0 {
		t.Fatalf("GitHub was asked %d times for refused states", f.gh.exchanges)
	}
	// The person's own fresh state works once.
	state = f.start(t, admin)
	if code, _ := f.finish(admin, state, "code-1", 101); code != 201 {
		t.Fatalf("own state: %d", code)
	}
	if code, out := f.finish(admin, state, "code-2", 101); code != 400 || out.Error.Code != "github_state" {
		t.Fatalf("state used twice: %d %+v", code, out)
	}
	if f.gh.exchanges != 1 {
		t.Fatalf("exchanges: %d", f.gh.exchanges)
	}
	_ = ws2
}

// TestGitHubAppRefusesForgedInstallation is the account-takeover case: an
// admin of another organisation, with their own valid state and their own
// GitHub account, sends the victim's installation_id.
func TestGitHubAppRefusesForgedInstallation(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	ws2, _, err := e.st.CreateWorkspace(context.Background(), "Beta Corp", "", "beta-admin@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	beta := e.login("beta-admin@x.io")
	// The attacker's GitHub account sees only their own installation.
	f.gh.user("code-attacker", 202)
	if code, out := f.finish(beta, f.start(t, beta), "code-attacker", 101); code != 403 || out.Error.Code != "github_installation" {
		t.Fatalf("forged installation_id: %d %+v", code, out)
	}
	// Nor can they claim an installation of another GitHub App (the API
	// lists only this app's installations, and its JWT is checked too).
	f.gh.user("code-attacker-2", 303)
	if code, _ := f.finish(beta, f.start(t, beta), "code-attacker-2", 303); code != 403 {
		t.Fatalf("another app's installation: %d", code)
	}
	// Nor with a code GitHub did not issue.
	if code, out := f.finish(beta, f.start(t, beta), "made-up-code", 101); code != 502 || out.Error.Code != "github_refused" {
		t.Fatalf("made-up code: %d %+v", code, out)
	}
	if n := dbScalar[int64](t, e, `SELECT count(*) FROM github_installations`); n != 0 {
		t.Fatalf("installations bound: %d", n)
	}

	// The victim connects it; an installation belongs to one organisation,
	// so even a GitHub user who can see it (a member of both) cannot bind
	// it to a second one.
	f.install(t)
	f.gh.user("code-member-of-both", 101, 202)
	if code, out := f.finish(beta, f.start(t, beta), "code-member-of-both", 101); code != 409 || out.Error.Code != "github_installation_taken" {
		t.Fatalf("second binding: %d %+v", code, out)
	}
	if owner := dbScalar[int64](t, e, `SELECT workspace_id FROM github_installations WHERE installation_id = 101`); owner != tenant.DefaultWorkspace {
		t.Fatalf("installation 101 now belongs to %d", owner)
	}
	// Their own installation binds to their organisation.
	f.gh.user("code-beta", 202)
	if code, _ := f.finish(beta, f.start(t, beta), "code-beta", "202"); code != 201 {
		t.Fatalf("own installation: %d", code)
	}
	f.drain(t)
	if ints := appIntegrations(t, e, ws2.ID); len(ints) != 1 || ints["beta/api"].ID == 0 {
		t.Fatalf("beta's integrations: %+v", ints)
	}
	if ints := appIntegrations(t, e, tenant.DefaultWorkspace); len(ints) != 2 {
		t.Fatalf("acme's integrations: %+v", ints)
	}
	// Beta cannot see or disconnect acme's installation.
	var status struct{ Installations []store.GitHubInstallation }
	beta.do("GET", "/api/v1/integrations/github", nil, &status)
	if len(status.Installations) != 1 || status.Installations[0].InstallationID != 202 {
		t.Fatalf("beta sees %+v", status.Installations)
	}
	if code := beta.do("DELETE", "/api/v1/integrations/github/installations/101", nil, nil); code != 404 {
		t.Fatalf("beta disconnects acme's installation: %d", code)
	}
}

func TestGitHubAppWebhookSignature(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	f.install(t)
	f.drain(t)
	body, _ := json.Marshal(map[string]any{"action": "deleted", "installation": map[string]any{"id": 101}})
	sign := func(secret string, b []byte) string {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write(b)
		return "sha256=" + hex.EncodeToString(m.Sum(nil))
	}
	hdr := func(sig string) map[string]string {
		h := map[string]string{"X-GitHub-Event": "installation", "X-GitHub-Delivery": "d-forged"}
		if sig != "" {
			h["X-Hub-Signature-256"] = sig
		}
		return h
	}
	tampered := bytes.Replace(body, []byte("101"), []byte("102"), 1)
	for name, h := range map[string]map[string]string{
		"missing":         hdr(""),
		"wrong secret":    hdr(sign("not-the-secret", body)),
		"other body":      hdr(sign(ghWebhookSecret, tampered)),
		"sha1 style":      hdr("sha1=" + strings.Repeat("0", 40)),
		"not hex":         hdr("sha256=zz"),
		"truncated":       hdr(sign(ghWebhookSecret, body)[:40]),
		"empty signature": hdr("sha256="),
	} {
		if code, _ := f.rawWebhook(t, body, h); code != 401 {
			t.Errorf("%s signature: %d", name, code)
		}
	}
	if st := dbScalar[string](t, e, `SELECT status FROM github_installations WHERE installation_id = 101`); st != "active" {
		t.Fatalf("an unverified delivery changed the installation: %s", st)
	}
	// Missing delivery id: refused even when signed.
	if code, _ := f.rawWebhook(t, body, map[string]string{"X-GitHub-Event": "installation", "X-Hub-Signature-256": sign(ghWebhookSecret, body)}); code != 400 {
		t.Fatalf("missing delivery: %d", code)
	}
	// A verified suspend works once; the redelivery and a replay of the same
	// body under another delivery id are acknowledged and ignored.
	sus := map[string]any{"action": "suspend", "installation": map[string]any{"id": 101}}
	if code, res := f.webhook(t, "installation", "d-1", sus); code != 200 || res != "suspended" {
		t.Fatalf("suspend: %d %q", code, res)
	}
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE github_installations SET status = 'active'`); err != nil {
		t.Fatal(err)
	}
	if code, res := f.webhook(t, "installation", "d-1", sus); code != 200 || res != "duplicate" {
		t.Fatalf("redelivery: %d %q", code, res)
	}
	if code, res := f.webhook(t, "installation", "d-1-replayed", sus); code != 200 || res != "duplicate" {
		t.Fatalf("replay under a new delivery id: %d %q", code, res)
	}
	if st := dbScalar[string](t, e, `SELECT status FROM github_installations WHERE installation_id = 101`); st != "active" {
		t.Fatalf("a duplicate was acted on: %s", st)
	}
	// Events for installations not connected here change nothing.
	if code, res := f.webhook(t, "installation", "d-2", map[string]any{"action": "deleted", "installation": map[string]any{"id": 999}}); code != 200 || res != "not connected" {
		t.Fatalf("unknown installation: %d %q", code, res)
	}
	if code, res := f.webhook(t, "ping", "d-3", map[string]any{"zen": "x"}); code != 200 || res != "pong" {
		t.Fatalf("ping: %d %q", code, res)
	}
}

func pushEvent(ref string, files ...string) map[string]any {
	return map[string]any{"ref": ref, "installation": map[string]any{"id": 101},
		"repository": map[string]any{"id": 11, "full_name": "acme/shop", "default_branch": "main"},
		"commits":    []map[string]any{{"added": []string{}, "removed": []string{}, "modified": files}}}
}

func TestGitHubAppPushScansOnlyLockfileChanges(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	f.install(t)
	f.drain(t)
	shop := appIntegrations(t, e, tenant.DefaultWorkspace)["acme/shop"].ID
	pending := func() int64 {
		return dbScalar[int64](t, e, `SELECT count(*) FROM jobs WHERE kind = 'integration.run' AND done_at IS NULL AND failed_at IS NULL
			AND payload->>'integration_id' = $1`, itoa(shop))
	}
	for i, c := range []struct {
		ev   map[string]any
		want string
	}{
		{pushEvent("refs/heads/main", "README.md", "src/app.js"), "ignored: no lockfile or manifest changed"},
		{pushEvent("refs/heads/feature", "package-lock.json"), "ignored: not the default branch"},
		{pushEvent("refs/tags/v1", "package-lock.json"), "ignored: not the default branch"},
		{map[string]any{"ref": "refs/heads/main", "deleted": true, "installation": map[string]any{"id": 101},
			"repository": map[string]any{"id": 11, "default_branch": "main"}, "commits": []any{}}, "ignored: not the default branch"},
		{map[string]any{"ref": "refs/heads/main", "installation": map[string]any{"id": 101},
			"repository": map[string]any{"id": 13, "default_branch": "main"}, "commits": []any{}}, "ignored: repository not scanned"},
	} {
		if code, res := f.webhook(t, "push", fmt.Sprintf("p-%d", i), c.ev); code != 200 || res != c.want {
			t.Fatalf("push %d: %d %q, want %q", i, code, res, c.want)
		}
	}
	if n := pending(); n != 0 {
		t.Fatalf("scans queued for irrelevant pushes: %d", n)
	}
	// A lockfile in a subdirectory, a manifest, or an unknown change.
	for i, ev := range []map[string]any{
		pushEvent("refs/heads/main", "README.md", "services/web/package-lock.json"),
		pushEvent("refs/heads/main", "package.json"),
		{"ref": "refs/heads/main", "installation": map[string]any{"id": 101}, "repository": map[string]any{"id": 11, "default_branch": "main"}, "commits": []any{}},
	} {
		if code, res := f.webhook(t, "push", fmt.Sprintf("q-%d", i), ev); code != 200 || res != "scan queued" {
			t.Fatalf("lockfile push %d: %d %q", i, code, res)
		}
	}
	if n := pending(); n != 1 {
		t.Fatalf("pushes queue one scan (deduplicated), got %d", n)
	}
	before := f.gh.clones["acme/shop"]
	f.drain(t)
	if f.gh.clones["acme/shop"] != before+1 {
		t.Fatalf("clones after push: %d (before %d)", f.gh.clones["acme/shop"], before)
	}
	// A push for a switched-off integration is ignored.
	admin := e.login("admin@x.io")
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(shop), map[string]any{"enabled": false}, nil); code != 200 {
		t.Fatal(code)
	}
	if _, res := f.webhook(t, "push", "r-1", pushEvent("refs/heads/main", "package-lock.json")); res != "ignored: repository not scanned" {
		t.Fatalf("push to a switched-off repository: %q", res)
	}
}

func TestGitHubAppRepositoriesAddedAndRemoved(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f.install(t)
	f.drain(t)
	blog := appIntegrations(t, e, tenant.DefaultWorkspace)["acme/blog"]
	blogAsset := *mustIntegration(t, e, blog.ID).AssetID

	// acme/blog removed from the installation on GitHub.
	f.gh.mu.Lock()
	f.gh.installs[101].repos = []int64{11}
	f.gh.mu.Unlock()
	if code, res := f.webhook(t, "installation_repositories", "r-1", map[string]any{"action": "removed", "installation": map[string]any{"id": 101},
		"repositories_removed": []map[string]any{{"id": 12, "full_name": "acme/blog"}}, "repositories_added": []any{}}); code != 200 || res != "sync queued" {
		t.Fatalf("removed: %d %q", code, res)
	}
	got := mustIntegration(t, e, blog.ID)
	if got.Enabled || !strings.Contains(got.LastError, "No longer granted") {
		t.Fatalf("removed repository's integration: %+v", got)
	}
	// Resolved as removed, not deleted: the asset and its history stay.
	a, err := e.st.GetAsset(ctx, blogAsset)
	if err != nil {
		t.Fatalf("the asset was deleted: %v", err)
	}
	if a.CollectionStatus != store.AssetRemoved {
		t.Fatalf("asset status %q", a.CollectionStatus)
	}
	if n := dbScalar[int64](t, e, `SELECT count(*) FROM inventory WHERE asset_id = $1 AND removed_at IS NULL`, blogAsset); n != 0 {
		t.Fatalf("inventory still present: %d", n)
	}
	if n := dbScalar[int64](t, e, `SELECT count(*) FROM inventory WHERE asset_id = $1`, blogAsset); n == 0 {
		t.Fatal("inventory history deleted")
	}
	// Its scan does not run, and asks GitHub for nothing.
	reqs := len(f.gh.tokenReqs)
	if err := f.runner.Run(store.WithReportSource(ctx, store.ReportSource{Source: store.SourceIntegration, IntegrationID: blog.ID}), got); err != nil {
		t.Fatal(err)
	}
	if len(f.gh.tokenReqs) != reqs || !strings.Contains(mustIntegration(t, e, blog.ID).LastError, "no longer granted") {
		t.Fatalf("a removed repository was scanned: %d token requests, %q", len(f.gh.tokenReqs)-reqs, mustIntegration(t, e, blog.ID).LastError)
	}
	f.drain(t) // the sync agrees

	// acme/docs and acme/blog added: the sync (from GitHub's API) adds and
	// scans them; blog's integration is switched back on.
	f.gh.mu.Lock()
	f.gh.installs[101].repos = []int64{11, 12, 13}
	f.gh.mu.Unlock()
	if code, res := f.webhook(t, "installation_repositories", "r-2", map[string]any{"action": "added", "installation": map[string]any{"id": 101},
		"repositories_added": []map[string]any{{"id": 13}, {"id": 12}}, "repositories_removed": []any{}}); code != 200 || res != "sync queued" {
		t.Fatalf("added: %d %q", code, res)
	}
	f.drain(t)
	ints := appIntegrations(t, e, tenant.DefaultWorkspace)
	if len(ints) != 3 || !ints["acme/docs"].Enabled || !ints["acme/blog"].Enabled || ints["acme/blog"].ID != blog.ID {
		t.Fatalf("after adding: %+v", ints)
	}
	if f.gh.clones["acme/docs"] != 1 || f.gh.clones["acme/blog"] != 2 {
		t.Fatalf("clones: %v", f.gh.clones)
	}
	if a, _ := e.st.GetAsset(ctx, blogAsset); a.CollectionStatus == store.AssetRemoved {
		t.Fatal("blog's asset still removed after it was granted and scanned again")
	}
}

func TestGitHubAppSuspendUninstallAndDisconnect(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	admin := f.install(t)
	f.drain(t)
	shop := appIntegrations(t, e, tenant.DefaultWorkspace)["acme/shop"]

	// The customer switches one repository off themselves.
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(appIntegrations(t, e, 1)["acme/blog"].ID), map[string]any{"enabled": false}, nil); code != 200 {
		t.Fatal(code)
	}
	if code, res := f.webhook(t, "installation", "s-1", map[string]any{"action": "suspend", "installation": map[string]any{"id": 101}}); code != 200 || res != "suspended" {
		t.Fatalf("suspend: %d %q", code, res)
	}
	for name, in := range appIntegrations(t, e, 1) {
		if in.Enabled {
			t.Fatalf("%s still enabled while suspended", name)
		}
	}
	reqs := len(f.gh.tokenReqs)
	_ = f.runner.Run(ctx, mustIntegration(t, e, shop.ID))
	if len(f.gh.tokenReqs) != reqs || !strings.Contains(mustIntegration(t, e, shop.ID).LastError, "suspended") {
		t.Fatalf("scanned while suspended: %q", mustIntegration(t, e, shop.ID).LastError)
	}
	if code, res := f.webhook(t, "installation", "s-2", map[string]any{"action": "unsuspend", "installation": map[string]any{"id": 101}}); code != 200 || res != "unsuspended" {
		t.Fatalf("unsuspend: %d %q", code, res)
	}
	ints := appIntegrations(t, e, 1)
	if !ints["acme/shop"].Enabled || ints["acme/blog"].Enabled {
		t.Fatalf("after unsuspend, only what Stackurity switched off is switched on: %+v", ints)
	}

	// Uninstalled on GitHub: switched off, history kept, never active again.
	if code, res := f.webhook(t, "installation", "u-1", map[string]any{"action": "deleted", "installation": map[string]any{"id": 101}}); code != 200 || res != "uninstalled" {
		t.Fatalf("deleted: %d %q", code, res)
	}
	if st := dbScalar[string](t, e, `SELECT status FROM github_installations WHERE installation_id = 101`); st != "deleted" {
		t.Fatalf("status %s", st)
	}
	if code, _ := f.webhook(t, "installation", "u-2", map[string]any{"action": "unsuspend", "installation": map[string]any{"id": 101}}); code != 200 {
		t.Fatal(code)
	}
	if st := dbScalar[string](t, e, `SELECT status FROM github_installations WHERE installation_id = 101`); st != "deleted" {
		t.Fatalf("a deleted installation came back: %s", st)
	}
	in := mustIntegration(t, e, shop.ID)
	if in.Enabled || !strings.Contains(in.LastError, "uninstalled") || in.AssetID == nil {
		t.Fatalf("after uninstall: %+v", in)
	}
	if _, err := e.st.GetAsset(ctx, *in.AssetID); err != nil {
		t.Fatalf("asset gone after uninstall: %v", err)
	}

	// Disconnect from Stackurity: the binding goes and the app is removed
	// from the GitHub account (here, a fresh installation 202 in beta's
	// place is not needed: disconnect 101 again works on what is left).
	if code := admin.do("DELETE", "/api/v1/integrations/github/installations/101", nil, nil); code != 200 {
		t.Fatalf("disconnect: %d", code)
	}
	if n := dbScalar[int64](t, e, `SELECT count(*) FROM github_installations`); n != 0 {
		t.Fatalf("binding kept: %d", n)
	}
	if len(f.gh.deleted) != 0 {
		t.Fatalf("an installation already removed on GitHub was uninstalled again: %v", f.gh.deleted)
	}
}

func TestGitHubAppDisconnectUninstalls(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	admin := f.install(t)
	f.drain(t)
	if code := e.login("eng@x.io").do("DELETE", "/api/v1/integrations/github/installations/101", nil, nil); code != 403 {
		t.Fatalf("engineer disconnects: %d", code)
	}
	if code := admin.do("DELETE", "/api/v1/integrations/github/installations/101", nil, nil); code != 200 {
		t.Fatalf("disconnect: %d", code)
	}
	if len(f.gh.deleted) != 1 || f.gh.deleted[0] != 101 {
		t.Fatalf("uninstalled on GitHub: %v", f.gh.deleted)
	}
	for name, in := range appIntegrations(t, e, 1) {
		if in.Enabled {
			t.Fatalf("%s still enabled", name)
		}
	}
	// Its scans stop without asking GitHub.
	reqs := len(f.gh.tokenReqs)
	shop := mustIntegration(t, e, appIntegrations(t, e, 1)["acme/shop"].ID)
	_ = f.runner.Run(tenant.WithWorkspace(context.Background(), 1), shop)
	if len(f.gh.tokenReqs) != reqs {
		t.Fatal("a disconnected installation's repository was scanned")
	}

	// Installed again (a new installation of the same repositories): the
	// same integrations carry on, with their assets and history.
	before := appIntegrations(t, e, 1)
	f.gh.mu.Lock()
	f.gh.installs[104] = &ghInstall{id: 104, appID: ghAppID, login: "acme", repos: []int64{11, 12}}
	f.gh.mu.Unlock()
	f.gh.user("code-again", 104)
	if code, _ := f.finish(admin, f.start(t, admin), "code-again", 104); code != 201 {
		t.Fatalf("install again: %d", code)
	}
	f.drain(t)
	after := appIntegrations(t, e, 1)
	if len(after) != 2 || after["acme/shop"].ID != before["acme/shop"].ID || !after["acme/shop"].Enabled || after["acme/shop"].AssetID == nil {
		t.Fatalf("after installing again: %+v (before %+v)", after, before)
	}
	assertNoTokenMaterial(t, f)
}

func TestGitHubAppLimits(t *testing.T) {
	f := githubAppSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	// Asset limit: room for one asset, two repositories granted.
	one := int64(1)
	if err := e.st.SetAssetLimit(tenant.System(context.Background()), tenant.DefaultWorkspace, &one); err != nil {
		t.Fatal(err)
	}
	f.install(t)
	f.drain(t)
	if ints := appIntegrations(t, e, 1); len(ints) != 1 {
		t.Fatalf("integrations at the limit: %+v", ints)
	}
	in, err := e.st.GetGitHubInstallation(ctx, 101)
	if err != nil || !strings.Contains(in.Note, "1 repository is not scanned") || !strings.Contains(in.Note, "limit of 1 monitored asset") {
		t.Fatalf("installation note: %+v %v", in, err)
	}
	if err := e.st.SetAssetLimit(tenant.System(context.Background()), tenant.DefaultWorkspace, nil); err != nil {
		t.Fatal(err)
	}
	if code := e.login("admin@x.io").do("POST", "/api/v1/integrations/github/installations/101/sync", nil, nil); code != 202 {
		t.Fatalf("sync: %d", code)
	}
	f.drain(t)
	if ints := appIntegrations(t, e, 1); len(ints) != 2 {
		t.Fatalf("integrations once there is room: %+v", ints)
	}

	// Scans per installation per minute: past the limit a scan waits
	// (worker.Deferred) and no token is minted.
	f.runner.TokensPerMinute = 1
	shop := mustIntegration(t, e, appIntegrations(t, e, 1)["acme/shop"].ID)
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `DELETE FROM rate_limits`); err != nil {
		t.Fatal(err)
	}
	// The limit counts in fixed one-minute windows of the database's clock:
	// start both scans early in one, or the second may land in the next.
	var sec float64
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT (extract(epoch FROM now()) % 60)::float8`).Scan(&sec); err != nil {
		t.Fatal(err)
	}
	if sec > 45 {
		time.Sleep(time.Duration((61 - sec) * float64(time.Second)))
	}
	if err := f.runner.Run(ctx, shop); err != nil {
		t.Fatal(err)
	}
	reqs := len(f.gh.tokenReqs)
	err = f.runner.Run(ctx, shop)
	var d *worker.Deferred
	if !errors.As(err, &d) || len(f.gh.tokenReqs) != reqs {
		t.Fatalf("second scan in the minute: %v, %d token requests", err, len(f.gh.tokenReqs)-reqs)
	}

	// The app's requests go through netguard: an organisation that may not
	// reach private addresses cannot make the server call this (private)
	// GitHub.
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "none"})
	if _, err := f.app.Installation(tenant.WithWorkspace(context.Background(), 2), 101); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("private GitHub from a workspace without private access: %v", err)
	}
}
