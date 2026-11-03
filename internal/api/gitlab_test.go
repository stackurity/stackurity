package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/gitlab"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/worker"
)

// Connect GitLab (gitlab.go, internal/gitlab) on the real path: the API
// server, the store, the runner and gitrepo's hardened clone, against a
// fake GitLab (OAuth, REST API v4 and git smart HTTP over TLS) that serves
// real bare repositories through git http-backend.
//
// Names here start with gl so they never collide with the GitHub App's
// test helpers (github_app_test.go, PR #169) in this package.

const (
	glClientID     = "gl-client-id-7f8e"
	glClientSecret = "gl-client-secret-9a8b7c"
	glPageSize     = 2 // the fake's page size, so listing paginates
)

type glUser struct {
	id       int64
	username string
}

type glGroup struct {
	id      int64
	path    string
	name    string
	premium bool          // group access tokens and group webhooks
	members map[int64]int // user id -> access level
}

type glProject struct {
	id     int64
	path   string
	branch string
}

// glToken is a token the fake issued.
type glToken struct {
	kind    string // oauth, gat
	user    int64  // oauth
	group   int64  // gat
	scopes  []string
	access  int // gat
	expires time.Time
	refresh string // oauth: its refresh token
	id      int64  // gat
	revoked bool
}

type glHook struct {
	id      int64
	group   int64
	url     string
	secret  string
	deleted bool
}

// fakeGitLab is GitLab with one OAuth application.
type fakeGitLab struct {
	t       *testing.T
	gitRoot string
	backend string
	base    string // set once the server starts

	mu       sync.Mutex
	users    map[int64]*glUser
	groups   map[int64]*glGroup
	projects map[int64]*glProject
	// codes maps an OAuth code to the user and the scopes asked.
	codes map[string]struct {
		user   int64
		scopes []string
	}
	tokens               map[string]*glToken
	refresh              map[string]string // refresh token -> its access token
	hooks                map[int64]*glHook
	nextID               int64
	issued               []string // every token handed out
	exchanges, refreshes int
	refreshDelay         time.Duration
	accessTTL            int64 // expires_in of OAuth access tokens
	revokedOAuth         []string
	selfRevoked          []string
	gatsCreated          []map[string]any
	clones               map[string]int
	badGitAuth           int
	rateLimitNext        int
}

func newFakeGitLab(t *testing.T) *fakeGitLab {
	backend := filepath.Join(strings.TrimSpace(glGit(t, "", "--exec-path")), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not available")
	}
	return &fakeGitLab{t: t, gitRoot: t.TempDir(), backend: backend, users: map[int64]*glUser{}, groups: map[int64]*glGroup{},
		projects: map[int64]*glProject{}, codes: map[string]struct {
			user   int64
			scopes []string
		}{}, tokens: map[string]*glToken{}, refresh: map[string]string{}, hooks: map[int64]*glHook{}, nextID: 1000,
		clones: map[string]int{}, accessTTL: 7200}
}

func glGit(t *testing.T, dir string, args ...string) string {
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

func (f *fakeGitLab) addProject(id int64, path string, files map[string]string) {
	f.t.Helper()
	work := f.t.TempDir()
	glGit(f.t, work, "init", "-q", "-b", "main")
	for name, body := range files {
		p := filepath.Join(work, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
	glGit(f.t, work, "add", ".")
	glGit(f.t, work, "commit", "-qm", "init")
	glGit(f.t, "", "clone", "-q", "--bare", work, filepath.Join(f.gitRoot, path+".git"))
	f.mu.Lock()
	f.projects[id] = &glProject{id: id, path: path, branch: "main"}
	f.mu.Unlock()
}

func (f *fakeGitLab) newSecret(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	s := prefix + hex.EncodeToString(b)
	f.issued = append(f.issued, s)
	return s
}

// signIn makes code sign user in (with whatever scopes the authorise URL
// asked; the test passes them).
func (f *fakeGitLab) signIn(code string, user int64, scopes ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[code] = struct {
		user   int64
		scopes []string
	}{user, scopes}
	f.issued = append(f.issued, code)
}

func (f *fakeGitLab) oauthPair(user int64, scopes []string) (string, string) {
	access, refresh := f.newSecret("gloas-"), f.newSecret("glort-")
	f.tokens[access] = &glToken{kind: "oauth", user: user, scopes: scopes, expires: time.Now().Add(time.Duration(f.accessTTL) * time.Second), refresh: refresh}
	f.refresh[refresh] = access
	return access, refresh
}

func hasScope(tk *glToken, want ...string) bool {
	for _, s := range tk.scopes {
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	return false
}

func (f *fakeGitLab) bearer(r *http.Request) *glToken {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return nil
	}
	tk := f.tokens[raw]
	if tk == nil || tk.revoked || time.Now().After(tk.expires) {
		return nil
	}
	return tk
}

// access is what tk may do in group g: the user's level for an OAuth
// token, the token's own for a group access token of g or a group above.
func (f *fakeGitLab) access(tk *glToken, g *glGroup) int {
	if tk.kind == "oauth" {
		return g.members[tk.user]
	}
	if bound := f.groups[tk.group]; bound != nil && (bound.id == g.id || strings.HasPrefix(g.path, bound.path+"/")) {
		return tk.access
	}
	return 0
}

func (f *fakeGitLab) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if f.rateLimitNext > 0 && strings.HasPrefix(p, "/api/v4/") {
		f.rateLimitNext--
		w.Header().Set("Retry-After", "42")
		writeJSON(429, map[string]string{"message": "Retry later"})
		return
	}
	// page serves a slice glPageSize at a time with X-Next-Page.
	page := func(n int) (int, int) {
		pg, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if pg < 1 {
			pg = 1
		}
		lo, hi := min((pg-1)*glPageSize, n), min(pg*glPageSize, n)
		if hi < n {
			w.Header().Set("X-Next-Page", strconv.Itoa(pg+1))
		}
		return lo, hi
	}
	switch {
	case r.Method == "POST" && p == "/oauth/token":
		_ = r.ParseForm()
		if r.PostForm.Get("client_id") != glClientID || r.PostForm.Get("client_secret") != glClientSecret {
			writeJSON(401, map[string]string{"error": "invalid_client"})
			return
		}
		var access, refresh string
		var scopes []string
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			f.exchanges++
			c, ok := f.codes[r.PostForm.Get("code")]
			if !ok || r.PostForm.Get("redirect_uri") != "https://stk.example/integrations/gitlab/callback" {
				writeJSON(400, map[string]string{"error": "invalid_grant"})
				return
			}
			delete(f.codes, r.PostForm.Get("code"))
			scopes = c.scopes
			access, refresh = f.oauthPair(c.user, c.scopes)
		case "refresh_token":
			f.refreshes++
			old, ok := f.refresh[r.PostForm.Get("refresh_token")]
			if !ok {
				writeJSON(400, map[string]string{"error": "invalid_grant", "error_description": "The provided authorization grant is invalid"})
				return
			}
			// Rotation: the old refresh token and its access token stop
			// working; only the new pair does.
			tk := f.tokens[old]
			delete(f.refresh, r.PostForm.Get("refresh_token"))
			tk.revoked = true
			scopes = tk.scopes
			access, refresh = f.oauthPair(tk.user, tk.scopes)
			if d := f.refreshDelay; d > 0 {
				f.mu.Unlock()
				time.Sleep(d)
				f.mu.Lock()
			}
		default:
			writeJSON(400, map[string]string{"error": "unsupported_grant_type"})
			return
		}
		writeJSON(200, map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
			"expires_in": f.tokens[access].expires.Unix() - time.Now().Unix(), "created_at": time.Now().Unix(), "scope": strings.Join(scopes, " ")})
	case r.Method == "POST" && p == "/oauth/revoke":
		_ = r.ParseForm()
		if r.PostForm.Get("client_id") != glClientID || r.PostForm.Get("client_secret") != glClientSecret {
			writeJSON(403, map[string]string{"error": "unauthorized_client"})
			return
		}
		tok := r.PostForm.Get("token")
		f.revokedOAuth = append(f.revokedOAuth, tok)
		if a, ok := f.refresh[tok]; ok {
			tok = a
		}
		if tk := f.tokens[tok]; tk != nil && tk.kind == "oauth" {
			tk.revoked = true
			delete(f.refresh, tk.refresh)
		}
		writeJSON(200, map[string]any{})
	case strings.HasPrefix(p, "/api/v4/"):
		tk := f.bearer(r)
		if tk == nil {
			writeJSON(401, map[string]string{"message": "401 Unauthorized"})
			return
		}
		write := r.Method != "GET"
		if rest := strings.TrimPrefix(p, "/api/v4"); rest == "/personal_access_tokens/self" {
			write = false // "any token can use this endpoint"
		} else if write && !hasScope(tk, "api") || !write && !hasScope(tk, "api", "read_api") {
			writeJSON(403, map[string]string{"error": "insufficient_scope"})
			return
		}
		rest := strings.TrimPrefix(p, "/api/v4")
		parts := strings.Split(strings.Trim(rest, "/"), "/")
		switch {
		case r.Method == "GET" && rest == "/user":
			if tk.kind != "oauth" {
				writeJSON(200, map[string]any{"id": 9000 + tk.group, "username": "group_bot"})
				return
			}
			u := f.users[tk.user]
			writeJSON(200, map[string]any{"id": u.id, "username": u.username})
		case r.Method == "DELETE" && rest == "/personal_access_tokens/self":
			for s, x := range f.tokens {
				if x == tk {
					f.selfRevoked = append(f.selfRevoked, s)
				}
			}
			tk.revoked = true
			w.WriteHeader(204)
		case r.Method == "GET" && rest == "/groups":
			min, _ := strconv.Atoi(r.URL.Query().Get("min_access_level"))
			var list []map[string]any
			var ids []int64
			for id := range f.groups {
				ids = append(ids, id)
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			for _, id := range ids {
				g := f.groups[id]
				if a := f.access(tk, g); a > 0 && a >= min {
					list = append(list, map[string]any{"id": g.id, "full_path": g.path, "name": g.name})
				}
			}
			lo, hi := page(len(list))
			writeJSON(200, append([]map[string]any{}, list[lo:hi]...))
		case len(parts) >= 2 && parts[0] == "groups":
			gid, _ := strconv.ParseInt(parts[1], 10, 64)
			g := f.groups[gid]
			if g == nil || f.access(tk, g) == 0 {
				writeJSON(404, map[string]string{"message": "404 Group Not Found"})
				return
			}
			level := f.access(tk, g)
			sub := strings.Join(parts[2:], "/")
			switch {
			case r.Method == "GET" && sub == "":
				writeJSON(200, map[string]any{"id": g.id, "full_path": g.path, "name": g.name})
			case r.Method == "GET" && len(parts) == 5 && parts[2] == "members" && parts[3] == "all":
				uid, _ := strconv.ParseInt(parts[4], 10, 64)
				if lvl, ok := g.members[uid]; ok {
					writeJSON(200, map[string]any{"id": uid, "access_level": lvl, "state": "active"})
					return
				}
				writeJSON(404, map[string]string{"message": "404 Not found"})
			case r.Method == "GET" && sub == "projects":
				var list []map[string]any
				var ids []int64
				for id := range f.projects {
					ids = append(ids, id)
				}
				sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
				for _, id := range ids {
					pr := f.projects[id]
					if strings.HasPrefix(pr.path, g.path+"/") {
						list = append(list, map[string]any{"id": pr.id, "path_with_namespace": pr.path, "default_branch": pr.branch})
					}
				}
				lo, hi := page(len(list))
				writeJSON(200, append([]map[string]any{}, list[lo:hi]...))
			case r.Method == "POST" && sub == "access_tokens":
				if level < 50 || !g.premium {
					writeJSON(403, map[string]string{"message": "403 Forbidden"})
					return
				}
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				f.gatsCreated = append(f.gatsCreated, body)
				var scopes []string
				for _, s := range body["scopes"].([]any) {
					scopes = append(scopes, s.(string))
				}
				exp, _ := time.Parse("2006-01-02", body["expires_at"].(string))
				lvl := int(body["access_level"].(float64))
				f.nextID++
				tok := f.newSecret("glpat-")
				f.tokens[tok] = &glToken{kind: "gat", group: g.id, scopes: scopes, access: lvl, expires: exp, id: f.nextID}
				writeJSON(201, map[string]any{"id": f.nextID, "token": tok, "scopes": scopes, "access_level": lvl, "expires_at": body["expires_at"]})
			case r.Method == "DELETE" && len(parts) == 4 && parts[2] == "access_tokens":
				if level < 50 {
					writeJSON(403, map[string]string{"message": "403 Forbidden"})
					return
				}
				tid, _ := strconv.ParseInt(parts[3], 10, 64)
				for _, x := range f.tokens {
					if x.kind == "gat" && x.group == g.id && x.id == tid {
						x.revoked = true
					}
				}
				w.WriteHeader(204)
			case r.Method == "POST" && sub == "hooks":
				if level < 50 || !g.premium {
					writeJSON(403, map[string]string{"message": "403 Forbidden"})
					return
				}
				var body struct {
					URL   string `json:"url"`
					Token string `json:"token"`
					Push  bool   `json:"push_events"`
					SSL   bool   `json:"enable_ssl_verification"`
				}
				_ = json.NewDecoder(r.Body).Decode(&body)
				if !body.Push || !body.SSL || body.Token == "" {
					writeJSON(400, map[string]string{"message": "bad hook"})
					return
				}
				f.nextID++
				f.hooks[f.nextID] = &glHook{id: f.nextID, group: g.id, url: body.URL, secret: body.Token}
				writeJSON(201, map[string]any{"id": f.nextID, "url": body.URL})
			case r.Method == "DELETE" && len(parts) == 4 && parts[2] == "hooks":
				hid, _ := strconv.ParseInt(parts[3], 10, 64)
				if level < 50 {
					writeJSON(403, map[string]string{"message": "403 Forbidden"})
					return
				}
				if h := f.hooks[hid]; h != nil && h.group == g.id {
					h.deleted = true
				}
				w.WriteHeader(204)
			default:
				writeJSON(404, map[string]string{"message": "404 Not Found"})
			}
		default:
			writeJSON(404, map[string]string{"message": "404 Not Found"})
		}
	case strings.Contains(p, ".git/"):
		// git smart HTTP: Basic oauth2:<token> with read_repository on a
		// group the project is in.
		full := strings.TrimPrefix(p[:strings.Index(p, ".git/")], "/")
		_, tok, _ := r.BasicAuth()
		tk := f.tokens[tok]
		var proj *glProject
		for _, pr := range f.projects {
			if pr.path == full {
				proj = pr
			}
		}
		ok := tk != nil && !tk.revoked && time.Now().Before(tk.expires) && proj != nil && hasScope(tk, "read_repository", "api")
		if ok {
			ok = false
			for _, g := range f.groups {
				if strings.HasPrefix(proj.path, g.path+"/") && f.access(tk, g) >= 20 {
					ok = true
				}
			}
		}
		if !ok {
			f.badGitAuth++
			w.Header().Set("WWW-Authenticate", `Basic realm="GitLab"`)
			w.WriteHeader(401)
			return
		}
		if strings.HasSuffix(p, "/info/refs") {
			f.clones[full]++
		}
		f.mu.Unlock()
		unlock = false
		h := &cgi.Handler{Path: f.backend, Env: []string{"GIT_PROJECT_ROOT=" + f.gitRoot, "GIT_HTTP_EXPORT_ALL=1"}, InheritEnv: []string{"PATH"}}
		h.ServeHTTP(w, r)
	default:
		writeJSON(404, map[string]string{"message": "404 Not Found"})
	}
}

// --- fixture

type glFx struct {
	e      *env
	gl     *fakeGitLab
	srv    *httptest.Server
	client *gitlab.Client
	runner *gitlab.Runner
	box    *secrets.Box
}

const glShopLock = `{"name":"shop","lockfileVersion":3,"packages":{"":{"name":"shop"},"node_modules/lodash":{"version":"4.17.20"}}}`
const glBlogLock = `{"name":"blog","lockfileVersion":3,"packages":{"":{"name":"blog"},"node_modules/minimist":{"version":"1.2.5"}}}`

// Users on the fake GitLab: alice owns acme (Premium) and is a Reporter of
// beta; bob owns beta (Free) and nothing of acme; mallory is in no group.
const (
	glAlice   = 1
	glBob     = 2
	glMallory = 3
)

func gitlabSetup(t *testing.T) *glFx {
	t.Helper()
	gl := newFakeGitLab(t)
	srv := httptest.NewTLSServer(gl)
	t.Cleanup(srv.Close)
	gl.base = srv.URL
	gl.users[glAlice] = &glUser{id: glAlice, username: "alice"}
	gl.users[glBob] = &glUser{id: glBob, username: "bob"}
	gl.users[glMallory] = &glUser{id: glMallory, username: "mallory"}
	gl.groups[10] = &glGroup{id: 10, path: "acme", name: "Acme", premium: true, members: map[int64]int{glAlice: 50}}
	gl.groups[11] = &glGroup{id: 11, path: "acme/backend", name: "Backend", premium: true, members: map[int64]int{glAlice: 50}}
	gl.groups[20] = &glGroup{id: 20, path: "beta", name: "Beta", members: map[int64]int{glBob: 50, glAlice: 20}}
	gl.addProject(101, "acme/shop", map[string]string{"package-lock.json": glShopLock, "README.md": "shop"})
	gl.addProject(102, "acme/blog", map[string]string{"package-lock.json": glBlogLock})
	gl.addProject(103, "acme/backend/api", map[string]string{"package-lock.json": glShopLock})
	gl.addProject(201, "beta/site", map[string]string{"package-lock.json": glBlogLock})

	// The fake GitLab is on 127.0.0.1, a private address: every
	// organisation may reach it here, as with STACKURITY_PRIVATE_CIDRS.
	restore := netguard.FromEnv()
	netguard.Set(netguard.Config{Mode: "default", Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	t.Cleanup(func() { netguard.Set(restore) })
	tlsCfg := srv.Client().Transport.(*http.Transport).TLSClientConfig
	httpc := &http.Client{Timeout: 10 * time.Second,
		Transport:     &http.Transport{DialContext: netguard.DialContext, TLSClientConfig: tlsCfg, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	client := &gitlab.Client{Base: srv.URL, ClientID: glClientID, ClientSecret: glClientSecret, HTTP: httpc}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, err := secrets.NewBox(key)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	e := newEnvWith(t, func(s *api.Server) { s.GitLab = client; s.SecretBox = box; s.BaseURL = "https://stk.example" })
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("other-admin@x.io", auth.RoleAdmin)
	e.user("eng@x.io", auth.RoleEngineer)
	runner := &gitlab.Runner{Store: e.st, Client: client, Box: box, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Spacing: -1,
		RedirectURL: "https://stk.example/integrations/gitlab/callback",
		Scanner:     &gitrepo.Scanner{WorkDir: t.TempDir(), Version: "test", CAFile: caFile, Timeout: time.Minute}}
	return &glFx{e: e, gl: gl, srv: srv, client: client, runner: runner, box: box}
}

// start begins an authorisation as s and returns the state and the scopes
// GitLab is asked for.
func (f *glFx) start(t *testing.T, s *session, path string, body any) (string, []string) {
	t.Helper()
	var out struct{ URL string }
	if code := s.do("POST", path, body, &out); code != 200 {
		t.Fatalf("%s: %d", path, code)
	}
	u, err := url.Parse(out.URL)
	if err != nil || "https://"+u.Host != f.srv.URL || u.Path != "/oauth/authorize" {
		t.Fatalf("authorize url %q", out.URL)
	}
	q := u.Query()
	if q.Get("client_id") != glClientID || q.Get("redirect_uri") != "https://stk.example/integrations/gitlab/callback" || q.Get("response_type") != "code" {
		t.Fatalf("authorize url %q", out.URL)
	}
	if len(q.Get("state")) < 40 {
		t.Fatalf("state %q", q.Get("state"))
	}
	return q.Get("state"), strings.Fields(q.Get("scope"))
}

// authorize is GitLab's consent: user signs in and the browser comes back
// with a code for the scopes asked.
func (f *glFx) authorize(t *testing.T, s *session, user int64) string {
	t.Helper()
	state, scopes := f.start(t, s, "/api/v1/integrations/gitlab/connect", map[string]string{"return_to": "/settings/integrations"})
	code := fmt.Sprintf("code-%d-%d", user, time.Now().UnixNano())
	f.gl.signIn(code, user, scopes...)
	return state + " " + code
}

type glOAuthAnswer struct {
	Pick   string `json:"pick"`
	Groups []struct {
		ID       int64  `json:"id"`
		FullPath string `json:"full_path"`
		Owner    bool   `json:"owner"`
	} `json:"groups"`
	Connection    store.GitLabConnection `json:"connection"`
	NeedsReadOnly bool                   `json:"needs_readonly"`
	Notes         []string               `json:"notes"`
	Error         struct{ Code string }  `json:"error"`
	WebhookDel    bool                   `json:"webhook_deleted"`
	TokenRevoked  bool                   `json:"token_revoked"`
}

func (f *glFx) oauth(s *session, stateCode string) (int, glOAuthAnswer) {
	state, code, _ := strings.Cut(stateCode, " ")
	var out glOAuthAnswer
	st := s.do("POST", "/api/v1/integrations/gitlab/oauth", map[string]string{"state": state, "code": code}, &out)
	return st, out
}

func (f *glFx) pick(s *session, pick string, group any) (int, glOAuthAnswer) {
	var out glOAuthAnswer
	st := s.do("POST", "/api/v1/integrations/gitlab/connections", map[string]any{"pick": pick, "group_id": group}, &out)
	return st, out
}

// connect connects acme (group 10) to the default workspace as admin@x.io,
// signed in at GitLab as alice (its Owner).
func (f *glFx) connect(t *testing.T) (*session, store.GitLabConnection) {
	t.Helper()
	admin := f.e.login("admin@x.io")
	code, out := f.oauth(admin, f.authorize(t, admin, glAlice))
	if code != 200 || out.Pick == "" {
		t.Fatalf("oauth: %d %+v", code, out)
	}
	code, out = f.pick(admin, out.Pick, 10)
	if code != 201 || out.Connection.ID == 0 || out.NeedsReadOnly {
		t.Fatalf("connect: %d %+v", code, out)
	}
	return admin, out.Connection
}

// drain runs queued Connect GitLab jobs as the worker would.
func (f *glFx) drain(t *testing.T) map[int64]error {
	t.Helper()
	ctx := tenant.System(context.Background())
	errs := map[int64]error{}
	if _, err := f.e.st.Pool.Exec(ctx, `UPDATE jobs SET run_at = now() WHERE done_at IS NULL AND failed_at IS NULL AND kind IN ('integration.run', 'gitlab.sync')`); err != nil {
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
			ConnectionID  int64 `json:"connection_id"`
			IntegrationID int64 `json:"integration_id"`
		}
		_ = json.Unmarshal(j.Payload, &p)
		var runErr error
		switch j.Kind {
		case "gitlab.sync":
			runErr = f.runner.Sync(jctx, p.ConnectionID)
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

// hook delivers an event to connection id with secret.
func (f *glFx) hook(t *testing.T, id int64, secret, event, uuid string, payload any) (int, string) {
	t.Helper()
	body, _ := json.Marshal(payload)
	hdr := map[string]string{"X-Gitlab-Event": event, "X-Gitlab-Event-UUID": uuid}
	if secret != "" {
		hdr["X-Gitlab-Token"] = secret
	}
	return f.rawHook(t, id, body, hdr)
}

func (f *glFx) rawHook(t *testing.T, id int64, body []byte, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", f.e.srv.URL+"/api/v1/integrations/gitlab/webhook/"+itoa(id), bytes.NewReader(body))
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

// secret is the webhook secret GitLab holds for group.
func (f *glFx) secret(t *testing.T, group int64) string {
	t.Helper()
	f.gl.mu.Lock()
	defer f.gl.mu.Unlock()
	for _, h := range f.gl.hooks {
		if h.group == group && !h.deleted {
			return h.secret
		}
	}
	t.Fatalf("no webhook on group %d", group)
	return ""
}

func glIntegrations(t *testing.T, e *env, ws int64) map[string]store.Integration {
	t.Helper()
	is, err := e.st.ListIntegrations(tenant.WithWorkspace(context.Background(), ws))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.Integration{}
	for _, in := range is {
		if in.Kind == store.KindGitLab {
			out[in.Name] = in
		}
	}
	return out
}

func glScalar[T any](t *testing.T, e *env, q string, args ...any) T {
	t.Helper()
	var v T
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}

func glIntegration(t *testing.T, e *env, ws, id int64) *store.Integration {
	t.Helper()
	in, err := e.st.GetIntegration(tenant.WithWorkspace(context.Background(), ws), id)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// glNoTokenMaterial reads every row of every table as text: no GitLab
// token, OAuth code, client secret or webhook secret may be anywhere in the
// database, other than inside the sealed credential (which is AES-GCM
// ciphertext, so it holds none of them in clear either).
func glNoTokenMaterial(t *testing.T, f *glFx) {
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
	f.gl.mu.Lock()
	secrets := append([]string{glClientSecret}, f.gl.issued...)
	for _, h := range f.gl.hooks {
		secrets = append(secrets, h.secret)
	}
	f.gl.mu.Unlock()
	if len(secrets) < 5 {
		t.Fatalf("only %d secrets issued: the check would prove little", len(secrets))
	}
	var dump strings.Builder
	for _, tb := range tables {
		rs, err := f.e.st.Pool.Query(ctx, `SELECT t::text FROM "`+strings.ReplaceAll(tb, `"`, `""`)+`" t`)
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
		// Hex-encoded bytea would hide a match in clear text.
		if h := hex.EncodeToString([]byte(s)); len(s) > 8 && strings.Contains(all, h) {
			t.Fatalf("token material %q found hex-encoded in the database", s[:8]+"...")
		}
	}
}

// --- tests

func TestGitLabConnectScansGroupProjects(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	// Engineers see the status, not the connect.
	var status struct {
		Configured  bool
		Connections []store.GitLabConnection
	}
	eng := e.login("eng@x.io")
	if code := eng.do("GET", "/api/v1/integrations/gitlab", nil, &status); code != 200 || !status.Configured || len(status.Connections) != 0 {
		t.Fatalf("status: %d %+v", code, status)
	}
	if code := eng.do("POST", "/api/v1/integrations/gitlab/connect", map[string]string{}, nil); code != 403 {
		t.Fatalf("engineer connect: %d", code)
	}

	admin := e.login("admin@x.io")
	stateCode := f.authorize(t, admin, glAlice)
	f.gl.mu.Lock()
	var asked []string
	for _, c := range f.gl.codes {
		asked = c.scopes
	}
	f.gl.mu.Unlock()
	if strings.Join(asked, " ") != "api" {
		t.Fatalf("setup asked for %v", asked)
	}
	code, out := f.oauth(admin, stateCode)
	if code != 200 || out.Pick == "" {
		t.Fatalf("oauth: %d %+v", code, out)
	}
	// Alice's groups, all pages (the fake pages two at a time): acme and
	// acme/backend as Owner, beta as Reporter.
	got := map[string]bool{}
	for _, g := range out.Groups {
		got[g.FullPath] = g.Owner
	}
	if len(got) != 3 || !got["acme"] || !got["acme/backend"] || got["beta"] {
		t.Fatalf("groups: %+v", out.Groups)
	}
	// The setup token is held sealed until the pick, and not revoked yet.
	if n := glScalar[int64](t, e, `SELECT count(*) FROM gitlab_oauth_states WHERE user_token IS NOT NULL`); n != 1 {
		t.Fatalf("sealed setup tokens: %d", n)
	}
	code, out = f.pick(admin, out.Pick, "10")
	if code != 201 || out.NeedsReadOnly || out.Connection.CredentialKind != "group_token" || out.Connection.Webhook != "active" {
		t.Fatalf("connect: %d %+v", code, out)
	}
	conn := out.Connection
	// The setup token is gone from the database and revoked at GitLab.
	if n := glScalar[int64](t, e, `SELECT count(*) FROM gitlab_oauth_states WHERE user_token IS NOT NULL`); n != 0 {
		t.Fatalf("sealed setup tokens after the pick: %d", n)
	}
	f.gl.mu.Lock()
	revokedSetup := len(f.gl.revokedOAuth)
	gats := f.gl.gatsCreated
	var hook *glHook
	for _, h := range f.gl.hooks {
		hook = h
	}
	f.gl.mu.Unlock()
	if revokedSetup != 1 {
		t.Fatalf("setup token revoked %d times", revokedSetup)
	}
	// The group access token: read_api + read_repository, Reporter, under a
	// year.
	if len(gats) != 1 {
		t.Fatalf("group access tokens created: %d", len(gats))
	}
	sc, _ := json.Marshal(gats[0]["scopes"])
	exp, _ := time.Parse("2006-01-02", gats[0]["expires_at"].(string))
	if string(sc) != `["read_api","read_repository"]` || gats[0]["access_level"].(float64) != 20 || time.Until(exp) > 365*24*time.Hour || time.Until(exp) < 300*24*time.Hour {
		t.Fatalf("group access token asked: %v", gats[0])
	}
	if hook == nil || hook.url != "https://stk.example/api/v1/integrations/gitlab/webhook/"+itoa(conn.ID) || len(hook.secret) < 40 {
		t.Fatalf("webhook: %+v", hook)
	}

	f.drain(t)
	ints := glIntegrations(t, e, tenant.DefaultWorkspace)
	if len(ints) != 3 || ints["acme/shop"].ID == 0 || ints["acme/blog"].ID == 0 || ints["acme/backend/api"].ID == 0 {
		t.Fatalf("integrations: %+v", ints)
	}
	for name, in := range ints {
		got := glIntegration(t, e, 1, in.ID)
		if got.LastError != "" || got.LastSuccess == nil || got.AssetID == nil || got.SecretRef != "" {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	shop := glIntegration(t, e, 1, ints["acme/shop"].ID)
	if n := glScalar[int64](t, e, `SELECT count(*) FROM inventory i JOIN components c ON c.id = i.component_id
		WHERE i.asset_id = $1 AND c.name = 'lodash' AND i.version = '4.17.20' AND i.removed_at IS NULL`, *shop.AssetID); n != 1 {
		t.Fatalf("lodash on the shop asset: %d", n)
	}
	if v := glScalar[string](t, e, `SELECT value FROM asset_identifiers WHERE asset_id = $1 AND scheme = 'git-url'`, *shop.AssetID); v != gitrepo.NormalizeURL(f.srv.URL+"/acme/shop.git") {
		t.Fatalf("git-url %q", v)
	}
	f.gl.mu.Lock()
	clones, bad := f.gl.clones, f.gl.badGitAuth
	f.gl.mu.Unlock()
	if clones["acme/shop"] != 1 || clones["acme/blog"] != 1 || clones["acme/backend/api"] != 1 || clones["beta/site"] != 0 || bad != 0 {
		t.Fatalf("clones: %v, refused %d", clones, bad)
	}

	var list struct{ Connections []store.GitLabConnection }
	if code := admin.do("GET", "/api/v1/integrations/gitlab", nil, &list); code != 200 || len(list.Connections) != 1 ||
		list.Connections[0].Projects != 3 || list.Connections[0].GroupPath != "acme" || list.Connections[0].Status != "active" {
		t.Fatalf("status after connect: %+v", list)
	}

	// The integration is Connect GitLab's: no config, name or secret
	// changes, no manual gitlab integrations; switching off and
	// rescheduling work.
	id := ints["acme/shop"].ID
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(id), map[string]any{"config": map[string]any{"project_id": 201}}, nil); code != 400 {
		t.Fatalf("config change: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(id), map[string]any{"secret_ref": "env:STACKURITY_SECRET_X"}, nil); code != 400 {
		t.Fatalf("secret change: %d", code)
	}
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(id), map[string]any{"schedule_minutes": 720, "enabled": true}, nil); code != 200 {
		t.Fatalf("schedule change: %d", code)
	}
	if code := admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "gitlab",
		"config": map[string]any{"connection_id": conn.ID, "project_id": 201, "path_with_namespace": "beta/site"}}, nil); code != 400 {
		t.Fatalf("manual gitlab integration: %d", code)
	}
	_ = ctx
	glNoTokenMaterial(t, f)
}

func TestGitLabStateIsBoundAndSingleUse(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	admin, other := e.login("admin@x.io"), e.login("other-admin@x.io")

	// Another admin of the same organisation cannot use admin's state.
	sc := f.authorize(t, admin, glAlice)
	if code, out := f.oauth(other, sc); code != 400 || out.Error.Code != "gitlab_state" {
		t.Fatalf("someone else's state: %d %+v", code, out)
	}
	// Nor can a person of another organisation.
	if _, _, err := e.st.CreateWorkspace(context.Background(), "Beta Corp", "", "beta-admin@x.io", "", pw); err != nil {
		t.Fatal(err)
	}
	beta := e.login("beta-admin@x.io")
	if code, _ := f.oauth(beta, sc); code != 400 {
		t.Fatalf("another organisation's state: %d", code)
	}
	// Missing, forged and expired states.
	_, code1, _ := strings.Cut(sc, " ")
	for _, s := range []string{"", "forged-state-value-that-is-long-enough-xxxxxxxx"} {
		if code, _ := f.oauth(admin, s+" "+code1); code != 400 {
			t.Fatalf("state %q: %d", s, code)
		}
	}
	old := f.authorize(t, admin, glAlice)
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE gitlab_oauth_states SET expires_at = now() - interval '1 second' WHERE used_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.oauth(admin, old); code != 400 {
		t.Fatalf("expired state: %d", code)
	}
	// None of those reached GitLab: the state is checked first.
	if f.gl.exchanges != 0 {
		t.Fatalf("GitLab was asked %d times for refused states", f.gl.exchanges)
	}
	// The person's own fresh state works once.
	sc = f.authorize(t, admin, glAlice)
	code, out := f.oauth(admin, sc)
	if code != 200 {
		t.Fatalf("own state: %d", code)
	}
	if code, out := f.oauth(admin, sc); code != 400 || out.Error.Code != "gitlab_state" {
		t.Fatalf("state used twice: %d %+v", code, out)
	}
	if f.gl.exchanges != 1 {
		t.Fatalf("exchanges: %d", f.gl.exchanges)
	}
	// The pick is the same person's, and single use.
	if code, _ := f.pick(other, out.Pick, 10); code != 400 {
		t.Fatalf("someone else's pick: %d", code)
	}
	if code, _ := f.pick(admin, out.Pick, 10); code != 201 {
		t.Fatalf("own pick: %d", code)
	}
	if code, _ := f.pick(admin, out.Pick, 11); code != 400 {
		t.Fatalf("pick used twice: %d", code)
	}

	// An abandoned setup's token is revoked at GitLab and deleted once it
	// expires.
	sc = f.authorize(t, admin, glAlice)
	if code, _ := f.oauth(admin, sc); code != 200 {
		t.Fatal(code)
	}
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE gitlab_oauth_states SET expires_at = now() - interval '1 second' WHERE user_token IS NOT NULL`); err != nil {
		t.Fatal(err)
	}
	toks, err := e.st.TakeExpiredGitLabPicks(context.Background(), f.box)
	if err != nil || len(toks) != 1 {
		t.Fatalf("expired picks: %v %v", toks, err)
	}
	if n := glScalar[int64](t, e, `SELECT count(*) FROM gitlab_oauth_states WHERE user_token IS NOT NULL`); n != 0 {
		t.Fatalf("setup tokens left: %d", n)
	}
}

// TestGitLabRefusesForgedGroup: the group id the browser sends is not
// trusted, and a group belongs to one organisation.
func TestGitLabRefusesForgedGroup(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	ws2, _, err := e.st.CreateWorkspace(context.Background(), "Beta Corp", "", "beta-admin@x.io", "", pw)
	if err != nil {
		t.Fatal(err)
	}
	beta := e.login("beta-admin@x.io")

	// Mallory, in no group, sends acme's id.
	_, out := f.oauth(beta, f.authorize(t, beta, glMallory))
	if out.Pick != "" {
		t.Fatalf("mallory got a pick: %+v", out)
	}
	// Bob (beta's Owner) sends acme's id with his own valid pick.
	code, out := f.oauth(beta, f.authorize(t, beta, glBob))
	if code != 200 || len(out.Groups) != 1 || out.Groups[0].FullPath != "beta" {
		t.Fatalf("bob's groups: %d %+v", code, out)
	}
	if code, out := f.pick(beta, out.Pick, 10); code != 403 || out.Error.Code != "gitlab_group" {
		t.Fatalf("forged group: %d %+v", code, out)
	}
	if n := glScalar[int64](t, e, `SELECT count(*) FROM gitlab_connections`); n != 0 {
		t.Fatalf("connections: %d", n)
	}
	f.gl.mu.Lock()
	revoked := len(f.gl.revokedOAuth)
	f.gl.mu.Unlock()
	if revoked != 2 {
		t.Fatalf("refused setups' tokens revoked: %d", revoked)
	}

	// Acme connects. Alice is also beta's Reporter, but a group belongs to
	// one organisation: beta's admin cannot connect acme, or the subgroup
	// acme/backend, with her account either.
	f.connect(t)
	for _, g := range []int64{10, 11} {
		_, out := f.oauth(beta, f.authorize(t, beta, glAlice))
		if code, out := f.pick(beta, out.Pick, g); code != 409 || out.Error.Code != "gitlab_group_taken" {
			t.Fatalf("group %d for a second organisation: %d %+v", g, code, out)
		}
	}
	if owner := glScalar[int64](t, e, `SELECT workspace_id FROM gitlab_connections WHERE group_id = 10`); owner != tenant.DefaultWorkspace {
		t.Fatalf("acme now belongs to %d", owner)
	}
	// Bob connects beta (Free: no group access token, no webhook), and
	// beta cannot see or disconnect acme's connection.
	_, out = f.oauth(beta, f.authorize(t, beta, glBob))
	if code, out := f.pick(beta, out.Pick, 20); code != 201 || !out.NeedsReadOnly {
		t.Fatalf("beta: %d %+v", code, out)
	}
	var list struct{ Connections []store.GitLabConnection }
	beta.do("GET", "/api/v1/integrations/gitlab", nil, &list)
	if len(list.Connections) != 1 || list.Connections[0].GroupPath != "beta" {
		t.Fatalf("beta sees %+v", list.Connections)
	}
	acme := glScalar[int64](t, e, `SELECT id FROM gitlab_connections WHERE group_id = 10`)
	if code := beta.do("DELETE", "/api/v1/integrations/gitlab/connections/"+itoa(acme), nil, nil); code != 404 {
		t.Fatalf("beta disconnects acme: %d", code)
	}
	if code := beta.do("POST", "/api/v1/integrations/gitlab/connections/"+itoa(acme)+"/authorize", map[string]string{"purpose": "cleanup"}, nil); code != 404 {
		t.Fatalf("beta cleans acme up: %d", code)
	}
	_ = ws2
}

func TestGitLabReadOnlyFallbackAndRefreshRotation(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	bobAdmin := e.login("admin@x.io")
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	// Beta is on a tier without group access tokens or group webhooks.
	_, out := f.oauth(bobAdmin, f.authorize(t, bobAdmin, glBob))
	code, out := f.pick(bobAdmin, out.Pick, 20)
	if code != 201 || !out.NeedsReadOnly || out.Connection.Webhook != "not_permitted" || out.Connection.Status != "needs_credential" ||
		len(out.Notes) != 2 {
		t.Fatalf("fallback: %d %+v", code, out)
	}
	conn := out.Connection
	f.drain(t)
	if n := len(glIntegrations(t, e, 1)); n != 0 {
		t.Fatalf("scanned without a credential: %d", n)
	}

	// The read-only authorisation asks for read_api and read_repository
	// only, and is kept (sealed) and refreshed.
	f.gl.accessTTL = 60 // the first access token is about to expire
	state, scopes := f.start(t, bobAdmin, "/api/v1/integrations/gitlab/connections/"+itoa(conn.ID)+"/authorize", map[string]string{"purpose": "readonly"})
	if strings.Join(scopes, " ") != "read_api read_repository" {
		t.Fatalf("read-only scopes %v", scopes)
	}
	// GitLab granting more than asked is refused, and that token revoked.
	f.gl.signIn("code-ro-too-much-77a", glBob, "api")
	if code, out := f.oauth(bobAdmin, state+" code-ro-too-much-77a"); code != 400 || out.Error.Code != "gitlab_scopes" {
		t.Fatalf("api scope kept: %d %+v", code, out)
	}
	state, scopes = f.start(t, bobAdmin, "/api/v1/integrations/gitlab/connections/"+itoa(conn.ID)+"/authorize", map[string]string{"purpose": "readonly"})
	f.gl.signIn("code-ro-ok-3c9d", glBob, scopes...)
	if code, out := f.oauth(bobAdmin, state+" code-ro-ok-3c9d"); code != 201 || out.Connection.CredentialKind != "oauth" || out.Connection.Status != "active" {
		t.Fatalf("read-only: %d %+v", code, out)
	}
	f.gl.accessTTL = 7200

	// Two scans at once with an expiring access token: one refresh, and
	// both use the rotated token. GitLab revokes the old refresh token when
	// it is used, so a second refresh with it would fail.
	f.gl.mu.Lock()
	f.gl.refreshDelay = 300 * time.Millisecond
	f.gl.mu.Unlock()
	var wg sync.WaitGroup
	toks := make([]string, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			toks[i], errs[i] = e.st.GitLabAccessToken(ctx, f.box, conn.ID, gitlab.Refresher(f.client, f.runner.RedirectURL))
		}()
	}
	wg.Wait()
	f.gl.mu.Lock()
	refreshes := f.gl.refreshes
	f.gl.refreshDelay = 0
	f.gl.mu.Unlock()
	if errs[0] != nil || errs[1] != nil || toks[0] != toks[1] || toks[0] == "" || refreshes != 1 {
		t.Fatalf("concurrent refresh: tokens %v, errors %v, refreshes %d", toks, errs, refreshes)
	}
	// The stored credential is the rotated one: it works, and holds the
	// refresh token GitLab issued last.
	sec, err := e.st.GitLabConnectionSecrets(ctx, f.box, conn.ID)
	if err != nil || sec.Credential.Token != toks[0] {
		t.Fatalf("stored credential: %+v %v", sec, err)
	}
	f.gl.mu.Lock()
	_, live := f.gl.refresh[sec.Credential.RefreshToken]
	f.gl.mu.Unlock()
	if !live {
		t.Fatal("the stored refresh token is not the one GitLab holds: the rotated token was lost")
	}
	f.drain(t)
	ints := glIntegrations(t, e, 1)
	if len(ints) != 1 || glIntegration(t, e, 1, ints["beta/site"].ID).LastSuccess == nil {
		t.Fatalf("scanned with the OAuth credential: %+v", ints)
	}

	// Revoked at GitLab: the next refresh fails, the connection says so and
	// scans stop asking.
	f.gl.mu.Lock()
	for rt := range f.gl.refresh {
		delete(f.gl.refresh, rt)
	}
	f.gl.mu.Unlock()
	// Force a refresh: store a credential that has expired.
	if err := e.st.SetGitLabCredential(ctx, f.box, conn.ID, "oauth", store.GitLabCredential{Token: "expired", RefreshToken: sec.Credential.RefreshToken,
		ExpiresAt: time.Now().Add(-time.Minute)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.GitLabAccessToken(ctx, f.box, conn.ID, gitlab.Refresher(f.client, f.runner.RedirectURL)); !errors.Is(err, store.ErrGitLabCredentialRevoked) {
		t.Fatalf("revoked refresh token: %v", err)
	}
	if st := glScalar[string](t, e, `SELECT status FROM gitlab_connections WHERE id = $1`, conn.ID); st != "expired" {
		t.Fatalf("status %s", st)
	}
	glNoTokenMaterial(t, f)
}

func TestGitLabWebhookSecret(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	_, conn := f.connect(t)
	f.drain(t)
	secret := f.secret(t, 10)
	body, _ := json.Marshal(map[string]any{"object_kind": "push", "ref": "refs/heads/main", "after": "abc", "project_id": 101,
		"project": map[string]any{"id": 101, "default_branch": "main"}, "total_commits_count": 1,
		"commits": []map[string]any{{"added": []string{}, "removed": []string{}, "modified": []string{"package-lock.json"}}}})
	hdr := func(tok string) map[string]string {
		h := map[string]string{"X-Gitlab-Event": "Push Hook", "X-Gitlab-Event-UUID": "u-forged"}
		if tok != "" {
			h["X-Gitlab-Token"] = tok
		}
		return h
	}
	for name, h := range map[string]map[string]string{
		"missing":  hdr(""),
		"wrong":    hdr("not-the-secret"),
		"prefix":   hdr(secret[:20]),
		"its hash": hdr(hex.EncodeToString([]byte(secret))),
	} {
		if code, _ := f.rawHook(t, conn.ID, body, h); code != 401 {
			t.Errorf("%s token: %d", name, code)
		}
	}
	// The right secret for another (or no) connection.
	for _, id := range []int64{conn.ID + 1, 0} {
		if code, _ := f.rawHook(t, id, body, hdr(secret)); code != 401 {
			t.Errorf("connection %d: %d", id, code)
		}
	}
	if n := glScalar[int64](t, e, `SELECT count(*) FROM jobs WHERE kind = 'integration.run' AND done_at IS NULL`); n != 0 {
		t.Fatalf("an unverified delivery queued %d scans", n)
	}
	// Missing delivery id: refused even with the secret.
	if code, _ := f.rawHook(t, conn.ID, body, map[string]string{"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": secret}); code != 400 {
		t.Fatalf("missing uuid: %d", code)
	}
	// Verified: handled once; the redelivery and a replay of the same body
	// under another uuid are acknowledged and ignored.
	if code, res := f.rawHook(t, conn.ID, body, map[string]string{"X-Gitlab-Event": "Push Hook", "X-Gitlab-Event-UUID": "u-1", "X-Gitlab-Token": secret}); code != 200 || res != "scan queued" {
		t.Fatalf("push: %d %q", code, res)
	}
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `DELETE FROM jobs WHERE kind = 'integration.run'`); err != nil {
		t.Fatal(err)
	}
	for _, uuid := range []string{"u-1", "u-1-replayed"} {
		if code, res := f.rawHook(t, conn.ID, body, map[string]string{"X-Gitlab-Event": "Push Hook", "X-Gitlab-Event-UUID": uuid, "X-Gitlab-Token": secret}); code != 200 || res != "duplicate" {
			t.Fatalf("%s: %d %q", uuid, code, res)
		}
	}
	if n := glScalar[int64](t, e, `SELECT count(*) FROM jobs WHERE kind = 'integration.run' AND done_at IS NULL`); n != 0 {
		t.Fatalf("a duplicate queued %d scans", n)
	}
	// Only the hash of the secret is stored.
	if h := glScalar[[]byte](t, e, `SELECT hook_secret_hash FROM gitlab_connections WHERE id = $1`, conn.ID); len(h) != 32 {
		t.Fatalf("stored hash: %d bytes", len(h))
	}
}

func glPush(ref string, project int64, files ...string) map[string]any {
	return map[string]any{"object_kind": "push", "ref": ref, "after": "1111111111111111111111111111111111111111", "project_id": project,
		"project": map[string]any{"id": project, "default_branch": "main"}, "total_commits_count": 1,
		"commits": []map[string]any{{"added": []string{}, "removed": []string{}, "modified": files}}}
}

func TestGitLabPushScansOnlyLockfileChanges(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	admin, conn := f.connect(t)
	f.drain(t)
	secret := f.secret(t, 10)
	shop := glIntegrations(t, e, 1)["acme/shop"].ID
	pending := func() int64 {
		return glScalar[int64](t, e, `SELECT count(*) FROM jobs WHERE kind = 'integration.run' AND done_at IS NULL AND failed_at IS NULL
			AND payload->>'integration_id' = $1`, itoa(shop))
	}
	deleted := glPush("refs/heads/main", 101, "package-lock.json")
	deleted["after"] = "0000000000000000000000000000000000000000"
	many := glPush("refs/heads/main", 101, "README.md")
	many["total_commits_count"] = 25
	for i, c := range []struct {
		ev   map[string]any
		want string
	}{
		{glPush("refs/heads/main", 101, "README.md", "src/app.js"), "ignored: no lockfile or manifest changed"},
		{glPush("refs/heads/feature", 101, "package-lock.json"), "ignored: not the default branch"},
		{glPush("refs/tags/v1", 101, "package-lock.json"), "ignored: not the default branch"},
		{deleted, "ignored: not the default branch"},
	} {
		if code, res := f.hook(t, conn.ID, secret, "Push Hook", fmt.Sprintf("p-%d", i), c.ev); code != 200 || res != c.want {
			t.Fatalf("push %d: %d %q, want %q", i, code, res, c.want)
		}
	}
	if n := pending(); n != 0 {
		t.Fatalf("scans queued for irrelevant pushes: %d", n)
	}
	for i, ev := range []map[string]any{
		glPush("refs/heads/main", 101, "README.md", "services/web/package-lock.json"),
		glPush("refs/heads/main", 101, "package.json"),
		many, // more commits than listed: not known what changed
	} {
		if code, res := f.hook(t, conn.ID, secret, "Push Hook", fmt.Sprintf("q-%d", i), ev); code != 200 || res != "scan queued" {
			t.Fatalf("lockfile push %d: %d %q", i, code, res)
		}
	}
	if n := pending(); n != 1 {
		t.Fatalf("pushes queue one scan (deduplicated), got %d", n)
	}
	before := f.gl.clones["acme/shop"]
	f.drain(t)
	if f.gl.clones["acme/shop"] != before+1 {
		t.Fatalf("clones after push: %d (before %d)", f.gl.clones["acme/shop"], before)
	}
	// A push for a project Stackurity does not know lists the group again;
	// one for a switched-off integration is ignored.
	if _, res := f.hook(t, conn.ID, secret, "Push Hook", "n-1", glPush("refs/heads/main", 999, "package-lock.json")); res != "sync queued" {
		t.Fatalf("unknown project: %q", res)
	}
	if code := admin.do("PATCH", "/api/v1/integrations/"+itoa(shop), map[string]any{"enabled": false}, nil); code != 200 {
		t.Fatal(code)
	}
	if _, res := f.hook(t, conn.ID, secret, "Push Hook", "r-1", glPush("refs/heads/main", 101, "package-lock.json")); res != "ignored: project not scanned" {
		t.Fatalf("push to a switched-off project: %q", res)
	}
}

func TestGitLabProjectRemovedAndAdded(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, conn := f.connect(t)
	f.drain(t)
	blog := glIntegrations(t, e, 1)["acme/blog"]
	blogAsset := *glIntegration(t, e, 1, blog.ID).AssetID

	// acme/blog is deleted on GitLab; the daily (or manual) sync notices.
	f.gl.mu.Lock()
	delete(f.gl.projects, 102)
	f.gl.mu.Unlock()
	if code := e.login("admin@x.io").do("POST", "/api/v1/integrations/gitlab/connections/"+itoa(conn.ID)+"/sync", nil, nil); code != 202 {
		t.Fatalf("sync: %d", code)
	}
	f.drain(t)
	got := glIntegration(t, e, 1, blog.ID)
	if got.Enabled || !strings.Contains(got.LastError, "No longer in the connected GitLab group") {
		t.Fatalf("removed project's integration: %+v", got)
	}
	a, err := e.st.GetAsset(ctx, blogAsset)
	if err != nil {
		t.Fatalf("the asset was deleted: %v", err)
	}
	if a.CollectionStatus != store.AssetRemoved {
		t.Fatalf("asset status %q", a.CollectionStatus)
	}
	if n := glScalar[int64](t, e, `SELECT count(*) FROM inventory WHERE asset_id = $1 AND removed_at IS NULL`, blogAsset); n != 0 {
		t.Fatalf("inventory still present: %d", n)
	}
	if n := glScalar[int64](t, e, `SELECT count(*) FROM inventory WHERE asset_id = $1`, blogAsset); n == 0 {
		t.Fatal("inventory history deleted")
	}
	// Its scan does not run, and asks GitLab for nothing.
	clones := f.gl.clones["acme/blog"]
	if err := f.runner.Run(store.WithReportSource(ctx, store.ReportSource{Source: store.SourceIntegration, IntegrationID: blog.ID}), got); err != nil {
		t.Fatal(err)
	}
	if f.gl.clones["acme/blog"] != clones || !strings.Contains(glIntegration(t, e, 1, blog.ID).LastError, "no longer in the connected GitLab group") {
		t.Fatalf("a removed project was scanned: %q", glIntegration(t, e, 1, blog.ID).LastError)
	}

	// Back in the group, and a new project: a non-push event (here a test
	// delivery) lists the group again.
	f.gl.mu.Lock()
	f.gl.projects[102] = &glProject{id: 102, path: "acme/blog", branch: "main"}
	f.gl.mu.Unlock()
	f.gl.addProject(104, "acme/docs", map[string]string{"README.md": "docs"})
	if code, res := f.hook(t, conn.ID, f.secret(t, 10), "Project Hook", "s-1", map[string]any{"event_name": "project_create"}); code != 200 || res != "sync queued" {
		t.Fatalf("event: %d %q", code, res)
	}
	f.drain(t)
	ints := glIntegrations(t, e, 1)
	if len(ints) != 4 || !ints["acme/docs"].Enabled || !ints["acme/blog"].Enabled || ints["acme/blog"].ID != blog.ID {
		t.Fatalf("after adding: %+v", ints)
	}
	if a, _ := e.st.GetAsset(ctx, blogAsset); a.CollectionStatus == store.AssetRemoved {
		t.Fatal("blog's asset still removed after it was back and scanned")
	}
}

func TestGitLabDisconnect(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	admin, conn := f.connect(t)
	f.drain(t)
	f.gl.mu.Lock()
	var gat string
	for s, tk := range f.gl.tokens {
		if tk.kind == "gat" {
			gat = s
		}
	}
	f.gl.mu.Unlock()
	if code := e.login("eng@x.io").do("DELETE", "/api/v1/integrations/gitlab/connections/"+itoa(conn.ID), nil, nil); code != 403 {
		t.Fatalf("engineer disconnects: %d", code)
	}

	// Disconnect with cleanup: GitLab's consent (api), then the webhook and
	// the group access token are deleted with the person's token, which is
	// revoked too.
	state, scopes := f.start(t, admin, "/api/v1/integrations/gitlab/connections/"+itoa(conn.ID)+"/authorize", map[string]string{"purpose": "cleanup"})
	f.gl.signIn("code-cleanup-5f1e", glAlice, scopes...)
	code, out := f.oauth(admin, state+" code-cleanup-5f1e")
	if code != 200 || !out.WebhookDel || !out.TokenRevoked {
		t.Fatalf("cleanup: %d %+v", code, out)
	}
	f.gl.mu.Lock()
	hookDeleted := true
	for _, h := range f.gl.hooks {
		hookDeleted = hookDeleted && h.deleted
	}
	gatRevoked := f.gl.tokens[gat].revoked
	revokedLast := f.gl.revokedOAuth[len(f.gl.revokedOAuth)-1]
	cleanupTok := ""
	for s, tk := range f.gl.tokens {
		if tk.kind == "oauth" && hasScope(tk, "api") && !tk.revoked {
			cleanupTok = s
		}
	}
	f.gl.mu.Unlock()
	if !hookDeleted || !gatRevoked || cleanupTok != "" || revokedLast == "" {
		t.Fatalf("on GitLab: hook deleted %v, token revoked %v, a person's api token still live %q", hookDeleted, gatRevoked, cleanupTok)
	}
	if n := glScalar[int64](t, e, `SELECT count(*) FROM gitlab_connections`); n != 0 {
		t.Fatalf("connection kept: %d", n)
	}
	for name, in := range glIntegrations(t, e, 1) {
		if in.Enabled || in.AssetID == nil {
			t.Fatalf("%s after disconnect: %+v", name, in)
		}
	}
	// Its scans stop without asking GitLab.
	shop := glIntegration(t, e, 1, glIntegrations(t, e, 1)["acme/shop"].ID)
	clones := f.gl.clones["acme/shop"]
	_ = f.runner.Run(tenant.WithWorkspace(context.Background(), 1), shop)
	if f.gl.clones["acme/shop"] != clones || !strings.Contains(glIntegration(t, e, 1, shop.ID).LastError, "disconnected") {
		t.Fatalf("a disconnected group's project was scanned: %q", glIntegration(t, e, 1, shop.ID).LastError)
	}
	// The old webhook URL is refused.
	if code, _ := f.hook(t, conn.ID, "anything", "Push Hook", "x-1", glPush("refs/heads/main", 101, "package-lock.json")); code != 401 {
		t.Fatalf("webhook after disconnect: %d", code)
	}

	// Connected again: the same integrations carry on, with their assets.
	_, conn2 := f.connect(t)
	f.drain(t)
	after := glIntegrations(t, e, 1)
	if len(after) != 3 || after["acme/shop"].ID != shop.ID || !after["acme/shop"].Enabled {
		t.Fatalf("after connecting again: %+v", after)
	}

	// Disconnect here only: the group access token revokes itself; the
	// webhook is left (deleting it needs the group's Owner) and says so.
	var res struct {
		CredentialRevoked bool `json:"credential_revoked"`
		WebhookLeft       bool `json:"webhook_left_on_gitlab"`
	}
	if code := admin.do("DELETE", "/api/v1/integrations/gitlab/connections/"+itoa(conn2.ID), nil, &res); code != 200 || !res.CredentialRevoked || !res.WebhookLeft {
		t.Fatalf("disconnect here: %d %+v", code, res)
	}
	f.gl.mu.Lock()
	selfRevoked := len(f.gl.selfRevoked)
	f.gl.mu.Unlock()
	if selfRevoked != 1 {
		t.Fatalf("self-revoked tokens: %d", selfRevoked)
	}
	glNoTokenMaterial(t, f)

	// An OAuth credential is revoked at GitLab on disconnect.
	_, out = f.oauth(admin, f.authorize(t, admin, glBob))
	_, out = f.pick(admin, out.Pick, 20)
	state, scopes = f.start(t, admin, "/api/v1/integrations/gitlab/connections/"+itoa(out.Connection.ID)+"/authorize", map[string]string{"purpose": "readonly"})
	f.gl.signIn("code-ro-b2e4", glBob, scopes...)
	if code, _ := f.oauth(admin, state+" code-ro-b2e4"); code != 201 {
		t.Fatal(code)
	}
	if code := admin.do("DELETE", "/api/v1/integrations/gitlab/connections/"+itoa(out.Connection.ID), nil, &res); code != 200 || !res.CredentialRevoked || res.WebhookLeft {
		t.Fatalf("disconnect oauth: %d %+v", code, res)
	}
	f.gl.mu.Lock()
	live := 0
	for _, tk := range f.gl.tokens {
		if tk.kind == "oauth" && !tk.revoked && tk.user == glBob {
			live++
		}
	}
	f.gl.mu.Unlock()
	if live != 0 {
		t.Fatalf("live OAuth tokens after disconnect: %d", live)
	}
}

func TestGitLabLimits(t *testing.T) {
	// The webhook's limit is read when the routes are built.
	const hookLimit = 5
	t.Cleanup(api.SetGitLabWebhookLimit(hookLimit))
	f := gitlabSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)

	// Asset limit: room for one asset, three projects.
	one := int64(1)
	if err := e.st.SetAssetLimit(tenant.System(context.Background()), tenant.DefaultWorkspace, &one); err != nil {
		t.Fatal(err)
	}
	_, conn := f.connect(t)
	f.drain(t)
	if ints := glIntegrations(t, e, 1); len(ints) != 1 {
		t.Fatalf("integrations at the limit: %+v", ints)
	}
	c, err := e.st.GetGitLabConnection(ctx, conn.ID)
	if err != nil || !strings.Contains(c.Note, "2 projects are not scanned") || !strings.Contains(c.Note, "limit of 1 monitored asset") {
		t.Fatalf("connection note: %+v %v", c, err)
	}
	if err := e.st.SetAssetLimit(tenant.System(context.Background()), tenant.DefaultWorkspace, nil); err != nil {
		t.Fatal(err)
	}
	if code := e.login("admin@x.io").do("POST", "/api/v1/integrations/gitlab/connections/"+itoa(conn.ID)+"/sync", nil, nil); code != 202 {
		t.Fatalf("sync: %d", code)
	}
	f.drain(t)
	if ints := glIntegrations(t, e, 1); len(ints) != 3 {
		t.Fatalf("integrations once there is room: %+v", ints)
	}

	// Clones per connection per minute: past the limit a scan waits. The
	// limit counts in fixed minutes of the database clock, so two scans can
	// fall either side of a boundary and both run. Three scans made within
	// a minute span at most two windows, so with a limit of one, at least
	// one of them must wait, and a scan that waits clones nothing.
	f.runner.ClonesPerMinute = 1
	shop := glIntegration(t, e, 1, glIntegrations(t, e, 1)["acme/shop"].ID)
	if _, err := e.st.Pool.Exec(tenant.System(context.Background()), `DELETE FROM rate_limits`); err != nil {
		t.Fatal(err)
	}
	clones := f.gl.clones["acme/shop"]
	var d *worker.Deferred
	ran, waited := 0, 0
	for range 3 {
		switch err := f.runner.Run(ctx, shop); {
		case err == nil:
			ran++
		case errors.As(err, &d):
			waited++
		default:
			t.Fatal(err)
		}
	}
	if waited == 0 || f.gl.clones["acme/shop"]-clones != ran {
		t.Fatalf("three scans with a limit of one a minute: %d ran, %d waited, %d clones", ran, waited, f.gl.clones["acme/shop"]-clones)
	}

	// GitLab's rate limit (429, Retry-After) defers a sync, no error.
	f.gl.mu.Lock()
	f.gl.rateLimitNext = 1
	f.gl.mu.Unlock()
	err = f.runner.Sync(ctx, conn.ID)
	if !errors.As(err, &d) || d.After < 42*time.Second {
		t.Fatalf("rate-limited sync: %v", err)
	}

	// The webhook is limited per address. Its windows are fixed minutes
	// too: 2n+1 deliveries within a minute put more than n in one window.
	limited := false
	for i := 0; i < 2*hookLimit+1 && !limited; i++ {
		code, _ := f.hook(t, conn.ID, "x", "Push Hook", "l-"+itoa(int64(i)), map[string]any{})
		limited = code == 429
	}
	if !limited {
		t.Fatal("webhook not rate limited")
	}

	// Requests go through netguard: an organisation that may not reach
	// private addresses cannot make the server call this (private) GitLab,
	// for the API or for a clone.
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "none"})
	if _, err := f.client.Group(tenant.WithWorkspace(context.Background(), 2), "tok", 10); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("private GitLab from a workspace without private access: %v", err)
	}
	if _, err := f.runner.Scanner.Scan(tenant.WithWorkspace(context.Background(), 2), gitrepo.Config{URL: f.srv.URL + "/acme/shop.git", Username: "oauth2"}, "tok"); err == nil || !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("clone of a private GitLab from a workspace without private access: %v", err)
	}
}

// TestGitLabTokenExpiryAndReconnect: a group access token near its expiry
// is announced, an expired one stops the connection, and connecting the
// group again renews it on the same connection (the old token revoked, no
// second webhook).
func TestGitLabTokenExpiryAndReconnect(t *testing.T) {
	f := gitlabSetup(t)
	e := f.e
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	_, conn := f.connect(t)
	f.drain(t)
	sec, err := e.st.GitLabConnectionSecrets(ctx, f.box, conn.ID)
	if err != nil || sec.Credential == nil || sec.TokenID == nil {
		t.Fatalf("secrets: %+v %v", sec, err)
	}
	oldTok := sec.Credential.Token

	// Ten days left: the sync says so.
	soon := time.Now().Add(10 * 24 * time.Hour)
	if err := e.st.SetGitLabCredential(ctx, f.box, conn.ID, "group_token", store.GitLabCredential{Token: oldTok, ExpiresAt: soon}, sec.TokenID, &soon); err != nil {
		t.Fatal(err)
	}
	if err := f.runner.Sync(ctx, conn.ID); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.st.GetGitLabConnection(ctx, conn.ID); !strings.Contains(c.Note, "expires on") || c.Status != "active" {
		t.Fatalf("near expiry: %+v", c)
	}
	// Expired: the connection says connect again, and scans stop.
	past := time.Now().Add(-time.Hour)
	if err := e.st.SetGitLabCredential(ctx, f.box, conn.ID, "group_token", store.GitLabCredential{Token: oldTok, ExpiresAt: past}, sec.TokenID, &past); err != nil {
		t.Fatal(err)
	}
	if err := f.runner.Sync(ctx, conn.ID); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.st.GetGitLabConnection(ctx, conn.ID); c.Status != "expired" || !strings.Contains(c.Note, "Connect GitLab again") {
		t.Fatalf("expired: %+v", c)
	}

	// Connect again: same connection, new token, old one revoked, one hook.
	_, again := f.connect(t)
	if again.ID != conn.ID || again.Status != "active" || again.Webhook != "active" {
		t.Fatalf("connected again: %+v (was %d)", again, conn.ID)
	}
	sec2, _ := e.st.GitLabConnectionSecrets(ctx, f.box, conn.ID)
	f.gl.mu.Lock()
	hooks := len(f.gl.hooks)
	oldRevoked := f.gl.tokens[oldTok].revoked
	newLive := !f.gl.tokens[sec2.Credential.Token].revoked
	f.gl.mu.Unlock()
	if hooks != 1 || sec2.Credential.Token == oldTok || !newLive {
		t.Fatalf("after reconnect: %d hooks, new token live %v", hooks, newLive)
	}
	if !oldRevoked {
		t.Fatal("the old group access token was not revoked")
	}
	f.drain(t)
	if n := len(glIntegrations(t, e, 1)); n != 3 {
		t.Fatalf("integrations after reconnect: %d", n)
	}
}
