package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestJWT(t *testing.T) {
	k := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	a := &App{ID: 77, Key: k, Now: func() time.Time { return now }}
	tok, err := a.JWT()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt %q", tok)
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, sum[:], sig); err != nil {
		t.Fatalf("signature: %v", err)
	}
	var h map[string]string
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	_ = json.Unmarshal(hb, &h)
	var c map[string]any
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	_ = json.Unmarshal(cb, &c)
	if h["alg"] != "RS256" || c["iss"] != "77" || int64(c["iat"].(float64)) != now.Unix()-60 || int64(c["exp"].(float64)) != now.Unix()+540 {
		t.Fatalf("header %v claims %v", h, c)
	}
}

func TestVerifySignature(t *testing.T) {
	a := &App{WebhookSecret: "s3cret"}
	body := []byte(`{"action":"deleted"}`)
	good := "sha256=" + hex.EncodeToString(Sign("s3cret", body))
	if !a.VerifySignature(body, good) {
		t.Fatal("good signature refused")
	}
	for _, bad := range []string{"", "sha256=", good[:len(good)-2], "sha1=" + good[7:], "sha256=" + hex.EncodeToString(Sign("other", body)), strings.ToUpper(good)} {
		if a.VerifySignature(body, bad) {
			t.Errorf("signature %q accepted", bad)
		}
	}
	if a.VerifySignature([]byte(`{"action":"created"}`), good) {
		t.Error("signature of another body accepted")
	}
	if (&App{}).VerifySignature(body, "sha256="+hex.EncodeToString(Sign("", body))) {
		t.Error("an empty webhook secret verifies")
	}
}

func TestFromEnv(t *testing.T) {
	for _, n := range []string{"ID", "SLUG", "CLIENT_ID", "CLIENT_SECRET", "PRIVATE_KEY", "WEBHOOK_SECRET"} {
		t.Setenv("STACKURITY_GITHUB_APP_"+n, "")
		t.Setenv("STACKURITY_GITHUB_APP_"+n+"_FILE", "")
	}
	t.Setenv("STACKURITY_GITHUB_URL", "")
	if a, err := FromEnv(); a != nil || err != nil {
		t.Fatalf("none set: %v %v", a, err)
	}
	t.Setenv("STACKURITY_GITHUB_APP_ID", "123")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "STACKURITY_GITHUB_APP_WEBHOOK_SECRET") {
		t.Fatalf("some set: %v", err)
	}
	k := testKey(t)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}), 0o600)
	t.Setenv("STACKURITY_GITHUB_APP_SLUG", "stackurity")
	t.Setenv("STACKURITY_GITHUB_APP_CLIENT_ID", "Iv1.x")
	t.Setenv("STACKURITY_GITHUB_APP_CLIENT_SECRET", "cs")
	t.Setenv("STACKURITY_GITHUB_APP_PRIVATE_KEY_FILE", keyFile)
	t.Setenv("STACKURITY_GITHUB_APP_WEBHOOK_SECRET", "ws")
	a, err := FromEnv()
	if err != nil || a.ID != 123 || a.Web != "https://github.com" || a.API != "https://api.github.com" || a.Key.N.Cmp(k.N) != 0 {
		t.Fatalf("all set: %+v %v", a, err)
	}
	if u := a.InstallURL("st"); u != "https://github.com/apps/stackurity/installations/new?state=st" {
		t.Fatalf("install url %q", u)
	}
	t.Setenv("STACKURITY_GITHUB_URL", "https://ghe.example.com/")
	if a, err = FromEnv(); err != nil || a.API != "https://ghe.example.com/api/v3" || a.InstallURL("") != "https://ghe.example.com/github-apps/stackurity/installations/new" {
		t.Fatalf("GHES: %+v %v", a, err)
	}
	for _, bad := range []string{"http://ghe.example.com", "https://u:p@ghe.example.com", "https://ghe.example.com/path", "ghe.example.com"} {
		t.Setenv("STACKURITY_GITHUB_URL", bad)
		if _, err := FromEnv(); err == nil {
			t.Errorf("STACKURITY_GITHUB_URL %q accepted", bad)
		}
	}
	t.Setenv("STACKURITY_GITHUB_URL", "")
	t.Setenv("STACKURITY_GITHUB_APP_ID", "abc")
	if _, err := FromEnv(); err == nil {
		t.Error("a non-numeric app ID accepted")
	}
	t.Setenv("STACKURITY_GITHUB_APP_ID", "123")
	t.Setenv("STACKURITY_GITHUB_APP_PRIVATE_KEY_FILE", "")
	t.Setenv("STACKURITY_GITHUB_APP_PRIVATE_KEY", "not a key")
	if _, err := FromEnv(); err == nil {
		t.Error("a bad private key accepted")
	}
}

func TestCloneURLComesFromTheServerAddress(t *testing.T) {
	a := &App{Web: "https://github.com"}
	if u, err := a.CloneURL("acme/shop.js"); err != nil || u != "https://github.com/acme/shop.js.git" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []string{"acme", "acme/..", "acme/.", "../etc/passwd", "acme/shop/extra", "evil.example/x", "acme/shop?x=1", "acme/shop#x",
		"-acme/shop", "acme/sh op", "@evil.example/x", "acme/" + strings.Repeat("a", 101), ""} {
		if _, err := a.CloneURL(bad); err == nil {
			t.Errorf("full name %q accepted", bad)
		}
	}
}

func TestTokenRefusesWriteAccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"token":"ghs_x","permissions":{"contents":"write","metadata":"read"}}`))
	}))
	defer srv.Close()
	a := &App{ID: 1, Key: testKey(t), API: srv.URL, HTTP: srv.Client()}
	if tok, err := a.Token(context.Background(), 5, []int64{9}, nil); err == nil || tok != "" {
		t.Fatalf("a token with write access was used: %q %v", tok, err)
	}
}

func TestRateLimitAnswers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "42")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	a := &App{ID: 1, Key: testKey(t), API: srv.URL, HTTP: srv.Client()}
	_, err := a.Installation(context.Background(), 5)
	rl, ok := err.(*RateLimited)
	if !ok || rl.Wait != 42*time.Second {
		t.Fatalf("rate limit: %v", err)
	}
}

func TestPushTouchesInventory(t *testing.T) {
	push := func(files ...string) *PushEvent {
		p := &PushEvent{Ref: "refs/heads/main"}
		p.Repository.DefaultBranch = "main"
		p.Commits = append(p.Commits, struct {
			Added    []string `json:"added"`
			Removed  []string `json:"removed"`
			Modified []string `json:"modified"`
		}{Modified: files})
		return p
	}
	for files, want := range map[string]bool{
		"README.md,src/a.go":       false,
		"docs/package-lock.md":     false,
		"go.mod":                   true,
		"web/yarn.lock":            true,
		"api/composer.json":        true,
		"svc/pyproject.toml":       true,
		"pom.xml":                  true, // recognised, reported as unsupported coverage
		".gitignore":               true,
		"a/b/c/requirements.txt":   true,
		"Gemfile.lock,README.md":   true,
		"package-lock.json.backup": false,
	} {
		if got := push(strings.Split(files, ",")...).TouchesInventory(nil); got != want {
			t.Errorf("%s: %v, want %v", files, got, want)
		}
	}
	empty := &PushEvent{}
	if !empty.TouchesInventory(nil) {
		t.Error("a push listing no commits must be scanned")
	}
	p := push("README.md")
	for len(p.Commits) < pushCommitsListed {
		p.Commits = append(p.Commits, p.Commits[0])
	}
	if !p.TouchesInventory(nil) {
		t.Error("a push with as many commits as GitHub lists must be scanned")
	}
	d := push("go.mod")
	if !d.ToDefaultBranch() {
		t.Error("main push")
	}
	d.Ref = "refs/heads/main-old"
	if d.ToDefaultBranch() {
		t.Error("another branch")
	}
	d.Ref, d.Deleted = "refs/heads/main", true
	if d.ToDefaultBranch() {
		t.Error("a deleted branch")
	}
}
