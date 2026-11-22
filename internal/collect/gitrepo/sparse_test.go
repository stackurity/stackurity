package gitrepo

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/collect/limits"
	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/pkg/pack"
)

type extFake struct{ suffix string }

func (e extFake) ID() string               { return "fake" }
func (e extFake) Matches(name string) bool { return strings.HasSuffix(strings.ToLower(name), e.suffix) }
func (e extFake) Scan(context.Context, []pack.File) ([]model.Observation, []model.CoverageItem, error) {
	return nil, nil, nil
}

// The checkout leaves out what the leak scan skips (images, fonts, media),
// in any case, but keeps what another reader needs: stylesheets for the
// import walk, and Java archives when the Java pack is installed.
func TestSparsePatterns(t *testing.T) {
	p := sparsePatterns(nil)
	if p[0] != "/*" {
		t.Fatalf("first pattern %q; want everything included first", p[0])
	}
	for _, want := range []string{"!*.[pP][nN][gG]", "!*.[sS][vV][gG]", "!*.[wW][oO][fF][fF]2", "!*.[mM][pP]4", "!*.[jJ][aA][rR]"} {
		if !slices.Contains(p, want) {
			t.Errorf("patterns lack %q: %v", want, p)
		}
	}
	for _, p := range p[1:] {
		if !strings.HasPrefix(p, "!*.") || strings.ContainsAny(p, "/\n") {
			t.Errorf("unexpected pattern %q", p)
		}
		if strings.Contains(p, "[cC][sS][sS]") {
			t.Errorf("stylesheets left out (%q): the import walk reads them", p)
		}
	}
	withJava := sparsePatterns([]lockfile.Extension{extFake{".jar"}})
	if slices.Contains(withJava, "!*.[jJ][aA][rR]") || !slices.Contains(withJava, "!*.[pP][nN][gG]") {
		t.Errorf("with a pack reading .jar: %v", withJava)
	}
}

// fakeGitLog is a git stand-in that succeeds, records each call's
// arguments, environment and input, and on clone creates the destination.
func fakeGitLog(t *testing.T) (bin, logDir string) {
	t.Helper()
	logDir = t.TempDir()
	bin = filepath.Join(t.TempDir(), "git")
	script := "#!/bin/sh\nn=$(ls " + logDir + " | grep -c args)\n" +
		"printf '%s\\n' \"$@\" > " + logDir + "/$n.args\nenv > " + logDir + "/$n.env.txt\n" +
		"for a; do [ \"$a\" = clone ] && c=1; d=$a; done\n" +
		"case \" $* \" in *' --stdin'*) cat > " + logDir + "/$n.stdin.txt;; esac\n" +
		"[ -n \"$c\" ] && mkdir -p \"$d/.git\"\nexit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, logDir
}

// Every git command that can fetch from the server (the clone, and the
// sparse checkout that fetches file contents from the same remote) gets the
// same pinned address, transport limits and credential; the remote is then
// removed, and rev-parse runs without the credential and cannot fetch.
func TestEveryGitStepIsHardened(t *testing.T) {
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("140.82.112.3")}, nil
	})()
	bin, logDir := fakeGitLog(t)
	s := &Scanner{WorkDir: t.TempDir(), Git: bin}
	const token = "ghp_S3cretTokenValue1234567890"
	if _, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{URL: "https://github.com/acme/shop.git", Ref: "v1"}, token); err != nil {
		t.Fatal(err)
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	var steps []string
	for i := 0; ; i++ {
		a, err := os.ReadFile(filepath.Join(logDir, strconv.Itoa(i)+".args"))
		if err != nil {
			break
		}
		e, _ := os.ReadFile(filepath.Join(logDir, strconv.Itoa(i)+".env.txt"))
		args, env := string(a), string(e)
		switch {
		case strings.Contains(args, "\nrev-parse\n"):
			steps = append(steps, "rev-parse")
			if !strings.Contains(env, "GIT_NO_LAZY_FETCH=1") || strings.Contains(env, basic) || strings.Contains(env, "STACKURITY_") {
				t.Errorf("rev-parse environment:\n%s", env)
			}
			continue
		case strings.Contains(args, "\nclone\n"):
			steps = append(steps, "clone")
			for _, want := range []string{"--filter=blob:none", "--no-checkout", "--sparse", "--depth\n1", "--single-branch",
				"--no-tags", "--no-recurse-submodules", "--branch\nv1", "--\nhttps://github.com/acme/shop.git\n"} {
				if !strings.Contains(args, want) {
					t.Errorf("clone lacks %q:\n%s", want, args)
				}
			}
		case strings.Contains(args, "\nsparse-checkout\nset\n--no-cone\n--stdin\n"):
			steps = append(steps, "sparse-checkout")
			in, _ := os.ReadFile(filepath.Join(logDir, strconv.Itoa(i)+".stdin.txt"))
			if !strings.HasPrefix(string(in), "/*\n") || !strings.Contains(string(in), "!*.[pP][nN][gG]\n") {
				t.Errorf("sparse patterns:\n%s", in)
			}
		case strings.Contains(args, "\ncheckout\n"):
			steps = append(steps, "checkout")
		case strings.Contains(args, "\nremote\nremove\norigin\n"):
			steps = append(steps, "remote-remove")
		default:
			t.Errorf("unexpected git call:\n%s", args)
			continue
		}
		for _, want := range []string{"http.curloptResolve=github.com:443:140.82.112.3", "http.followRedirects=false",
			"protocol.allow=never", "protocol.https.allow=always", "core.hooksPath=/dev/null", "core.symlinks=false",
			"filter.lfs.smudge=", "filter.lfs.process=", "core.fsmonitor=false"} {
			if !strings.Contains(args, want+"\n") {
				t.Errorf("%s lacks %q:\n%s", steps[len(steps)-1], want, args)
			}
		}
		if strings.Contains(args, token) || strings.Contains(args, basic) {
			t.Errorf("%s: credential in arguments", steps[len(steps)-1])
		}
		if !strings.Contains(env, "GIT_CONFIG_VALUE_0=Authorization: Basic "+basic) || !strings.Contains(env, "GIT_CONFIG_NOSYSTEM=1") ||
			strings.Contains(env, "STACKURITY_") || strings.Contains(env, "HTTPS_PROXY") {
			t.Errorf("%s environment:\n%s", steps[len(steps)-1], env)
		}
	}
	want := []string{"clone", "sparse-checkout", "checkout", "remote-remove", "rev-parse"}
	if !slices.Equal(steps, want) {
		t.Errorf("git steps %v; want %v", steps, want)
	}
}

// A repository whose images alone are past the size limit is scanned on the
// real path (git smart HTTP over TLS, partial clone): the images are never
// downloaded, the lockfile is read, and every request git made, the blob
// fetches of the checkout included, went to the pinned address with the
// credential.
func TestSparseCloneSkipsImages(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	execPath, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skip("git --exec-path")
	}
	backend := filepath.Join(strings.TrimSpace(string(execPath)), "git-http-backend")
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git http-backend not available")
	}
	root, work := t.TempDir(), t.TempDir()
	git := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
			"GIT_CONFIG_NOSYSTEM=1", "HOME="+t.TempDir())
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	git(work, "init", "-q", "-b", "main")
	files := map[string]string{
		"package-lock.json": `{"name":"shop","lockfileVersion":3,"packages":{"":{"name":"shop"},"node_modules/lodash":{"version":"4.17.20"}}}`,
		"web/app.css":       "@import 'normalize.css';\n",
	}
	for name, body := range files {
		_ = os.MkdirAll(filepath.Dir(filepath.Join(work, name)), 0o755)
		if err := os.WriteFile(filepath.Join(work, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// 3 MiB of incompressible images against a 1 MiB limit.
	_ = os.MkdirAll(filepath.Join(work, "img"), 0o755)
	for _, name := range []string{"img/hero.png", "img/LOGO.PNG", "img/clip.mp4"} {
		b := make([]byte, 1<<20)
		_, _ = rand.Read(b)
		if err := os.WriteFile(filepath.Join(work, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git(work, "add", ".")
	git(work, "commit", "-qm", "init")
	bare := filepath.Join(root, "acme", "shop.git")
	git("", "clone", "-q", "--bare", work, bare)
	git(bare, "config", "uploadpack.allowFilter", "true")

	const token = "ghp_SparseTestToken0123456789"
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	var mu sync.Mutex
	var requests, unauth int
	h := &cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}, InheritEnv: []string{"PATH"}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		bad := r.Header.Get("Authorization") != wantAuth
		if bad {
			unauth++
		}
		mu.Unlock()
		if bad {
			http.Error(w, "unauthorised", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	// The server's certificate names example.com; the name resolves (once,
	// in the scanner) to the test server, and git is pinned to it. A git
	// step that resolved the name itself would fail.
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "default", Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	defer netguard.SetResolver(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})()
	port := srv.URL[strings.LastIndex(srv.URL, ":")+1:]
	url := "https://example.com:" + port + "/acme/shop.git"

	// A step that is not pinned would try the real example.com: the
	// timeout makes that a quick failure.
	s := &Scanner{WorkDir: t.TempDir(), Version: "test", CAFile: caFile, MaxBytes: 1 << 20, Timeout: 20 * time.Second}
	b, err := s.Scan(tenant.WithWorkspace(context.Background(), 2), Config{URL: url}, token)
	if errors.Is(err, limits.ErrTooLarge) {
		t.Fatalf("the images were downloaded: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range b.Observations {
		if o.Purl == "pkg:npm/lodash@4.17.20" {
			found = true
		}
	}
	if !found {
		t.Errorf("lockfile not read: %+v", b.Observations)
	}
	if b.Asset.Attributes["git_commit"] == "" {
		t.Error("commit not recorded")
	}
	mu.Lock()
	defer mu.Unlock()
	if requests < 2 || unauth != 0 {
		t.Errorf("requests %d, without the credential %d; want the clone and the blob fetch, all authorised", requests, unauth)
	}
}
