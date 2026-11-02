//go:build !windows

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Self-hosted Stackurity promises not to phone home: licence keys are
// verified offline, and every outbound request is something the operator can
// see and turn off. These tests start the real server (the same wiring as
// `stackurity server`) and record every connection it tries to open, through
// each way the code can open one:
//
//   - http:     http.DefaultTransport, which every http.Client without its own
//     Transport uses (feeds, update check, breach check, Slack app, the agent's
//     API client);
//   - netguard: netguard.DialContext, which the guarded clients (webhooks,
//     email, assistants, Slack) and the CONNECT proxy for Syft use;
//   - dns:      the resolver, which any connection to a host name needs,
//     including raw net.Dialer users such as the account-mail SMTP client;
//   - exec:     git, syft and other network tools run as processes, found on
//     a PATH that holds only recording stubs.
//
// Every attempt is refused unless it goes to loopback (the database and the
// server itself). The verdict comes from what was recorded, never from
// whether startup succeeded: code may log and swallow a failed request. The
// guard proves itself first: a deliberate attempt through each path must be
// recorded, otherwise the test fails rather than pass blind.
//
// Not covered: a raw net.Dialer dialling an IP literal (no name to resolve,
// no shared transport). Outside the database driver the code has none.

// defaultEgress is everything a server started with nothing but a database
// URL connects to on its own, on an empty install, in its first periodic
// ticks. Each is documented and can be turned off. Adding to this list is a
// product decision: say why in the PR and in docs/network.md.
var defaultEgress = []attempt{
	// Intelligence feeds every install has (internal/intel.EnsureFeeds);
	// STACKURITY_FEEDS=off, or a mirror via STACKURITY_KEV_URL,
	// STACKURITY_ENDOFLIFE_URL, STACKURITY_EPSS_URL. Ecosystem feeds (OSV,
	// registries) are added only once inventory of that ecosystem exists.
	{"http", "www.cisa.gov:443"},               // CISA KEV catalogue
	{"http", "endoflife.date:443"},             // lifecycle dates
	{"http", "epss.empiricalsecurity.com:443"}, // FIRST EPSS scores
	// The release check (internal/updates): an anonymous GET of the public
	// release list, up to 30 s after start, then every 12 hours;
	// STACKURITY_UPDATE_CHECK=off, or STACKURITY_UPDATE_URL for a mirror.
	{"http", "api.github.com:443"},
}

// Edition hooks, set by egress_*_test.go files built with that edition's
// tags. editionEnv is the least configuration the edition's server needs to
// start (the Community and licensed self-hosted editions need none), and
// editionEgress is what that edition adds to defaultEgress, with the same
// rules: each entry documented in docs/network.md with its off switch.
var (
	editionEnv    func(t *testing.T) map[string]string
	editionEgress []attempt
)

type attempt struct{ via, dest string }

var errEgress = errors.New("outbound connection refused by the egress test")

type egressGuard struct {
	active atomic.Bool
	mu     sync.Mutex
	seen   []attempt
	execs  string // file the exec stubs append to
}

var (
	guard     = &egressGuard{}
	guardOnce sync.Once
)

func (g *egressGuard) record(via, dest string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := attempt{via, dest}
	if !slices.Contains(g.seen, a) {
		g.seen = append(g.seen, a)
	}
}

// attempts returns what was recorded, the exec stubs' log included.
func (g *egressGuard) attempts() []attempt {
	if b, err := os.ReadFile(g.execs); err == nil {
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if l != "" {
				g.record("exec", l)
			}
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := slices.Clone(g.seen)
	slices.SortFunc(out, func(a, b attempt) int { return strings.Compare(a.via+" "+a.dest, b.via+" "+b.dest) })
	return out
}

func (g *egressGuard) reset() {
	g.mu.Lock()
	g.seen = nil
	g.mu.Unlock()
	_ = os.Remove(g.execs)
}

func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil && ip.Unmap().IsLoopback()
}

// installGuard hooks every path once per test binary; the hooks pass
// connections through unchanged while no test has the guard active.
func installGuard(t *testing.T) *egressGuard {
	t.Helper()
	if os.Getenv("STACKURITY_TEST_DATABASE_URL") == "" {
		t.Skip("STACKURITY_TEST_DATABASE_URL not set")
	}
	guardOnce.Do(func() {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		// Environment proxies would hide the destination behind the proxy's
		// address (and are read once per process).
		tr.Proxy = nil
		d := &net.Dialer{Timeout: 30 * time.Second}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if guard.active.Load() {
				if host, _, err := net.SplitHostPort(addr); err != nil || !loopback(host) {
					guard.record("http", addr)
					return nil, errEgress
				}
			}
			return d.DialContext(ctx, network, addr)
		}
		http.DefaultTransport = tr
		net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if guard.active.Load() {
				return &dnsTrap{}, nil
			}
			return d.DialContext(ctx, network, address)
		}}
		netguard.ObserveDials(func(_, address string) error {
			if !guard.active.Load() {
				return nil
			}
			if host, _, err := net.SplitHostPort(address); err == nil && loopback(host) {
				return nil
			}
			guard.record("netguard", address)
			return errEgress
		})
	})
	stubs := t.TempDir()
	guard.execs = filepath.Join(t.TempDir(), "exec.log")
	for _, name := range []string{"git", "syft", "curl", "wget", "ssh", "docker", "go", "npm", "trivy", "grype"} {
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"${0##*/} $*\" >> %q\nexit 1\n", guard.execs)
		if err := os.WriteFile(filepath.Join(stubs, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", stubs)
	guard.reset()
	guard.active.Store(true)
	t.Cleanup(func() { guard.active.Store(false); guard.reset() })
	proveGuard(t)
	return guard
}

// proveGuard makes one deliberate public attempt through each path and fails
// the test if the guard did not see and refuse it.
func proveGuard(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if resp, err := (&http.Client{}).Get("https://example.com/"); err == nil {
		resp.Body.Close()
		t.Fatal("egress guard let an HTTP request through http.DefaultTransport")
	}
	if c, err := netguard.DialContext(tenant.System(ctx), "tcp", "1.1.1.1:443"); err == nil {
		c.Close()
		t.Fatal("egress guard let netguard.DialContext connect")
	}
	if _, err := net.DefaultResolver.LookupHost(ctx, "example.com"); err == nil {
		t.Fatal("egress guard let a DNS lookup through")
	}
	_ = exec.CommandContext(ctx, "git", "ls-remote", "https://example.com/x.git").Run()
	got := guard.attempts()
	for _, want := range []attempt{
		{"http", "example.com:443"},
		{"netguard", "1.1.1.1:443"},
		{"dns", "example.com"},
		{"exec", "git ls-remote https://example.com/x.git"},
	} {
		if !slices.Contains(got, want) {
			t.Fatalf("the egress guard is blind to %s (recorded %v): fix the test before trusting it", want.via, got)
		}
	}
	guard.reset()
}

// dnsTrap is the resolver's connection to a name server: it records the name
// in the query and fails the exchange.
type dnsTrap struct{}

func (dnsTrap) Write(b []byte) (int, error) {
	// A stream query has a 2-byte length; the name follows the 12-byte header.
	for _, off := range []int{2, 0} {
		if name, ok := dnsName(b, off+12); ok {
			guard.record("dns", name)
			break
		}
	}
	return len(b), nil
}
func (dnsTrap) Read([]byte) (int, error)         { return 0, errEgress }
func (dnsTrap) Close() error                     { return nil }
func (dnsTrap) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (dnsTrap) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (dnsTrap) SetDeadline(time.Time) error      { return nil }
func (dnsTrap) SetReadDeadline(time.Time) error  { return nil }
func (dnsTrap) SetWriteDeadline(time.Time) error { return nil }

func dnsName(b []byte, i int) (string, bool) {
	var labels []string
	for i < len(b) {
		n := int(b[i])
		if n == 0 {
			return strings.Join(labels, "."), len(labels) > 0
		}
		if n > 63 || i+1+n > len(b) {
			return "", false
		}
		labels = append(labels, string(b[i+1:i+1+n]))
		i += 1 + n
	}
	return "", false
}

// egressServer is one `stackurity server` running in this process on a
// fresh database.
type egressServer struct {
	addr    string
	url     string
	started time.Time
	admin   *pgx.Conn
	errc    chan error
}

// startServer runs the server with only env (and the database) configured:
// every other STACKURITY_ variable is cleared.
func startServer(t *testing.T, env map[string]string) *egressServer {
	t.Helper()
	base := os.Getenv("STACKURITY_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("STACKURITY_TEST_DATABASE_URL not set")
	}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "STACKURITY_") {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
	ctx := context.Background()
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	name := "egress_" + hex.EncodeToString(b)
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	// A loopback address, so no lookup of "localhost" reaches the resolver.
	if u.Hostname() == "localhost" {
		u.Host = net.JoinHostPort("127.0.0.1", u.Port())
	}
	admin, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	u.Path = "/" + name
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	t.Setenv("STACKURITY_DATABASE_URL", u.String())
	t.Setenv("STACKURITY_LISTEN", addr)
	t.Setenv("STACKURITY_DATA_DIR", t.TempDir())
	// Periodic tasks every 200 ms and jobs polled as often, so the first
	// ticks fit in seconds.
	t.Setenv("STACKURITY_TEST_TIMINGS", "tick=200ms,poll=200ms")
	if editionEnv != nil {
		for k, v := range editionEnv(t) {
			t.Setenv(k, v)
		}
	}
	for k, v := range env {
		t.Setenv(k, v)
	}

	s := &egressServer{addr: addr, url: u.String(), errc: make(chan error, 1), started: time.Now()}
	sctx, stop := context.WithCancel(ctx)
	cmd := serverCmd()
	cmd.SetArgs([]string{})
	go func() { s.errc <- cmd.ExecuteContext(sctx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-s.errc:
			if err != nil {
				t.Errorf("server: %v", err)
			}
		case <-time.After(45 * time.Second):
			t.Error("server did not stop")
		}
	})
	if s.admin, err = pgx.Connect(ctx, u.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.admin.Close(context.Background()) })
	s.waitFor(t, 60*time.Second, "the server to answer /healthz", func() bool {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	return s
}

func (s *egressServer) waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		select {
		case err := <-s.errc:
			s.errc <- err // for the cleanup, which waits for the server to stop
			t.Fatalf("server stopped while waiting for %s: %v (recorded attempts: %v)", what, err, guard.attempts())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// settle waits until every periodic task has finished a run and every job
// that was due has been tried, then for a few more ticks.
func (s *egressServer) settle(t *testing.T) {
	t.Helper()
	s.waitFor(t, 90*time.Second, "every periodic task to run and every due job to be tried", func() bool {
		var tasks, unfinished, untried int
		if err := s.admin.QueryRow(context.Background(), `SELECT
			(SELECT count(*) FROM periodic_tasks),
			(SELECT count(*) FROM periodic_tasks WHERE last_finished_at IS NULL),
			(SELECT count(*) FROM jobs WHERE done_at IS NULL AND failed_at IS NULL AND attempts = 0 AND run_at <= now())`,
		).Scan(&tasks, &unfinished, &untried); err != nil {
			t.Fatal(err)
		}
		return tasks > 0 && unfinished == 0 && untried == 0
	})
	time.Sleep(time.Second)
}

// With the feeds and the release check off, the server, and an agent
// reporting to it, connect to nothing but the database and each other.
func TestNoEgressWithFeedsAndUpdateCheckOff(t *testing.T) {
	g := installGuard(t)
	s := startServer(t, map[string]string{"STACKURITY_FEEDS": "off", "STACKURITY_UPDATE_CHECK": "off"})
	s.settle(t)

	// The agent's default run, against this server: --once only so that it
	// exits, and a fake Alpine root so that it reads the same files on any OS.
	pool, err := db.Open(context.Background(), s.url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, token, err := store.New(pool).CreateToken(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace),
		"egress-test", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for path, body := range map[string]string{
		"etc/os-release":       "ID=alpine\nVERSION_ID=3.20.3\nPRETTY_NAME=\"Alpine Linux v3.20\"\n",
		"lib/apk/db/installed": "P:musl\nV:1.2.5-r0\nA:aarch64\no:musl\n\n",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("STACKURITY_TOKEN", token)
	agent := agentCmd()
	agent.SetArgs([]string{"--server", "http://" + s.addr, "--once", "--root", root})
	if err := agent.ExecuteContext(context.Background()); err != nil {
		t.Errorf("agent: %v", err)
	}
	s.settle(t)

	if got := g.attempts(); len(got) > 0 {
		t.Errorf("with STACKURITY_FEEDS=off and STACKURITY_UPDATE_CHECK=off nothing may leave this machine; recorded:\n%s", list(got))
	}
}

// With nothing configured but the database (and, on Stackurity Cloud, the
// configuration it refuses to start without), the server connects only to
// the destinations in defaultEgress and editionEgress.
func TestDefaultEgressIsAllowListed(t *testing.T) {
	g := installGuard(t)
	s := startServer(t, nil)
	s.settle(t)
	// The release check waits up to 30 s (jitter) before its request. The
	// window is fixed, not "until everything expected was seen", so that a
	// new destination tried late in it is caught too.
	time.Sleep(time.Until(s.started.Add(35 * time.Second)))
	got := g.attempts()
	allowed := slices.Concat(defaultEgress, editionEgress)
	var extra []attempt
	for _, a := range got {
		if !slices.Contains(allowed, a) {
			extra = append(extra, a)
		}
	}
	if len(extra) > 0 {
		t.Errorf("a default install connects somewhere new; if intended, add it to defaultEgress with the reason and its off switch, and document it in docs/network.md:\n%s", list(extra))
	}
	t.Logf("default egress:\n%s", list(got))
}

func list(as []attempt) string {
	var b strings.Builder
	for _, a := range as {
		fmt.Fprintf(&b, "  %-8s %s\n", a.via, a.dest)
	}
	return b.String()
}
