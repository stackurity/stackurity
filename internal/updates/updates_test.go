package updates

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/worker"
)

func rel(tag string, opts ...func(*ghRelease)) ghRelease {
	r := ghRelease{TagName: tag, Name: "Stackurity " + tag, HTMLURL: "https://github.com/stackurity/stackurity/releases/tag/" + tag,
		PublishedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Body: "### Fixed\n\n- Something in " + tag + ".\n"}
	for _, o := range opts {
		o(&r)
	}
	return r
}

func draft(r *ghRelease)      { r.Draft = true }
func prerelease(r *ghRelease) { r.Prerelease = true }
func security(r *ghRelease) {
	r.Body = "### Security\n\n- Fixed a vulnerability.\n\n### Fixed\n\n- Other.\n"
}

// fake serves a release list and records every request it gets.
type fake struct {
	mu     sync.Mutex
	status int
	body   string
	reqs   []*http.Request
	srv    *httptest.Server
}

func newFake(t *testing.T, rels ...ghRelease) *fake {
	f := &fake{status: 200}
	f.set(rels...)
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.reqs = append(f.reqs, r.Clone(context.Background()))
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, f.body)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) set(rels ...ghRelease) {
	b, _ := json.Marshal(rels)
	f.mu.Lock()
	f.body = string(b)
	f.mu.Unlock()
}

func (f *fake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newChecker(t *testing.T, f *fake) (*Checker, *store.Store) {
	st := store.New(testdb.New(t))
	c := NewChecker(st, quiet(), Config{Enabled: true, URL: f.srv.URL + "/repos/stackurity/stackurity/releases?per_page=20"})
	c.Jitter = 0
	return c, st
}

func status(t *testing.T, st *store.Store, running string) *Report {
	t.Helper()
	r, err := Status(context.Background(), st, running, true)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestParseSkipsDraftsPrereleasesAndOddTags(t *testing.T) {
	b, _ := json.Marshal([]ghRelease{
		rel("v0.3.1"), rel("v0.5.0", draft), rel("v0.4.1-rc.1"), rel("v0.4.1", prerelease), rel("v0.4.0", security),
		rel("nightly"), rel("v0.10.0"), rel("0.2.0"), rel("v0.3.1"),
	})
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	var vs []string
	for _, r := range got {
		vs = append(vs, r.Version)
	}
	// Sorted by semver, not by string or by the order GitHub returned.
	if strings.Join(vs, ",") != "0.10.0,0.4.0,0.3.1,0.2.0" {
		t.Fatalf("versions: %v", vs)
	}
	if !got[1].Security || got[0].Security {
		t.Errorf("security flags: %+v", got)
	}
	if _, err := Parse([]byte(`{"message": "not a list"`)); err == nil {
		t.Error("malformed JSON accepted")
	}
}

func TestParseKeepsOnlyWebLinksAndCapsNotes(t *testing.T) {
	big := strings.Repeat("- a line of release notes é\n", 2000)
	b, _ := json.Marshal([]ghRelease{rel("v1.0.0", func(r *ghRelease) { r.HTMLURL = "javascript:alert(1)"; r.Body = big })})
	got, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].URL != "" {
		t.Errorf("unsafe URL kept: %q", got[0].URL)
	}
	if len(got[0].Notes) > maxNotes || !got[0].NotesTruncated || !strings.HasSuffix(got[0].Notes, "é") {
		t.Errorf("notes: %d bytes, truncated %v, ends %q", len(got[0].Notes), got[0].NotesTruncated, got[0].Notes[len(got[0].Notes)-5:])
	}
}

func TestIsSecurity(t *testing.T) {
	for notes, want := range map[string]bool{
		"### Security\n- x":         true,
		"## Security\n":             true,
		"### security  \r\n- x":     true,
		"### Fixed\n- Security fix": false,
		"### Security fixes\n":      false,
		"Security\n":                false,
	} {
		if IsSecurity(notes) != want {
			t.Errorf("IsSecurity(%q) = %v", notes, !want)
		}
	}
}

func TestRunning(t *testing.T) {
	for in, want := range map[string]string{
		"v0.3.1":             "0.3.1",
		"0.3.1":              "0.3.1",
		"v0.3.1-ee":          "0.3.1",
		"v0.3.1-dirty":       "0.3.1",
		"v0.3.1-4-gabc1234":  "0.3.1",
		"v0.3.1-4-gabc12-ee": "0.3.1",
		"v0.4.0-rc.1":        "0.4.0-rc.1",
		"dev":                "",
		"abc1234":            "",
		"":                   "",
		"test":               "",
		"v1":                 "",
	} {
		if got := Running(in); got != want {
			t.Errorf("Running(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckCompare(t *testing.T) {
	f := newFake(t, rel("v0.4.0", func(r *ghRelease) { r.Name = "" }), rel("v0.3.2", security), rel("v0.3.1"), rel("v0.3.0"),
		rel("v0.5.0", draft), rel("v0.5.0-rc.1", prerelease))
	c, st := newChecker(t, f)
	ctx := tenant.System(context.Background())

	// Before any check there is nothing to show.
	if r := status(t, st, "v0.3.1"); r.UpdateAvailable || r.CheckedAt != nil || r.Latest != "" || !r.Comparable {
		t.Fatalf("before a check: %+v", r)
	}
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		running           string
		newer             string
		comparable, avail bool
		security          bool
	}{
		{"v0.3.1", "0.4.0,0.3.2", true, true, true}, // newer, with a security release among them
		{"v0.3.2", "0.4.0", true, true, false},      // newer, the security release is already installed
		{"v0.4.0", "", true, false, false},          // same
		{"v0.9.0", "", true, false, false},          // older releases only (a build ahead of the list)
		{"v0.4.0-rc.1", "0.4.0", true, true, false}, // a release candidate sees its final release
		{"v0.3.1-ee", "0.4.0,0.3.2", true, true, true},
		{"dev", "", false, false, false}, // development builds never show an update
	}
	for _, tc := range cases {
		r := status(t, st, tc.running)
		var vs []string
		for _, x := range r.Releases {
			vs = append(vs, x.Version)
		}
		if strings.Join(vs, ",") != tc.newer || r.UpdateAvailable != tc.avail || r.Security != tc.security || r.Comparable != tc.comparable {
			t.Errorf("%s: newer %v avail %v security %v comparable %v", tc.running, vs, r.UpdateAvailable, r.Security, r.Comparable)
		}
		if r.Latest != "0.4.0" || r.CheckedAt == nil || r.LatestURL == "" || r.Current != tc.running {
			t.Errorf("%s: %+v", tc.running, r)
		}
	}

	// Turned off: says so and shows nothing, even with a stored result.
	off, err := Status(ctx, st, "v0.3.1", false)
	if err != nil || off.Enabled || off.UpdateAvailable || off.Latest != "" || len(off.Releases) != 0 {
		t.Errorf("off: %+v %v", off, err)
	}
}

// The request carries nothing about the installation: no version, no id,
// no credentials, no cookies, only a generic User-Agent.
func TestRequestSendsNothingIdentifying(t *testing.T) {
	f := newFake(t, rel("v0.4.0"))
	c, _ := newChecker(t, f)
	if err := c.Run(tenant.System(context.Background())); err != nil {
		t.Fatal(err)
	}
	if f.count() != 1 {
		t.Fatalf("requests: %d", f.count())
	}
	r := f.reqs[0]
	if r.Method != "GET" || r.URL.Path != "/repos/stackurity/stackurity/releases" || r.URL.RawQuery != "per_page=20" {
		t.Errorf("request: %s %s", r.Method, r.URL)
	}
	if r.ContentLength > 0 {
		t.Errorf("request has a body")
	}
	allowed := map[string]bool{"User-Agent": true, "Accept": true, "Accept-Encoding": true}
	for k := range r.Header {
		if !allowed[k] {
			t.Errorf("unexpected header %s: %v", k, r.Header[k])
		}
	}
	if ua := r.Header.Get("User-Agent"); ua != "stackurity" {
		t.Errorf("User-Agent %q", ua)
	}
	if a := r.Header.Get("Accept"); a != "application/vnd.github+json" {
		t.Errorf("Accept %q", a)
	}
}

// Failures never surface as task errors and keep the last good result.
func TestFailuresKeepLastResult(t *testing.T) {
	f := newFake(t, rel("v0.4.0"))
	c, st := newChecker(t, f)
	ctx := tenant.System(context.Background())
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	first := status(t, st, "v0.3.1")
	if !first.UpdateAvailable {
		t.Fatalf("first: %+v", first)
	}

	f.set(rel("v0.5.0"))
	for _, tc := range []struct {
		status int
		body   string
	}{
		{403, `{"message":"API rate limit exceeded"}`},
		{429, ``},
		{500, `oops`},
		{200, `[{"tag_name": "v0.5.0", "draft": fal`},
		{200, `{"message":"Not Found"}`},
	} {
		f.mu.Lock()
		f.status = tc.status
		if tc.body != "" {
			f.body = tc.body
		}
		f.mu.Unlock()
		if err := c.Run(ctx); err != nil {
			t.Errorf("HTTP %d %q: task error %v", tc.status, tc.body, err)
		}
		r := status(t, st, "v0.3.1")
		if r.Latest != "0.4.0" || !r.CheckedAt.Equal(*first.CheckedAt) {
			t.Errorf("HTTP %d %q: result changed: %+v", tc.status, tc.body, r)
		}
	}

	// Offline.
	c.URL = "http://127.0.0.1:1/releases"
	if err := c.Run(ctx); err != nil {
		t.Errorf("offline: %v", err)
	}
	if r := status(t, st, "v0.3.1"); r.Latest != "0.4.0" {
		t.Errorf("offline: %+v", r)
	}

	// Recovery replaces it.
	c.URL = f.srv.URL
	f.mu.Lock()
	f.status = 200
	f.mu.Unlock()
	f.set(rel("v0.5.0"), rel("v0.4.0"))
	if err := c.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if r := status(t, st, "v0.3.1"); r.Latest != "0.5.0" || len(r.Releases) != 2 {
		t.Errorf("after recovery: %+v", r)
	}
}

type sched struct{ names []string }

func (s *sched) Every(name string, _ time.Duration, _ func(context.Context) error) {
	s.names = append(s.names, name)
}

func TestOptOutMakesNoRequest(t *testing.T) {
	f := newFake(t, rel("v0.4.0"))
	t.Setenv("STACKURITY_UPDATE_CHECK", "off")
	t.Setenv("STACKURITY_UPDATE_URL", f.srv.URL)
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.Enabled || cfg.URL != f.srv.URL {
		t.Fatalf("config: %+v %v", cfg, err)
	}
	var s sched
	if Register(context.Background(), &s, nil, quiet(), cfg) || len(s.names) != 0 {
		t.Errorf("registered while off: %v", s.names)
	}
	if f.count() != 0 {
		t.Errorf("requests while off: %d", f.count())
	}

	t.Setenv("STACKURITY_UPDATE_CHECK", "")
	if cfg, err = ConfigFromEnv(); err != nil || !cfg.Enabled {
		t.Fatalf("default: %+v %v", cfg, err)
	}
	if !Register(context.Background(), &s, nil, quiet(), cfg) || fmt.Sprint(s.names) != "[update-check]" {
		t.Errorf("not registered: %v", s.names)
	}
	t.Setenv("STACKURITY_UPDATE_CHECK", "maybe")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("bad value accepted")
	}
	t.Setenv("STACKURITY_UPDATE_CHECK", "")
	t.Setenv("STACKURITY_UPDATE_URL", "file:///etc/passwd")
	if _, err := ConfigFromEnv(); err == nil {
		t.Error("non-HTTP URL accepted")
	}
}

// The stored result is platform state: a workspace cannot read it.
func TestStateIsPlatformOnly(t *testing.T) {
	f := newFake(t, rel("v0.4.0"))
	c, st := newChecker(t, f)
	if err := c.Run(tenant.System(context.Background())); err != nil {
		t.Fatal(err)
	}
	var n int
	ws := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	if err := st.Pool.QueryRow(ws, `SELECT count(*) FROM instance_state WHERE key = 'update_check'`).Scan(&n); err != nil || n != 0 {
		t.Errorf("workspace sees %d rows (%v)", n, err)
	}
}

// The worker runs periodic tasks one after another. The release check's
// random wait and its request run in the background, so the other tasks
// (the notification tick among them) keep their pace while it is due and
// in flight. Before, they stopped for the whole wait and request.
func TestCheckDoesNotHoldUpOtherTasks(t *testing.T) {
	f := newFake(t, rel("v0.4.0"))
	gate := make(chan struct{})
	inFlight := make(chan struct{}, 1)
	slow := f.srv.Config.Handler
	var requests atomic.Int64
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		select {
		case inFlight <- struct{}{}:
		default:
		}
		<-gate // the release service answers slowly
		slow.ServeHTTP(w, r)
	})
	c, st := newChecker(t, f)
	c.Jitter = 800 * time.Millisecond
	c.done = make(chan error, 2)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	c.Base = ctx

	w := worker.New(st, quiet())
	w.Tick, w.Lease = 20*time.Millisecond, 2*time.Second
	var ticks atomic.Int64
	w.Every("alerts", 50*time.Millisecond, func(context.Context) error { ticks.Add(1); return nil })
	w.Every("update-check", Every, c.Start)
	go w.Run(ctx)

	// Due: the random wait, then the request, which hangs.
	select {
	case <-inFlight:
	case <-time.After(5 * time.Second):
		t.Fatal("the check never sent its request")
	}
	before := ticks.Load()
	time.Sleep(time.Second)
	if n := ticks.Load() - before; n < 5 {
		t.Errorf("the notification tick ran %d times in a second while the check was in flight, want at least 5", n)
	}
	// A second start while one runs does nothing.
	if err := c.Start(tenant.System(ctx)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(c.Jitter + 200*time.Millisecond)
	if n := requests.Load(); n != 1 {
		t.Errorf("a second start while one runs: %d requests, want 1", n)
	}
	close(gate)
	select {
	case err := <-c.done:
		if err != nil {
			t.Fatalf("check: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the check did not finish")
	}
	if r := status(t, st, "v0.3.1"); r.Latest != "0.4.0" {
		t.Errorf("after the check: %+v", r)
	}
}

// Shutdown stops a check that is waiting or in flight.
func TestCheckStopsAtShutdown(t *testing.T) {
	f := newFake(t, rel("v0.4.0"))
	c, st := newChecker(t, f)
	c.Jitter = time.Hour
	c.done = make(chan error, 1)
	ctx, stop := context.WithCancel(context.Background())
	c.Base = ctx
	if err := c.Start(tenant.System(context.Background())); err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case err := <-c.done:
		if err == nil {
			t.Error("a cancelled check reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the check kept waiting after shutdown")
	}
	if f.count() != 0 {
		t.Errorf("%d requests after shutdown", f.count())
	}
	if r := status(t, st, "v0.3.1"); r.CheckedAt != nil {
		t.Errorf("stored after shutdown: %+v", r)
	}
}
