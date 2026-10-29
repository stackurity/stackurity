//go:build crash

package crashtest

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/db"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The server runs with these timings (STACKURITY_TEST_TIMINGS) so that what
// takes minutes in production takes seconds here: a crashed worker's job is
// claimed again after jobLock, a periodic task after taskLease, and a claimed
// notification is retried after deliveryLease.
const (
	jobLock       = 3 * time.Second
	taskLease     = 2 * time.Second
	deliveryLease = 2 * time.Second
)

var timings = fmt.Sprintf("job-lock=%s,task-lease=%s,tick=200ms,poll=200ms,delivery-lease=%s,alerts=1s",
	jobLock, taskLease, deliveryLease)

// binary is the server under test, built once by TestMain.
var binary string

func TestMain(m *testing.M) {
	if os.Getenv("STACKURITY_TEST_DATABASE_URL") == "" {
		fmt.Println("crashtest: STACKURITY_TEST_DATABASE_URL not set; skipping")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "stk-crash-")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "stackurity")
	if out, err := exec.Command("go", "build", "-o", binary, "github.com/stackurity/stackurity/cmd/stackurity").CombinedOutput(); err != nil {
		fmt.Printf("build server: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// env is one scenario: its own database, fake upstreams and server processes.
type env struct {
	t    *testing.T
	name string // database name
	url  string
	// db is a superuser connection for checks; it sees every workspace.
	db *pgxpool.Pool
	// st connects as the server does, for the store's own reads.
	st      *store.Store
	up      *upstream
	upURL   string
	hook    *receiver
	hookURL string
	dir     string
	servers []*server
	began   time.Time
}

// logf logs with the time since the scenario began.
func (e *env) logf(format string, args ...any) {
	e.t.Helper()
	e.t.Logf("[%5.1fs] "+format, append([]any{time.Since(e.began).Seconds()}, args...)...)
}

var (
	ws  = tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	sys = tenant.System(context.Background())
)

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	base := os.Getenv("STACKURITY_TEST_DATABASE_URL")
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	e := &env{t: t, name: "crash_" + hex.EncodeToString(b), dir: t.TempDir(), began: time.Now()}
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+e.name); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + e.name
	e.url = u.String()
	t.Cleanup(func() {
		if e.db != nil {
			e.db.Close()
		}
		if e.st != nil {
			e.st.Pool.Close()
		}
		_, _ = admin.Exec(context.Background(), "DROP DATABASE "+e.name+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})

	pool, err := db.Open(ctx, e.url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	pool.Reset()
	e.st = store.New(pool)
	e.st.JobLockTimeout = jobLock
	if e.db, err = pgxpool.New(ctx, e.url); err != nil {
		t.Fatal(err)
	}

	e.up = &upstream{files: map[string][]byte{}, hits: map[string]int{}, slow: map[string]time.Duration{}, hang: map[string]bool{}}
	us := httptest.NewServer(e.up)
	t.Cleanup(us.Close)
	e.upURL = us.URL
	e.hook = &receiver{held: make(chan string, 16), release: make(chan struct{})}
	hs := httptest.NewServer(e.hook)
	t.Cleanup(hs.Close)
	e.hookURL = hs.URL
	// Registered last so it runs first: the fake upstreams wait for open
	// requests when they close.
	t.Cleanup(func() {
		for _, s := range e.servers {
			s.kill()
		}
		if t.Failed() {
			e.dumpState()
			for _, s := range e.servers {
				t.Logf("--- %s (last lines)\n%s", filepath.Base(s.logPath), tail(s.logPath, 25))
			}
		}
	})
	return e
}

// server is one running server process.
type server struct {
	t       *testing.T
	cmd     *exec.Cmd
	addr    string
	metrics string
	logPath string
	exited  chan struct{}
}

// start runs a server and waits until it answers.
func (e *env) start(extra ...string) *server {
	e.t.Helper()
	s := &server{t: e.t, addr: freeAddr(e.t), metrics: freeAddr(e.t), exited: make(chan struct{}),
		logPath: filepath.Join(e.dir, fmt.Sprintf("server-%d.log", len(e.servers)+1))}
	logf, err := os.Create(s.logPath)
	if err != nil {
		e.t.Fatal(err)
	}
	s.cmd = exec.Command(binary, "server")
	// Nothing from the developer's own STACKURITY_ settings leaks in.
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "STACKURITY_") {
			s.cmd.Env = append(s.cmd.Env, kv)
		}
	}
	up := e.upURL
	s.cmd.Env = append(s.cmd.Env,
		"STACKURITY_DATABASE_URL="+e.url,
		"STACKURITY_LISTEN="+s.addr,
		"STACKURITY_METRICS_ADDR="+s.metrics,
		"STACKURITY_DATA_DIR="+e.dir,
		"STACKURITY_LOG_FORMAT=text",
		"STACKURITY_COOKIE_SECURE=false",
		"STACKURITY_ALLOW_HTTP_WEBHOOKS=true",
		"STACKURITY_SETUP_TOKEN=crash-test",
		"STACKURITY_TEST_TIMINGS="+timings,
		// The drills make no call outside the machine, so the release
		// check (a request to GitHub) is off.
		"STACKURITY_UPDATE_CHECK=off",
		"STACKURITY_OSV_URL="+up+"/osv",
		"STACKURITY_KEV_URL="+up+"/kev.json",
		"STACKURITY_ENDOFLIFE_URL="+up+"/eol.json",
		"STACKURITY_AMAZON_LINUX_URL="+up+"/al",
	)
	for _, k := range []string{"NPM_REGISTRY", "PACKAGIST_URL", "PYPI_URL", "GOPROXY_URL", "CRATES_INDEX_URL", "RUBYGEMS_URL", "NUGET_URL", "MAVEN_URL", "PUB_URL"} {
		s.cmd.Env = append(s.cmd.Env, "STACKURITY_"+k+"="+up+"/registry")
	}
	s.cmd.Env = append(s.cmd.Env, extra...)
	s.cmd.Stdout, s.cmd.Stderr = logf, logf
	if err := s.cmd.Start(); err != nil {
		e.t.Fatal(err)
	}
	go func() {
		_ = s.cmd.Wait()
		_ = logf.Close()
		close(s.exited)
	}()
	e.servers = append(e.servers, s)
	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case <-s.exited:
			e.t.Fatalf("server exited during start:\n%s", tail(s.logPath, 40))
		default:
		}
		if resp, err := http.Get("http://" + s.addr + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return s
			}
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("server did not start:\n%s", tail(s.logPath, 40))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// kill stops the process with SIGKILL: no shutdown code runs.
func (s *server) kill() {
	select {
	case <-s.exited:
		return
	default:
	}
	_ = s.cmd.Process.Signal(syscall.SIGKILL)
	<-s.exited
}

// owns reports whether a worker or lease id belongs to this process.
func (s *server) owns(id string) bool {
	return strings.Contains(id, fmt.Sprintf("-%d-", s.cmd.Process.Pid))
}

func (s *server) scrape() string {
	resp, err := http.Get("http://" + s.metrics + "/metrics")
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func tail(path string, n int) string {
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// waitFor polls cond until it holds or the timeout passes.
// firstEvaluation is how long a freshly started server may take for its
// first feed sync and evaluation: on a busy CI runner that is the slowest
// step (it took over a minute on GitHub's runners, 30-40 s locally).
const firstEvaluation = 2 * time.Minute

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// --- database checks (superuser: no workspace scoping). No row reads as
// the zero value.

func (e *env) int(sql string, args ...any) int64 {
	e.t.Helper()
	var n int64
	if err := e.db.QueryRow(context.Background(), sql, args...).Scan(&n); err != nil && err != pgx.ErrNoRows {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (e *env) str(sql string, args ...any) string {
	e.t.Helper()
	var s *string
	if err := e.db.QueryRow(context.Background(), sql, args...).Scan(&s); err != nil && err != pgx.ErrNoRows {
		e.t.Fatalf("%s: %v", sql, err)
	}
	if s == nil {
		return ""
	}
	return *s
}

func (e *env) when(sql string, args ...any) *time.Time {
	e.t.Helper()
	var at *time.Time
	if err := e.db.QueryRow(context.Background(), sql, args...).Scan(&at); err != nil && err != pgx.ErrNoRows {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return at
}

func (e *env) exec(sql string, args ...any) {
	e.t.Helper()
	if _, err := e.db.Exec(context.Background(), sql, args...); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

// job is a job row as the checks need it.
type job struct {
	ID        int64
	Attempts  int
	LockedBy  string
	LockedAt  *time.Time
	LastError string
	DoneAt    *time.Time
	FailedAt  *time.Time
}

func (e *env) job(where string, args ...any) *job {
	e.t.Helper()
	var j job
	var by *string
	err := e.db.QueryRow(context.Background(), `SELECT id, attempts, locked_by, locked_at, last_error, done_at, failed_at
		FROM jobs WHERE `+where+` ORDER BY id DESC LIMIT 1`, args...).Scan(&j.ID, &j.Attempts, &by, &j.LockedAt, &j.LastError, &j.DoneAt, &j.FailedAt)
	if err == pgx.ErrNoRows {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	if by != nil {
		j.LockedBy = *by
	}
	return &j
}

// evaluationsDone reports whether no evaluation is due or running (the daily
// one is scheduled ten minutes ahead and does not count).
func (e *env) evaluationsDone() bool {
	return e.int(`SELECT count(*) FROM jobs WHERE kind = 'evaluate' AND done_at IS NULL AND failed_at IS NULL
		AND (run_at <= now() + interval '1 minute' OR locked_at IS NOT NULL)`) == 0
}

// findings returns the asset's findings by key: id and status.
func (e *env) findings(assetID int64) map[string]string {
	e.t.Helper()
	rows, err := e.db.Query(context.Background(), `SELECT key, id || ':' || status FROM findings WHERE asset_id = $1`, assetID)
	if err != nil {
		e.t.Fatal(err)
	}
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			e.t.Fatal(err)
		}
		if _, dup := out[k]; dup {
			e.t.Errorf("finding %s appears twice on asset %d", k, assetID)
		}
		out[k] = v
	}
	return out
}

// noDuplicateFindings fails if any asset has two findings for the same
// component, version and issue.
func (e *env) noDuplicateFindings() {
	e.t.Helper()
	if n := e.int(`SELECT count(*) FROM (SELECT 1 FROM findings f JOIN inventory i ON i.id = f.inventory_id
		GROUP BY f.asset_id, f.component_id, i.version, f.kind, f.key HAVING count(*) > 1) d`); n > 0 {
		e.t.Errorf("%d duplicated findings", n)
	}
}

// --- inventory

func debPurl(name, version string) string {
	return fmt.Sprintf("pkg:deb/debian/%s@%s?distro=debian-12", name, version)
}

func hostBatch(host string, purls ...string) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: "crash-agent", Version: "1", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: host, Identifiers: []model.Identifier{{Scheme: "hostname", Value: host}}})
	b.Complete = true
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed, Scope: "runtime"})
	}
	return b
}

// ingest stores a batch directly, as setup before a server starts.
func (e *env) ingest(b *model.ObservationBatch) int64 {
	e.t.Helper()
	if err := b.Validate(); err != nil {
		e.t.Fatal(err)
	}
	r, err := e.st.Ingest(ws, b, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return r.AssetID
}

func (e *env) collectorToken() string {
	e.t.Helper()
	_, secret, err := e.st.CreateToken(ws, "crash-agent", auth.RoleCollector, nil, 0, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	return secret
}

// post submits a batch the way the agent does.
func post(ctx context.Context, addr, token string, b *model.ObservationBatch) (*store.IngestResult, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(b); err != nil {
		return nil, err
	}
	_ = gz.Close()
	req, _ := http.NewRequestWithContext(ctx, "POST", "http://"+addr+"/api/v1/ingest", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
	}
	var r store.IngestResult
	return &r, json.Unmarshal(body, &r)
}

// collectionStatus is what a CI gate reads for a submitted collection.
func collectionStatus(t *testing.T, addr, token string, id int64) string {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/v1/collections/%d/result", addr, id), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var r store.CollectionResult
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r.Status
}

// --- intelligence

// advisory is a Debian advisory for one package, fixed in fixed.
type advisory struct {
	id, cve, pkg, fixed string
	modified            time.Time
}

func (a advisory) json() []byte {
	b, _ := json.Marshal(map[string]any{
		"id": a.id, "modified": a.modified.UTC().Format(time.RFC3339), "upstream": []string{a.cve},
		"summary": a.pkg + " security update", "database_specific": map[string]string{"severity": "HIGH"},
		"affected": []any{map[string]any{
			"package": map[string]string{"ecosystem": "Debian:12", "name": a.pkg},
			"ranges":  []any{map[string]any{"type": "ECOSYSTEM", "events": []any{map[string]string{"introduced": "0"}, map[string]string{"fixed": a.fixed}}}},
		}},
	})
	return b
}

// fillers are advisories for packages no asset has: volume for an import.
func fillers(prefix string, n int, modified time.Time) []advisory {
	out := make([]advisory, n)
	for i := range out {
		out[i] = advisory{id: fmt.Sprintf("%s-%06d", prefix, i), cve: fmt.Sprintf("CVE-2099-%s%06d", prefix, i),
			pkg: fmt.Sprintf("filler-%s-%d", strings.ToLower(prefix), i), fixed: "1.0-1", modified: modified}
	}
	return out
}

// osvArchive is an all.zip holding the advisories.
func osvArchive(t *testing.T, advs []advisory) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, a := range advs {
		f, err := zw.Create(a.id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write(a.json())
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// modifiedCSV lists every advisory as changed at the given time, newest
// first as OSV publishes it.
func modifiedCSV(advs []advisory, at time.Time) []byte {
	var b strings.Builder
	for _, a := range advs {
		fmt.Fprintf(&b, "%s,%s\n", at.UTC().Format(time.RFC3339Nano), a.id)
	}
	return []byte(b.String())
}

// serveIntel publishes a Debian archive, a KEV catalogue listing kevCVE and a
// small endoflife.date document.
func (e *env) serveIntel(advs []advisory, kevCVE string) {
	e.up.set("/osv/Debian/all.zip", osvArchive(e.t, advs))
	e.up.set("/kev.json", []byte(`{"vulnerabilities":[{"cveID":"`+kevCVE+`","vendorProject":"x","product":"x","vulnerabilityName":"x",`+
		`"dateAdded":"2024-02-01","dueDate":"2024-02-22","knownRansomwareCampaignUse":"Unknown"}]}`))
	e.up.set("/eol.json", []byte(`{"result":[{"name":"debian","label":"Debian","links":{"html":"https://endoflife.date/debian"},"identifiers":[],`+
		`"releases":[{"name":"12","label":"12","releaseDate":"2023-06-10","isLts":false,"isEol":false,"eolFrom":"2028-06-10"}]}]}`))
}

// upstream fakes OSV, KEV and endoflife.date. A slow path is sent in 32 KiB
// chunks with a pause between them; a hanging path sends a little and then
// stalls until the client goes away.
type upstream struct {
	mu    sync.Mutex
	files map[string][]byte
	hits  map[string]int
	slow  map[string]time.Duration
	hang  map[string]bool
	// sent counts the bytes of slow responses written so far.
	sent atomic.Int64
	// down makes every request fail with 503, as an unreachable or
	// overloaded upstream does.
	down atomic.Bool
}

func (u *upstream) set(path string, body []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.files[path] = body
}

func (u *upstream) setSlow(path string, pause time.Duration) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if pause > 0 {
		u.slow[path] = pause
	} else {
		delete(u.slow, path)
	}
}

func (u *upstream) setHang(path string, on bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.hang[path] = on
}

func (u *upstream) hitCount(path string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hits[path]
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.EscapedPath()
	if u.down.Load() {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		return
	}
	u.mu.Lock()
	u.hits[p]++
	body, ok := u.files[p]
	pause, hang := u.slow[p], u.hang[p]
	u.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if hang {
		_, _ = w.Write(body[:min(len(body), 1024)])
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Minute):
		}
		return
	}
	if pause == 0 {
		_, _ = w.Write(body)
		return
	}
	u.sent.Store(0)
	for off := 0; off < len(body); off += 32 << 10 {
		end := min(off+32<<10, len(body))
		if _, err := w.Write(body[off:end]); err != nil {
			return
		}
		w.(http.Flusher).Flush()
		u.sent.Add(int64(end - off))
		select {
		case <-r.Context().Done():
			return
		case <-time.After(pause):
		}
	}
}

// --- webhook receiver

type receipt struct {
	id, event, title string
	at               time.Time
}

// receiver is a webhook endpoint that counts what it processed, by the
// X-Stackurity-Delivery id a real receiver deduplicates on. It can be told to
// stall the next request, before processing it ("before": the message is
// never taken in) or after ("after": taken in, but no response is sent), and
// reports the stalled delivery id on held. A stalled request ends when the
// client goes away or when release is closed; a released "after" request
// is answered 204.
type receiver struct {
	mu      sync.Mutex
	got     []receipt
	hold    string
	held    chan string
	release chan struct{}
	// fail answers every request 500 without processing it, as a failing
	// notification provider does.
	fail atomic.Bool
}

func (r *receiver) holdNext(mode string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hold = mode
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	if r.fail.Load() {
		http.Error(w, "provider unavailable", http.StatusInternalServerError)
		return
	}
	var m struct {
		Event, Title string
	}
	_ = json.Unmarshal(body, &m)
	rc := receipt{id: req.Header.Get("X-Stackurity-Delivery"), event: m.Event, title: m.Title, at: time.Now()}
	r.mu.Lock()
	mode := r.hold
	r.hold = ""
	r.mu.Unlock()
	stall := func() bool {
		r.held <- rc.id
		select {
		case <-req.Context().Done():
		case <-time.After(2 * time.Minute):
		case <-r.release:
			return true
		}
		return false
	}
	if mode == "before" {
		stall()
		return
	}
	r.mu.Lock()
	r.got = append(r.got, rc)
	r.mu.Unlock()
	if mode == "after" && !stall() {
		return
	}
	w.WriteHeader(204)
}

// counts returns how many times each delivery id was processed.
func (r *receiver) counts() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int{}
	for _, g := range r.got {
		out[g.id]++
	}
	return out
}

func (r *receiver) receipts(id string) []receipt {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []receipt
	for _, g := range r.got {
		if g.id == id {
			out = append(out, g)
		}
	}
	return out
}

// dumpState logs what a failed drill needs to tell a product defect from a
// race in the scenario: incidents, deliveries and periodic task outcomes.
func (e *env) dumpState() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, q := range []string{
		`SELECT id || ' ' || kind || ' ' || key || ' ' || status || ' notified=' || COALESCE(notified_at::text, '-') FROM incidents ORDER BY id`,
		`SELECT id || ' ' || event || ' ' || status || ' attempts=' || attempts FROM deliveries ORDER BY id`,
		`SELECT name || ' started=' || COALESCE(last_started_at::text, '-') || ' finished=' || COALESCE(last_finished_at::text, '-') ||
		   ' error=' || COALESCE(last_error, '') FROM periodic_tasks ORDER BY name`,
		`SELECT f.id || ' ' || f.key || ' ' || f.status || ' ' || COALESCE(f.resolution, '') FROM findings f ORDER BY f.id`,
	} {
		rows, err := e.db.Query(ctx, q)
		if err != nil {
			e.t.Logf("state: %v", err)
			continue
		}
		var lines []string
		for rows.Next() {
			var l string
			if rows.Scan(&l) == nil {
				lines = append(lines, l)
			}
		}
		rows.Close()
		e.t.Logf("state %.40s...:\n  %s", q[7:], strings.Join(lines, "\n  "))
	}
}
