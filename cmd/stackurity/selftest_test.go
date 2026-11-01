package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/diag"
	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
	"github.com/stackurity/stackurity/internal/worker"
)

// lodashAdvisory is GHSA-35jh-r3h4-6jhm as OSV publishes it (trimmed).
const lodashAdvisory = `{"id":"GHSA-35jh-r3h4-6jhm","modified":"2024-01-01T00:00:00Z","aliases":["CVE-2021-23337"],
 "summary":"Command Injection in lodash","database_specific":{"severity":"HIGH"},
 "affected":[{"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`

// selftestEnv is a running installation: the API on a real store, a worker
// that evaluates uploads (with work), and a webhook channel with a route
// for every event, whose receiver counts what it gets.
type selftestEnv struct {
	st    *store.Store
	srv   *httptest.Server
	token string
	hits  *int64
	d     *notify.Dispatcher
	mu    sync.Mutex
}

func newSelftestEnv(t *testing.T, work bool) *selftestEnv {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	holder := &license.Holder{}
	s := &api.Server{Store: st, Log: log, Version: "test", Licence: holder, Gate: &license.Gate{Licence: holder},
		Health: &health.Checker{Store: st, FeedsEnabled: true}}
	e := &selftestEnv{st: st, srv: httptest.NewServer(s.Handler()), hits: new(int64)}
	t.Cleanup(e.srv.Close)

	u, err := st.CreateUser(ctx, "admin@x.io", "", auth.RoleAdmin, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, e.token, err = st.CreateToken(ctx, "selftest", auth.RoleAdmin, &u.ID, u.ID, 0); err != nil {
		t.Fatal(err)
	}

	// The npm feed has synced and holds the advisory.
	var v osv.Vulnerability
	if err := json.Unmarshal([]byte(lodashAdvisory), &v); err != nil {
		t.Fatal(err)
	}
	sys := tenant.System(ctx)
	if err := st.EnsureFeed(sys, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertAdvisories(sys, "osv:npm", []*osv.Vulnerability{&v}); err != nil {
		t.Fatal(err)
	}
	if err := st.FeedAttempt(sys, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	if err := st.FeedResult(sys, "osv:npm", "", 1, nil); err != nil {
		t.Fatal(err)
	}

	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		*e.hits++
		e.mu.Unlock()
	}))
	t.Cleanup(hook.Close)
	cfg, _ := json.Marshal(notify.ChannelConfig{URL: hook.URL})
	ch, err := st.CreateChannel(ctx, notify.KindWebhook, "hook", cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveRoute(ctx, store.Route{Name: "everything", ChannelID: ch.ID, Enabled: true, MinPriority: "P4", NewMinPriority: "P4",
		Timezone: "UTC", MaxPerHour: 100, Events: []string{store.EventUrgent, store.EventNewIssues, store.EventRegressed, store.EventOverdue,
			store.EventConnected, store.EventProblems, store.EventDailySummary, store.EventWeeklySummary}}); err != nil {
		t.Fatal(err)
	}
	e.d = &notify.Dispatcher{Store: st, Sender: notify.NewSender(true), Log: log}

	if work {
		t.Setenv("STACKURITY_FEEDS", "off") // no feed tasks: the advisory above is the data
		w := worker.New(st, log)
		w.Poll = 50 * time.Millisecond
		registerIntel(w, st, t.TempDir(), log)
		wctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { w.Run(wctx); close(done) }()
		t.Cleanup(func() { stop(); <-done })
	}
	return e
}

// run runs the selftest while the dispatcher ticks as a server's would,
// then ticks and sends the hourly digest once more.
func (e *selftestEnv) run(t *testing.T, wait time.Duration) (*selftest, string) {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	cl, err := client.New(e.srv.URL, e.token, "test")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	s := &selftest{cl: cl, out: &out, await: gate{wait: wait, poll: 50 * time.Millisecond}}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			case <-time.After(20 * time.Millisecond):
			}
			// A tick that overlaps the asset's deletion can fail (its
			// action plan refers to the asset); a server retries it on the
			// next tick, as the one below does.
			_ = e.d.Tick(ctx)
		}
	}()
	s.run(context.Background())
	close(stop)
	<-done
	if err := e.d.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.d.Digest(ctx); err != nil {
		t.Fatal(err)
	}
	return s, out.String()
}

func (e *selftestEnv) quiet(t *testing.T) {
	t.Helper()
	var queued int
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT count(*) FROM deliveries`).Scan(&queued); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if queued != 0 || *e.hits != 0 {
		t.Errorf("the selftest notified: %d deliveries queued, %d received", queued, *e.hits)
	}
}

func stages(s *selftest) map[string]diag.Status {
	m := map[string]diag.Status{}
	for _, r := range s.results {
		m[r.Check] = r.Status
	}
	return m
}

// A selftest against a running installation passes every stage through
// the API, finds the advisory's finding, deletes its asset, and attempts
// no delivery on any channel. It also deletes what an interrupted run
// left, and nothing else.
func TestSelftest(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e := newSelftestEnv(t, true)

	// An interrupted run's asset, and a real asset whose name only looks
	// like one.
	ingest := func(name string, ids ...model.Identifier) int64 {
		b := model.NewBatch(model.Collector{ID: "t", Method: "selftest"}, model.AssetRef{Kind: model.AssetRepository, Name: name, Identifiers: ids})
		b.Observations = []model.Observation{{Purl: "pkg:generic/x@1", Confidence: model.ConfidenceConfirmed}}
		r, err := e.st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	ingest(selftestPrefix+"old", model.Identifier{Scheme: store.SelftestScheme, Value: "old"})
	decoy := ingest(selftestPrefix+"decoy", model.Identifier{Scheme: "git-url", Value: "https://example.com/decoy"})

	s, out := e.run(t, time.Minute)
	t.Log("\n" + out)
	got := stages(s)
	for _, stage := range []string{"server", "leftovers", "advisory", "ingest", "evaluate", "finding", "cleanup"} {
		if got[stage] != diag.Pass {
			t.Errorf("stage %s = %q", stage, got[stage])
		}
	}
	if s.failed() || !strings.Contains(out, "CVE-2021-23337") {
		t.Errorf("output:\n%s", out)
	}
	assets, _, err := e.st.ListAssets(ctx, store.AssetFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].ID != decoy {
		t.Errorf("assets left: %+v", assets)
	}
	e.quiet(t)
}

// When evaluation does not happen (no worker), the stage fails and the
// asset is still deleted. A token that is not an admin's stops before
// anything is created.
func TestSelftestFailsAndCleansUp(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	e := newSelftestEnv(t, false)
	s, out := e.run(t, 300*time.Millisecond)
	got := stages(s)
	if got["ingest"] != diag.Pass || got["evaluate"] != diag.Fail || got["cleanup"] != diag.Pass || !s.failed() {
		t.Errorf("stages %v\n%s", got, out)
	}
	if _, total, _ := e.st.ListAssets(ctx, store.AssetFilter{}); total != 0 {
		t.Errorf("%d assets left after a failed run", total)
	}
	e.quiet(t)

	u, err := e.st.CreateUser(ctx, "viewer@x.io", "", auth.RoleViewer, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, e.token, err = e.st.CreateToken(ctx, "viewer", auth.RoleViewer, &u.ID, u.ID, 0); err != nil {
		t.Fatal(err)
	}
	s, _ = e.run(t, time.Second)
	if got := stages(s); got["server"] != diag.Fail || len(got) != 1 {
		t.Errorf("viewer token: %v", got)
	}
}
