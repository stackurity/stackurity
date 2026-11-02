package diag

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func byCheck(r *Report) map[string]Result {
	m := map[string]Result{}
	for _, x := range r.Results {
		m[x.Check] = x
	}
	return m
}

func want(t *testing.T, got map[string]Result, check string, st Status, title string) {
	t.Helper()
	r, ok := got[check]
	switch {
	case !ok:
		t.Errorf("no %s result", check)
	case r.Status != st || !strings.Contains(r.Title, title):
		t.Errorf("%s = %s %q (%s), want %s with %q", check, r.Status, r.Title, r.Detail, st, title)
	case r.Status != Pass && r.Status != Skip && r.Next == "":
		t.Errorf("%s: %s without a next step", check, r.Status)
	}
}

// feed creates a feed that last synced ago (never when ago is 0).
func feed(t *testing.T, st *store.Store, name, kind string, refresh, stale, ago time.Duration) {
	t.Helper()
	ctx := tenant.System(context.Background())
	if err := st.EnsureFeed(ctx, name, kind, refresh, stale); err != nil {
		t.Fatal(err)
	}
	if ago == 0 {
		return
	}
	if err := st.FeedAttempt(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := st.FeedResult(ctx, name, "", 1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `UPDATE feeds SET last_success = now() - $2::interval, last_attempt = now() - $2::interval WHERE name = $1`,
		name, ago); err != nil {
		t.Fatal(err)
	}
}

// The checks read the real state: fresh, stale, behind and disabled feeds,
// a reachable mirror and an unreachable source, an agent's report, a
// failing background task, the disk and the memory limit.
func TestDoctor(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))

	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer mirror.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close() // a source nothing answers at

	feed(t, st, "osv:npm", "vulnerability", time.Hour, 6*time.Hour, 10*time.Minute)
	feed(t, st, "osv:PyPI", "vulnerability", time.Hour, 6*time.Hour, 50*time.Hour)
	feed(t, st, "releases:npm", "release", time.Hour, 72*time.Hour, 5*time.Hour)
	feed(t, st, "lifecycle:endoflife", "lifecycle", 24*time.Hour, 7*24*time.Hour, 0)
	feed(t, st, "kev:cisa", "vulnerability", time.Hour, 12*time.Hour, time.Hour)
	if err := st.SetFeedEnabled(tenant.System(ctx), "kev:cisa", false); err != nil {
		t.Fatal(err)
	}

	b := model.NewBatch(model.Collector{ID: "a", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-1",
		Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "m1"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.20", Confidence: model.ConfidenceConfirmed}}
	if _, err := st.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	sys := tenant.System(ctx)
	if err := st.RegisterPeriodic(sys, "prune", time.Hour); err != nil {
		t.Fatal(err)
	}
	if ok, err := st.ClaimPeriodic(sys, "prune", "w1", time.Hour, time.Minute); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if err := st.FinishPeriodic(sys, "prune", "w1", errors.New("disk full")); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Version: "test", Edition: "community", FeedsEnabled: true, Intel: intel.DefaultConfig(),
		Disks: []Disk{{Setting: "STACKURITY_DATA_DIR", Path: t.TempDir(), Explicit: true},
			{Setting: "--backup-dir", Path: "/nonexistent/stackurity-backups", Explicit: true}},
		Memory: func() MemoryInfo { return MemoryInfo{Limit: 2 << 30, LimitFrom: "container limit"} }}
	cfg.Intel.OSVBaseURL = mirror.URL + "/osv"
	cfg.Intel.NpmRegistry = gone.URL
	// An upgraded server inside its grace period (migration 0085).
	if _, err := st.Pool.Exec(tenant.System(context.Background()),
		`UPDATE license_requirement SET upgraded = true, required_from = now() + interval '30 days', observed_seconds = 0`); err != nil {
		t.Fatal(err)
	}
	rep := Doctor(context.Background(), st, nil, cfg)
	got := byCheck(rep)

	want(t, got, "database", Pass, "answers")
	want(t, got, "isolation", Pass, "Row-level security applies")
	want(t, got, "migrations", Pass, "migrations applied")
	want(t, got, "licence", Warn, "needs a free Community key or a licence by")
	want(t, got, "feed:osv:npm", Pass, "Last synced 10m ago")
	want(t, got, "feed:osv:PyPI", Fail, "is stale: last synced 2d ago")
	want(t, got, "feed:releases:npm", Warn, "Behind schedule")
	want(t, got, "feed:lifecycle:endoflife", Warn, "Has not synced yet")
	want(t, got, "feed:kev:cisa", Warn, "Turned off")
	mirrorHost := strings.TrimPrefix(mirror.URL, "http://")
	want(t, got, "reach:"+mirrorHost, Pass, "answers (HTTP 404), used by osv:PyPI, osv:npm")
	want(t, got, "reach:"+strings.TrimPrefix(gone.URL, "http://"), Warn, "Cannot reach")
	if _, ok := got["reach:www.cisa.gov"]; ok {
		t.Error("a disabled feed's source was checked")
	}
	want(t, got, "assets", Pass, "1 asset: agent 1 (latest report")
	want(t, got, "health:task:prune", Warn, "failed its last 1 run(s)")
	want(t, got, "memory", Warn, "GOMEMLIMIT is not set")
	if !strings.Contains(got["memory"].Next, "GOMEMLIMIT=1433MiB") {
		t.Errorf("memory next step: %q", got["memory"].Next)
	}
	var disks []Result
	for _, r := range rep.Results {
		if r.Check == "disk" {
			disks = append(disks, r)
		}
	}
	if len(disks) != 2 || disks[0].Status == Skip || disks[1].Status != Warn {
		t.Errorf("disks = %+v", disks)
	}
	if rep.Status != Fail || rep.Failed() != 1 {
		t.Errorf("report status %s with %d failed: %s", rep.Status, rep.Failed(), rep.Summary())
	}

	// Offline, nothing is requested.
	cfg.Offline = true
	got = byCheck(Doctor(context.Background(), st, nil, cfg))
	want(t, got, "reach", Skip, "--offline")
}

// Without a database the rest still runs, and the database fails.
func TestDoctorWithoutDatabase(t *testing.T) {
	rep := Doctor(context.Background(), nil, errors.New("connect to database: connection refused"),
		Config{Memory: func() MemoryInfo { return MemoryInfo{} }})
	got := byCheck(rep)
	want(t, got, "database", Fail, "Cannot connect")
	want(t, got, "checks", Skip, "skipped")
	want(t, got, "memory", Skip, "not detectable")
	if rep.Failed() != 1 {
		t.Errorf("%d failed", rep.Failed())
	}
}

// A database a newer version migrated fails, as every command refuses it;
// a new install without a key fails, a key that does not verify says so,
// and an upgraded server warns during its grace period and fails after it.
func TestDoctorSchemaAndLicence(t *testing.T) {
	ctx := tenant.System(context.Background())
	st := store.New(testdb.New(t))
	cfg := Config{Memory: func() MemoryInfo { return MemoryInfo{} }, Offline: true}

	want(t, byCheck(Doctor(ctx, st, nil, cfg)), "licence", Fail, "the dashboard and API wait")
	cfg.LicenceKey, cfg.LicenceFrom = "not-a-key", "STACKURITY_LICENSE"
	r := byCheck(Doctor(ctx, st, nil, cfg))["licence"]
	if r.Status != Fail || !strings.Contains(r.Title, "does not verify") || !strings.Contains(r.Detail, "the dashboard and API wait") {
		t.Errorf("licence = %s %q (%s)", r.Status, r.Title, r.Detail)
	}
	cfg.LicenceKey, cfg.LicenceFrom = "", ""

	if _, err := st.Pool.Exec(ctx, `UPDATE license_requirement SET upgraded = true, required_from = now() + interval '30 days', observed_seconds = 0`); err != nil {
		t.Fatal(err)
	}
	want(t, byCheck(Doctor(ctx, st, nil, cfg)), "licence", Warn, "needs a free Community key or a licence by")
	// The date has passed, but the server has not run 7 days of it yet.
	if _, err := st.Pool.Exec(ctx, `UPDATE license_requirement SET required_from = now() - interval '1 day'`); err != nil {
		t.Fatal(err)
	}
	want(t, byCheck(Doctor(ctx, st, nil, cfg)), "licence", Warn, "needs a free Community key or a licence by")
	if _, err := st.Pool.Exec(ctx, `UPDATE license_requirement SET observed_seconds = 8 * 86400`); err != nil {
		t.Fatal(err)
	}
	want(t, byCheck(Doctor(ctx, st, nil, cfg)), "licence", Fail, "the dashboard and API wait")

	if _, err := st.Pool.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ('9999_from_the_future')`); err != nil {
		t.Fatal(err)
	}
	want(t, byCheck(Doctor(ctx, st, nil, cfg)), "migrations", Fail, "upgraded by a newer Stackurity")
}

func TestMemory(t *testing.T) {
	const gib = 1 << 30
	for _, c := range []struct {
		m     MemoryInfo
		st    Status
		title string
	}{
		{MemoryInfo{}, Skip, "not detectable"},
		{MemoryInfo{Limit: 2 * gib, LimitFrom: "container limit"}, Warn, "GOMEMLIMIT is not set"},
		{MemoryInfo{Limit: 2 * gib, LimitFrom: "container limit", GoLimit: 2 * gib, GoLimitRaw: "2GiB"}, Fail, "at or above"},
		{MemoryInfo{Limit: 2 * gib, LimitFrom: "container limit", GoLimit: 1900 << 20, GoLimitRaw: "1900MiB"}, Warn, "92%"},
		{MemoryInfo{Limit: 2 * gib, LimitFrom: "container limit", GoLimit: 1400 << 20, GoLimitRaw: "1400MiB"}, Pass, "68% of the container limit (2GiB)"},
	} {
		r := checkMemory(c.m)
		if r.Status != c.st || !strings.Contains(r.Title, c.title) {
			t.Errorf("%+v: %s %q", c.m, r.Status, r.Title)
		}
	}
	files := map[string]string{cgroupV2: "max\n", cgroupV1: "9223372036854771712\n", meminfo: "MemTotal:        4030464 kB\nMemFree: 1 kB\n"}
	read := func(f string) ([]byte, error) {
		if v, ok := files[f]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("no file")
	}
	if n, from := memoryLimit(read); n != 4030464<<10 || !strings.HasPrefix(from, "host memory") {
		t.Errorf("no container limit: %d %s", n, from)
	}
	files[cgroupV2] = "1610612736\n"
	if n, from := memoryLimit(read); n != 1610612736 || !strings.HasPrefix(from, "container limit") {
		t.Errorf("cgroup v2: %d %s", n, from)
	}
}
