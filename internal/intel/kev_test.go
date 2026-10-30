package intel

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// kevServer serves one KEV catalogue with an ETag, answering 304 to a
// matching If-None-Match unless plain is set (a mirror that sends no
// validators). stuck answers 304 to every conditional request, as a cache
// that has stopped revalidating.
type kevServer struct {
	mu          sync.Mutex
	body        string
	plain       bool
	stuck       bool
	full, short int
}

func (k *kevServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if !k.plain {
		tag := fmt.Sprintf(`"%x"`, sha256.Sum256([]byte(k.body)))
		if r.Header.Get("If-None-Match") == tag || k.stuck && r.Header.Get("If-None-Match") != "" {
			k.short++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", tag)
	}
	k.full++
	_, _ = w.Write([]byte(k.body))
}

func (k *kevServer) set(body string, plain bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.body, k.plain = body, plain
}

const kevOther = `{"vulnerabilities":[{"cveID":"CVE-2020-0001","vendorProject":"x","product":"x","vulnerabilityName":"x","shortDescription":"x","dateAdded":"2024-01-01","dueDate":"2024-01-22","knownRansomwareCampaignUse":"Unknown"}]}`

// KEV is checked hourly. An unchanged catalogue is not downloaded again
// (conditional GET), or, from a server that ignores that, not parsed and
// stored again; a changed one is stored and re-evaluates findings, which
// then carry the known-exploited flag that urgent alerts read.
func TestKEVUnchangedIsNotRewritten(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	k := &kevServer{}
	srv := httptest.NewServer(k)
	t.Cleanup(srv.Close)
	sy.f.cfg.KEVURL = srv.URL + "/kev.json"
	var evaluated []int
	sy.Changed = func(ctx context.Context, feed string, res *SyncResult) error {
		ids, err := ComponentsToEvaluate(ctx, st, feed, res)
		if err != nil || ids == nil || feed != FeedKEV {
			return err
		}
		evaluated = append(evaluated, len(ids))
		_, err = ev.Evaluate(ctx, ids, 0)
		return err
	}

	app := ingest(t, st, model.AssetRepository, "shop", true, confirmed("pkg:npm/lodash@4.17.15", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/npm/all.zip", zipOf(t, map[string]string{"GHSA-p6mc.json": ghsaLodash}))
	if _, err := sy.Sync(ctx, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	exploited := func() bool {
		t.Helper()
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: app})
		if err != nil || len(fs) != 1 {
			t.Fatalf("findings: %v %+v", err, fs)
		}
		return fs[0].KnownExploited
	}
	marked := func() bool {
		t.Helper()
		var n int
		if err := st.Pool.QueryRow(tenant.System(ctx), `SELECT count(*) FROM known_exploited WHERE short_description = 'marker'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}
	resync := func(wantChanged int) {
		t.Helper()
		res, err := sy.Sync(ctx, FeedKEV)
		if err != nil {
			t.Fatal(err)
		}
		if res.Changed != wantChanged {
			t.Errorf("changed = %d, want %d", res.Changed, wantChanged)
		}
		if f, _ := st.GetFeed(ctx, FeedKEV); f.LastError != "" || f.Stale || f.Records != 1 {
			t.Errorf("feed after sync: %+v", f)
		}
	}

	k.set(kevOther, false)
	resync(1)
	if exploited() || len(evaluated) != 1 {
		t.Fatalf("after the first catalogue: exploited %v, evaluations %v", exploited(), evaluated)
	}
	// A rewrite of the table would drop this.
	if _, err := st.Pool.Exec(tenant.System(ctx), `UPDATE known_exploited SET short_description = 'marker'`); err != nil {
		t.Fatal(err)
	}

	// Unchanged: one 304, nothing parsed, stored or re-evaluated.
	resync(0)
	if k.full != 1 || k.short != 1 || !marked() || len(evaluated) != 1 {
		t.Errorf("unchanged: %d full and %d short responses, kept %v, evaluations %v", k.full, k.short, marked(), evaluated)
	}
	// A server that ignores conditional requests: same bytes, not stored.
	k.set(kevOther, true)
	resync(0)
	if k.full != 2 || !marked() || len(evaluated) != 1 {
		t.Errorf("same file again: %d full responses, kept %v, evaluations %v", k.full, marked(), evaluated)
	}

	// CISA adds lodash's CVE: stored, re-evaluated, and the finding is
	// known exploited.
	k.set(kev, false)
	resync(1)
	if marked() || len(evaluated) != 2 || !exploited() {
		t.Errorf("changed catalogue: kept old rows %v, evaluations %v, exploited %v", marked(), evaluated, exploited())
	}

	// Another URL (a mirror): no validators from the old one are sent, and
	// its file is stored once.
	other := &kevServer{body: kev}
	srv2 := httptest.NewServer(other)
	t.Cleanup(srv2.Close)
	sy.f.cfg.KEVURL = srv2.URL + "/kev.json"
	resync(1)
	if other.full != 1 || other.short != 0 {
		t.Errorf("new URL: %d full and %d short responses", other.full, other.short)
	}
}

// Installations whose KEV feed has the old daily settings move to hourly;
// settings changed by hand are kept.
func TestKEVRetuned(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, _, _, _ := setup(t)
	check := func(refresh, stale int64) {
		t.Helper()
		f, err := st.GetFeed(ctx, FeedKEV)
		if err != nil {
			t.Fatal(err)
		}
		if f.RefreshMin != refresh || f.StaleMin != stale {
			t.Errorf("refresh %dm, stale %dm; want %dm, %dm", f.RefreshMin, f.StaleMin, refresh, stale)
		}
	}
	if err := st.EnsureFeed(ctx, FeedKEV, "vulnerability", 24*time.Hour, 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	check(60, 12*60)
	if _, err := st.Pool.Exec(ctx, `UPDATE feeds SET refresh = '24 hours', stale_after = '5 days' WHERE name = $1`, FeedKEV); err != nil {
		t.Fatal(err)
	}
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	check(24*60, 5*24*60)
}

// A cache that answers 304 whatever changed upstream cannot hold KEV back
// for long: a copy read more than a day ago is downloaded in full.
func TestKEVFullReadDaily(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, _ := setup(t)
	k := &kevServer{body: kevOther}
	srv := httptest.NewServer(k)
	t.Cleanup(srv.Close)
	sy.f.cfg.KEVURL = srv.URL + "/kev.json"
	now := time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)
	sy.now = func() time.Time { return now }
	if err := st.EnsureFeed(ctx, FeedKEV, "vulnerability", time.Hour, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	stored := func() int {
		t.Helper()
		var n int
		if err := st.Pool.QueryRow(ctx, `SELECT count(*) FROM known_exploited WHERE cve = 'CVE-2021-23337'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	resync := func() {
		t.Helper()
		if _, err := sy.Sync(ctx, FeedKEV); err != nil {
			t.Fatal(err)
		}
	}
	resync()
	k.mu.Lock()
	k.body, k.stuck = kev, true // CISA changes the file; the cache keeps saying 304
	k.mu.Unlock()
	for _, h := range []time.Duration{1, 12, 24} {
		now = time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC).Add(h * time.Hour)
		resync()
	}
	if k.full != 1 || k.short != 3 || stored() != 0 {
		t.Fatalf("within a day: %d full and %d short responses, stored %d", k.full, k.short, stored())
	}
	now = now.Add(time.Hour + time.Minute)
	resync()
	if k.full != 2 || k.short != 3 || stored() != 1 {
		t.Errorf("after a day: %d full and %d short responses, stored %d", k.full, k.short, stored())
	}
	// The full read starts a new day of conditional requests.
	now = now.Add(time.Hour)
	resync()
	if k.full != 2 || k.short != 4 {
		t.Errorf("an hour later: %d full and %d short responses", k.full, k.short)
	}
}

// A corrupt or empty catalogue after a good one is refused: the stored
// entries and the cursor stay as they were, and the next good file is
// stored.
func TestKEVBadBodyKeepsCursor(t *testing.T) {
	ctx := tenant.System(context.Background())
	st, sy, _, _ := setup(t)
	k := &kevServer{body: kevOther}
	srv := httptest.NewServer(k)
	t.Cleanup(srv.Close)
	sy.f.cfg.KEVURL = srv.URL + "/kev.json"
	if err := st.EnsureFeed(ctx, FeedKEV, "vulnerability", time.Hour, 12*time.Hour); err != nil {
		t.Fatal(err)
	}
	cves := func() []string {
		t.Helper()
		var out []string
		if err := st.Pool.QueryRow(ctx, `SELECT COALESCE(array_agg(cve ORDER BY cve), '{}') FROM known_exploited`).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if _, err := sy.Sync(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	good, _ := st.GetFeed(ctx, FeedKEV)
	for _, bad := range []struct{ body, err string }{
		{`{"vulnerabilities":[{"cveID":`, "parse KEV"},
		{`{"vulnerabilities":[]}`, "empty"},
		{``, "parse KEV"},
	} {
		k.set(bad.body, false)
		if _, err := sy.Sync(ctx, FeedKEV); err == nil || !strings.Contains(err.Error(), bad.err) {
			t.Errorf("body %q: err = %v, want %q", bad.body, err, bad.err)
		}
		f, _ := st.GetFeed(ctx, FeedKEV)
		if f.Cursor != good.Cursor || !strings.Contains(f.LastError, bad.err) {
			t.Errorf("body %q: cursor %q (was %q), error %q", bad.body, f.Cursor, good.Cursor, f.LastError)
		}
		if got := cves(); len(got) != 1 || got[0] != "CVE-2020-0001" {
			t.Errorf("body %q: stored %v", bad.body, got)
		}
	}
	k.set(kev, false)
	res, err := sy.Sync(ctx, FeedKEV)
	if err != nil || res.Changed != 1 {
		t.Fatalf("good file after bad ones: %v %+v", err, res)
	}
	if f, _ := st.GetFeed(ctx, FeedKEV); f.Cursor == good.Cursor || f.LastError != "" {
		t.Errorf("after the good file: cursor %q, error %q", f.Cursor, f.LastError)
	}
	if got := cves(); len(got) != 1 || got[0] != "CVE-2021-23337" {
		t.Errorf("stored %v", got)
	}
}
