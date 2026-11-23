package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/testdb"
)

// The real USN-9182-1 (ubuntu.com, 20 Nov 2026), trimmed to its source
// packages: on 23 Nov it was in neither OSV nor Canonical's OSV export.
func usn9182(t *testing.T) ubuntuNotice {
	t.Helper()
	b, err := os.ReadFile("testdata/ubuntu-notices/USN-9182-1.json")
	if err != nil {
		t.Fatal(err)
	}
	var n ubuntuNotice
	if err := json.Unmarshal(b, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUbuntuNoticeRecord(t *testing.T) {
	v, published, ok, err := ubuntuNoticeRecord(usn9182(t))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if want := time.Date(2026, 11, 20, 3, 15, 31, 773953000, time.UTC); !published.Equal(want) {
		t.Errorf("published %v, want %v (ubuntu.com's times are UTC)", published, want)
	}
	if v.ID != "USN-9182-1" || strings.Join(v.Upstream, ",") != "UBUNTU-CVE-2026-123640,UBUNTU-CVE-2026-125283,UBUNTU-CVE-2026-118899" {
		t.Errorf("id/upstream: %s %v", v.ID, v.Upstream)
	}
	got := map[string]string{}
	for _, a := range v.Affected {
		got[a.Package.Ecosystem+"/"+a.Package.Name] = a.Ranges[0].Events[1].Fixed
	}
	want := map[string]string{
		"Ubuntu:26.10/nginx":     "1.30.4-7ubuntu1.3",
		"Ubuntu:26.04:LTS/nginx": "1.28.3-2ubuntu1.14",
		"Ubuntu:24.04:LTS/nginx": "1.24.0-2ubuntu7.21",
		"Ubuntu:22.04:LTS/nginx": "1.18.0-6ubuntu14.24",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("affected (free channels only; focal, bionic, xenial and trusty are ESM):\n got %v\nwant %v", got, want)
	}

	n := usn9182(t)
	n.Hidden = true
	if _, _, ok, _ := ubuntuNoticeRecord(n); ok {
		t.Error("a hidden notice is not stored")
	}
	n = usn9182(t)
	n.CVEs = nil
	if _, _, ok, _ := ubuntuNoticeRecord(n); ok {
		t.Error("a notice that fixes no CVE gives ubuntuUSNFixes nothing")
	}
	n = usn9182(t)
	n.ID = "LSN-0101-1"
	if _, _, ok, _ := ubuntuNoticeRecord(n); ok {
		t.Error("a Livepatch notice is not a USN")
	}
}

// fakeNotices serves notices newest first, paginated as ubuntu.com does.
type fakeNotices struct {
	mu       sync.Mutex
	notices  []map[string]any
	offsets  []int
	failWith int
}

func (f *fakeNotices) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWith != 0 {
		http.Error(w, "no", f.failWith)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if r.URL.Query().Get("order") != "newest" || limit <= 0 {
		http.Error(w, "bad query", 400)
		return
	}
	f.offsets = append(f.offsets, offset)
	end := min(offset+limit, len(f.notices))
	page := []map[string]any{}
	if offset < len(f.notices) {
		page = f.notices[offset:end]
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"notices": page, "offset": offset, "limit": limit, "total_results": len(f.notices)})
}

// notice is a minimal free-channel nginx notice for 22.04.
func notice(id string, published time.Time, cve, fixed string) map[string]any {
	return map[string]any{"id": id, "type": "USN", "title": "nginx vulnerabilities", "published": published.Format("2006-01-02T15:04:05.999999"),
		"cves_ids":         []string{cve},
		"releases":         []map[string]any{{"codename": "jammy", "version": "22.04", "support_tag": "LTS"}},
		"release_packages": map[string]any{"jammy": []map[string]any{{"name": "nginx", "version": fixed, "is_source": true}}}}
}

func TestSyncUbuntuNotices(t *testing.T) {
	st := store.New(testdb.New(t))
	ctx := context.Background()
	now := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	fake := &fakeNotices{}
	// 90 notices, one every 12 hours back from now: 60 within the 30-day
	// first window, the rest older.
	for i := 0; i < 90; i++ {
		fake.notices = append(fake.notices, notice(fmt.Sprintf("USN-%d-1", 9200-i), now.Add(-time.Duration(i)*12*time.Hour),
			fmt.Sprintf("CVE-2026-%d", 500000+i), "1.18.0-6ubuntu14."+strconv.Itoa(30+i)))
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	cfg := DefaultConfig()
	cfg.UbuntuNoticesURL = srv.URL + "/security/notices.json"
	sy := NewSyncer(st, slog.New(slog.DiscardHandler), cfg)
	sy.now = func() time.Time { return now }
	for _, f := range []string{FeedUbuntuNotices, "osv:Ubuntu"} {
		if err := st.EnsureFeed(ctx, f, "vulnerability", 3*time.Hour, 48*time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	res, err := sy.Sync(ctx, FeedUbuntuNotices)
	if err != nil {
		t.Fatal(err)
	}
	// 30 days at two a day: 61 notices (the one exactly 30 days back is
	// inside the window), the 62nd is past it.
	if res.Changed != 61 {
		t.Errorf("first sync stored %d notices, want 61 (30 days)", res.Changed)
	}
	if fmt.Sprint(fake.offsets) != "[0 20 40 60]" {
		t.Errorf("pages read %v: the first sync stops at the page that passes the window", fake.offsets)
	}
	if !res.Packages[store.PackageRef{BaseEcosystem: "Ubuntu", Name: "nginx"}] {
		t.Error("the fixes stored hand nginx to re-evaluation")
	}
	feed, err := st.GetFeed(ctx, FeedUbuntuNotices)
	if err != nil {
		t.Fatal(err)
	}
	var cur ubuntuNoticesCursor
	if err := json.Unmarshal([]byte(feed.Cursor), &cur); err != nil || !cur.Newest.Equal(now) {
		t.Errorf("cursor %q, want the newest notice %v", feed.Cursor, now)
	}

	// A new notice; the next sync reads back to the cursor less a day only.
	fake.mu.Lock()
	fake.offsets = nil
	fake.notices = append([]map[string]any{notice("USN-9300-1", now.Add(time.Hour), "CVE-2026-600000", "1.18.0-6ubuntu14.99")}, fake.notices...)
	fake.mu.Unlock()
	res, err = sy.Sync(ctx, FeedUbuntuNotices)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed != 1 || fmt.Sprint(fake.offsets) != "[0]" {
		t.Errorf("incremental sync: changed %d, pages %v; want 1 notice from one page", res.Changed, fake.offsets)
	}

	// OSV delivers USN-9200-1: its record is kept, never overwritten.
	osvCopy := &osv.Vulnerability{ID: "USN-9200-1", Modified: now, Summary: "from OSV", Upstream: []string{"UBUNTU-CVE-2026-500000"},
		Affected: []osv.Affected{{Package: osv.Package{Ecosystem: "Ubuntu:22.04:LTS", Name: "nginx"},
			Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.18.0-6ubuntu14.30"}}}}}}}
	if _, err := st.UpsertAdvisories(ctx, "osv:Ubuntu", []*osv.Vulnerability{osvCopy}); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	fake.notices[1]["title"] = "nginx vulnerabilities (revised)" // USN-9200-1, within the overlap
	fake.mu.Unlock()
	if _, err := sy.Sync(ctx, FeedUbuntuNotices); err != nil {
		t.Fatal(err)
	}
	feeds, err := st.AdvisoryFeeds(ctx, []string{"USN-9200-1", "USN-9300-1"})
	if err != nil {
		t.Fatal(err)
	}
	if feeds["USN-9200-1"] != "osv:Ubuntu" || feeds["USN-9300-1"] != FeedUbuntuNotices {
		t.Errorf("feeds %v: OSV's copy stays OSV's, the notice OSV lacks stays the notices feed's", feeds)
	}

	// A failed read fails the sync and keeps the cursor; nothing panics.
	// (404: not retried, so the test does not wait out the fetcher's
	// backoff for a 503; both end in the same error path.)
	fake.mu.Lock()
	fake.failWith = 404
	fake.mu.Unlock()
	before, _ := st.GetFeed(ctx, FeedUbuntuNotices)
	if _, err := sy.Sync(ctx, FeedUbuntuNotices); err == nil {
		t.Error("an outage is a failed sync (shown as the feed's last error)")
	}
	after, _ := st.GetFeed(ctx, FeedUbuntuNotices)
	if after.Cursor != before.Cursor || after.LastError == "" {
		t.Errorf("after an outage: cursor %q (was %q), last error %q", after.Cursor, before.Cursor, after.LastError)
	}
}

// A notice OSV has not delivered gives its fix to the stale UBUNTU-CVE
// record, but never opens a finding of its own.
func TestNoticesFeedRecordIsAFixSourceOnly(t *testing.T) {
	notices := func(id string) store.AdvisoryMatch {
		return store.AdvisoryMatch{ID: id, GroupKey: id, Ecosystem: "Ubuntu:22.04:LTS", Feed: FeedUbuntuNotices,
			Upstream: []string{"UBUNTU-CVE-2026-125283"},
			Affected: osv.Affected{Package: osv.Package{Ecosystem: "Ubuntu:22.04:LTS", Name: "nginx"},
				Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}, {Fixed: "1.18.0-6ubuntu14.24"}}}}}}
	}
	stale := store.AdvisoryMatch{ID: "UBUNTU-CVE-2026-125283", GroupKey: "CVE-2026-125283", Ecosystem: "Ubuntu:22.04:LTS", Feed: "osv:Ubuntu",
		SeverityLevel: "medium", Affected: osv.Affected{Package: osv.Package{Ecosystem: "Ubuntu:22.04:LTS", Name: "nginx"},
			Ranges: []osv.Range{{Type: "ECOSYSTEM", Events: []osv.Event{{Introduced: "0"}}}}}}

	got := usnFixMatch(t, "1.18.0-6ubuntu14.24", []store.AdvisoryMatch{stale, notices("USN-9182-1")})
	if len(got) != 0 {
		t.Errorf("14.24 has USN-9182-1's fix: want no findings, got %v", noticeKeys(got))
	}
	got = usnFixMatch(t, "1.18.0-6ubuntu14.23", []store.AdvisoryMatch{stale, notices("USN-9182-1")})
	f, ok := got["CVE-2026-125283"]
	if !ok || f.FixedVersion != "1.18.0-6ubuntu14.24" {
		t.Fatalf("14.23: want CVE-2026-125283 fixed in 14.24 from the notice: %+v", got)
	}
	m := f.Evidence["match"].(map[string]any)
	if m["fix_from"] != "USN-9182-1" || m["fix_from_source"] != "ubuntu.com" {
		t.Errorf("evidence must name the notice and that it came from ubuntu.com: %v", m)
	}
	if _, own := got["USN-9182-1"]; own {
		t.Error("a notices-feed record must not open a finding of its own")
	}
	// Without a stale CVE record, the notice alone opens nothing.
	if got := usnFixMatch(t, "1.18.0-6ubuntu14.23", []store.AdvisoryMatch{notices("USN-9182-1")}); len(got) != 0 {
		t.Errorf("the notice alone opened %v", noticeKeys(got))
	}
}

func noticeKeys(m map[string]store.FindingInput) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
