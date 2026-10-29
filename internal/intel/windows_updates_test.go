package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// msrcNow is when the fixtures are read: the 24-month window starts at
// November 2024, so 2024-Oct (in the index) is outside it.
var msrcNow = time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)

// serveMSRC serves the Security Update Guide fixtures at /msrc.
func serveMSRC(t *testing.T, up *upstream) {
	t.Helper()
	for _, name := range []string{"updates", "2024-Oct", "2025-Sep", "2025-Oct", "2026-Oct"} {
		b, err := os.ReadFile(filepath.Join("testdata", "msrc", name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		path := "/msrc/cvrf/" + name
		if name == "updates" {
			path = "/msrc/updates"
		}
		up.set(path, string(b))
	}
}

// syncWindowsUpdates serves the fixtures and syncs the msrc:Windows feed.
func syncWindowsUpdates(t *testing.T, ctx context.Context, st *store.Store, sy *Syncer, up *upstream) {
	t.Helper()
	serveMSRC(t, up)
	sy.now = func() time.Time { return msrcNow }
	if err := st.EnsureFeed(ctx, FeedMSRC, "vulnerability", 6*time.Hour, 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := sy.Sync(ctx, FeedMSRC); err != nil {
		t.Fatal(err)
	}
}

// openKeys returns an asset's open vulnerability findings by key.
func openKeys(t *testing.T, st *store.Store, ctx context.Context, asset int64) map[string]store.Finding {
	t.Helper()
	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Kind: "vulnerability", Page: store.Page{Limit: 500}})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.Finding{}
	for _, f := range fs {
		out[f.Key] = f
	}
	return out
}

func sortedFindingKeys(m map[string]store.Finding) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, " ")
}

func TestWindowsUpdates(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	// Server 2022 before September's update (.4171): older than every
	// monthly update read. Server 2022 on September's update. Server 2022
	// on October 2026's. Windows 11 24H2 (its ProductName says Windows 10),
	// Windows 10 22H2 (ended 2025-10-14) on September 2025's update.
	old2022 := ingestWindows(t, st, "ws2022-old", winOS("10.0.20348.4052", "Windows Server 2022 Datacenter", "ServerDatacenter", "21H2"))
	sep2022 := ingestWindows(t, st, "ws2022-sep", winOS("10.0.20348.4171", "Windows Server 2022 Standard", "ServerStandardCor", "21H2"))
	cur2022 := ingestWindows(t, st, "ws2022-cur", winOS("10.0.20348.5761", "Windows Server 2022 Datacenter", "ServerDatacenter", "21H2"))
	win11 := ingestWindows(t, st, "laptop-11", winOS("10.0.26100.6584", "Windows 10 Pro", "Professional", "24H2"))
	win10 := ingestWindows(t, st, "laptop-10", winOS("10.0.19045.6332", "Windows 10 Pro", "Professional", "22H2"))
	// Not evaluated: a Server 2025 host on a hotpatch build, Azure
	// Edition, Server 2012 R2, and a build without its revision.
	hot2025 := ingestWindows(t, st, "ws2025-hotpatch", winOS("10.0.26100.6508", "Windows Server 2025 Datacenter", "ServerDatacenter", "24H2"))
	azure := ingestWindows(t, st, "ws2022-azure", winOS("10.0.20348.4171", "Windows Server 2022 Datacenter: Azure Edition", "ServerTurbine", "21H2"))
	ws2012 := ingestWindows(t, st, "ws2012r2", winOS("10.0.9600.21620", "Windows Server 2012 R2 Standard", "ServerStandard", ""))
	noUBR := ingestWindows(t, st, "ws2022-noubr", winOS("10.0.20348", "Windows Server 2022 Datacenter", "ServerDatacenter", "21H2"))

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	if f, err := st.GetFeed(ctx, FeedMSRC); err != nil || f.Kind != "vulnerability" || f.RefreshMin != 360 {
		t.Fatalf("Windows hosts must create the %s feed: %+v %v", FeedMSRC, f, err)
	}
	up.set("/eol.json", windowsEOL)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	up.set("/kev.json", `{"vulnerabilities":[{"cveID":"CVE-2025-59287","vendorProject":"Microsoft","product":"Windows","dateAdded":"2025-10-24"},
		{"cveID":"CVE-2025-59230","vendorProject":"Microsoft","product":"Windows","dateAdded":"2025-10-14"}]}`)
	if _, err := sy.Sync(ctx, FeedKEV); err != nil {
		t.Fatal(err)
	}
	var reevaluate []int64
	sy.Changed = func(ctx context.Context, feed string, res *SyncResult) error {
		ids, err := ComponentsToEvaluate(ctx, st, feed, res)
		reevaluate = ids
		return err
	}
	syncWindowsUpdates(t, ctx, st, sy, up)
	if len(reevaluate) != 1 {
		t.Errorf("the first sync re-evaluates the Windows component, got %v", reevaluate)
	}
	for _, r := range up.requests {
		if strings.Contains(r, "2024-Oct") || strings.Contains(r, "1999-Sep") {
			t.Errorf("%s is outside the 24-month window but was read", r)
		}
	}
	f, _ := st.GetFeed(ctx, FeedMSRC)
	// 2 CVEs from 2025-Sep, 4 from 2025-Oct (not the .NET one), 1 from 2026-Oct.
	if f.Records != 7 || f.LastError != "" || !slices.Contains(f.Ecosystems, "Windows:Server 2022") || slices.Contains(f.Ecosystems, "Windows:Server 2012 R2") {
		t.Errorf("feed = %+v", f)
	}

	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	ev.Now = func() time.Time { return now }
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}

	// One finding per CVE fixed above the host's build.
	for _, c := range []struct {
		name  string
		asset int64
		keys  string
	}{
		{"Server 2022 before September", old2022, "CVE-2016-9535 CVE-2025-53803 CVE-2025-59220 CVE-2025-59230 CVE-2025-59287 CVE-2025-59289 CVE-2026-69950"},
		{"Server 2022 on September's update", sep2022, "CVE-2016-9535 CVE-2025-59230 CVE-2025-59287 CVE-2026-69950"},
		{"Server 2022 up to date", cur2022, ""},
		{"Windows 11 24H2 on September's update (WSUS is Server only)", win11, "CVE-2016-9535 CVE-2025-59230 CVE-2026-69950"},
		{"Windows 10 22H2 on September's update", win10, "CVE-2016-9535 CVE-2025-59230 CVE-2026-69950"},
		{"hotpatch build", hot2025, ""},
		{"Azure Edition", azure, ""},
		{"Server 2012 R2", ws2012, ""},
		{"no update revision", noUBR, ""},
	} {
		if got := sortedFindingKeys(openKeys(t, st, ctx, c.asset)); got != c.keys {
			t.Errorf("%s: findings %q, want %q", c.name, got, c.keys)
		}
	}

	// The finding names the update, its build and a link; KEV applies.
	sep := openKeys(t, st, ctx, sep2022)
	wsus := sep["CVE-2025-59287"]
	var e map[string]any
	_ = json.Unmarshal(wsus.Evidence, &e)
	if wsus.FixedVersion != "10.0.20348.4297" || wsus.Title != "Windows Server Update Service (WSUS) Remote Code Execution Vulnerability" ||
		wsus.Severity != "critical" || !wsus.KnownExploited || e["kb"] != "KB5070884" || e["kb_url"] != "https://support.microsoft.com/help/5070884" ||
		e["fixed_build"] != "10.0.20348.4297" || e["installed_build"] != "10.0.20348.4171" || e["update_line"] != "Windows Server 2022" ||
		e["update_released"] != "2025-10-14" || e["feed"] != FeedMSRC {
		t.Errorf("CVE-2025-59287 finding = %+v %v", wsus, e)
	}
	if m, _ := e["match"].(map[string]any); m["rule"] != "range" || m["record"] != "MSRC-2025-Oct-CVE-2025-59287" {
		t.Errorf("match = %v", e["match"])
	}
	// Disclosed in October, fixed by September's update: dated and named
	// by September's.
	old := openKeys(t, st, ctx, old2022)
	_ = json.Unmarshal(old["CVE-2025-59289"].Evidence, &e)
	if old["CVE-2025-59289"].FixedVersion != "10.0.20348.4171" || e["kb"] != "KB5065432" || e["update_released"] != "2025-09-09" ||
		e["older_than_data"] != "2025-09" {
		t.Errorf("CVE-2025-59289 = %+v %v", old["CVE-2025-59289"], e)
	}
	// Windows 10 22H2 ended on 2025-10-14: October 2025's update was its
	// last free one; October 2026's comes only with paid Extended Security
	// Updates.
	w10 := openKeys(t, st, ctx, win10)
	_ = json.Unmarshal(w10["CVE-2016-9535"].Evidence, &e)
	if _, paid := e["requires_subscription"]; paid || e["kb"] != "KB5066791" {
		t.Errorf("Windows 10 October 2025 fix = %v", e)
	}
	_ = json.Unmarshal(w10["CVE-2026-69950"].Evidence, &e)
	if e["requires_subscription"] != ESUChannel || e["fixed_build"] != "10.0.19045.7807" {
		t.Errorf("Windows 10 October 2026 fix = %v", e)
	}

	// Coverage: every Windows row is evaluated or says why not.
	cov := func(asset int64) (string, string) {
		rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
		if err != nil || len(rows) != 1 {
			t.Fatalf("inventory of %d: %v %v", asset, rows, err)
		}
		return rows[0].Coverage, rows[0].CoverageReason
	}
	for _, c := range []struct {
		name         string
		asset        int64
		state, words string
	}{
		{"up to date", cur2022, store.CoverageEvaluated, windowsCumulativeOnly},
		{"older than the data", old2022, store.CoverageEvaluated, "build 10.0.20348.4052 is older than the oldest update read (KB5065432, September 2025)"},
		{"hotpatch", hot2025, store.CoverageUnsupported, "build 10.0.26100.6508 is a hotpatch build (KB5065474)"},
		{"Azure Edition", azure, store.CoverageUnsupported, "Azure Edition"},
		{"2012 R2", ws2012, store.CoverageUnsupported, "Extended Security Updates"},
		{"no revision", noUBR, store.CoverageNotEvaluated, "no update revision"},
	} {
		if s, r := cov(c.asset); s != c.state || !strings.Contains(r, c.words) {
			t.Errorf("%s: coverage %s %q, want %s with %q", c.name, s, r, c.state, c.words)
		}
	}

	// The coverage-gap report counts the hosts that are not evaluated by why.
	rep, err := CoverageGaps(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, g := range rep.NoVulnerabilitySource {
		if g.Label == "Windows hosts" {
			got[g.Kind] = g.Assets
		}
	}
	if got["generic|windows_hotpatch"] != 2 || got["generic|windows_esu"] != 1 || len(got) != 2 {
		t.Errorf("Windows gaps in the report = %v", got)
	}

	// The action plan: one update per host, the newest among its findings,
	// which fixes all of them. Same KB and build on several hosts: one fix.
	if _, err := planner.Rebuild(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	group := func(asset int64, kind string) fixplan.Group {
		t.Helper()
		raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: asset, Kind: kind})
		if err != nil || len(raw) != 1 {
			t.Fatalf("asset %d %s groups = %d %v", asset, kind, len(raw), err)
		}
		var g fixplan.Group
		_ = json.Unmarshal(raw[0], &g)
		return g
	}
	g := group(old2022, fixplan.WindowsUpdate)
	if g.Title != "Install Windows update KB5126655" || g.ToVersion != "10.0.20348.5761" || g.FromVersion != "10.0.20348.4052" ||
		g.FindingCount != 7 || g.KnownExploited != 2 || g.FixKey != "windows_update:KB5126655>10.0.20348.5761" || g.Effort != "low" ||
		!strings.HasPrefix(g.Action, "Install KB5126655 (build 10.0.20348.5761, the October 2026 update) through Windows Update") ||
		!strings.Contains(g.Note, "first fixed in 4 updates: KB5065432, KB5066782, KB5070884, KB5126655") ||
		!strings.Contains(g.Note, "older than the oldest update Stackurity reads (September 2025)") {
		t.Errorf("old Server 2022 group = %+v", g)
	}
	if g2 := group(sep2022, fixplan.WindowsUpdate); g2.FixKey != g.FixKey || g2.FindingCount != 4 {
		t.Errorf("September Server 2022 group = %+v", g2)
	}
	// Windows 10 22H2: the free fixes are one update; the ESU-only one
	// goes to the release upgrade, with ESU named as the paid option.
	if g := group(win10, fixplan.WindowsUpdate); g.Title != "Install Windows update KB5066791" || g.FindingCount != 2 {
		t.Errorf("Windows 10 update = %+v", g)
	}
	if g := group(win10, fixplan.ReleaseUpgrade); g.FindingCount != 2 || g.Needs != ESUChannel ||
		!strings.Contains(g.Action, "fixed in "+ESUChannel+" (paid subscription)") {
		t.Errorf("Windows 10 release upgrade = %+v", g)
	}
}

// A sync reads only the documents that changed since the last one; a CVE a
// document no longer lists is withdrawn and its findings close.
func TestWindowsUpdatesIncremental(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	host := ingestWindows(t, st, "ws2022", winOS("10.0.20348.4171", "Windows Server 2022 Datacenter", "ServerDatacenter", "21H2"))
	syncWindowsUpdates(t, ctx, st, sy, up)
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if got := sortedFindingKeys(openKeys(t, st, ctx, host)); got != "CVE-2016-9535 CVE-2025-59230 CVE-2025-59287 CVE-2026-69950" {
		t.Fatalf("findings %q", got)
	}

	// Nothing changed: only the index is read.
	up.requests = nil
	res, err := sy.Sync(ctx, FeedMSRC)
	if err != nil || len(up.requests) != 1 || up.requests[0] != "/msrc/updates" || res.Changed != 0 || res.All {
		t.Errorf("unchanged sync read %v: %+v %v", up.requests, res, err)
	}

	// Microsoft revises 2025-Oct and drops CVE-2016-9535 from it.
	idx, _ := os.ReadFile(filepath.Join("testdata", "msrc", "updates.json"))
	up.set("/msrc/updates", strings.Replace(string(idx), `"CurrentReleaseDate":"2026-10-28T01:49:06Z"`, `"CurrentReleaseDate":"2026-10-29T08:00:00Z"`, 1))
	var doc map[string]any
	b, _ := os.ReadFile(filepath.Join("testdata", "msrc", "2025-Oct.json"))
	_ = json.Unmarshal(b, &doc)
	var kept []any
	for _, v := range doc["Vulnerability"].([]any) {
		if v.(map[string]any)["CVE"] != "CVE-2016-9535" {
			kept = append(kept, v)
		}
	}
	doc["Vulnerability"] = kept
	b, _ = json.Marshal(doc)
	up.set("/msrc/cvrf/2025-Oct", string(b))
	up.requests = nil
	res, err = sy.Sync(ctx, FeedMSRC)
	if err != nil || !slices.Equal(up.requests, []string{"/msrc/updates", "/msrc/cvrf/2025-Oct"}) || res.Changed != 1 || !res.All {
		t.Fatalf("revised sync read %v: %+v %v", up.requests, res, err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if got := sortedFindingKeys(openKeys(t, st, ctx, host)); got != "CVE-2025-59230 CVE-2025-59287 CVE-2026-69950" {
		t.Errorf("after the withdrawal: %q", got)
	}

	// Every 30 days every document in the window is read again.
	sy.now = func() time.Time { return msrcNow.Add(31 * 24 * time.Hour) }
	up.requests = nil
	if _, err := sy.Sync(ctx, FeedMSRC); err != nil {
		t.Fatal(err)
	}
	// November 2026: the window is December 2024 to November 2026.
	if !slices.Equal(up.requests, []string{"/msrc/updates", "/msrc/cvrf/2025-Sep", "/msrc/cvrf/2025-Oct", "/msrc/cvrf/2026-Oct"}) {
		t.Errorf("monthly full read %v", up.requests)
	}

	// One document that cannot be read does not hold up the others: the
	// sync succeeds with a warning, saves the cursor of what it read and
	// queues re-evaluation, and only that document is read again.
	sepDoc, _ := os.ReadFile(filepath.Join("testdata", "msrc", "2025-Sep.json"))
	up.set("/msrc/cvrf/2025-Sep", `{"DocumentTracking":`)
	sy.now = func() time.Time { return msrcNow.Add(62 * 24 * time.Hour) } // a full read is due
	before, _ := st.GetFeed(ctx, FeedMSRC)
	queued := 0
	sy.Changed = func(context.Context, string, *SyncResult) error { queued++; return nil }
	up.requests = nil
	res, err = sy.Sync(ctx, FeedMSRC)
	if err != nil || res.Full || !res.All || queued != 1 || len(up.requests) != 4 {
		t.Fatalf("partial sync: %+v %v, re-evaluations %d, requests %v", res, err, queued, up.requests)
	}
	f, _ := st.GetFeed(ctx, FeedMSRC)
	var cur msrcCursor
	_ = json.Unmarshal([]byte(f.Cursor), &cur)
	if !strings.HasPrefix(f.LastError, "warning: 1 Security Update Guide documents could not be read") || !strings.Contains(f.LastError, "2025-Sep") ||
		f.LastSuccess == nil || !f.LastSuccess.After(*before.LastSuccess) || cur.Docs["2025-Sep"] != "" || cur.Docs["2025-Oct"] == "" ||
		!cur.Full.Equal(msrcNow.Add(62*24*time.Hour)) {
		t.Errorf("after a partial sync: %+v, cursor %+v", f, cur)
	}
	// Its stored advisories stay, and so do the findings they give.
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	if got := sortedFindingKeys(openKeys(t, st, ctx, host)); got != "CVE-2025-59230 CVE-2025-59287 CVE-2026-69950" {
		t.Errorf("after the partial sync: %q", got)
	}
	up.requests = nil
	if _, err := sy.Sync(ctx, FeedMSRC); err != nil || !slices.Equal(up.requests, []string{"/msrc/updates", "/msrc/cvrf/2025-Sep"}) {
		t.Errorf("retry read %v (%v); want only the failed document", up.requests, err)
	}
	up.set("/msrc/cvrf/2025-Sep", string(sepDoc))
	up.requests = nil
	if _, err := sy.Sync(ctx, FeedMSRC); err != nil || !slices.Equal(up.requests, []string{"/msrc/updates", "/msrc/cvrf/2025-Sep"}) {
		t.Errorf("repaired read %v (%v)", up.requests, err)
	}
	if f, _ := st.GetFeed(ctx, FeedMSRC); f.LastError != "" {
		t.Errorf("a clean sync clears the warning: %q", f.LastError)
	}

	// Nothing readable at all: the sync fails and keeps its cursor.
	before, _ = st.GetFeed(ctx, FeedMSRC)
	for _, d := range []string{"2025-Sep", "2025-Oct", "2026-Oct"} {
		up.set("/msrc/cvrf/"+d, "Service Unavailable")
	}
	sy.now = func() time.Time { return msrcNow.Add(93 * 24 * time.Hour) }
	if _, err := sy.Sync(ctx, FeedMSRC); err == nil || !strings.Contains(err.Error(), "no Security Update Guide document could be read") {
		t.Errorf("err = %v", err)
	}
	if f, _ := st.GetFeed(ctx, FeedMSRC); f.Cursor != before.Cursor || !strings.Contains(f.LastError, "no Security Update Guide document") {
		t.Errorf("after the failure: %+v", f)
	}
}

// A document that suddenly lists far fewer CVEs than are stored for its
// month (truncated, or broken upstream) is refused: the month's advisories
// are not withdrawn and their findings stay open.
func TestWindowsUpdatesShrunkDocument(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	host := ingestWindows(t, st, "ws2022", winOS("10.0.20348.4171", "Windows Server 2022 Datacenter", "ServerDatacenter", "21H2"))
	syncWindowsUpdates(t, ctx, st, sy, up)
	idx, _ := os.ReadFile(filepath.Join("testdata", "msrc", "updates.json"))
	b, _ := os.ReadFile(filepath.Join("testdata", "msrc", "2025-Oct.json"))
	for i, keep := range []int{0, 1} { // 4 stored: none listed, then 1
		var doc map[string]any
		_ = json.Unmarshal(b, &doc)
		vs := doc["Vulnerability"].([]any)
		var kept []any
		for _, v := range vs {
			if c := v.(map[string]any)["CVE"]; len(kept) < keep && c != "CVE-2025-55247" {
				kept = append(kept, v)
			}
		}
		doc["Vulnerability"] = kept
		out, _ := json.Marshal(doc)
		up.set("/msrc/cvrf/2025-Oct", string(out))
		up.set("/msrc/updates", strings.Replace(string(idx), `"CurrentReleaseDate":"2026-10-28T01:49:06Z"`,
			fmt.Sprintf(`"CurrentReleaseDate":"2026-10-29T0%d:00:00Z"`, i+8), 1))
		if _, err := sy.Sync(ctx, FeedMSRC); err != nil {
			t.Fatal(err)
		}
		f, _ := st.GetFeed(ctx, FeedMSRC)
		if !strings.Contains(f.LastError, fmt.Sprintf("2025-Oct: lists %d Windows CVEs where 4 are stored; refusing", keep)) {
			t.Errorf("listing %d: last error %q", keep, f.LastError)
		}
		if ids, _ := st.AdvisoryIDs(ctx, FeedMSRC, "MSRC-2025-Oct-"); len(ids) != 4 {
			t.Errorf("listing %d: stored October advisories %v", keep, ids)
		}
		if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
			t.Fatal(err)
		}
		if got := sortedFindingKeys(openKeys(t, st, ctx, host)); got != "CVE-2016-9535 CVE-2025-59230 CVE-2025-59287 CVE-2026-69950" {
			t.Errorf("listing %d: findings %q", keep, got)
		}
	}
}

// An index with nothing in the window is an error, not an empty feed.
func TestWindowsUpdatesEmptyIndex(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, _, up := setup(t)
	serveMSRC(t, up)
	up.set("/msrc/updates", `{"value":[{"ID":"1999-Sep","CurrentReleaseDate":"2025-10-01T23:10:48Z"},{"ID":"../../etc","CurrentReleaseDate":"x"}]}`)
	sy.now = func() time.Time { return msrcNow }
	if err := st.EnsureFeed(ctx, FeedMSRC, "vulnerability", 6*time.Hour, 72*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := sy.Sync(ctx, FeedMSRC); err == nil || !strings.Contains(err.Error(), "lists no monthly document") {
		t.Errorf("err = %v", err)
	}
	if len(up.requests) != 1 {
		t.Errorf("requests %v: an id that is not a month is never fetched", up.requests)
	}
}
