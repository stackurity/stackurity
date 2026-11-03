package intel

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/darwin"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// endoflife.date data for macOS and Node.js, with the real dates
// (api/v1/products/macos and nodejs on 2026-11-01).
const macEOL = `{"result":[
 {"name":"macos","label":"Apple macOS","links":{"html":"https://endoflife.date/macos"},
  "identifiers":[{"type":"cpe","id":"cpe:2.3:o:apple:macos"}],
  "releases":[
   {"name":"27","label":"macOS 27 (Golden Gate)","releaseDate":"2026-09-14","isEol":false,"latest":{"name":"27.2"}},
   {"name":"15","label":"macOS 15 (Sequoia)","releaseDate":"2024-09-16","isEol":false,"latest":{"name":"15.8.2"}},
   {"name":"14","label":"macOS 14 (Sonoma)","releaseDate":"2023-09-26","isEol":true,"eolFrom":"2026-09-14","latest":{"name":"14.8.9"}},
   {"name":"10.15","label":"macOS 10.15 (Catalina)","releaseDate":"2019-10-07","isEol":true,"eolFrom":"2026-02-02","latest":{"name":"10.15.8"}}]},
 {"name":"nodejs","label":"Node.js","links":{"html":"https://endoflife.date/nodejs"},"identifiers":[],
  "releases":[
   {"name":"22","label":"22 (LTS)","releaseDate":"2024-04-24","isLts":true,"isEol":false,"eolFrom":"2027-04-30","latest":{"name":"22.23.4"}},
   {"name":"20","label":"20 (LTS)","releaseDate":"2023-04-18","isLts":true,"isEol":true,"eolFrom":"2026-04-30","latest":{"name":"20.20.2"}},
   {"name":"18","label":"18 (LTS)","releaseDate":"2022-04-19","isLts":true,"isEol":true,"eolFrom":"2025-04-30","latest":{"name":"18.20.8"}}]}]}`

// A Mac as the agent reports it (the collector run on its fixture tree):
// end of life for macOS and for Node.js however it was installed, and
// every row the matcher cannot assess says why.
func TestMacOSHost(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	root, err := filepath.Abs("../collect/darwin/testdata/mac")
	if err != nil {
		t.Fatal(err)
	}
	col := &darwin.Collector{Root: root, Version: "t", Runtimes: true,
		PlatformUUID: func(context.Context) string { return "00000000-0000-4000-8000-0000000000aa" }}
	col.Global = (&apps.Scanner{Root: root}).ScanGlobalDirs
	sys, err := col.Collect(ctx, "mac-build-01")
	if err != nil {
		t.Fatal(err)
	}
	sw := col.CollectSoftware(ctx, sys)
	var host int64
	for i, b := range []*model.ObservationBatch{sys, sw} {
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			host = r.AssetID
		} else if r.AssetID != host {
			t.Fatalf("both batches must land on one host: %d and %d", host, r.AssetID)
		}
	}
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/eol.json", macEOL)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	ev.Now = func() time.Time { return time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := ev.Evaluate(ctx, nil, host); err != nil {
		t.Fatal(err)
	}

	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: host})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, f := range fs {
		keys = append(keys, f.Kind+" "+f.Key+" "+f.ComponentName+"@"+f.Version)
	}
	sort.Strings(keys)
	// macOS 14 ended on 2026-09-14; Node.js 18 (nodejs.org installer and
	// nvm) and 20 (an old Homebrew keg) have ended; 22 has not.
	want := []string{
		"end_of_life macos:14 macos@14.7",
		"end_of_life nodejs:18 nodejs@18.19.1",
		"end_of_life nodejs:18 nodejs@18.20.4",
		"end_of_life nodejs:20 nodejs@20.18.0",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(keys, "\n"), strings.Join(want, "\n"))
	}

	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: host})
	if err != nil {
		t.Fatal(err)
	}
	reasons := map[string]string{}
	for _, r := range rows {
		reasons[r.Purl] = r.Coverage + ": " + r.CoverageReason
	}
	for purl, want := range map[string]string{
		"pkg:generic/macos@14.7":        "unsupported: macOS security updates are not evaluated",
		"pkg:generic/Firefox@131.0.3":   "unsupported: macOS application: inventory only",
		"pkg:brew/jq@1.7.1":             "unsupported: Homebrew packages have no vulnerability source",
		"pkg:brew/cask/firefox@131.0.3": "unsupported: Homebrew packages have no vulnerability source",
		"pkg:generic/nodejs@22.11.0":    "unsupported: runtime installed by Homebrew",
		"pkg:generic/nodejs@18.20.4":    "unsupported: runtime installed outside a package manager",
	} {
		if !strings.HasPrefix(reasons[purl], want) {
			t.Errorf("%s: coverage %q, want %q", purl, reasons[purl], want)
		}
	}
	// Global npm packages are matched like any npm package (the OSV feed
	// is not synced here, so it says so rather than looking clean).
	if r := reasons["pkg:npm/npm@10.9.0"]; !strings.HasPrefix(r, "not_evaluated") {
		t.Errorf("global npm package: %q", r)
	}
}
