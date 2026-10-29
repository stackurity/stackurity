package intel

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// endoflife.date data for Windows and .NET, with the real dates
// (api/v1/products/windows-server, windows and dotnet on 2026-10-28).
const windowsEOL = `{"result":[
 {"name":"windows-server","label":"Microsoft Windows Server","links":{"html":"https://endoflife.date/windows-server"},"identifiers":[],
  "releases":[
   {"name":"2025","label":"Windows Server 2025 (LTSC)","releaseDate":"2024-11-01","isLts":true,"eoasFrom":"2029-11-13","isEol":false,"eolFrom":"2034-11-14","latest":{"name":"10.0.26100"}},
   {"name":"2022","label":"Windows Server 2022 (LTSC)","releaseDate":"2021-08-18","isLts":true,"eoasFrom":"2026-10-13","isEol":false,"eolFrom":"2031-10-14","latest":{"name":"10.0.20348"}},
   {"name":"2019","label":"Windows Server 2019 (LTSC)","releaseDate":"2018-11-13","isLts":true,"eoasFrom":"2024-01-09","isEol":false,"eolFrom":"2029-01-09","latest":{"name":"10.0.17763"}},
   {"name":"1809-sac","label":"Windows Server 1809 SAC","releaseDate":"2018-11-13","isLts":false,"eoasFrom":"2020-11-10","isEol":true,"eolFrom":"2020-11-10","latest":{"name":"10.0.17763"}},
   {"name":"2016","label":"Windows Server 2016 (LTSC)","releaseDate":"2016-10-15","isLts":true,"eoasFrom":"2022-01-11","isEol":false,"eolFrom":"2027-01-12","eoesFrom":"2030-01-12","latest":{"name":"10.0.14393"}},
   {"name":"2012-r2","label":"Windows Server 2012 R2 (LTSC)","releaseDate":"2013-11-25","isLts":true,"eoasFrom":"2018-10-09","isEol":true,"eolFrom":"2023-10-10","eoesFrom":"2026-10-13","latest":{"name":"6.3.9600"}}]},
 {"name":"windows","label":"Microsoft Windows","links":{"html":"https://endoflife.date/windows"},"identifiers":[],
  "releases":[
   {"name":"11-23h2-e","label":"11 23H2 (E)","releaseDate":"2023-10-31","isEol":false,"eolFrom":"2026-11-10","latest":{"name":"10.0.22631"}},
   {"name":"11-23h2-w","label":"11 23H2 (W)","releaseDate":"2023-10-31","isEol":true,"eolFrom":"2025-11-11","latest":{"name":"10.0.22631"}},
   {"name":"10-22h2","label":"10 22H2","releaseDate":"2022-10-18","isEol":true,"eolFrom":"2025-10-14","eoesFrom":"2028-10-10","latest":{"name":"10.0.19045"}}]},
 {"name":"dotnet","label":".NET","links":{"html":"https://endoflife.date/dotnet"},
  "identifiers":[{"type":"purl","id":"pkg:nuget/Microsoft.NETCore.App"},{"type":"purl","id":"pkg:rpm/redhat/dotnet-sdk-8.0"}],
  "releases":[
   {"name":"8","label":"8 (LTS)","releaseDate":"2023-11-14","isLts":true,"isEol":false,"eolFrom":"2026-11-10"},
   {"name":"6","label":"6 (LTS)","releaseDate":"2021-11-08","isLts":true,"isEol":true,"eolFrom":"2024-11-12"}]},
 {"name":"rhel","label":"Red Hat Enterprise Linux","links":{"html":"https://endoflife.date/rhel"},"identifiers":[],
  "releases":[{"name":"9","label":"9","releaseDate":"2022-05-17","isEol":false,"eolFrom":"2032-05-31"}]},
 {"name":"ubuntu","label":"Ubuntu","links":{"html":"https://endoflife.date/ubuntu"},"identifiers":[],
  "releases":[{"name":"22.04","label":"22.04 'Jammy Jellyfish'","releaseDate":"2022-04-21","isLts":true,"isEol":false,"eolFrom":"2027-06-30"}]},
 {"name":"debian","label":"Debian","links":{"html":"https://endoflife.date/debian"},"identifiers":[],
  "releases":[{"name":"12","label":"12","releaseDate":"2023-06-10","isEol":false,"eolFrom":"2028-06-10"}]}]}`

// ingestWindows ingests a host as the Windows agent reports it: asset
// attributes os and os_name, and the operating system row.
func ingestWindows(t *testing.T, st *store.Store, id string, os model.Observation) int64 {
	t.Helper()
	b := model.NewBatch(model.Collector{ID: "t-windows", Method: "test"},
		model.AssetRef{Kind: model.AssetHost, Name: id, Identifiers: []model.Identifier{{Scheme: "test", Value: id}},
			Attributes: map[string]string{"os": "windows", "os_version": os.Version, "os_name": os.Evidence["product_name"]}})
	b.Observations, b.Complete = []model.Observation{os}, true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := st.Ingest(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

// winOS is the operating system row the Windows agent reports.
func winOS(version, productName, editionID, displayVersion string) model.Observation {
	o := confirmed("pkg:generic/windows@"+version, map[string]string{"kind": "operating-system",
		"product_name": productName, "edition_id": editionID, "display_version": displayVersion})
	o.Version = version
	return o
}

func TestWindowsLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	ws2016 := ingestWindows(t, st, "ws2016", winOS("10.0.14393.7428", "Windows Server 2016 Datacenter", "ServerDatacenter", ""))
	ws2012 := ingestWindows(t, st, "ws2012r2", winOS("10.0.9600.21620", "Windows Server 2012 R2 Standard", "", ""))
	ws2019 := ingestWindows(t, st, "ws2019", winOS("10.0.17763.6532", "Windows Server 2019 Standard", "ServerStandard", ""))
	sac := ingestWindows(t, st, "ws1809core", winOS("10.0.17763.1577", "Windows Server Datacenter", "ServerDatacenterACor", ""))
	ws2022 := ingestWindows(t, st, "ws2022", winOS("10.0.20348.2227", "Windows Server 2022 Datacenter", "ServerDatacenter", "21H2"))
	unknown := ingestWindows(t, st, "ws-insider", winOS("10.0.27000.1", "Windows Server Datacenter", "ServerDatacenter", ""))
	win10 := ingestWindows(t, st, "laptop", winOS("10.0.19045.5011", "Windows 10 Pro", "Professional", "22H2"))
	win11 := ingestWindows(t, st, "desktop", winOS("10.0.22631.4317", "Windows 10 Enterprise", "Enterprise", "23H2"))

	// .NET from distribution packages: one finding per installation, on
	// the dotnet-runtime package the SDK and ASP.NET Core runtime pull in.
	rhel := ingest(t, st, model.AssetHost, "rhel9", true, osRow("rhel", "9.4"),
		confirmed("pkg:rpm/rhel/dotnet-runtime-6.0@6.0.36-1.el9_5?distro=rhel-9.4", map[string]string{"evr": "6.0.36-1.el9_5"}),
		confirmed("pkg:rpm/rhel/dotnet-sdk-6.0@6.0.136-1.el9_5?distro=rhel-9.4", map[string]string{"evr": "6.0.136-1.el9_5"}),
		confirmed("pkg:rpm/rhel/aspnetcore-runtime-6.0@6.0.36-1.el9_5?distro=rhel-9.4", map[string]string{"evr": "6.0.36-1.el9_5"}))
	jammy := ingest(t, st, model.AssetHost, "jammy", true, osRow("ubuntu", "22.04"),
		confirmed("pkg:deb/ubuntu/dotnet-runtime-6.0@6.0.136-0ubuntu1~22.04.1?distro=ubuntu-22.04&upstream=dotnet6", nil),
		confirmed("pkg:deb/ubuntu/dotnet-sdk-6.0@6.0.136-0ubuntu1~22.04.1?distro=ubuntu-22.04&upstream=dotnet6", nil))
	// packages.microsoft.com on Debian (Debian ships no .NET).
	bookworm := ingest(t, st, model.AssetHost, "bookworm", true, osRow("debian", "12"),
		confirmed("pkg:deb/debian/dotnet-runtime-8.0@8.0.11-1?distro=debian-12", nil))

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/eol.json", windowsEOL)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	syncWindowsUpdates(t, ctx, st, sy, up)
	now := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	ev.Now = func() time.Time { return now }
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	eolKeys := func(asset int64) string {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Kind: "end_of_life"})
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, f := range fs {
			keys = append(keys, f.Key)
		}
		sort.Strings(keys)
		return strings.Join(keys, ",")
	}
	coverage := func(asset int64, name string) (string, string) {
		rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Name == name {
				return r.Coverage, r.CoverageReason
			}
		}
		t.Fatalf("asset %d has no %s row", asset, name)
		return "", ""
	}
	type want struct {
		name  string
		asset int64
		keys  string
	}
	check := func(cases []want) {
		t.Helper()
		for _, c := range cases {
			if got := eolKeys(c.asset); got != c.keys {
				t.Errorf("%s on %s: end-of-life findings %q, want %q", c.name, now.Format("2006-01-02"), got, c.keys)
			}
		}
	}

	// 2026-10-28: 2016 is supported until 2027-01-12. 2012 R2 ended on
	// 2023-10-10; paid Extended Security Updates (to 2026-10-13) do not
	// count, as Ubuntu Pro and RHEL ELS do not.
	check([]want{
		{"Windows Server 2016", ws2016, ""},
		{"Windows Server 2012 R2", ws2012, "windows-server:2012-r2"},
		{"Windows Server 2019", ws2019, ""},
		{"Windows Server 1809 (semi-annual channel, same build as 2019)", sac, "windows-server:1809-sac"},
		{"Windows Server 2022", ws2022, ""},
		{"unknown build", unknown, ""},
		{"Windows 10 22H2 Pro", win10, "windows:10-22h2"},
		{"Windows 11 23H2 Enterprise", win11, ""},
		{"RHEL 9 .NET 6: Red Hat follows Microsoft", rhel, "dotnet:6"},
		{"Ubuntu 22.04 .NET 6: Canonical supports its archive package", jammy, ""},
		{"Debian 12 with Microsoft's .NET 8", bookworm, ""},
	})
	if c, _ := coverage(ws2016, "windows"); c != store.CoverageEvaluated {
		t.Errorf("a mapped Windows Server release must be evaluated, got %s", c)
	}
	// An unknown build is a coverage gap, never supported.
	if c, reason := coverage(unknown, "windows"); c != store.CoverageNotEvaluated ||
		reason != "end of life and missing updates not evaluated: Windows Server build 27000 is not a known release" {
		t.Errorf("unknown build coverage = %s %q", c, reason)
	}
	gaps, _, err := st.ListEvaluationGaps(ctx, store.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var winGaps []string
	for _, g := range gaps {
		if g.PurlKey == "pkg:generic/windows" {
			winGaps = append(winGaps, g.Reason)
		}
	}
	// Besides the unknown build: 2012 R2 (paid updates) and the 1809
	// semi-annual channel release (no updates since it ended) have no
	// missing-update check; their end of life is known.
	joined := strings.Join(winGaps, "\n")
	if len(winGaps) != 3 || !strings.Contains(joined, "Windows Server 2012 R2: missing updates are not evaluated") ||
		!strings.Contains(joined, "1809-sac, semi-annual channel") || !strings.Contains(joined, "build 27000") {
		t.Errorf("Windows gaps = %q", winGaps)
	}

	// The finding on 2012 R2 names the release and how it was matched.
	fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: ws2012, Kind: "end_of_life"})
	if len(fs) != 1 || fs[0].Title != "Windows Server 2012 R2 is end-of-life since 2023-10-10" {
		t.Fatalf("2012 R2 finding = %+v", fs)
	}
	var evd map[string]any
	_ = json.Unmarshal(fs[0].Evidence, &evd)
	if evd["product"] != "windows-server" || evd["cycle"] != "2012-r2" || evd["eol_date"] != "2023-10-10" {
		t.Errorf("2012 R2 evidence = %v", evd)
	}
	if m, _ := evd["match"].(map[string]any); m["rule"] != "windows_build" || m["build"] != float64(9600) {
		t.Errorf("2012 R2 match = %v", evd["match"])
	}
	fs, _, _ = st.ListFindings(ctx, store.FindingFilter{AssetID: win10, Kind: "end_of_life"})
	if len(fs) != 1 || fs[0].Title != "Windows 10 22H2 is end-of-life since 2025-10-14" {
		t.Errorf("Windows 10 finding = %+v", fs)
	}
	fs, _, _ = st.ListFindings(ctx, store.FindingFilter{AssetID: rhel, Kind: "end_of_life"})
	if len(fs) != 1 || !strings.HasSuffix(fs[0].ComponentName, "dotnet-runtime-6.0") || !strings.Contains(string(fs[0].Evidence), `"status": "follows_upstream"`) {
		t.Errorf("RHEL .NET 6 finding = %+v", fs)
	}

	// 2027-02-01: Windows Server 2016 has ended, with its date from the
	// data; so have Windows 11 23H2 Enterprise and .NET 8.
	now = time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	check([]want{
		{"Windows Server 2016", ws2016, "windows-server:2016"},
		{"Windows Server 2019", ws2019, ""},
		{"Windows Server 2022", ws2022, ""},
		{"unknown build", unknown, ""},
		{"Windows 11 23H2 Enterprise", win11, "windows:11-23h2-e"},
		{"Debian 12 with Microsoft's .NET 8", bookworm, "dotnet:8"},
		{"Ubuntu 22.04 .NET 6", jammy, ""},
	})
	fs, _, _ = st.ListFindings(ctx, store.FindingFilter{AssetID: ws2016, Kind: "end_of_life"})
	if len(fs) != 1 {
		t.Fatalf("2016 findings = %+v", fs)
	}
	_ = json.Unmarshal(fs[0].Evidence, &evd)
	if f := fs[0]; f.Title != "Windows Server 2016 is end-of-life since 2027-01-12" || f.Verification != "confirmed" ||
		evd["eol_date"] != "2027-01-12" || evd["cycle"] != "2016" || evd["product"] != "windows-server" {
		t.Errorf("2016 finding = %+v %v", f, evd)
	}

	// The action plan's release upgrade names the newest LTSC release.
	if _, err := planner.Rebuild(ctx, st, now); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: ws2016, Kind: fixplan.ReleaseUpgrade})
	if err != nil || len(raw) != 1 {
		t.Fatalf("2016 groups = %d %v", len(raw), err)
	}
	var g fixplan.Group
	_ = json.Unmarshal(raw[0], &g)
	if g.Kind != fixplan.ReleaseUpgrade || g.Title != "Upgrade Windows Server 2016 to a supported release" ||
		g.Action != "Windows Server 2016 is end of life (since 2027-01-12); upgrade to 2025." {
		t.Errorf("2016 release upgrade = %+v", g)
	}
}

func TestVersionedPackages(t *testing.T) {
	for _, c := range []struct{ purlKey, product, cycle string }{
		{"pkg:deb/ubuntu/php8.1-common", "php", "8.1"},
		{"pkg:deb/debian/ruby3.1", "ruby", "3.1"},
		{"pkg:deb/ubuntu/dotnet-runtime-8.0", "dotnet", "8.0"},
		{"pkg:deb/debian/dotnet-runtime-6.0", "dotnet", "6.0"},
		{"pkg:rpm/rhel/dotnet-runtime-8.0", "dotnet", "8.0"},
		{"pkg:rpm/almalinux/dotnet-runtime-9.0", "dotnet", "9.0"},
		// One finding per installation: the SDK, ASP.NET Core runtime and
		// other parts of the same release are not matched.
		{"pkg:deb/ubuntu/dotnet-sdk-8.0", "", ""},
		{"pkg:rpm/rhel/aspnetcore-runtime-8.0", "", ""},
		{"pkg:deb/ubuntu/dotnet-runtime-deps-8.0", "", ""},
		{"pkg:rpm/rhel/php8.1-common", "", ""},
		{"pkg:apk/alpine/dotnet-runtime-8.0", "", ""},
	} {
		p, cy, ok := versionedDebProduct(c.purlKey)
		if p != c.product || cy != c.cycle || ok != (c.product != "") {
			t.Errorf("%s = %q %q %v, want %q %q", c.purlKey, p, cy, ok, c.product, c.cycle)
		}
	}
}

func TestFollowsUpstream(t *testing.T) {
	for _, c := range []struct {
		product, typ, version string
		want                  bool
	}{
		{"dotnet", "rpm", "8.0.11-1.el9_5", true},                // Red Hat
		{"dotnet", "deb", "8.0.11-1", true},                      // packages.microsoft.com
		{"dotnet", "deb", "6.0.136-0ubuntu1~22.04.1", false},     // Ubuntu's archive
		{"dotnet", "deb", "6.0.136-0ubuntu1~24.04.1~ppa1", true}, // Ubuntu .NET backports PPA
		{"nginx", "rpm", "1.20.1-16.el9", false},
	} {
		if got := followsUpstream(c.product, c.typ, c.version); got != c.want {
			t.Errorf("followsUpstream(%s %s %s) = %v", c.product, c.typ, c.version, got)
		}
	}
}
