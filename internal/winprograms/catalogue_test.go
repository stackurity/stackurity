package winprograms

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestEmbeddedCatalogue(t *testing.T) {
	c := Default()
	if c.Version() == "" || len(c.Programs()) < 25 {
		t.Fatalf("catalogue %s has %d programs", c.Version(), len(c.Programs()))
	}
	matched := 0
	for _, p := range c.Programs() {
		if p.Source != nil {
			matched++
			if p.version == nil || p.Update == "" {
				t.Errorf("%s: a matched program needs a version rule and update advice", p.ID)
			}
		} else if p.Unmatched == "" {
			t.Errorf("%s: no source and no reason", p.ID)
		}
		if c.Program(p.ID) != p {
			t.Errorf("%s: not found by id", p.ID)
		}
	}
	if matched < 20 {
		t.Errorf("%d matched programs", matched)
	}
}

// TestRegistrySamples reads real Add/Remove Programs entries (DisplayName,
// Publisher, DisplayVersion) from published Windows inventories and registry
// exports, each with its source, and checks what the catalogue makes of
// them: the program and the version compared, a recognised program that is
// not matched, or nothing.
func TestRegistrySamples(t *testing.T) {
	b, err := os.ReadFile("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Name    string `json:"display_name"`
		Pub     string `json:"publisher"`
		Version string `json:"display_version"`
		Source  string `json:"source"`
		Expect  string `json:"expect"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.Source == "" {
			t.Errorf("%q has no source", r.Name)
		}
		id := Default().Identify(r.Name, r.Pub, r.Version)
		got := "not identified"
		if p := id.Program; p != nil {
			seen[p.ID] = true
			switch v, err := p.NormaliseVersion(r.Name, r.Version); {
			case p.Source == nil:
				got = p.ID + " (not matched)"
			case err != nil:
				got = p.ID + " (version not read)"
			default:
				got = p.ID + " " + v
			}
		}
		if got != r.Expect {
			t.Errorf("%q %q %q: got %q, want %q", r.Name, r.Pub, r.Version, got, r.Expect)
		}
	}
	// Every catalogued program has real samples, except those whose
	// registry entries were not found in published inventories.
	for _, p := range Default().Programs() {
		switch p.ID {
		case "mozilla-firefox-esr", "adobe-acrobat-classic", "vmware-tools", "teamviewer":
			continue // covered by TestVersionRules and TestFalsePositives
		}
		if !seen[p.ID] {
			t.Errorf("%s has no real registry sample", p.ID)
		}
	}
}

// TestVersionRules checks each matched program's version reading, with the
// registry's quirks.
func TestVersionRules(t *testing.T) {
	for _, c := range []struct{ id, name, version, want string }{
		{"google-chrome", "Google Chrome", "156.0.8078.74", "156.0.8078.74"},
		{"google-chrome", "Google Chrome", "156.0.8078", ""}, // not Chrome's four parts
		{"microsoft-edge", "Microsoft Edge", "151.0.4129.72", "151.0.4129.72"},
		{"mozilla-firefox", "Mozilla Firefox (x64 en-US)", "144.0", "144.0"},
		{"mozilla-firefox", "Mozilla Firefox (x64 en-US)", "153.0.3", "153.0.3"},
		{"mozilla-firefox", "Mozilla Firefox (x64 en-US)", "154.0b3", ""}, // a beta
		{"mozilla-firefox-esr", "Mozilla Firefox ESR (x64 en-US)", "128.3.1", "128.3.1"},
		{"mozilla-firefox-esr", "Mozilla Firefox 115.16.1 ESR (x64 en-US)", "115.16.1", "115.16.1"},
		{"mozilla-thunderbird", "Mozilla Thunderbird (x64 en-US)", "128.3.1", "128.3.1"},
		{"7-zip", "7-Zip 26.02 (x64 edition)", "26.02.00.0", "26.02"}, // the MSI's form
		{"7-zip", "7-Zip 24.09 (x64)", "24.09", "24.09"},
		{"winrar", "WinRAR 7.13 (64-bit)", "7.13.0", "7.13"},
		{"notepad-plus-plus", "Notepad++ (64-bit x64)", "8.6.2", "8.6.2"},
		{"putty", "PuTTY release 0.83 (64-bit)", "0.83.0.0", "0.83"},
		{"winscp", "WinSCP 6.5.5", "6.5.5", "6.5.5"},
		{"git-for-windows", "Git", "2.53.0.2", "2.53.0.2"},               // v2.53.0.windows.2
		{"python", "Python 3.12.10 (64-bit)", "3.12.10150.0", "3.12.10"}, // the version encodes the release level
		{"nodejs", "Node.js", "24.16.0", "24.16.0"},
		{"openssl-shining-light", "OpenSSL 3.5.0 (64-bit)", "3.5.0", "3.5.0"},
		{"openssl-shining-light", "OpenSSL 1.1.1w (64-bit)", "1.1.1w", ""}, // not identified: letter suffix
		{"zoom-workplace", "Zoom Workplace", "7.0.6 (43848)", "7.0.6"},
		{"zoom-workplace", "Zoom Workplace (64-bit)", "7.0.33767", ""}, // the MSI: major.minor.build
		{"adobe-acrobat", "Adobe Acrobat (64-bit)", "26.001.21346", "26.001.21346"},
		{"adobe-acrobat-classic", "Adobe Acrobat 2020", "20.005.30574", "20.005.30574"},
		{"dotnet-runtime", "Microsoft .NET Runtime - 8.0.27 (x64)", "64.108.52182", "8.0.27"}, // the MSI's version
		{"dotnet-runtime", "Microsoft .NET Core Runtime - 3.1.14 (x64)", "24.120.29915", "3.1.14"},
		{"aspnetcore-runtime", "Microsoft ASP.NET Core 8.0.14 - Shared Framework (x86)", "8.0.14.25112", "8.0.14"},
		{"aspnetcore-runtime", "Microsoft ASP.NET Core Runtime - 10.0.10 (x64)", "80.40.55332", "10.0.10"},
		{"wireshark", "Wireshark 4.6.7 x64", "4.6.7", "4.6.7"},
		{"libreoffice", "LibreOffice 25.8.3.2", "25.8.3.2", "25.8.3"},
		{"foxit-pdf-reader", "Foxit PDF Reader", "2025.2.0.33046", "2025.2.0.33046"},
	} {
		p := Default().Program(c.id)
		if p == nil {
			t.Fatalf("no program %s", c.id)
		}
		got, err := p.NormaliseVersion(c.name, c.version)
		if (err != nil) != (c.want == "") || got != c.want {
			if c.id == "openssl-shining-light" && c.want == "" {
				// The name pattern itself refuses letter suffixes.
				if id := Default().Identify(c.name, "OpenSSL Win64 Installer Team", c.version); id.Program == nil {
					continue
				}
			}
			t.Errorf("%s %q %q = %q, %v; want %q", c.id, c.name, c.version, got, err, c.want)
		}
	}
}

// TestFalsePositives checks registry entries that look like a catalogued
// program but are not it, or are a different edition or track of it.
func TestFalsePositives(t *testing.T) {
	for _, c := range []struct{ name, pub, version, want string }{
		{"Google Chrome Helper", "Google LLC", "156.0.8078.74", ""}, // not an Add/Remove Programs entry Chrome has; a guard
		{"Google Chrome Beta", "Google LLC", "147.0.7727.24", ""},
		{"Chrome Remote Desktop Host", "Google LLC", "146.0.7680.5", ""},
		{"Google Chrome", "Evil Corp", "156.0.8078.74", ""}, // another publisher
		{"Google Chrome", "", "156.0.8078.74", "google-chrome"},
		{"Java Auto Updater", "Oracle Corporation", "2.8.491.10", ""},
		{"Java 8 Update 491 (64-bit)", "Oracle Corporation", "8.0.4910.10", "oracle-java"},
		{"Microsoft Edge Update", "", "1.3.193.5", ""},
		{"Microsoft Edge WebView2 Runtime", "Microsoft Corporation", "151.0.4129.72", "microsoft-edge-webview2"},
		{"Mozilla Firefox ESR (x64 en-US)", "Mozilla", "128.3.1", "mozilla-firefox-esr"},
		{"Mozilla Firefox (x64 en-US)", "Mozilla", "128.3.1", "mozilla-firefox"},
		{"Mozilla Maintenance Service", "Mozilla", "128.0", ""},
		{"Python 3.12.3 Core Interpreter (64-bit)", "Python Software Foundation", "3.12.3150.0", ""},
		{"Python Launcher", "Python Software Foundation", "3.12.3150.0", ""},
		{"Anaconda3 2024.10-1 (Python 3.12.7 64-bit)", "Anaconda, Inc.", "2024.10-1", ""},
		{"Microsoft .NET Host - 8.0.7 (x64)", "Microsoft Corporation", "64.28.16731", ""},
		{"Microsoft .NET SDK 8.0.303 (x64) from Visual Studio", "Microsoft Corporation", "8.3.324.31708", ""},
		{"Microsoft ASP.NET Core 8.0.27 Targeting Pack (x64)", "Microsoft Corporation", "8.0.27.26230", ""},
		{"Zoom VDI Plugin Management(64bit)", "Zoom Communications, Inc.", "6.6.26970", ""},
		{"GitHub Desktop", "GitHub, Inc.", "3.6.3", ""},
		{"Git", "GitHub, Inc.", "2.53.0", ""}, // a Git that is not Git for Windows
		{"Adobe Digital Editions 4.5", "Adobe Systems Incorporated", "4.5.12", ""},
		{"Adobe Acrobat (64-bit)", "Adobe", "26.001.21346", "adobe-acrobat"},
		{"Adobe Acrobat (64-bit)", "Adobe", "24.001.30264", "adobe-acrobat-classic"},
		{"Adobe Acrobat (64-bit)", "Adobe", "11.0.23", ""}, // neither track
		{"VMware Workstation", "VMware, Inc.", "25.0.1", ""},
		{"VMware Tools", "Broadcom Inc.", "12.4.0.23259341", "vmware-tools"},
		{"TeamViewer", "TeamViewer", "15.58.4", "teamviewer"},
		{"WinRAR archiver", "", "", ""},
		{"OpenVPN Connect", "OpenVPN Inc.", "3.7.3", ""},
	} {
		id := Default().Identify(c.name, c.pub, c.version)
		got := ""
		if id.Program != nil {
			got = id.Program.ID
		} else if id.Reason == "" {
			t.Errorf("%q: no program and no reason", c.name)
		}
		if got != c.want {
			t.Errorf("%q %q %q = %q (%s), want %q", c.name, c.pub, c.version, got, id.Reason, c.want)
		}
		if c.pub == "" && got != "" && !id.PublisherMissing {
			t.Errorf("%q: matched with no publisher must need validation", c.name)
		}
	}
	if r := Default().Identify("Some Tool", "Acme", "1.0").Reason; !strings.HasPrefix(r, "not in the curated catalogue of Windows programs") {
		t.Errorf("reason %q", r)
	}
}

func TestOwnsCPE(t *testing.T) {
	np := Default().Program("notepad-plus-plus")
	chrome, acro := Default().Program("google-chrome"), Default().Program("adobe-acrobat")
	// Mozilla programs are read from Mozilla's advisories, not NVD; give
	// the test a Firefox ESR source with an edition.
	esrNVD := &Program{ID: "esr", Source: &Source{Type: SourceNVD, CPEs: []string{"cpe:2.3:a:mozilla:firefox:*:*:*:*:esr", "cpe:2.3:a:mozilla:firefox_esr"}}}
	relNVD := &Program{ID: "rel", Source: &Source{Type: SourceNVD, CPEs: []string{"cpe:2.3:a:mozilla:firefox"}}}
	for _, c := range []struct {
		p        *Program
		criteria string
		want     bool
	}{
		{relNVD, "cpe:2.3:a:mozilla:firefox:*:*:*:*:-:*:*:*", true},
		{relNVD, "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*", true},
		{relNVD, "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*", false}, // ESR's range is not the release's
		{relNVD, "cpe:2.3:a:mozilla:firefox:*:*:*:*:-:iphone_os:*:*", false},
		{esrNVD, "cpe:2.3:a:mozilla:firefox:*:*:*:*:esr:*:*:*", true},
		{esrNVD, "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*", false}, // no edition: not applied to ESR
		{esrNVD, "cpe:2.3:a:mozilla:firefox_esr:*:*:*:*:*:*:*:*", true},
		{chrome, "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", true},
		{chrome, "cpe:2.3:a:google:chrome:*:*:*:*:*:android:*:*", false},
		{chrome, "cpe:2.3:a:google:chrome:*:*:*:*:*:windows:*:*", true},
		{chrome, "cpe:2.3:a:google:chromium:*:*:*:*:*:*:*:*", false},
		{np, `cpe:2.3:a:notepad-plus-plus:notepad\+\+:*:*:*:*:*:*:*:*`, true},
		{acro, "cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:continuous:*:*:*", true},
		{acro, "cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:classic:*:*:*", false},
		{acro, "cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*", false},
		{Default().Program("adobe-acrobat-classic"), "cpe:2.3:a:adobe:acrobat:*:*:*:*:classic:*:*:*", true},
		{Default().Program("adobe-acrobat-classic"), "cpe:2.3:a:adobe:acrobat_dc:*:*:*:*:continuous:*:*:*", false},
	} {
		if got := c.p.OwnsCPE(c.criteria); got != c.want {
			t.Errorf("%s owns %s = %v", c.p.ID, c.criteria, got)
		}
	}
	if v := CPEVersion("cpe:2.3:a:oracle:jdk:1.8.0:update491:*:*:-:*:*:*"); v != "1.8.0:update491" {
		t.Errorf("CPEVersion = %q", v)
	}
	if v := CPEVersion(`cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6.2:*:*:*:*:*:*:*`); v != "8.6.2" {
		t.Errorf("CPEVersion = %q", v)
	}
}

func TestParseRefuses(t *testing.T) {
	entry := func(extra string) string {
		return `{"schema":1,"version":"t","programs":[{"id":"x","label":"X","names":["^X$"],"publishers":["^P$"],"sources":["s"],"verified":"2026-10-30",` + extra + `}]}`
	}
	good := `"version":{"pattern":"^(\\d+)$","format":"$1"},"source":{"type":"nvd_cpe","cpes":["cpe:2.3:a:v:x"]},"update":"u"`
	if _, err := Parse([]byte(entry(good))); err != nil {
		t.Fatalf("good entry refused: %v", err)
	}
	for name, doc := range map[string]string{
		"unknown field":   entry(good + `,"cpe":"x"`),
		"schema":          strings.Replace(entry(good), `"schema":1`, `"schema":2`, 1),
		"unanchored name": strings.Replace(entry(good), `"^X$"`, `"X"`, 1),
		"bad id":          strings.Replace(entry(good), `"id":"x"`, `"id":"X Y"`, 1),
		"no source":       entry(`"version":{"pattern":"^(\\d+)$","format":"$1"}`),
		"both":            entry(good + `,"unmatched":"why"`),
		"group":           entry(strings.Replace(good, `"$1"`, `"$2"`, 1)),
		"bad cpe":         entry(strings.Replace(good, "cpe:2.3:a:v:x", "cpe:2.3:o:v:x", 1)),
		"msrc elsewhere":  entry(`"version":{"pattern":"^(\\d+)$","format":"$1"},"source":{"type":"msrc"},"update":"u"`),
		"mfsa product":    entry(`"version":{"pattern":"^(\\d+)$","format":"$1"},"source":{"type":"mfsa","products":["Firefox for iOS"]},"update":"u"`),
		"date":            strings.Replace(entry(good), "2026-10-30", "soon", 1),
		"parity":          entry(good + `,"extended_parity":"third"`),
	} {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := `{"schema":1,"version":"t","programs":[` + strings.TrimSuffix(strings.TrimPrefix(entry(good), `{"schema":1,"version":"t","programs":[`), "]}") + "," +
		strings.TrimSuffix(strings.TrimPrefix(entry(good), `{"schema":1,"version":"t","programs":[`), "]}") + "]}"
	if _, err := Parse([]byte(dup)); err == nil {
		t.Error("a program listed twice was accepted")
	}
}

func TestSideBySideLines(t *testing.T) {
	for _, c := range []struct{ id, version, want string }{
		{"dotnet-runtime", "8.0.20", "8"},
		{"aspnetcore-runtime", "10.0.10", "10"},
		{"python", "3.12.10", "3.12"},
		{"google-chrome", "156.0.8078.74", ""},
	} {
		if got := Default().Program(c.id).Line(c.version); got != c.want {
			t.Errorf("%s %s line %q, want %q", c.id, c.version, got, c.want)
		}
	}
	bad := `{"schema":1,"version":"t","programs":[{"id":"x","label":"X","names":["^X$"],"publishers":["^P$"],"sources":["s"],"verified":"2026-10-30","side_by_side":"minor","unmatched":"why"}]}`
	if _, err := Parse([]byte(bad)); err == nil {
		t.Error("side_by_side minor was accepted")
	}
}
