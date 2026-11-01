package darwin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/model"
)

func fixture(t *testing.T) *Collector {
	t.Helper()
	root, err := filepath.Abs("testdata/mac")
	if err != nil {
		t.Fatal(err)
	}
	return &Collector{Root: root, Version: "t", Runtimes: true,
		PlatformUUID: func(context.Context) string { return "00000000-0000-4000-8000-0000000000aa" }}
}

func byPurl(b *model.ObservationBatch) map[string]model.Observation {
	out := map[string]model.Observation{}
	for _, o := range b.Observations {
		out[o.Purl] = o
	}
	return out
}

func coverage(b *model.ObservationBatch) map[string]model.CoverageItem {
	out := map[string]model.CoverageItem{}
	for _, c := range b.Coverage {
		out[c.Scope] = c
	}
	return out
}

func TestCollectSystem(t *testing.T) {
	c := fixture(t)
	b, err := c.Collect(context.Background(), "mac-build-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Collector.ID != CollectorID || !b.Complete {
		t.Errorf("collector %s complete %v; coverage %+v", b.Collector.ID, b.Complete, b.Coverage)
	}
	a := b.Asset
	if a.Identifiers[0].Scheme != "macos-platform-uuid" || a.Identifiers[0].Value != "00000000-0000-4000-8000-0000000000aa" ||
		a.Identifiers[1] != (model.Identifier{Scheme: "hostname", Value: "mac-build-01"}) {
		t.Errorf("identifiers %+v", a.Identifiers)
	}
	if a.Attributes["os"] != "macos" || a.Attributes["os_version"] != "14.7" || a.Attributes["os_build"] != "23H124" {
		t.Errorf("attributes %+v", a.Attributes)
	}
	if o := b.Observations[0]; o.Purl != "pkg:generic/macos@14.7" || o.Evidence["kind"] != "operating-system" {
		t.Errorf("the OS must come first: %+v", o)
	}
	got := byPurl(b)
	want := map[string]struct {
		conf, kind string
	}{
		"pkg:generic/macos@14.7": {"confirmed", "operating-system"},
		// XML and binary Info.plist; a subfolder; the display name wins.
		"pkg:generic/Firefox@131.0.3":               {"confirmed", "macos-app"},
		"pkg:generic/Google%20Chrome@130.0.6723.92": {"confirmed", "macos-app"},
		"pkg:generic/Tool@412":                      {"inferred", "macos-app"},  // CFBundleVersion only
		"pkg:generic/Game@2.1":                      {"confirmed", "macos-app"}, // iOS app in a wrapper
		// Unreadable or missing Info.plist: reported, version unknown.
		"pkg:generic/Broken":  {"unknown", "macos-app"},
		"pkg:generic/NoPlist": {"unknown", "macos-app"},
		"pkg:generic/Escape":  {"unknown", "macos-app"},
		// Formulae mapped to endoflife.date products, on both prefixes.
		"pkg:generic/nodejs@22.11.0":    {"confirmed", "runtime"},
		"pkg:generic/nodejs@20.18.0":    {"confirmed", "runtime"},
		"pkg:generic/python@3.12.7":     {"confirmed", "runtime"},
		"pkg:generic/mongodb@8.0.3":     {"confirmed", "runtime"},
		"pkg:brew/jq@1.7.1":             {"confirmed", "homebrew-formula"},
		"pkg:brew/openssl%403@3.4.0":    {"inferred", "homebrew-formula"}, // no receipt
		"pkg:brew/wget@1.24.5":          {"confirmed", "homebrew-formula"},
		"pkg:brew/cask/firefox@131.0.3": {"confirmed", "homebrew-cask"},
		"pkg:brew/cask/google-chrome":   {"unknown", "homebrew-cask"},
	}
	for purl, w := range want {
		o, ok := got[purl]
		if !ok {
			t.Errorf("missing %s", purl)
			continue
		}
		if string(o.Confidence) != w.conf || o.Evidence["kind"] != w.kind {
			t.Errorf("%s: confidence %s kind %s, want %s %s", purl, o.Confidence, o.Evidence["kind"], w.conf, w.kind)
		}
	}
	if len(got) != len(want) {
		var extra []string
		for p := range got {
			if _, ok := want[p]; !ok {
				extra = append(extra, p)
			}
		}
		t.Errorf("%d rows, want %d; unexpected %v", len(got), len(want), extra)
	}
	if ff := got["pkg:generic/Firefox@131.0.3"]; ff.Evidence["bundle_id"] != "org.mozilla.firefox" || ff.Evidence["bundle_version"] != "13124.10.8" ||
		ff.Location != "/Applications/Firefox.app" {
		t.Errorf("firefox %+v", ff)
	}
	if g := got["pkg:generic/Game@2.1"]; g.Evidence["platform"] != "ios" {
		t.Errorf("game %+v", g)
	}
	// A WrappedBundle link out of the bundle is not followed.
	if e := got["pkg:generic/Escape"]; e.Evidence["platform"] != "" {
		t.Errorf("escape %+v", e)
	}
	node := got["pkg:generic/nodejs@22.11.0"]
	if node.Evidence["install"] != "homebrew" || node.Evidence["formula"] != "node" || node.Evidence["linked"] != "true" ||
		node.Location != "/opt/homebrew/Cellar/node/22.11.0_1" || node.Evidence["keg_version"] != "22.11.0_1" {
		t.Errorf("node %+v", node)
	}
	if old := got["pkg:generic/nodejs@20.18.0"]; old.Evidence["linked"] != "" {
		t.Errorf("an unlinked keg is not linked: %+v", old)
	}
	if py := got["pkg:generic/python@3.12.7"]; py.Evidence["installed_on_request"] != "false" {
		t.Errorf("python %+v", py)
	}
	if m := got["pkg:generic/mongodb@8.0.3"]; m.Evidence["tap"] != "mongodb/brew" {
		t.Errorf("mongodb %+v", m)
	}
	if w := got["pkg:brew/wget@1.24.5"]; w.Evidence["homebrew_prefix"] != "/usr/local" {
		t.Errorf("wget %+v", w)
	}
	cov := coverage(b)
	for _, s := range []string{"path:/Applications", "path:/opt/homebrew/Cellar", "path:/opt/homebrew/Caskroom", "path:/usr/local/Cellar"} {
		if cov[s].Status != "checked" {
			t.Errorf("%s: %+v", s, cov[s])
		}
	}
	if cov["macos:software-updates"].Status != "unsupported" {
		t.Errorf("pending updates must be reported as not read: %+v", cov)
	}
}

func TestCollectSoftware(t *testing.T) {
	c := fixture(t)
	c.Global = (&apps.Scanner{Root: c.Root}).ScanGlobalDirs
	sys, err := c.Collect(context.Background(), "mac-build-01")
	if err != nil {
		t.Fatal(err)
	}
	b := c.CollectSoftware(context.Background(), sys)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Collector.ID != SoftwareCollectorID || b.Asset.Identifiers[0] != sys.Asset.Identifiers[0] {
		t.Errorf("collector %s asset %+v", b.Collector.ID, b.Asset)
	}
	got := byPurl(b)
	for purl, install := range map[string]string{
		"pkg:generic/go@1.22.4":              "installer",
		"pkg:generic/nodejs@18.19.1":         "nodejs.org",
		"pkg:generic/python@3.12.4":          "python.org",
		"pkg:generic/eclipse-temurin@21.0.5": "jdk", // binary Info.plist
		"pkg:generic/azul-zulu@8.0.432":      "jdk",
		"pkg:generic/nodejs@18.20.4":         "nvm",
		"pkg:generic/python@3.11.9":          "pyenv",
		"pkg:generic/ruby@3.3.5":             "rbenv",
	} {
		o, ok := got[purl]
		if !ok || o.Evidence["install"] != install || o.Evidence["kind"] != "runtime" {
			t.Errorf("%s: %+v", purl, o)
		}
	}
	if o := got["pkg:generic/python@3.12.4"]; o.Location != "/Library/Frameworks/Python.framework/Versions/3.12" {
		t.Errorf("the framework's Current link must not be read twice: %+v", o)
	}
	if o := got["pkg:generic/Personal@1.0"]; o.Evidence["per_user"] != "true" || o.Location != "/Users/alice/Applications/Personal.app" {
		t.Errorf("per-user app %+v", o)
	}
	if o := got["pkg:npm/npm@10.9.0"]; o.Evidence["global"] != "true" {
		t.Errorf("global npm %+v", o)
	}
	if o := got["pkg:pypi/requests@2.31.0"]; o.Location == "" {
		t.Errorf("framework site-packages %+v", got)
	}
	for p := range got {
		if strings.Contains(p, "miniconda") {
			t.Errorf("a pyenv install that is not CPython must not be read as Python: %s", p)
		}
	}
	n := 0
	for _, c := range b.Coverage {
		if strings.Contains(c.Scope, "Versions/Current") {
			t.Errorf("Current read as its own site-packages: %+v", c)
		}
		if c.Scope == "python-installed:/Library/Frameworks/Python.framework/Versions/3.12/lib/python3.12/site-packages" {
			n++
		}
	}
	if n != 1 || !b.Complete {
		t.Errorf("site-packages coverage %d, complete %v: %+v", n, b.Complete, b.Coverage)
	}
}

func TestNoRuntimes(t *testing.T) {
	c := fixture(t)
	c.Runtimes = false
	sys, err := c.Collect(context.Background(), "h")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range c.CollectSoftware(context.Background(), sys).Observations {
		if o.Evidence["kind"] == "runtime" {
			t.Errorf("--no-runtimes: %s", o.Purl)
		}
	}
}

func TestMissingSystemVersion(t *testing.T) {
	c := &Collector{Root: t.TempDir()}
	if _, err := c.Collect(context.Background(), "h"); err == nil || !strings.Contains(err.Error(), "macOS version") {
		t.Errorf("err = %v", err)
	}
}

func TestParseIOReg(t *testing.T) {
	out := []byte(`+-o J316sAP  <class IOPlatformExpertDevice, id 0x100000226, registered, matched, active, busy 0 (2 ms), retain 39>
    {
      "IOPlatformSerialNumber" = "C02XXXXXXX"
      "IOPlatformUUID" = "8C1F6A5E-2B3D-5E4F-9A0B-1C2D3E4F5A6B"
      "IOPolledInterface" = "AppleARMWatchdogTimerHibernateHandler is not serializable"
    }`)
	if got := ParseIOReg(out); got != "8c1f6a5e-2b3d-5e4f-9a0b-1c2d3e4f5a6b" {
		t.Errorf("uuid %q", got)
	}
	for _, bad := range []string{``, `"IOPlatformUUID" = "not-a-uuid"`, `"IOPlatformSerialNumber" = "8C1F6A5E-2B3D-5E4F-9A0B-1C2D3E4F5A6B"`} {
		if got := ParseIOReg([]byte(bad)); got != "" {
			t.Errorf("%q: %q", bad, got)
		}
	}
}

// writeApp writes an application bundle with an XML Info.plist.
func writeApp(t *testing.T, dir, name, version string) {
	t.Helper()
	p := filepath.Join(dir, name+".app", "Contents")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
<key>CFBundleName</key><string>%s</string><key>CFBundleShortVersionString</key><string>%s</string></dict></plist>`, name, version)
	if err := os.WriteFile(filepath.Join(p, "Info.plist"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func minimalRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	sv := filepath.Join(root, "System/Library/CoreServices")
	if err := os.MkdirAll(sv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sv, "SystemVersion.plist"), []byte(`<?xml version="1.0"?><plist version="1.0"><dict>
<key>ProductName</key><string>macOS</string><key>ProductVersion</key><string>15.1</string></dict></plist>`), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestBoundedApplications(t *testing.T) {
	root := minimalRoot(t)
	for i := 0; i < 30; i++ {
		writeApp(t, filepath.Join(root, "Applications"), fmt.Sprintf("App%02d", i), "1.0")
	}
	c := &Collector{Root: root, MaxBundles: 10}
	b, err := c.Collect(context.Background(), "h")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(b.Observations); n != 11 { // the OS and ten applications
		t.Errorf("%d rows", n)
	}
	cov := coverage(b)["path:/Applications"]
	if cov.Status != "partial" || !strings.Contains(cov.Reason, "stopped after 10") || b.Complete {
		t.Errorf("a truncated folder must be partial and the batch incomplete: %+v complete=%v", cov, b.Complete)
	}
}

func TestOversizedPlist(t *testing.T) {
	root := minimalRoot(t)
	p := filepath.Join(root, "Applications/Huge.app/Contents")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	big := `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>9.9</string><key>X</key><string>` +
		strings.Repeat("a", maxPlistBytes) + `</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(p, "Info.plist"), []byte(big), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := (&Collector{Root: root}).Collect(context.Background(), "h")
	if err != nil {
		t.Fatal(err)
	}
	o := byPurl(b)["pkg:generic/Huge"]
	if o.Confidence != model.ConfidenceUnknown || !strings.Contains(o.Evidence["error"], "larger than 1 MiB") {
		t.Errorf("an oversized Info.plist must not be read: %+v", o)
	}
}

func TestMalformedBinaryPlist(t *testing.T) {
	root := minimalRoot(t)
	p := filepath.Join(root, "Applications/Bad.app/Contents")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	// A binary plist header with a trailer pointing far outside the file.
	data := append([]byte("bplist00"), make([]byte, 40)...)
	for i := len(data) - 32; i < len(data); i++ {
		data[i] = 0xff
	}
	if err := os.WriteFile(filepath.Join(p, "Info.plist"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := (&Collector{Root: root}).Collect(context.Background(), "h")
	if err != nil {
		t.Fatal(err)
	}
	if o := byPurl(b)["pkg:generic/Bad"]; o.Confidence != model.ConfidenceUnknown || o.Evidence["error"] == "" {
		t.Errorf("%+v", o)
	}
}

func TestUnreadableDirectories(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	root := minimalRoot(t)
	writeApp(t, filepath.Join(root, "Applications"), "Visible", "1.0")
	locked := filepath.Join(root, "Applications/Vendor")
	writeApp(t, locked, "Hidden", "2.0")
	for _, d := range []string{"Users/alice/Applications", "Users/bob"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeApp(t, filepath.Join(root, "Users/alice/Applications"), "Mine", "3.0")
	cellar := filepath.Join(root, "opt/homebrew/Cellar")
	if err := os.MkdirAll(cellar, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{locked, filepath.Join(root, "Users/bob"), cellar} {
		if err := os.Chmod(d, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(d, 0o755) })
	}
	c := &Collector{Root: root, Runtimes: true}
	b, err := c.Collect(context.Background(), "h")
	if err != nil {
		t.Fatal(err)
	}
	cov := coverage(b)
	if cov["path:/Applications/Vendor"].Status != "skipped" || cov["path:/opt/homebrew/Cellar"].Status != "skipped" || b.Complete {
		t.Errorf("unreadable folders must be reported: %+v", b.Coverage)
	}
	if _, ok := byPurl(b)["pkg:generic/Visible@1.0"]; !ok {
		t.Error("the readable application is still reported")
	}
	// Every gap names its path, so the server can still prove removals
	// elsewhere (store.blindPaths).
	for _, cv := range b.Coverage {
		if cv.Status != "checked" && cv.Status != "unsupported" && !strings.HasPrefix(cv.Scope, "path:/") {
			t.Errorf("a gap without a path: %+v", cv)
		}
	}
	sw := c.CollectSoftware(context.Background(), b)
	scov := coverage(sw)
	if scov["path:/Users/bob"].Status != "skipped" || !strings.Contains(scov["path:/Users/bob"].Reason, "permission denied") || sw.Complete {
		t.Errorf("an unreadable home must be reported: %+v", sw.Coverage)
	}
	if _, ok := byPurl(sw)["pkg:generic/Mine@3.0"]; !ok {
		t.Error("a readable home's applications are still reported")
	}
}

func TestCleanValues(t *testing.T) {
	if got := clean("‎WhatsApp\x00\n", 200); got != "WhatsApp" {
		t.Errorf("%q", got)
	}
	if got := clean(strings.Repeat("é", 200), 11); got != strings.Repeat("é", 5) {
		t.Errorf("clipped mid-rune: %q", got)
	}
	if got := cleanVersion("3.13.3, (c) 2001-2024 Python Software Foundation."); got != "3.13.3" {
		t.Errorf("%q", got)
	}
	if got := javaVersion("1.8.0_432"); got != "8.0.432" {
		t.Errorf("%q", got)
	}
}
