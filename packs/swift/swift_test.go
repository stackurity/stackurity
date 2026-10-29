package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/pkg/pack"
)

// The fixtures are real files from public repositories; testdata/README.md
// says where each one comes from.
func scanFixture(t *testing.T, path string) *pack.Response {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Scan(&pack.Request{Files: []pack.File{{Path: path, Content: data}}})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func find(out *pack.Response, purl string) *pack.Observation {
	for i := range out.Observations {
		if out.Observations[i].Purl == purl {
			return &out.Observations[i]
		}
	}
	return nil
}

func TestPackageResolvedFormats(t *testing.T) {
	for _, tc := range []struct {
		file     string
		n        int
		want     []string
		coverage string // status, then words of the reason
	}{
		{"penny-bot-v1/Package.resolved", 3, []string{
			"pkg:swift/github.com/apple/swift-nio@2.38.0",
			"pkg:swift/github.com/swift-server/swift-backtrace@1.3.1",
		}, "partial 1 package is pinned to a branch"},
		{"swiftlint-v2/Package.resolved", 6, []string{
			"pkg:swift/github.com/jpsim/SourceKitten@0.33.1", // case kept: OSV names it the same way
			"pkg:swift/github.com/apple/swift-argument-parser@1.2.0",
		}, "partial 1 package"},
		{"penny-bot-v3/Package.resolved", 46, []string{
			"pkg:swift/github.com/swift-server/async-http-client@1.36.2",
			"pkg:swift/github.com/DiscordBM/DiscordLogger@1.0.0-rc.3",
		}, "partial 1 package"},
		// Registry pins (Tuist mirrors packages in a registry) carry the
		// repository they mirror.
		{"tuist-registry-v3/Package.resolved", 83, []string{
			"pkg:swift/github.com/1024jp/GzipSwift@5.2.0",
			"pkg:swift/github.com/apple/swift-argument-parser@1.8.2",
		}, "checked"},
		// Local packages are the project's own code; branch pins have no version.
		{"chriseidhofnl-local-v2/Package.resolved", 2, []string{
			"pkg:swift/github.com/apple/swift-crypto@1.1.7",
			"pkg:swift/github.com/jpsim/Yams@2.0.0",
		}, "partial 4 packages are pinned"},
	} {
		out := scanFixture(t, tc.file)
		if len(out.Observations) != tc.n {
			t.Errorf("%s: %d packages, want %d", tc.file, len(out.Observations), tc.n)
		}
		for _, p := range tc.want {
			o := find(out, p)
			if o == nil || o.Location != tc.file || o.Confidence != pack.ConfidenceConfirmed || o.Evidence["lockfile"] != "Package.resolved" {
				t.Errorf("%s: missing %s: %+v", tc.file, p, o)
			}
		}
		if len(out.Coverage) != 1 || out.Coverage[0].Scope != "swift:"+tc.file {
			t.Fatalf("%s: coverage %+v", tc.file, out.Coverage)
		}
		status, words, _ := strings.Cut(tc.coverage, " ")
		if c := out.Coverage[0]; c.Status != status || !strings.Contains(c.Reason, words) {
			t.Errorf("%s: coverage %+v, want %s", tc.file, c, tc.coverage)
		}
	}
	out := scanFixture(t, "tuist-registry-v3/Package.resolved")
	if o := find(out, "pkg:swift/github.com/1024jp/GzipSwift@5.2.0"); o.Evidence["registry_identity"] != "1024jp.gzipswift" {
		t.Errorf("registry evidence: %+v", o.Evidence)
	}
}

func TestRepoPath(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/apple/swift-nio.git":         "github.com/apple swift-nio",
		"https://GitHub.com/apple/swift-nio/":            "github.com/apple swift-nio",
		"git@github.com:vapor/vapor.git":                 "github.com/vapor vapor",
		"ssh://git@gitlab.example.com:2222/team/lib.git": "gitlab.example.com/team lib",
		"https://user:token@example.com/a/b/c.git":       "example.com/a/b c",
		"/Users/me/Lib":                "",
		"https://github.com/onlyowner": "github.com onlyowner",
		"https://example.com/a/../b":   "",
	} {
		ns, name, ok := repoPath(in)
		got := ""
		if ok {
			got = ns + " " + name
		}
		if got != want {
			t.Errorf("repoPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegistryWithoutOriginalLocation(t *testing.T) {
	lock := `{"pins":[{"identity":"mona.LinkedList","kind":"registry","location":"https://packages.example.com","state":{"version":"1.1.0"}},
		{"identity":"bad","kind":"registry","location":"","state":{"version":"1.0.0"}}],"version":2}`
	out, _ := Scan(&pack.Request{Files: []pack.File{{Path: "Package.resolved", Content: []byte(lock)}}})
	if len(out.Observations) != 1 || out.Observations[0].Purl != "pkg:swift/mona/LinkedList@1.1.0" {
		t.Errorf("registry pin: %+v", out.Observations)
	}
	if out.Coverage[0].Status != "partial" {
		t.Errorf("an unreadable pin must make coverage partial: %+v", out.Coverage)
	}
}

func TestBrokenResolved(t *testing.T) {
	for content, want := range map[string]string{
		"not json":                     "not a Package.resolved file",
		`{"version": 9, "things": []}`: "format 9 is not understood",
	} {
		out, _ := Scan(&pack.Request{Files: []pack.File{{Path: "x/Package.resolved", Content: []byte(content)}}})
		if len(out.Coverage) != 1 || out.Coverage[0].Status != "failed" || !strings.Contains(out.Coverage[0].Reason, want) {
			t.Errorf("%q: %+v", content, out.Coverage)
		}
	}
}

func TestPodfileLock(t *testing.T) {
	// Signal: pods from git repositories, subspecs, a pod from a podspec.
	out := scanFixture(t, "signal-ios/Podfile.lock")
	if len(out.Observations) != 9 {
		t.Errorf("signal: %d pods: %+v", len(out.Observations), out.Observations)
	}
	o := find(out, "pkg:cocoapods/LibSignalClient@0.105.0")
	if o == nil || o.Evidence["source"] != "git" || o.Evidence["git"] != "https://github.com/signalapp/libsignal.git" || o.Direct == nil || !*o.Direct {
		t.Errorf("git pod: %+v", o)
	}
	// Subspecs (GRDB.swift/SQLCipher) are reported once, as their pod.
	if o := find(out, "pkg:cocoapods/GRDB.swift@5.26.0"); o == nil || !*o.Direct {
		t.Errorf("subspec root: %+v", o)
	}
	if o := find(out, "pkg:cocoapods/Logging@1.4.0"); o == nil || *o.Direct {
		t.Errorf("transitive pod: %+v", o)
	}
	if out.Coverage[0].Scope != "cocoapods:signal-ios/Podfile.lock" || out.Coverage[0].Status != "checked" {
		t.Errorf("coverage: %+v", out.Coverage)
	}

	// Mattermost (React Native): development pods from node_modules (:path:)
	// are not listed; pods from trunk and from podspec files are.
	out = scanFixture(t, "mattermost-mobile/Podfile.lock")
	if len(out.Observations) != 28 {
		t.Errorf("mattermost: %d pods", len(out.Observations))
	}
	if o := find(out, "pkg:cocoapods/Alamofire@5.11.2"); o == nil || o.Evidence["source"] != "" {
		t.Errorf("trunk pod: %+v", o)
	}
	if o := find(out, "pkg:cocoapods/boost@1.84.0"); o == nil || o.Evidence["source"] != "podspec" {
		t.Errorf("podspec pod: %+v", o)
	}
	for _, o := range out.Observations {
		if strings.HasPrefix(o.Purl, "pkg:cocoapods/React-") || strings.HasPrefix(o.Purl, "pkg:cocoapods/CookieManager@") {
			t.Errorf("development pod listed: %s", o.Purl)
		}
	}
}

func TestBrokenPodfileLock(t *testing.T) {
	out, _ := Scan(&pack.Request{Files: []pack.File{{Path: "Podfile.lock", Content: []byte("PODS:\n  - Good (1.0)\n  - what is this\n")}}})
	if len(out.Observations) != 1 || out.Coverage[0].Status != "partial" {
		t.Errorf("%+v %+v", out.Observations, out.Coverage)
	}
	out, _ = Scan(&pack.Request{Files: []pack.File{{Path: "Podfile.lock", Content: []byte("COCOAPODS: 1.15.2\n")}}})
	if out.Coverage[0].Status != "failed" {
		t.Errorf("%+v", out.Coverage)
	}
}
