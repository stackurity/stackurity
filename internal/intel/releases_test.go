package intel

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// registryFixtures maps request paths on the fake registry server to files
// under testdata/releases. The fixtures are trimmed copies of real
// responses; a few versions were added or flagged (a pre-release newer than
// the latest stable, a yanked or retracted newest version) so each rule is
// exercised.
var registryFixtures = map[string]string{
	"/pypi/pypi/django/json":                                       "pypi-django.json",
	"/go/github.com/!burnt!sushi/toml/@v/list":                     "go/toml-list.txt",
	"/go/github.com/!burnt!sushi/toml/@latest":                     "go/toml-latest.json",
	"/go/github.com/!burnt!sushi/toml/@v/v1.7.0-rc.1.mod":          "go/toml-v1.7.0-rc.1.mod",
	"/go/github.com/!burnt!sushi/toml/@v/v1.5.0.info":              "go/toml-v1.5.0.info",
	"/crates/se/rd/serde":                                          "crates-serde.ndjson",
	"/rubygems/api/v1/versions/rails.json":                         "rubygems-rails.json",
	"/rubygems/api/v1/versions/nokogiri.json":                      "rubygems-nokogiri.json",
	"/nuget/windowsazure.storage/index.json":                       "nuget-windowsazure.storage.json",
	"/nuget/awssdk.core/index.json":                                "nuget-awssdk.core-index.json",
	"/nuget/awssdk.core/page/4.0.7.2/4.0.102.13.json":              "nuget-awssdk.core-page2.json",
	"/nuget/awssdk.core/page/4.1.0-preview.1/4.1.0-preview.2.json": "nuget-awssdk.core-page3.json",
	"/maven/org/springframework/spring-core/maven-metadata.xml":    "maven-spring-core.xml",
	"/pub/api/packages/pedantic":                                   "pub-pedantic.json",
	"/hex/api/packages/cowboy":                                     "hex-cowboy.json",
}

type fixtureRegistry struct {
	t        *testing.T
	base     string
	mu       sync.Mutex
	requests []string
	down     map[string]bool // path prefixes that refuse every request
}

func (f *fixtureRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.EscapedPath()
	f.mu.Lock()
	f.requests = append(f.requests, p)
	for prefix := range f.down {
		if strings.HasPrefix(p, prefix) {
			f.mu.Unlock()
			// 403 rather than 503, which the fetcher would retry with backoff.
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
	}
	f.mu.Unlock()
	name, ok := registryFixtures[p]
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := os.ReadFile(filepath.Join("testdata", "releases", name))
	if err != nil {
		f.t.Error(err)
		http.Error(w, err.Error(), 500)
		return
	}
	// NuGet registration pages link each other by absolute URL.
	_, _ = w.Write([]byte(strings.ReplaceAll(string(b), "{{base}}", f.base+"/nuget")))
}

func (f *fixtureRegistry) requested(path string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.requests {
		if p == path {
			return true
		}
	}
	return false
}

func registryConfig(base string) Config {
	cfg := DefaultConfig()
	cfg.PyPIURL, cfg.GoProxyURL, cfg.CratesIndexURL = base+"/pypi", base+"/go", base+"/crates"
	cfg.RubyGemsURL, cfg.NuGetURL, cfg.MavenURL, cfg.PubURL = base+"/rubygems", base+"/nuget", base+"/maven", base+"/pub"
	cfg.HexURL = base + "/hex"
	return cfg
}

func newFixtureRegistry(t *testing.T) (*fixtureRegistry, Config) {
	t.Helper()
	reg := &fixtureRegistry{t: t, down: map[string]bool{}}
	srv := httptest.NewServer(reg)
	t.Cleanup(srv.Close)
	reg.base = srv.URL
	return reg, registryConfig(srv.URL)
}

func TestRegistryLookups(t *testing.T) {
	reg, cfg := newFixtureRegistry(t)
	s := &Syncer{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), f: newFetcher(cfg)}
	cases := []struct {
		name       string
		feed       string
		cand       store.ReleaseCandidate
		latest     string
		stable     string
		published  string // RFC 3339 of LatestPublished, "" for none
		yanked     map[string]string
		deprecated string // substring
		wantErr    string // substring
	}{
		{
			name: "pypi: pre-releases skipped, yanked and file-less releases ignored", feed: FeedPyPI,
			cand:   store.ReleaseCandidate{Type: "pypi", Name: "Django"},
			latest: "6.2a1", stable: "6.1.2", published: "2026-10-06T12:53:17.381365Z",
			yanked: map[string]string{"4.2.12": "Release files have Windows end-of-line characters and are missing executable bits."},
		},
		{
			name: "pypi: unknown package", feed: FeedPyPI,
			cand: store.ReleaseCandidate{Type: "pypi", Name: "no-such-package"}, wantErr: "HTTP 404",
		},
		{
			name: "go: case-escaped path, retractions and deprecation from the newest go.mod", feed: FeedGo,
			cand: store.ReleaseCandidate{Type: "golang", Namespace: "github.com/burntsushi", Name: "toml",
				Purl: "pkg:golang/github.com/BurntSushi/toml@v1.3.0"},
			latest: "v1.7.0-rc.1", stable: "v1.5.0", published: "2025-03-14T10:00:00Z",
			yanked:     map[string]string{"v1.6.0": "Decodes nested tables incorrectly.", "v0.1.0": "", "v0.2.0": ""},
			deprecated: "use github.com/BurntSushi/toml/v2 instead.",
		},
		{
			name: "go: standard library is not looked up", feed: FeedGo,
			cand: store.ReleaseCandidate{Type: "golang", Name: "stdlib", Purl: "pkg:golang/stdlib@1.22.1"},
		},
		{
			name: "crates: sparse index, yanked newest skipped", feed: FeedCrates,
			cand:   store.ReleaseCandidate{Type: "cargo", Name: "serde"},
			latest: "2.0.0-alpha.1", stable: "1.0.229", published: "2026-07-18T23:05:13Z",
			yanked: map[string]string{"0.7.6": "", "1.0.31": "", "1.0.230": ""},
		},
		{
			name: "crates: invalid name is not requested", feed: FeedCrates,
			cand: store.ReleaseCandidate{Type: "cargo", Name: "../etc"}, wantErr: "invalid crate name",
		},
		{
			name: "rubygems: prerelease flag", feed: FeedRubyGems,
			cand:   store.ReleaseCandidate{Type: "gem", Name: "rails"},
			latest: "8.2.0.beta1", stable: "8.1.4", published: "2026-09-24T14:22:14.18Z",
		},
		{
			name: "rubygems: platform builds collapse", feed: FeedRubyGems,
			cand:   store.ReleaseCandidate{Type: "gem", Name: "nokogiri"},
			latest: "1.19.4", stable: "1.19.4", published: "2026-06-18T15:18:35.798Z",
		},
		{
			name: "nuget: inlined pages, unlisted versions, package deprecation", feed: FeedNuGet,
			cand:   store.ReleaseCandidate{Type: "nuget", Name: "WindowsAzure.Storage"},
			latest: "9.3.3", stable: "9.3.3", published: "2018-11-27T00:08:28Z",
			yanked:     map[string]string{"8.1.2": "unlisted"},
			deprecated: "obsolete as of 3/31/2023",
		},
		{
			name: "nuget: linked pages read newest first until a stable version", feed: FeedNuGet,
			cand:   store.ReleaseCandidate{Type: "nuget", Name: "AWSSDK.Core"},
			latest: "4.1.0-preview.2", stable: "4.0.102.13", published: "2026-10-21T18:53:36Z",
		},
		{
			name: "maven: release candidates and milestones are not stable, no dates", feed: FeedMaven,
			cand:   store.ReleaseCandidate{Type: "maven", Namespace: "org.springframework", Name: "spring-core"},
			latest: "7.1.0-RC1", stable: "7.0.10",
		},
		{
			name: "maven: coordinates without a group", feed: FeedMaven,
			cand: store.ReleaseCandidate{Type: "maven", Name: "spring-core"}, wantErr: "invalid Maven coordinates",
		},
		{
			name: "pub: retracted version skipped, discontinued package", feed: FeedPub,
			cand:   store.ReleaseCandidate{Type: "pub", Name: "pedantic"},
			latest: "1.11.0", stable: "1.11.0", published: "2021-03-03T14:27:43.617646Z",
			yanked:     map[string]string{"1.11.1": "retracted"},
			deprecated: "Discontinued by its publisher. Replaced by lints.",
		},
		{
			name: "hex: retired version skipped, pre-release newer than stable", feed: FeedHex,
			cand:   store.ReleaseCandidate{Type: "hex", Name: "cowboy"},
			latest: "2.21.0-rc.1", stable: "2.20.0", published: "2026-10-08T12:26:28.985587Z",
			yanked: map[string]string{"2.6.2": "retired (invalid): cowlib version 2.7.2 retired"},
		},
		{
			name: "hex: a private organisation's package is not looked up", feed: FeedHex,
			cand: store.ReleaseCandidate{Type: "hex", Namespace: "acme", Name: "cowboy"}, wantErr: "private Hex organisation",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := registries[tc.feed].lookup(s, context.Background(), tc.cand)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.Latest != tc.latest || r.LatestStable != tc.stable {
				t.Errorf("latest = %q, stable = %q; want %q, %q", r.Latest, r.LatestStable, tc.latest, tc.stable)
			}
			pub := ""
			if r.LatestPublished != nil {
				pub = r.LatestPublished.Format(time.RFC3339Nano)
			}
			if pub != tc.published {
				t.Errorf("published = %q, want %q", pub, tc.published)
			}
			if len(r.Yanked) != len(tc.yanked) {
				t.Errorf("yanked = %v, want %v", r.Yanked, tc.yanked)
			}
			for v, reason := range tc.yanked {
				if got, ok := r.Yanked[v]; !ok || got != reason {
					t.Errorf("yanked[%s] = %q (%v), want %q", v, got, ok, reason)
				}
			}
			if (tc.deprecated == "") != (r.Deprecated == "") || !strings.Contains(r.Deprecated, tc.deprecated) {
				t.Errorf("deprecated = %q, want %q", r.Deprecated, tc.deprecated)
			}
			if r.Source != tc.feed || r.SourceURL == "" {
				t.Errorf("source = %q %q", r.Source, r.SourceURL)
			}
		})
	}
	if reg.requested("/nuget/awssdk.core/page/3.0.0-preview/3.3.5.json") {
		t.Error("NuGet lookup read a page older than the newest stable version")
	}
	if reg.requested("/pypi/pypi/Django/json") {
		t.Error("PyPI name was not normalised")
	}
}

func TestCratesIndexPath(t *testing.T) {
	for name, want := range map[string]string{"a": "1/a", "cc": "2/cc", "syn": "3/s/syn", "serde": "se/rd/serde", "Inflector": "in/fl/inflector"} {
		if got := cratesIndexPath(name); got != want {
			t.Errorf("cratesIndexPath(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestGoModulePath(t *testing.T) {
	for _, tc := range []struct {
		c    store.ReleaseCandidate
		want string
	}{
		{store.ReleaseCandidate{Namespace: "github.com/burntsushi", Name: "toml", Purl: "pkg:golang/github.com/BurntSushi/toml@v1.3.0"}, "github.com/BurntSushi/toml"},
		{store.ReleaseCandidate{Namespace: "github.com/azure/azure-sdk-for-go/sdk", Name: "azcore",
			Purl: "pkg:golang/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.9.0?type=module#sub"}, "github.com/Azure/azure-sdk-for-go/sdk/azcore"},
		{store.ReleaseCandidate{Namespace: "golang.org/x", Name: "net", Purl: "pkg:golang/golang.org/x/text@v0.14.0"}, "golang.org/x/net"},
		{store.ReleaseCandidate{Namespace: "gopkg.in", Name: "yaml.v3"}, "gopkg.in/yaml.v3"},
	} {
		if got := goModulePath(tc.c); got != tc.want {
			t.Errorf("goModulePath(%+v) = %q, want %q", tc.c, got, tc.want)
		}
	}
}

// One feed per registry is created from inventory, synced into the store,
// and a registry that is down fails only its own feed.
func TestRegistryFeeds(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, _, _, _ := setup(t)
	reg, cfg := newFixtureRegistry(t)
	cfg.WorkDir = t.TempDir()
	sy := NewSyncer(st, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)
	ingest(t, st, model.AssetRepository, "poly", true,
		confirmed("pkg:pypi/django@4.2.11", nil),
		confirmed("pkg:golang/github.com/BurntSushi/toml@v1.6.0", nil),
		confirmed("pkg:cargo/serde@1.0.228", nil),
		confirmed("pkg:gem/rails@7.2.2", nil),
		confirmed("pkg:nuget/WindowsAzure.Storage@9.3.2", nil),
		confirmed("pkg:maven/org.springframework/spring-core@6.2.12", nil),
		confirmed("pkg:pub/pedantic@1.9.0", nil),
		confirmed("pkg:hex/cowboy@2.12.0", nil),
	)
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	feeds, _ := st.ListFeeds(ctx)
	have := map[string]bool{}
	for _, f := range feeds {
		have[f.Name] = true
	}
	all := []string{FeedPyPI, FeedGo, FeedCrates, FeedRubyGems, FeedNuGet, FeedMaven, FeedPub, FeedHex}
	for _, f := range all {
		if !have[f] {
			t.Errorf("feed %s not created (have %v)", f, have)
		}
	}
	if have[FeedNpm] || have[FeedPackagist] {
		t.Error("release feeds created for ecosystems not in inventory")
	}

	reg.down["/pub/"] = true
	for _, f := range all {
		_, err := sy.Sync(ctx, f)
		if f == FeedPub {
			if err == nil {
				t.Error("pub.dev is down but its feed succeeded")
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}

	want := map[string]struct{ stable, update, yanked string }{
		"pypi":   {"6.1.2", "major", "4.2.12"},
		"golang": {"v1.5.0", "", "v1.6.0"}, // installed v1.6.0 is retracted; v1.5.0 is older
		"cargo":  {"1.0.229", "patch", "1.0.230"},
		"gem":    {"8.1.4", "major", ""},
		"nuget":  {"9.3.3", "patch", "8.1.2"},
		"maven":  {"7.0.10", "major", ""},
		"hex":    {"2.20.0", "minor", "2.6.2"},
	}
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		r, err := st.GetRelease(ctx, row.ComponentID)
		if row.Type == "pub" {
			if err != nil || r.LastError == "" || r.Source != FeedPub {
				t.Errorf("pub release should record the failure: %+v %v", r, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v", row.Purl, err)
		}
		w := want[row.Type]
		if r.LatestStable != w.stable || row.LatestStable != w.stable || row.UpdateType != w.update || r.LastError != "" {
			t.Errorf("%s: release %+v, inventory latest %q update %q; want %+v", row.Purl, r, row.LatestStable, row.UpdateType, w)
		}
		if _, ok := r.Yanked[w.yanked]; w.yanked != "" && !ok {
			t.Errorf("%s: yanked = %v, want %s", row.Purl, r.Yanked, w.yanked)
		}
	}
}
