package registry

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/tenant"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func ociConfig(f *fakeOCI) Config { return Config{Provider: OCI, URL: f.URL()} }

func repoOf(t *testing.T, res *Result, name string) RepoResult {
	t.Helper()
	for _, r := range res.Repositories {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("repository %s not in the result (%d repositories)", name, len(res.Repositories))
	return RepoResult{}
}

func tagsOf(rr RepoResult) [][]string {
	var out [][]string
	for _, im := range rr.Images {
		out = append(out, im.Tags)
	}
	return out
}

func TestDiscoverOCIPagesFiltersAndPicksRecentTags(t *testing.T) {
	f := newFakeOCI(t)
	// shop: tags pushed out of lexical order; 1.10 is the newest, and
	// "latest" is a second tag on it (one image, not two).
	newest := newFakeImage(t0.Add(3*time.Hour), "a")
	f.push("team/shop", "1.9", newFakeImage(t0.Add(2*time.Hour), "b"))
	f.push("team/shop", "1.10", newest)
	f.push("team/shop", "latest", newest)
	f.push("team/shop", "1.2", newFakeImage(t0.Add(1*time.Hour), "c"))
	f.push("team/shop", "dev-abc", newFakeImage(t0, "d"))
	f.push("team/api", "2.0.0", newFakeImage(t0, "e"))
	f.push("team/api-test", "1", newFakeImage(t0, "f"))
	f.push("other/x", "1", newFakeImage(t0, "g")) // outside the namespace

	cfg := ociConfig(f)
	cfg.Namespace = "team"
	cfg.Exclude = []string{"*-test"}
	cfg.RecentTags = 2
	res, err := Discover(ws1(), cfg, Credentials{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ListComplete || !res.Listed["team/api-test"] || res.Listed["other/x"] {
		t.Errorf("listing: complete=%v listed=%v (pages of 2 must all be read; namespace limits it)", res.ListComplete, res.Listed)
	}
	if len(res.Repositories) != 2 {
		t.Fatalf("tracked %d repositories, want team/api and team/shop (team/api-test excluded)", len(res.Repositories))
	}
	shop := repoOf(t, res, "team/shop")
	got := tagsOf(shop)
	if len(got) != 2 || strings.Join(got[0], ",") != "1.10,latest" || strings.Join(got[1], ",") != "1.9" {
		t.Errorf("shop images = %v, want [[1.10 latest] [1.9]]: the two most recently pushed, by build time, one image per digest", got)
	}
	if !shop.TagsComplete || len(shop.Tags) != 5 {
		t.Errorf("shop tags complete=%v %v", shop.TagsComplete, shop.Tags)
	}
	im := shop.Images[0]
	host := strings.TrimPrefix(f.URL(), "https://")
	if im.Ref != host+"/team/shop@"+newest.digest || im.Display != host+"/team/shop:1.10" || !im.Pushed.Equal(t0.Add(3*time.Hour)) {
		t.Errorf("image = %+v", im)
	}
	if res.Host != "127.0.0.1" {
		t.Errorf("host = %q", res.Host)
	}
}

func TestDiscoverPatternsAndDigestDedupe(t *testing.T) {
	f := newFakeOCI(t)
	one := newFakeImage(t0, "1")
	f.push("app", "v1.0.0", one)
	f.push("app", "stable", one) // a re-tag: same digest
	f.push("app", "v1.1.0-rc.1", newFakeImage(t0.Add(time.Hour), "2"))
	f.push("app", "nightly-2", newFakeImage(t0.Add(3*time.Hour), "3"))
	f.push("app", "notsemver1.0", newFakeImage(t0.Add(-time.Hour), "4"))
	cfg := ociConfig(f)
	cfg.TagPatterns = []string{"semver", "stable"}
	res, err := Discover(ws1(), cfg, Credentials{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := tagsOf(repoOf(t, res, "app"))
	want := "nightly-2|v1.1.0-rc.1|v1.0.0,stable"
	var parts []string
	for _, g := range got {
		parts = append(parts, strings.Join(g, ","))
	}
	if strings.Join(parts, "|") != want {
		t.Errorf("images = %v, want %s: the newest tag, then the pattern tags; one image for the digest behind two tags", got, want)
	}

	// A second run that knows the digests reads no configuration blob:
	// a digest seen before is not read again.
	known := map[string]time.Time{}
	for _, im := range repoOf(t, res, "app").Images {
		known[im.Digest] = im.Pushed
	}
	known[newFakeImage(t0.Add(-time.Hour), "4").digest] = t0.Add(-time.Hour)
	before := f.count("/v2/app/blobs/")
	if _, err := Discover(ws1(), cfg, Credentials{}, known); err != nil {
		t.Fatal(err)
	}
	if n := f.count("/v2/app/blobs/") - before; n != 0 {
		t.Errorf("second run read %d configuration blobs, want 0", n)
	}
}

func TestDiscoverTokenFlow(t *testing.T) {
	f := newFakeOCI(t)
	f.User, f.Secret = "robot", "s3cret-password"
	f.push("app", "1.0", newFakeImage(t0, "x"))
	cfg := ociConfig(f)
	cfg.Username = "robot"
	res, err := Discover(ws1(), cfg, Credentials{Secret: f.Secret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(repoOf(t, res, "app").Images) != 1 {
		t.Fatalf("no image found through the token flow")
	}
	basic := "Basic " + base64.StdEncoding.EncodeToString([]byte("robot:s3cret-password"))
	for _, q := range f.all() {
		switch {
		case q.Path == "/token" && q.Auth != basic:
			t.Errorf("token request without the credentials: %q", q.Auth)
		case q.Path != "/token" && strings.Contains(q.Auth, "Basic"):
			t.Errorf("credentials sent to %s %s; only the token service gets them", q.Method, q.Path)
		}
	}

	// Wrong credentials: the error says so and never echoes the secret.
	_, err = Discover(ws1(), cfg, Credentials{Secret: "wrong-password-xyz"}, nil)
	if err == nil || strings.Contains(err.Error(), "wrong-password-xyz") {
		t.Errorf("err = %v", err)
	}
}

// A registry's challenge names the host credentials go to. One naming a
// host other than the registry (or its configured token service) is
// refused without contacting it.
func TestHostileRealmGetsNoCredentials(t *testing.T) {
	evil := newFakeOther(t, nil)
	evilURL := on(evil.srv.URL, "evil.test")
	f := newFakeOCI(t)
	f.User, f.Secret = "robot", "s3cret-password"
	f.Realm = evilURL + "/token"
	f.push("app", "1.0", newFakeImage(t0, "x"))
	cfg := ociConfig(f)
	cfg.Username = "robot"
	_, err := Discover(ws1(), cfg, Credentials{Secret: f.Secret}, nil)
	if err == nil || !strings.Contains(err.Error(), "refused to authenticate at evil.test") {
		t.Errorf("err = %v, want a refusal naming evil.test", err)
	}
	if got := evil.all(); len(got) != 0 {
		t.Errorf("the hostile realm received %d requests: %+v", len(got), got)
	}

	// Anonymous access is refused the same way: the realm is never contacted.
	_, _ = Discover(ws1(), cfg, Credentials{}, nil)
	if got := evil.all(); len(got) != 0 {
		t.Errorf("the hostile realm received %d anonymous requests", len(got))
	}

	// Control: an admin who names that host as the token service sends the
	// credentials there (this test would see them).
	cfg.AuthHost = strings.TrimPrefix(evilURL, "https://")
	_, _ = Discover(ws1(), cfg, Credentials{Secret: f.Secret}, nil)
	sent := false
	for _, q := range evil.all() {
		if q.Auth != "" {
			sent = true
		}
	}
	if !sent {
		t.Error("control: with auth_host naming the realm, the credentials should reach it")
	}

	// The same host on another port is another host.
	f.Realm = on(evil.srv.URL, "127.0.0.1") + "/token"
	cfg.AuthHost = ""
	n := len(evil.all())
	if _, err := Discover(ws1(), cfg, Credentials{Secret: f.Secret}, nil); err == nil {
		t.Error("a realm on another port was accepted")
	}
	if len(evil.all()) != n {
		t.Error("a realm on another port was contacted")
	}
}

func TestRealmMustBeHTTPS(t *testing.T) {
	f := newFakeOCI(t)
	f.User, f.Secret = "robot", "pw"
	f.Realm = strings.Replace(f.URL(), "https://", "http://", 1) + "/token"
	f.push("app", "1.0", newFakeImage(t0, "x"))
	cfg := ociConfig(f)
	cfg.Username = "robot"
	if _, err := Discover(ws1(), cfg, Credentials{Secret: "pw"}, nil); err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Errorf("err = %v", err)
	}
}

// Blob downloads are redirected to storage on another host. The redirect
// is followed without the credentials.
func TestRedirectToAnotherHostDropsCredentials(t *testing.T) {
	var f *fakeOCI
	storage := newFakeOther(t, func(w http.ResponseWriter, r *http.Request) {
		d := strings.TrimPrefix(r.URL.Path, "/storage/")
		for _, tags := range f.repos {
			for _, im := range tags {
				if im.cfgDig == d {
					_, _ = w.Write(im.config)
					return
				}
			}
		}
		w.WriteHeader(404)
	})
	f = newFakeOCI(t)
	f.User, f.Secret, f.Basic = "robot", "s3cret-password", true
	// Storage on a subdomain of the registry: net/http itself would keep
	// the credentials on this redirect.
	f.BlobRedirect = on(storage.srv.URL, "cdn.registry.test")
	f.push("app", "1.0", newFakeImage(t0, "x"))
	cfg := ociConfig(f)
	cfg.URL = on(f.URL(), "registry.test")
	cfg.Username = "robot"
	res, err := Discover(ws1(), cfg, Credentials{Secret: f.Secret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if im := repoOf(t, res, "app").Images; len(im) != 1 || !im[0].Pushed.Equal(t0) {
		t.Fatalf("images = %+v: the configuration should have been read from storage", im)
	}
	got := storage.all()
	if len(got) == 0 {
		t.Fatal("storage was not asked: the test did not exercise the redirect")
	}
	for _, q := range got {
		if q.Auth != "" {
			t.Errorf("credentials sent to storage on another host: %q", q.Auth)
		}
	}
	// The registry itself did get them (basic authentication).
	if all := f.all(); all[len(all)-1].Auth == "" {
		t.Error("control: the registry should have received the credentials")
	}
}

func TestCheckRedirect(t *testing.T) {
	mk := func(u string) *http.Request {
		r, _ := http.NewRequest(http.MethodGet, u, nil)
		r.Header.Set("Authorization", "Bearer x")
		return r
	}
	via := []*http.Request{mk("https://registry.example.com/v2/a/blobs/x")}
	for _, c := range []struct {
		to       string
		keepAuth bool
		err      bool
	}{
		{"https://registry.example.com/other", true, false},
		{"https://registry.example.com:443/other", true, false},
		{"https://cdn.registry.example.com/blob", false, false}, // a subdomain is another host
		{"https://registry.example.com:8443/blob", false, false},
		{"https://storage.example.net/blob", false, false},
		{"http://registry.example.com/blob", false, true},
	} {
		r := mk(c.to)
		err := checkRedirect(r, via)
		if (err != nil) != c.err {
			t.Errorf("%s: err = %v", c.to, err)
		}
		if err == nil && (r.Header.Get("Authorization") != "") != c.keepAuth {
			t.Errorf("%s: authorization kept = %v, want %v", c.to, !c.keepAuth, c.keepAuth)
		}
	}
	long := make([]*http.Request, 5)
	for i := range long {
		long[i] = via[0]
	}
	if checkRedirect(mk("https://registry.example.com/x"), long) == nil {
		t.Error("a sixth redirect was followed")
	}
}

func TestNextPageOnAnotherHostRefused(t *testing.T) {
	evil := newFakeOther(t, nil)
	f := newFakeOCI(t)
	f.NextHost = strings.TrimPrefix(on(evil.srv.URL, "evil.test"), "https://")
	for _, r := range []string{"a", "b", "c"} {
		f.push(r, "1", newFakeImage(t0, r))
	}
	_, err := Discover(ws1(), ociConfig(f), Credentials{}, nil)
	if err == nil || !strings.Contains(err.Error(), "another host") {
		t.Errorf("err = %v", err)
	}
	if len(evil.all()) != 0 {
		t.Error("the next page on another host was requested")
	}
}

func TestNamedRepositoriesNeedNoCatalog(t *testing.T) {
	f := newFakeOCI(t)
	f.NoCatalog = true
	f.push("app", "1", newFakeImage(t0, "1"))
	if _, err := Discover(ws1(), ociConfig(f), Credentials{}, nil); err == nil || !strings.Contains(err.Error(), "repositories") {
		t.Errorf("err = %v, want advice to name the repositories", err)
	}
	cfg := ociConfig(f)
	cfg.Repositories = []string{"app", "gone"}
	res, err := Discover(ws1(), cfg, Credentials{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(repoOf(t, res, "app").Images) != 1 || !repoOf(t, res, "gone").Gone || res.ListComplete {
		t.Errorf("result = %+v", res)
	}
	if f.count("/v2/_catalog") != 1 {
		t.Error("the catalog was read although the repositories were named")
	}
}

// Registry requests go through netguard: a workspace that may not reach
// private networks cannot reach a registry on one.
func TestRegistryRequestsAreGuarded(t *testing.T) {
	defer netguard.Set(netguard.FromEnv())
	netguard.Set(netguard.Config{Mode: "default"})
	f := newFakeOCI(t)
	f.push("app", "1", newFakeImage(t0, "1"))
	ws2 := tenant.WithWorkspace(context.Background(), 2)
	_, err := Discover(ws2, ociConfig(f), Credentials{}, nil)
	if !errors.Is(err, netguard.ErrBlocked) {
		t.Errorf("err = %v, want netguard.ErrBlocked", err)
	}
	if len(f.all()) != 0 {
		t.Error("the registry on a private address was reached")
	}
	if _, err := Discover(ws1(), ociConfig(f), Credentials{}, nil); err != nil {
		t.Errorf("control: the default workspace may reach it: %v", err)
	}
}

func TestParseChallenge(t *testing.T) {
	c, ok := parseChallenge(`Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull,push"`)
	if !ok || c.scheme != "bearer" || c.params["realm"] != "https://auth.docker.io/token" || c.params["service"] != "registry.docker.io" ||
		c.params["scope"] != "repository:library/nginx:pull,push" {
		t.Errorf("%+v", c)
	}
	if c, _ := parseChallenge(`Basic realm=fake`); c.scheme != "basic" || c.params["realm"] != "fake" {
		t.Errorf("%+v", c)
	}
}

func TestAuthority(t *testing.T) {
	for in, want := range map[string]string{
		"https://Ghcr.io/token":       "ghcr.io:443",
		"https://ghcr.io:443/x":       "ghcr.io:443",
		"https://[::1]:5000/x":        "[::1]:5000",
		"http://registry.local/x":     "registry.local:80",
		"https://registry.local:8443": "registry.local:8443",
	} {
		u, _ := url.Parse(in)
		if got := authority(u); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

func TestStillTagged(t *testing.T) {
	a, b := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	rr := RepoResult{TagsComplete: true, Tags: map[string]string{"latest": b, "1.0": a, "old": ""}}
	for _, c := range []struct {
		digest string
		had    []string
		want   bool
	}{
		{a, []string{"1.0"}, true},                                       // still tagged
		{a, []string{"latest"}, true},                                    // another tag points to it
		{"sha256:" + strings.Repeat("c", 64), []string{"latest"}, false}, // its tag moved
		{"sha256:" + strings.Repeat("c", 64), []string{"gone"}, false},   // its tag was deleted
		{"sha256:" + strings.Repeat("c", 64), []string{"old"}, true},     // its tag is there, digest not read
	} {
		if got := rr.StillTagged(c.digest, c.had); got != c.want {
			t.Errorf("%s %v: %v", c.digest[:10], c.had, got)
		}
	}
	rr.TagsComplete = false
	if !rr.StillTagged("sha256:"+strings.Repeat("c", 64), []string{"gone"}) {
		t.Error("an incomplete tag list proved an image gone")
	}
}
