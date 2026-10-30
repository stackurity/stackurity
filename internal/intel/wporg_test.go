package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// fakeWPOrg answers wordpress.org's plugin and theme info APIs from canned
// answers keyed "plugins/<slug>" or "themes/<slug>".
type fakeWPOrg struct {
	mu        sync.Mutex
	answers   map[string]wpAnswer
	requested []string
	lists     map[string]string // "plugins" or "themes" -> listing
}

// svnListing is a Subversion root listing of slugs, as wordpress.org's
// repositories serve it; padding adds n made-up slugs.
func svnListing(padding int, slugs ...string) string {
	var b strings.Builder
	b.WriteString("<html><head><title> - Revision 3775963: /</title></head>\n<body>\n <h2> - Revision 3775963: /</h2>\n <ul>\n")
	for i := 0; i < padding; i++ {
		slugs = append(slugs, fmt.Sprintf("filler-%d", i))
	}
	for _, s := range slugs {
		fmt.Fprintf(&b, "  <li><a href=\"%s/\">%s/</a></li>\n", s, s)
	}
	b.WriteString(" </ul>\n <hr noshade><em>Powered by Apache Subversion</em>\n</body></html>\n")
	return b.String()
}

type wpAnswer struct {
	status int
	body   string
}

func (f *fakeWPOrg) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if list, ok := strings.CutPrefix(r.URL.Path, "/svn/"); ok {
		f.mu.Lock()
		body, ok := f.lists[strings.TrimSuffix(list, "/")]
		f.requested = append(f.requested, "list "+list)
		f.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, body)
		return
	}
	api := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/info/1.2/")
	q := r.URL.Query()
	key := api + "/" + q.Get("request[slug]")
	f.mu.Lock()
	f.requested = append(f.requested, key)
	a, ok := f.answers[key]
	f.mu.Unlock()
	if !ok || q.Get("action") != strings.TrimSuffix(api, "s")+"_information" || q.Get("request[fields][versions]") != "1" {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"error":"Plugin not found."}`)
		return
	}
	w.WriteHeader(a.status)
	_, _ = io.WriteString(w, a.body)
}

func (f *fakeWPOrg) set(key string, status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[key] = wpAnswer{status, body}
}

// wpVersions is a versions map with n stable 9.x releases, a release
// candidate, trunk, and extra.
func wpVersions(n int, extra ...string) string {
	m := map[string]string{"10.0.0-rc.1": "x", "trunk": "x"}
	for i := 0; i < n; i++ {
		m[fmt.Sprintf("9.%d.0", i)] = "x"
	}
	for _, v := range extra {
		m[v] = "x"
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func wpPlugin(slug, name, v string) model.Observation {
	return model.Observation{Purl: "pkg:generic/wordpress-plugin/" + slug + "@" + v, Version: v, Confidence: model.ConfidenceConfirmed,
		Location: "/var/www/shop/wp-content/plugins/" + slug + "/" + slug + ".php", Evidence: map[string]string{"kind": "wordpress-plugin", "name": name}}
}

// The latest releases of installed WordPress plugins and themes come from
// wordpress.org: only installed slugs, never those not from wordpress.org,
// and a closed, unknown, renamed-by-someone-else, truncated or shrunken
// answer says so or keeps what was stored, without failing the feed.
func TestWordPressOrgReleases(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st := store.New(testdb.New(t))
	wp := &fakeWPOrg{answers: map[string]wpAnswer{}, lists: map[string]string{
		"plugins": svnListing(100, "woocommerce", "akismet", "display-widgets", "wp-gdpr-compliance", "impostor", "broken", "hello-dolly", "%e8%b1%86%e7%93%a3"),
		"themes":  svnListing(20, "astra"),
	}}
	srv := httptest.NewServer(wp)
	t.Cleanup(srv.Close)
	cfg := DefaultConfig()
	cfg.WordPressOrgURL = srv.URL
	cfg.WordPressPluginsListURL, cfg.WordPressThemesListURL = srv.URL+"/svn/plugins/", srv.URL+"/svn/themes/"
	sy := NewSyncer(st, slog.New(slog.NewTextHandler(io.Discard, nil)), cfg)

	wp.set("plugins/woocommerce", 200, `{"name":"WooCommerce","slug":"woocommerce","version":"10.3.0","last_updated":"2026-10-09 3:35pm GMT",
		"versions":`+wpVersions(12, "10.3.0")+`}`)
	wp.set("plugins/akismet", 200, `{"name":"Akismet Anti-spam: Spam Protection","slug":"akismet","version":"5.7.2","versions":{"5.3":"x","5.7.2":"x"}}`)
	wp.set("plugins/display-widgets", 404, `{"error":"closed","name":"Display Widgets","slug":"display-widgets","closed":true,
		"closed_date":"2021-01-30","reason":"security-issue","reason_text":"Security Issue"}`)
	// Closed and renamed by wordpress.org: the closure shows all the same.
	wp.set("plugins/wp-gdpr-compliance", 404, `{"error":"closed","name":"Cookie Information | Free WP GDPR Consent Plugin","slug":"wp-gdpr-compliance",
		"closed":true,"closed_date":"2024-02-23","reason":"security-issue","reason_text":"Security Issue"}`)
	wp.set("plugins/hello-dolly", 200, `{"name":"Hello Dolly","slug":"hello-dolly","version":"1.7.2","versions":{"1.7.2":"x"}}`)
	wp.set("plugins/impostor", 200, `{"name":"Totally Different &amp; Unrelated","slug":"impostor","version":"9.0","versions":[]}`)
	wp.set("plugins/broken", 200, `{"name":"Broken","slug":"bro`)
	wp.set("themes/astra", 200, `{"name":"Astra","slug":"astra","version":"4.14.2","last_updated_time":"2026-10-29 13:22:58","versions":{"4.6.0":"x","4.14.2":"x"}}`)

	acme := wpPlugin("acme-pro", "Acme Pro", "3.2.1")
	acme.Evidence["wordpress_org"], acme.Evidence["wordpress_org_reason"] = "no", "its Update URI header says it is updated from updates.acme.example"
	theme := model.Observation{Purl: "pkg:generic/wordpress-theme/astra@4.6.0", Version: "4.6.0", Confidence: model.ConfidenceConfirmed,
		Location: "/var/www/shop/wp-content/themes/astra/style.css", Evidence: map[string]string{"kind": "wordpress-theme", "name": "Astra"}}
	app := ingest(t, st, model.AssetApplication, "/var/www/shop", true,
		wpPlugin("woocommerce", "WooCommerce", "9.9.5"),
		wpPlugin("akismet", "Akismet Anti-Spam", "5.3"), // its older, shorter name
		wpPlugin("display-widgets", "Display Widgets", "2.6.1"),
		wpPlugin("wp-gdpr-compliance", "WP GDPR Compliance", "1.5.5"),
		wpPlugin("hello-dolly", "Hello Dolly", "1.7.2"),
		wpPlugin("custom-thing", "Custom Thing", "1.0"),
		wpPlugin("impostor", "Impostor Pro", "2.0"),
		wpPlugin("broken", "Broken", "1.0"),
		acme, theme)

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	feeds, _ := st.ListFeeds(ctx)
	created := false
	for _, f := range feeds {
		created = created || f.Name == FeedWordPressOrg
		if f.Name == FeedNpm || f.Name == FeedPackagist {
			t.Errorf("feed %s created for WordPress plugins", f.Name)
		}
	}
	if !created {
		t.Fatalf("%s not created: %+v", FeedWordPressOrg, feeds)
	}
	if _, err := sy.Sync(ctx, FeedWordPressOrg); err != nil {
		t.Fatal(err)
	}
	// Nothing private is sent: neither the plugin updated from elsewhere
	// nor the in-house one missing from the public list.
	for _, k := range wp.requested {
		if k == "plugins/acme-pro" || k == "plugins/custom-thing" {
			t.Errorf("%s was sent to wordpress.org", k)
		}
	}

	rows := inventoryByName(t, st, ctx, app)
	for name, want := range map[string]struct{ latest, update, note string }{
		"woocommerce":        {"10.3.0", "major", ""},
		"akismet":            {"5.7.2", "minor", ""},
		"astra":              {"4.14.2", "minor", ""},
		"display-widgets":    {"", "", "closed on wordpress.org since 2021-01-30: Security Issue"},
		"wp-gdpr-compliance": {"", "", "closed on wordpress.org since 2024-02-23: Security Issue"},
		"hello-dolly":        {"1.7.2", "", ""},
		"custom-thing":       {"", "", `not on wordpress.org: "custom-thing" is not in wordpress.org's public plugin list`},
		"impostor":           {"", "", `not the wordpress.org plugin: wordpress.org's "impostor" is "Totally Different & Unrelated", the installed one "Impostor Pro"`},
		"acme-pro":           {"", "", "not from wordpress.org: its Update URI header says it is updated from updates.acme.example"},
	} {
		r := rows[name]
		if r.LatestStable != want.latest || r.UpdateType != want.update || r.ReleaseNote != want.note {
			t.Errorf("%s: latest %q, update %q, note %q", name, r.LatestStable, r.UpdateType, r.ReleaseNote)
		}
	}
	// A truncated answer is an error for that plugin alone.
	if r := rows["broken"]; r.LatestStable != "" || !strings.Contains(r.ReleaseNote, "unreadable or truncated answer") {
		t.Errorf("broken: %+v", r)
	}
	rel, err := st.ReleasesFor(ctx, []int64{rows["woocommerce"].ComponentID})
	if err != nil {
		t.Fatal(err)
	}
	if w := rel[rows["woocommerce"].ComponentID]; w == nil || len(w.StableVersions) != 13 || w.StableVersions[12] != "10.3.0" ||
		w.LatestPublished == nil || w.SourceURL != "https://wordpress.org/plugins/woocommerce/" {
		t.Errorf("woocommerce release = %+v", w)
	}

	// The next answer for WooCommerce has lost most of its versions: it
	// is refused and the stored release kept. Akismet's is truncated now:
	// its stored release is kept too.
	wp.set("plugins/woocommerce", 200, `{"name":"WooCommerce","slug":"woocommerce","version":"10.4.0","versions":{"10.4.0":"x"}}`)
	wp.set("plugins/akismet", 200, `{"name":"Akismet Anti-spam: Spam Protection","slug":"akismet","vers`)
	ageReleases(t, st)
	if _, err := sy.Sync(ctx, FeedWordPressOrg); err != nil {
		t.Fatal(err)
	}
	rows = inventoryByName(t, st, ctx, app)
	if r := rows["woocommerce"]; r.LatestStable != "10.3.0" {
		t.Errorf("shrunken answer replaced the release: %+v", r)
	}
	if r := rows["akismet"]; r.LatestStable != "5.7.2" {
		t.Errorf("truncated answer replaced the release: %+v", r)
	}

	// A truncated plugin list, and a theme list that shrank, are refused:
	// nothing is looked up or marked, what was stored stays, and the feed
	// warns rather than fails while one list is usable; with none, it fails.
	wp.mu.Lock()
	wp.requested = nil
	wp.lists["plugins"] = strings.Split(wp.lists["plugins"], " </ul>")[0]
	wp.lists["themes"] = svnListing(0, "astra")
	wp.mu.Unlock()
	ageReleases(t, st)
	if _, err := sy.Sync(ctx, FeedWordPressOrg); err == nil || !strings.Contains(err.Error(), "truncated") || !strings.Contains(err.Error(), "fewer than half") {
		t.Errorf("both lists refused: %v; requested %v", err, wp.requested)
	}
	for _, k := range wp.requested {
		if !strings.HasPrefix(k, "list ") {
			t.Errorf("%s looked up with no usable list", k)
		}
	}
	rows = inventoryByName(t, st, ctx, app)
	if rows["woocommerce"].LatestStable != "10.3.0" || rows["astra"].LatestStable != "4.14.2" {
		t.Errorf("refused lists changed stored releases: %+v %+v", rows["woocommerce"], rows["astra"])
	}
	wp.mu.Lock()
	wp.lists["themes"] = svnListing(20, "astra")
	wp.mu.Unlock()
	if res, err := sy.Sync(ctx, FeedWordPressOrg); err != nil || !strings.Contains(res.Warning, "truncated") {
		t.Errorf("one list refused: %+v %v", res, err)
	}

	// Vulnerabilities are not matched, and every row says so.
	ev := &Evaluator{Store: st}
	if _, err := ev.Evaluate(ctx, nil, app); err != nil {
		t.Fatal(err)
	}
	for name, r := range inventoryByName(t, st, ctx, app) {
		if r.Coverage != "unsupported" || !strings.HasPrefix(r.CoverageReason, "WordPress plugin or theme: vulnerabilities are not matched yet") {
			t.Errorf("%s coverage %s %q", name, r.Coverage, r.CoverageReason)
		}
	}
	rep, err := CoverageGaps(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	gap := false
	for _, g := range rep.NoVulnerabilitySource {
		gap = gap || g.Kind == "generic|wordpress_extension" && g.Label == "WordPress plugins and themes" && g.Components == 10
	}
	if !gap {
		t.Errorf("coverage gaps %+v", rep.NoVulnerabilitySource)
	}
}

func inventoryByName(t *testing.T, st *store.Store, ctx context.Context, asset int64) map[string]store.InventoryRow {
	t.Helper()
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: asset})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.InventoryRow{}
	for _, r := range rows {
		out[r.Name] = r
	}
	return out
}

func TestAnyNameMatches(t *testing.T) {
	for _, c := range []struct {
		org, installed string
		want           bool
	}{
		{"WooCommerce", "WooCommerce", true},
		{"Akismet Anti-spam: Spam Protection", "Akismet Anti-Spam", true},
		{"Yoast SEO", "Yoast SEO Premium", true},
		{"Contact Form 7", "Contact Form 7", true},
		{"WP Mail SMTP by WPForms &#8211; The SMTP and Email Log Plugin", "WP Mail SMTP", true},
		{"Totally Different", "Impostor Pro", false},
		{"Akismet", "Akis", false},
		{"Akismet", "", false},
	} {
		if got := anyNameMatches(c.org, []string{c.installed}); got != c.want {
			t.Errorf("%q vs %q = %v", c.org, c.installed, got)
		}
	}
}

// ageReleases makes every stored release due for a refresh.
func ageReleases(t *testing.T, st *store.Store) {
	t.Helper()
	tag, err := st.Pool.Exec(tenant.System(context.Background()), `UPDATE package_releases SET checked_at = now() - interval '2 days'`)
	if err != nil || tag.RowsAffected() == 0 {
		t.Fatalf("aged %d releases: %v", tag.RowsAffected(), err)
	}
}
