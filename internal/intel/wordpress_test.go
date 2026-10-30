package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// endoflife.date's wordpress product, trimmed: identifiers name Docker
// images and a CPE, never pkg:generic/wordpress, so the product is found by
// name, as for runtimes. 4.6 and older ended on 2025-07-31; 4.7 and later
// still get security releases.
const wordpressEOL = `{"result":[{"name":"wordpress","label":"WordPress","links":{"html":"https://endoflife.date/wordpress"},
  "identifiers":[{"type":"purl","id":"pkg:docker/library/wordpress"},{"type":"cpe","id":"cpe:2.3:a:wordpress:wordpress"}],
  "releases":[
    {"name":"6.9","label":"6.9","releaseDate":"2025-12-02","isEol":false,"latest":{"name":"6.9.11","date":"2026-10-01"}},
    {"name":"6.8","label":"6.8","releaseDate":"2025-04-15","isEol":false,"latest":{"name":"6.8.12","date":"2026-10-01"}},
    {"name":"6.5","label":"6.5","releaseDate":"2024-04-02","isEol":false,"latest":{"name":"6.5.14","date":"2026-10-01"}},
    {"name":"4.7","label":"4.7","releaseDate":"2016-12-06","isEol":false,"latest":{"name":"4.7.31","date":"2026-10-01"}},
    {"name":"4.6","label":"4.6","releaseDate":"2016-08-16","isEol":true,"eolFrom":"2025-07-31","latest":{"name":"4.6.30","date":"2025-04-15"}}]},
  {"name":"nodejs","label":"Node.js","links":{"html":"https://endoflife.date/nodejs"},"identifiers":[],
  "releases":[{"name":"20","label":"20","releaseDate":"2023-04-18","isEol":false,"eolFrom":"2099-04-30","latest":{"name":"20.19.0","date":"2025-03-13"}}]}]}`

func wpCore(version, dir string) model.Observation {
	return model.Observation{Purl: "pkg:generic/wordpress@" + version, Version: version, Confidence: model.ConfidenceConfirmed,
		Location: dir + "/wp-includes/version.php",
		Evidence: map[string]string{"kind": "cms", "product": "WordPress core", "source": "version-file", "app_dir": dir}}
}

// WordPress core, read from wp-includes/version.php, gets endoflife.date's
// wordpress release lines: an ended branch is an end-of-life finding naming
// the branch's latest release, in the stack's WordPress core layer; a
// supported branch behind its latest release is a finding fixed by that
// release; a supported branch at its latest release, or a pre-release or
// development build, has none. Vulnerabilities are not matched, and its
// rows say so.
func TestWordPressCoreLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	old := ingest(t, st, model.AssetApplication, "/var/www/old", true, wpCore("4.6.3", "/var/www/old"))
	current := ingest(t, st, model.AssetApplication, "/var/www/blog", true, wpCore("6.5.14", "/var/www/blog"))
	behind := ingest(t, st, model.AssetApplication, "/var/www/shop", true, wpCore("6.5.3", "/var/www/shop"))
	oneBehind := ingest(t, st, model.AssetApplication, "/var/www/news", true, wpCore("6.5.13", "/var/www/news"))
	// Behind is for WordPress only: a Node.js point release is not always a
	// security release.
	node := ingest(t, st, model.AssetHost, "web-1", true,
		confirmed("pkg:generic/nodejs@20.11.1", map[string]string{"kind": "runtime", "install": "unmanaged"}))
	rc := ingest(t, st, model.AssetApplication, "/var/www/next", true, wpCore("6.9-RC1", "/var/www/next"))
	dev := ingest(t, st, model.AssetApplication, "/var/www/dev", true, wpCore("7.2-alpha-61234-src", "/var/www/dev"))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/eol.json", wordpressEOL)
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	ev.Now = func() time.Time { return time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC) }
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}

	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: old})
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Key != "wordpress:4.6" || fs[0].Kind != "end_of_life" || fs[0].Verification != "confirmed" ||
		fs[0].Title != "WordPress 4.6 is end-of-life since 2025-07-31" || fs[0].Severity != "high" {
		t.Fatalf("4.6.3 findings = %+v", fs)
	}
	var evidence struct {
		Product string         `json:"product"`
		Latest  string         `json:"latest_in_cycle"`
		Behind  int            `json:"releases_behind"`
		Match   map[string]any `json:"match"`
	}
	// 27 releases behind 4.6.30 as well: high, as a behind finding would be.
	if err := json.Unmarshal(fs[0].Evidence, &evidence); err != nil || evidence.Product != "wordpress" || evidence.Latest != "4.6.30" ||
		evidence.Behind != 27 || evidence.Match["rule"] != "version_prefix" {
		t.Errorf("evidence = %s", fs[0].Evidence)
	}
	for name, id := range map[string]int64{"6.5.14": current, "6.9-RC1": rc, "7.2-alpha": dev, "nodejs 20.11.1": node} {
		if fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: id}); len(fs) != 0 {
			t.Errorf("%s: findings %+v", name, fs)
		}
	}

	// Behind 6.5.14: one finding fixed by it, high from three releases
	// behind. The ended 4.6 above has its end-of-life finding only, which
	// names 4.6.30 already.
	for id, want := range map[int64]struct {
		title, severity string
		n               float64
	}{
		behind:    {"WordPress 6.5.3 is 11 releases behind 6.5.14, the latest WordPress 6.5 release", "high", 11},
		oneBehind: {"WordPress 6.5.13 is 1 release behind 6.5.14, the latest WordPress 6.5 release", "medium", 1},
	} {
		fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: id})
		if len(fs) != 1 {
			t.Fatalf("%s: findings %+v", want.title, fs)
		}
		f := fs[0]
		var ev map[string]any
		_ = json.Unmarshal(f.Evidence, &ev)
		m, _ := ev["match"].(map[string]any)
		if f.Kind != "vulnerability" || f.Key != "behind:wordpress:6.5" || f.Title != want.title || f.Severity != want.severity ||
			f.FixedVersion != "6.5.14" || f.Verification != "confirmed" || ev["releases_behind"] != want.n || m["rule"] != "behind_latest_release" ||
			ev["group_title"] != "WordPress 6.5 sites behind 6.5.14" {
			t.Errorf("finding %+v, evidence %s", f, f.Evidence)
		}
	}

	// The action plan: update WordPress core to the branch's latest release.
	if _, err := planner.Rebuild(ctx, st, ev.Now()); err != nil {
		t.Fatal(err)
	}
	raw, _, err := st.ListFixGroups(ctx, store.FixGroupFilter{AssetID: behind})
	if err != nil || len(raw) != 1 {
		t.Fatalf("fix groups = %d, %v", len(raw), err)
	}
	var g fixplan.Group
	_ = json.Unmarshal(raw[0], &g)
	if g.Kind != fixplan.PackageUpgrade || g.TargetVersion != "6.5.14" || g.Title != "Update WordPress core 6.5.3 → 6.5.14" ||
		!strings.HasPrefix(g.Action, "Update WordPress core to 6.5.14") {
		t.Errorf("fix group = %+v", g)
	}

	stack, err := st.GetStack(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if len(stack.Layers) != 1 || stack.Layers[0].Layer != "cms" || len(stack.Findings) != 1 {
		t.Errorf("stack layers = %+v", stack.Layers)
	}

	gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{})
	wp := false
	for _, g := range gaps {
		wp = wp || g.PurlKey == "pkg:generic/wordpress" && g.AssetCount == 6 &&
			strings.HasPrefix(g.Reason, "content management system core: lifecycle is tracked")
	}
	if !wp {
		t.Errorf("gaps = %+v", gaps)
	}
	rep, err := CoverageGaps(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cms := false
	for _, g := range rep.NoVulnerabilitySource {
		cms = cms || g.Kind == "generic|cms" && g.Label == "WordPress core" && g.Assets == 6
	}
	// The development build's line (7.2) is not in the lifecycle data yet.
	line := false
	for _, g := range rep.NoLifecycle {
		line = line || g.Kind == "no_release_line|wordpress" && g.Label == "WordPress" && g.Assets == 1
	}
	if !cms || !line {
		t.Errorf("coverage gaps: no vulnerability source %+v, no lifecycle %+v", rep.NoVulnerabilitySource, rep.NoLifecycle)
	}

	// 6.5 ends: the end-of-life finding replaces the behind finding, keeps
	// its high severity, and the behind finding says why it closed.
	up.set("/eol.json", strings.Replace(wordpressEOL, `{"name":"6.5","label":"6.5","releaseDate":"2024-04-02","isEol":false,`,
		`{"name":"6.5","label":"6.5","releaseDate":"2024-04-02","isEol":true,"eolFrom":"2026-10-15",`, 1))
	if _, err := sy.Sync(ctx, FeedEndOfLife); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	all, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: behind, Status: "all"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]store.Finding{}
	for _, f := range all {
		got[f.Key] = f
	}
	if f := got["wordpress:6.5"]; f.Status != "open" || f.Kind != "end_of_life" || f.Severity != "high" {
		t.Errorf("end of life: %+v", f)
	}
	if f := got["behind:wordpress:6.5"]; f.Status != "resolved" || f.ResolutionKind != store.ResolutionAdvisoryChanged ||
		f.Resolution != "replaced by the end-of-life finding: wordpress 6.5 reached end of life" {
		t.Errorf("behind: %s %s %q", f.Status, f.ResolutionKind, f.Resolution)
	}
	if fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: oneBehind}); len(fs) != 1 || fs[0].Kind != "end_of_life" || fs[0].Severity != "medium" {
		t.Errorf("one behind, ended: %+v", fs)
	}
}
