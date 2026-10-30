package intel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

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
    {"name":"4.7","label":"4.7","releaseDate":"2016-12-06","isEol":false,"latest":{"name":"4.7.31","date":"2026-10-01"}},
    {"name":"4.6","label":"4.6","releaseDate":"2016-08-16","isEol":true,"eolFrom":"2025-07-31","latest":{"name":"4.6.30","date":"2025-04-15"}}]}]}`

func wpCore(version, dir string) model.Observation {
	return model.Observation{Purl: "pkg:generic/wordpress@" + version, Version: version, Confidence: model.ConfidenceConfirmed,
		Location: dir + "/wp-includes/version.php",
		Evidence: map[string]string{"kind": "cms", "product": "WordPress core", "source": "version-file", "app_dir": dir}}
}

// WordPress core, read from wp-includes/version.php, gets endoflife.date's
// wordpress release lines: an ended branch is an end-of-life finding naming
// the branch's latest release, in the stack's WordPress core layer; a
// supported branch or a pre-release of one is not. Vulnerabilities are not
// matched, and its rows say so.
func TestWordPressCoreLifecycle(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	old := ingest(t, st, model.AssetApplication, "/var/www/old", true, wpCore("4.6.3", "/var/www/old"))
	current := ingest(t, st, model.AssetApplication, "/var/www/blog", true, wpCore("6.8.1", "/var/www/blog"))
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
		fs[0].Title != "WordPress 4.6 is end-of-life since 2025-07-31" {
		t.Fatalf("4.6.3 findings = %+v", fs)
	}
	var evidence struct {
		Product string         `json:"product"`
		Latest  string         `json:"latest_in_cycle"`
		Match   map[string]any `json:"match"`
	}
	if err := json.Unmarshal(fs[0].Evidence, &evidence); err != nil || evidence.Product != "wordpress" || evidence.Latest != "4.6.30" ||
		evidence.Match["rule"] != "version_prefix" {
		t.Errorf("evidence = %s", fs[0].Evidence)
	}
	for name, id := range map[string]int64{"6.8.1": current, "6.9-RC1": rc, "7.2-alpha": dev} {
		if fs, _, _ := st.ListFindings(ctx, store.FindingFilter{AssetID: id}); len(fs) != 0 {
			t.Errorf("%s: findings %+v", name, fs)
		}
	}

	stack, err := st.GetStack(ctx, old)
	if err != nil {
		t.Fatal(err)
	}
	if len(stack.Layers) != 1 || stack.Layers[0].Layer != "cms" || len(stack.Findings) != 1 {
		t.Errorf("stack layers = %+v", stack.Layers)
	}

	gaps, _, _ := st.ListEvaluationGaps(ctx, store.Page{})
	if len(gaps) != 1 || gaps[0].AssetCount != 4 || !strings.HasPrefix(gaps[0].Reason, "content management system core: lifecycle is tracked") {
		t.Errorf("gaps = %+v", gaps)
	}
	rep, err := CoverageGaps(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	cms := false
	for _, g := range rep.NoVulnerabilitySource {
		cms = cms || g.Kind == "generic|cms" && g.Label == "WordPress core" && g.Assets == 4
	}
	// The development build's line (7.2) is not in the lifecycle data yet.
	line := false
	for _, g := range rep.NoLifecycle {
		line = line || g.Kind == "no_release_line|wordpress" && g.Label == "WordPress" && g.Assets == 1
	}
	if !cms || !line {
		t.Errorf("coverage gaps: no vulnerability source %+v, no lifecycle %+v", rep.NoVulnerabilitySource, rep.NoLifecycle)
	}
}
