package intel

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/javaapps"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
)

// rollerAdvisories reads NVD's answer for cpe:2.3:a:apache:roller (15 CVEs
// on 22 November 2026, saved from the CVE API) as the feed stores it.
func rollerAdvisories(t *testing.T) (map[string]*osv.Vulnerability, []store.AdvisoryMatch) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "javaapps", "nvd-apache-roller.json"))
	if err != nil {
		t.Fatal(err)
	}
	var page nvdResponse
	if err := json.Unmarshal(b, &page); err != nil {
		t.Fatal(err)
	}
	p := javaapps.Default().Product("apache-roller")
	recs := map[string]*osv.Vulnerability{}
	var advs []store.AdvisoryMatch
	for _, w := range page.Vulnerabilities {
		v := nvdRecord(p, w.CVE, nvdAnomalies{})
		if v == nil {
			continue
		}
		recs[w.CVE.ID] = v
		advs = append(advs, store.AdvisoryMatch{ID: v.ID, GroupKey: w.CVE.ID, Aliases: v.Aliases, Summary: v.Summary,
			Feed: FeedJavaApps, Ecosystem: p.Ecosystem(), Affected: v.Affected[0]})
	}
	return recs, advs
}

// The agent's evidence kind for a Java web application is the one the
// matcher reads.
func TestJavaAppKind(t *testing.T) {
	if apps.KindJavaWebapp != javaapps.Kind {
		t.Fatalf("agent kind %q, catalogue kind %q", apps.KindJavaWebapp, javaapps.Kind)
	}
}

func TestRollerNVDRecords(t *testing.T) {
	recs, _ := rollerAdvisories(t)
	v := recs["CVE-2026-129448"]
	if v == nil {
		t.Fatalf("CVE-2026-129448 not read: %v", recs)
	}
	if v.ID != "NVD-java-apache-roller-CVE-2026-129448" || v.Affected[0].Package.Ecosystem != "Java web applications:apache-roller" {
		t.Errorf("record: %s %+v", v.ID, v.Affected[0].Package)
	}
	evs := v.Affected[0].Ranges[0].Events
	if len(evs) != 2 || evs[0].Introduced != "4.0" || evs[1].Fixed != "6.1.5" {
		t.Errorf("range: %+v", evs)
	}
}

// Apache Roller rows are matched by their release against NVD's records:
// 6.1.4 is affected by the exploited CVE-2026-129448 and the action plan
// gets one update; 3.1 is older than its range; a development build is not
// matched, and an unread feed is a gap, never clean.
func TestEvaluateRoller(t *testing.T) {
	_, advs := rollerAdvisories(t)
	now := time.Now()
	p := javaapps.Default().Product("apache-roller")
	synced := map[string]store.Feed{FeedJavaApps: {Name: FeedJavaApps, Enabled: true, LastSuccess: &now, Ecosystems: []string{p.Ecosystem()}}}
	row := func(v string) store.EvalRow {
		return store.EvalRow{InventoryID: 1, AssetID: 1, ComponentID: 1, Type: "generic", PurlKey: "pkg:generic/apache-roller",
			Purl: "pkg:generic/apache-roller@" + v, Version: v, Confidence: "confirmed", Evidence: map[string]string{"kind": javaapps.Kind}}
	}
	e := &Evaluator{}
	eval := func(v string, feeds map[string]store.Feed) (map[string]store.FindingInput, store.RowCoverage) {
		t.Helper()
		rc := store.RowCoverage{InventoryID: 1, State: store.CoverageEvaluated}
		found, err := e.evaluateJavaApp(context.Background(), row(v), feeds, map[string][]store.AdvisoryMatch{p.ID: advs}, map[string]int{}, &rc)
		if err != nil {
			t.Fatal(err)
		}
		byKey := map[string]store.FindingInput{}
		for _, f := range found {
			byKey[f.Key] = f
		}
		return byKey, rc
	}

	found, rc := eval("6.1.4", synced)
	f, ok := found["CVE-2026-129448"]
	if !ok || f.FixedVersion != "6.1.5" {
		t.Fatalf("6.1.4: %v", keysOf(found))
	}
	if f.Evidence["program"] != "java:apache-roller" || f.Evidence["program_version"] != "6.1.4" || f.Evidence["java_app"] != "apache-roller" {
		t.Errorf("evidence: %v", f.Evidence)
	}
	if rc.State != store.CoverageEvaluated || rc.Feed != FeedJavaApps || !strings.Contains(rc.Reason, "Apache Roller 6.1.4") ||
		!strings.Contains(rc.Reason, "CVE-2026-82384") {
		t.Errorf("6.1.4 coverage: %+v", rc)
	}
	if _, ok := found["CVE-2025-24859"]; !ok {
		t.Errorf("6.1.4 is also before CVE-2025-24859's fix: %v", keysOf(found))
	}

	// NVD's range for CVE-2026-129448 starts at 4.0.
	if found, _ := eval("3.1", synced); found["CVE-2026-129448"].Key != "" {
		t.Errorf("3.1 matched CVE-2026-129448")
	}
	// 6.1.5 is outside NVD's ranges; its coverage says what NVD does not record.
	found, rc = eval("6.1.5", synced)
	if len(found) != 0 || rc.State != store.CoverageEvaluated || !strings.Contains(rc.Reason, "6.1.6") {
		t.Errorf("6.1.5: %v %+v", keysOf(found), rc)
	}
	// A development build is not a release.
	if found, rc := eval("6.1.6-SNAPSHOT", synced); len(found) != 0 || rc.State != store.CoverageUnsupported ||
		!strings.HasPrefix(rc.Reason, javaAppUnsupported+": ") {
		t.Errorf("snapshot: %v %+v", keysOf(found), rc)
	}
	// No feed yet, or one that never read the product: not evaluated.
	if found, rc := eval("6.1.4", map[string]store.Feed{}); len(found) != 0 || rc.State != store.CoverageNotEvaluated {
		t.Errorf("no feed: %+v", rc)
	}
	other := map[string]store.Feed{FeedJavaApps: {Name: FeedJavaApps, Enabled: true, LastSuccess: &now, Ecosystems: []string{"Java web applications:other"}}}
	if found, rc := eval("6.1.4", other); len(found) != 0 || rc.State != store.CoverageNotEvaluated {
		t.Errorf("not read: %+v", rc)
	}
	// A product the catalogue does not list.
	r := row("1.0")
	r.PurlKey, r.Purl = "pkg:generic/other-webapp", "pkg:generic/other-webapp@1.0"
	rc = store.RowCoverage{State: store.CoverageEvaluated}
	if found, err := e.evaluateJavaApp(context.Background(), r, synced, map[string][]store.AdvisoryMatch{}, nil, &rc); err != nil || len(found) != 0 ||
		rc.State != store.CoverageUnsupported {
		t.Errorf("uncatalogued: %v %+v", err, rc)
	}
}

func TestJavaAppFeedNames(t *testing.T) {
	if VulnFeed(javaapps.Ecosystem) != FeedJavaApps {
		t.Errorf("VulnFeed = %s", VulnFeed(javaapps.Ecosystem))
	}
	if base, ok := feedEcosystem(FeedJavaApps); !ok || base != javaapps.Ecosystem {
		t.Errorf("feedEcosystem = %s %v", base, ok)
	}
	cfg := DefaultConfig()
	if src := cfg.Sources(FeedJavaApps); len(src) != 1 || src[0] != cfg.NVDURL {
		t.Errorf("sources: %v", src)
	}
}
