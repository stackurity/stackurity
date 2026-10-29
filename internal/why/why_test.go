package why

import (
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
)

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func at(d time.Duration) *time.Time { t := now.Add(-d); return &t }

func vuln(ev map[string]any) Input {
	return Input{
		Finding: &store.Finding{ID: 1, Kind: "vulnerability", Key: "CVE-2099-1", Version: "6.10.0", FixedVersion: "7.0.7",
			Verification: "confirmed", ComponentType: "npm", AssetKind: "repository", Sources: []string{"GHSA-xxxx"}},
		Evidence: ev,
		Inventory: store.InventoryProvenance{CollectorID: "lockfile", Location: "web/package-lock.json", Confidence: "confirmed",
			LastSeen: at(2 * time.Hour)},
		Feed: &store.Feed{Name: "osv:npm", LastSuccess: at(3 * time.Hour)},
	}
}

func npmEvidence() map[string]any {
	return map[string]any{"matched_ranges": []any{"GHSA-xxxx: < 7.0.7"}, "comparator": "semver", "target_ecosystem": "npm",
		"osv_package": "nodemailer", "feed": "osv:npm", "match": map[string]any{"rule": "range", "record": "GHSA-xxxx"}}
}

func TestSentenceForAPackageAdvisory(t *testing.T) {
	e := Build(vuln(npmEvidence()), now)
	want := "Installed 6.10.0 (from web/package-lock.json, seen 2 h ago) is in the affected range < 7.0.7 of GHSA-xxxx " +
		"(osv:npm, refreshed 3 h ago), compared with SemVer rules; fixed in 7.0.7."
	if e.Sentence != want {
		t.Fatalf("sentence\n got %s\nwant %s", e.Sentence, want)
	}
	if e.Type != TypePackageAdvisory || e.Package == nil || e.Rule.Kind != "range" || len(e.Missing) != 0 ||
		!strings.Contains(e.StateText, "does not show that the issue can be exploited") {
		t.Fatalf("%+v", e)
	}
}

func TestRulesAndTypes(t *testing.T) {
	ev := npmEvidence()
	ev["match"] = map[string]any{"rule": "last_affected", "record": "GHSA-xxxx"}
	ev["matched_ranges"] = []any{"GHSA-xxxx: <= 7.0.6"}
	if e := Build(vuln(ev), now); !strings.Contains(e.Sentence, "<= 7.0.6 (last affected version included)") {
		t.Errorf("last_affected: %s", e.Sentence)
	}
	ev["match"] = map[string]any{"rule": "listed_version", "record": "GHSA-xxxx"}
	if e := Build(vuln(ev), now); !strings.Contains(e.Sentence, "is listed as affected by GHSA-xxxx") {
		t.Errorf("listed: %s", e.Sentence)
	}
	// A distro backport, in a container image.
	in := vuln(map[string]any{"matched_ranges": []any{"DEBIAN-CVE-2099-1: < 3.0.11-1~deb12u2"}, "comparator": "debian",
		"target_ecosystem": "Debian:12", "osv_package": "openssl", "feed": "osv:Debian",
		"match": map[string]any{"rule": "range", "record": "DEBIAN-CVE-2099-1", "backport": true}})
	in.Finding.ComponentType, in.Finding.AssetKind, in.Finding.AssetName = "deb", "image", "registry.example/web:1"
	in.Finding.Version, in.Finding.FixedVersion = "3.0.11-1~deb12u1", "3.0.11-1~deb12u2"
	in.Inventory = store.InventoryProvenance{CollectorID: "image-scan", Confidence: "confirmed", LastSeen: at(26 * time.Hour)}
	e := Build(in, now)
	if e.Type != TypeContainerImage || e.Image == nil || e.Image.Inner != TypeOSPackage || e.OS == nil || !e.OS.Backport ||
		!strings.Contains(e.Sentence, "backported the fix") || !strings.Contains(e.Sentence, "Debian version rules (dpkg)") ||
		!strings.Contains(e.Sentence, "the image-scan collector, seen 26 h ago") {
		t.Errorf("backport in an image: %s %+v", e.Sentence, e)
	}
	// Stored before 1.0: no rule recorded, said so, never guessed.
	old := npmEvidence()
	delete(old, "match")
	if e := Build(vuln(old), now); !strings.Contains(e.Rule.Text, "rule not recorded") {
		t.Errorf("legacy: %+v", e.Rule)
	}
}

func TestMissingInformation(t *testing.T) {
	in := vuln(npmEvidence())
	in.Finding.Verification = "needs_validation"
	in.Inventory.Confidence, in.Inventory.CollectorID = "inferred", "linux-software"
	in.Inventory.Evidence = map[string]string{"detected_by": "binary banner"}
	in.SecondCheck = &store.SecondCheck{Result: store.SecondCheckDisagreed, Reason: "fixed version: the matcher says 7.0.7, the second check finds 7.0.8"}
	in.Feed.Stale = true
	e := Build(in, now)
	if len(e.Missing) != 3 || !strings.Contains(e.Missing[0], `confidence "inferred" (detected by binary banner)`) ||
		!strings.Contains(e.Missing[1], "second check, which disagreed") || !strings.Contains(e.Missing[2], "successful refresh") ||
		!strings.Contains(e.SecondCheckText, "disagreed") || !e.NeedsReview ||
		!strings.HasPrefix(e.StateText, "Needs validation: the second check disagreed (fixed version") {
		t.Fatalf("%q\n%s", e.Missing, e.SecondCheckText)
	}
	in = vuln(npmEvidence())
	in.Finding.Verification = "stale"
	in.Inventory.LastSeen = at(5 * 24 * time.Hour)
	if e := Build(in, now); len(e.Missing) != 1 || !strings.Contains(e.Missing[0], "last seen 5 d ago") {
		t.Errorf("stale: %q", e.Missing)
	}
	in = vuln(npmEvidence())
	in.Covered = true
	if e := Build(in, now); !strings.Contains(e.SecondCheckText, "has not run") {
		t.Errorf("covered, not run: %s", e.SecondCheckText)
	}
}

func TestEndOfLifeSentence(t *testing.T) {
	in := Input{
		Finding: &store.Finding{Kind: "end_of_life", Version: "3.8.10", Verification: "confirmed", ComponentType: "generic"},
		Evidence: map[string]any{"product": "python", "cycle": "3.8", "eol_date": "2024-10-07", "source": "endoflife.date",
			"match": map[string]any{"rule": "version_prefix"}},
		Inventory: store.InventoryProvenance{CollectorID: "linux-agent", Confidence: "confirmed", LastSeen: at(2 * time.Hour)},
		Feed:      &store.Feed{Name: "endoflife.date", LastSuccess: at(30 * time.Hour)},
	}
	e := Build(in, now)
	want := "Installed 3.8.10 (from the package database, read by the linux-agent agent, seen 2 h ago) belongs to python release line 3.8, " +
		"which reached end of life on 2024-10-07 (endoflife.date, refreshed 30 h ago); release line 3.8 is the longest dotted prefix of the version."
	if e.Sentence != want || e.Type != TypeEndOfLife || !strings.Contains(e.StateText, "not a known vulnerability") {
		t.Fatalf("got  %s\nwant %s", e.Sentence, want)
	}
}

// The EPSS part of "why this priority" gives the score with its model and
// day, and says whether and why it counts: above the threshold, kept within
// the band after crossing it, below it, or replaced by KEV.
func TestEPSSExplanation(t *testing.T) {
	p := risk.DefaultPolicy()
	day := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	model := "v2026.06.15"
	counted := []byte(`[{"name":"CVSS base score","points":7.5,"detail":"CVSS 7.5"},{"name":"` + risk.FactorEPSS + `","points":1.5,"detail":"x"}]`)
	build := func(score *float32, factors []byte, kev bool) *EPSSDetail {
		in := vuln(npmEvidence())
		in.Policy = &p
		f := in.Finding
		f.EPSS, f.PriorityFactors, f.KnownExploited = score, factors, kev
		if score != nil {
			pct := float32(0.9185)
			f.EPSSPercentile, f.EPSSDate, f.EPSSModel = &pct, &day, &model
		}
		return Build(in, now).EPSS
	}
	s := func(v float32) *float32 { return &v }
	for _, c := range []struct {
		name    string
		score   *float32
		factors []byte
		kev     bool
		counted bool
		want    string
	}{
		{"above", s(0.42), counted, false, true, "a 42% chance of exploitation in the next 30 days, higher than 91.9% of scored CVEs (model v2026.06.15, scores of 2026-10-28). That is at or above the risk policy's 10% threshold, so it adds 1.5 points; it keeps them until it falls below 8%."},
		{"band", s(0.09), counted, false, true, "crossed the risk policy's 10% threshold earlier and is still at 8% or more, so it keeps its 1.5 points"},
		{"below", s(0.03), []byte(`[]`), false, false, "below the risk policy's 10% threshold, so it adds nothing"},
		{"not yet prioritised", s(0.5), []byte(`[]`), false, false, "from the next prioritisation"},
		{"KEV", s(0.97), []byte(`[]`), true, false, "CISA KEV, which already counts exploitation"},
		{"no score", nil, []byte(`[]`), false, false, "has no score for CVE-2099-1 yet"},
	} {
		d := build(c.score, c.factors, c.kev)
		if d == nil || d.Counted != c.counted || !strings.Contains(d.Text, c.want) || d.Threshold != 0.1 {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	// No CVE, no EPSS.
	in := vuln(npmEvidence())
	in.Policy = &p
	in.Finding.Key = "GHSA-xxxx"
	if e := Build(in, now); e.EPSS != nil {
		t.Errorf("EPSS for a finding without a CVE: %+v", e.EPSS)
	}
}

// When the score is another CVE's than the finding's key (an alias of a
// GHSA, another CVE fixed by the same distribution advisory), the
// explanation names the CVE the score is for.
func TestEPSSExplanationNamesTheCVE(t *testing.T) {
	p := risk.DefaultPolicy()
	score, other := float32(0.42), "CVE-2024-1001"
	for _, c := range []struct{ key, want string }{
		{"CVE-2024-1000", "FIRST EPSS gives CVE-2024-1001 (the highest score among the CVEs this issue's advisories cover; the issue is listed as CVE-2024-1000) a 42% chance"},
		{"GHSA-xxxx-yyyy-zzzz", "FIRST EPSS gives CVE-2024-1001 (the highest-scored CVE behind GHSA-xxxx-yyyy-zzzz) a 42% chance"},
		{"CVE-2024-1001", "FIRST EPSS gives CVE-2024-1001 a 42% chance"},
	} {
		in := vuln(npmEvidence())
		in.Policy = &p
		in.Finding.Key, in.Finding.EPSS, in.Finding.EPSSCVE = c.key, &score, &other
		d := Build(in, now).EPSS
		if d == nil || d.CVE != other || !strings.Contains(d.Text, c.want) {
			t.Errorf("key %s: %+v", c.key, d)
		}
	}
	// A finding keyed by a GHSA without a scored CVE has no EPSS part.
	in := vuln(npmEvidence())
	in.Policy = &p
	in.Finding.Key = "GHSA-xxxx-yyyy-zzzz"
	if d := Build(in, now).EPSS; d != nil {
		t.Errorf("GHSA without a score: %+v", d)
	}
}
