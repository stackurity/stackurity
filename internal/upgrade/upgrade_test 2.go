package upgrade

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

var now = time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)

func day(s string) *time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return &t
}

func rel(stable []string, yanked map[string]string) *store.Release {
	latest := ""
	if len(stable) > 0 {
		latest = stable[len(stable)-1]
	}
	return &store.Release{Source: "test", LatestStable: latest, StableVersions: stable, Yanked: yanked, CheckedAt: now}
}

func vuln(key, fixed string) Finding {
	return Finding{Kind: "vulnerability", Key: key, FixedVersion: fixed}
}

// versionToken matches version-like words in rationale text.
var versionToken = regexp.MustCompile(`\d+(?:[.:~+-]\w+)+`)

// checkNoInvented asserts that every version the rationale mentions came
// from the input: recommendations must never make up a version.
func checkNoInvented(t *testing.T, in Input, r Recommendation) {
	t.Helper()
	allowed := map[string]bool{in.Installed: true}
	for _, f := range in.Findings {
		allowed[f.FixedVersion] = true
	}
	if in.Release != nil {
		for _, v := range in.Release.StableVersions {
			allowed[v] = true
		}
		for v := range in.Release.Yanked {
			allowed[v] = true
		}
	}
	for _, c := range in.Cycles {
		allowed[c.Cycle], allowed[c.Latest] = true, true
	}
	for _, v := range []string{r.Recommended, r.MinimumFixed, r.LatestInLine, r.LatestStable} {
		if v != "" && !allowed[v] {
			t.Errorf("version %q is not in the input", v)
		}
	}
	for _, line := range r.Rationale {
		for _, tok := range versionToken.FindAllString(line, -1) {
			tok = strings.TrimRight(tok, ".")
			if strings.HasSuffix(tok, ".x") { // a major line, e.g. "4.x"
				continue
			}
			if !allowed[tok] {
				t.Errorf("rationale %q mentions %q, which is not in the input", line, tok)
			}
		}
	}
}

func TestRecommend(t *testing.T) {
	django := []store.LifecycleCycle{
		{Product: "django", Cycle: "5.0", ReleaseDate: day("2023-12-04"), EOLUntil: day("2027-04-01"), Latest: "5.0.3"},
		{Product: "django", Cycle: "4.2", ReleaseDate: day("2023-04-03"), LTS: true, SupportUntil: day("2023-12-04"), EOLUntil: day("2027-04-01"), Latest: "4.2.11"},
		{Product: "django", Cycle: "3.2", ReleaseDate: day("2021-04-06"), EOLUntil: day("2024-04-01"), IsEOL: true, Latest: "3.2.25"},
	}
	cases := []struct {
		name string
		in   Input
		want Recommendation
		say  string // a rationale line contains this
	}{
		{
			name: "npm: newest stable patch in the line, skipping withdrawn and later majors",
			in: Input{PurlType: "npm", Installed: "4.17.15",
				Findings: []Finding{vuln("CVE-A", "4.17.19"), vuln("CVE-B", "4.17.21")},
				Release:  rel([]string{"4.17.15", "4.17.19", "4.17.21", "4.17.23", "4.17.24", "5.0.0"}, map[string]string{"4.17.24": "bad build"})},
			want: Recommendation{MinimumFixed: "4.17.21", Recommended: "4.17.23", Basis: BasisLatestInLine, ChangeType: "patch",
				LatestInLine: "4.17.23", Fixes: []string{"CVE-A", "CVE-B"}, ReleaseData: ReleaseAvailable},
			say: "newest stable release in the 4.x line",
		},
		{
			name: "npm: the fix needs a new major",
			in: Input{PurlType: "npm", Installed: "1.2.0", Findings: []Finding{vuln("GHSA-1", "2.0.1")},
				Release: rel([]string{"1.2.0", "1.9.9", "2.0.1", "2.3.0", "3.0.0"}, nil)},
			want: Recommendation{MinimumFixed: "2.0.1", Recommended: "2.3.0", Basis: BasisLatestInLine, ChangeType: "major",
				RequiresMajor: true, LatestInLine: "2.3.0", Fixes: []string{"GHSA-1"}, ReleaseData: ReleaseAvailable},
			say: "major upgrade",
		},
		{
			name: "npm: no release data",
			in:   Input{PurlType: "npm", Installed: "1.0.0", Findings: []Finding{vuln("GHSA-2", "1.0.4")}},
			want: Recommendation{MinimumFixed: "1.0.4", Recommended: "1.0.4", Basis: BasisMinimumFixed, ChangeType: "patch",
				Fixes: []string{"GHSA-2"}, ReleaseData: ReleaseNone},
			say: "No release data",
		},
		{
			name: "npm: the registry lookup failed",
			in: Input{PurlType: "npm", Installed: "1.0.0", Findings: []Finding{vuln("GHSA-2", "1.0.4")},
				Release: &store.Release{Source: "osv:npm", LastError: "404", CheckedAt: now}},
			want: Recommendation{MinimumFixed: "1.0.4", Recommended: "1.0.4", Basis: BasisMinimumFixed, ChangeType: "patch",
				Fixes: []string{"GHSA-2"}, ReleaseData: ReleaseFailed},
			say: "last registry lookup failed",
		},
		{
			name: "npm: only the withdrawn fix exists",
			in: Input{PurlType: "npm", Installed: "1.0.0", Findings: []Finding{vuln("GHSA-3", "1.0.5")},
				Release: rel([]string{"1.0.0"}, map[string]string{"1.0.5": ""})},
			want: Recommendation{MinimumFixed: "1.0.5", Recommended: "1.0.5", Basis: BasisMinimumFixed, ChangeType: "patch",
				RecommendedYanked: true, MinimumFixedYanked: true, LatestInLine: "1.0.0", Fixes: []string{"GHSA-3"}, ReleaseData: ReleaseAvailable},
			say: "withdrawn by the registry",
		},
		{
			name: "npm: a pre-release fix and no stable release above it",
			in: Input{PurlType: "npm", Installed: "2.0.0", Findings: []Finding{vuln("GHSA-4", "3.0.0-rc.2")},
				Release: rel([]string{"2.0.0", "2.1.0"}, nil)},
			want: Recommendation{MinimumFixed: "3.0.0-rc.2", Recommended: "3.0.0-rc.2", Basis: BasisMinimumFixed, ChangeType: "major",
				RequiresMajor: true, Fixes: []string{"GHSA-4"}, ReleaseData: ReleaseAvailable},
			say: "is a pre-release",
		},
		{
			name: "npm: no fixed version anywhere",
			in:   Input{PurlType: "npm", Installed: "1.0.0", Findings: []Finding{vuln("GHSA-5", "")}, Release: rel([]string{"1.0.0", "1.1.0"}, nil)},
			want: Recommendation{Basis: BasisNone, Unfixed: []string{"GHSA-5"}, ReleaseData: ReleaseAvailable},
			say:  "No source lists a fixed version",
		},
		{
			name: "pypi: withdrawn minimum fix, pre-releases skipped",
			in: Input{PurlType: "pypi", Installed: "4.2.1", Findings: []Finding{vuln("PYSEC-1", "4.2.10")},
				Release: rel([]string{"4.2.1", "4.2.8", "4.2.11", "5.0.3"}, map[string]string{"4.2.10": "broken wheel"})},
			want: Recommendation{MinimumFixed: "4.2.10", Recommended: "4.2.11", Basis: BasisLatestInLine, ChangeType: "patch",
				MinimumFixedYanked: true, LatestInLine: "4.2.11", Fixes: []string{"PYSEC-1"}, ReleaseData: ReleaseAvailable},
			say: "was withdrawn by the registry (broken wheel)",
		},
		{
			name: "pypi: end-of-life line moves to the oldest supported line",
			in: Input{PurlType: "pypi", Installed: "3.2.20", Product: "django", Cycles: django,
				Findings: []Finding{vuln("CVE-D", "3.2.24"), {Kind: "end_of_life", Key: "django:3.2"}},
				Release:  rel([]string{"3.2.20", "3.2.24", "3.2.25", "4.2.10", "4.2.11", "5.0.3"}, nil)},
			want: Recommendation{MinimumFixed: "3.2.24", Recommended: "4.2.11", Basis: BasisSupportedLine, ChangeType: "major",
				RequiresMajor: true, LatestInLine: "3.2.25", Fixes: []string{"CVE-D", "django:3.2"}, ReleaseData: ReleaseAvailable},
			say: "oldest supported line after it",
		},
		{
			name: "maven: newest 2.x release",
			in: Input{PurlType: "maven", Installed: "2.14.1", Findings: []Finding{vuln("CVE-L1", "2.15.0"), vuln("CVE-L2", "2.17.1")},
				Release: rel([]string{"2.14.1", "2.15.0", "2.16.0", "2.17.0", "2.17.1", "2.17.2", "2.20.0", "3.0.0-beta1"}, nil)},
			want: Recommendation{MinimumFixed: "2.17.1", Recommended: "2.20.0", Basis: BasisLatestInLine, ChangeType: "minor",
				LatestInLine: "2.20.0", Fixes: []string{"CVE-L1", "CVE-L2"}, ReleaseData: ReleaseAvailable},
		},
		{
			name: "deb: the distribution's fixed build, behind a subscription",
			in: Input{PurlType: "deb", Installed: "1.1.1f-1ubuntu2.16", Findings: []Finding{
				vuln("CVE-O1", "1.1.1f-1ubuntu2.19"), {Kind: "vulnerability", Key: "CVE-O2", FixedVersion: "1.1.1f-1ubuntu2.20", Subscription: "Ubuntu Pro"}},
				Release: rel([]string{"9.9.9"}, nil)},
			want: Recommendation{MinimumFixed: "1.1.1f-1ubuntu2.20", Recommended: "1.1.1f-1ubuntu2.20", Basis: BasisDistroFixed,
				ChangeType: "distro", Subscription: "Ubuntu Pro", Fixes: []string{"CVE-O1", "CVE-O2"}, ReleaseData: ReleaseNotApplicable},
			say: "published only in Ubuntu Pro",
		},
		{
			name: "rpm: an upstream minor change",
			in:   Input{PurlType: "rpm", Installed: "0:1.0-1.el9", Findings: []Finding{vuln("CVE-R", "0:1.1-2.el9"), vuln("CVE-R2", "")}},
			want: Recommendation{MinimumFixed: "0:1.1-2.el9", Recommended: "0:1.1-2.el9", Basis: BasisDistroFixed, ChangeType: "minor",
				Fixes: []string{"CVE-R"}, Unfixed: []string{"CVE-R2"}, ReleaseData: ReleaseNotApplicable},
			say: "remain after this upgrade",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.in.Now = now
			got := Recommend(c.in)
			w := c.want
			if got.MinimumFixed != w.MinimumFixed || got.Recommended != w.Recommended || got.Basis != w.Basis ||
				got.ChangeType != w.ChangeType || got.RequiresMajor != w.RequiresMajor || got.ReleaseData != w.ReleaseData ||
				got.RecommendedYanked != w.RecommendedYanked || got.MinimumFixedYanked != w.MinimumFixedYanked ||
				got.Subscription != w.Subscription || (w.LatestInLine != "" && got.LatestInLine != w.LatestInLine) {
				t.Errorf("got %+v\nwant %+v", got, w)
			}
			if strings.Join(got.Fixes, ",") != strings.Join(w.Fixes, ",") || strings.Join(got.Unfixed, ",") != strings.Join(w.Unfixed, ",") {
				t.Errorf("fixes %v unfixed %v, want %v %v", got.Fixes, got.Unfixed, w.Fixes, w.Unfixed)
			}
			if c.say != "" && !strings.Contains(strings.Join(got.Rationale, " "), c.say) {
				t.Errorf("rationale %q lacks %q", got.Rationale, c.say)
			}
			checkNoInvented(t, c.in, got)
		})
	}
}

func TestLifecycleStatus(t *testing.T) {
	cycles := []store.LifecycleCycle{
		{Product: "nodejs", Cycle: "22", ReleaseDate: day("2024-04-24"), SupportUntil: day("2025-10-21"), EOLUntil: day("2027-04-30"), Latest: "22.11.0"},
		{Product: "nodejs", Cycle: "20", ReleaseDate: day("2023-04-18"), SupportUntil: day("2024-10-22"), EOLUntil: day("2026-04-30"), Latest: "20.18.0"},
		{Product: "nodejs", Cycle: "18", ReleaseDate: day("2022-04-19"), EOLUntil: day("2025-04-30"), Latest: "18.20.4"},
	}
	r := Recommend(Input{PurlType: "generic", Installed: "18.20.1", Product: "nodejs", Cycles: cycles, Now: now,
		Findings: []Finding{{Kind: "end_of_life", Key: "nodejs:18"}}})
	if r.Lifecycle == nil || r.Lifecycle.Status != "end_of_life" || r.SupportedLine == nil || r.SupportedLine.Cycle != "22" ||
		r.Recommended != "22.11.0" || r.Basis != BasisSupportedLine || r.TargetLifecycle == nil || r.TargetLifecycle.Status != "security_only" {
		t.Fatalf("%+v", r)
	}
	if len(r.Fixes) != 1 || r.Fixes[0] != "nodejs:18" {
		t.Errorf("fixes %v", r.Fixes)
	}
	// A supported installed line: nothing to recommend without findings.
	r = Recommend(Input{PurlType: "generic", Installed: "22.3.0", Product: "nodejs", Cycles: cycles, Now: now})
	if r.Recommended != "" || r.Lifecycle == nil || r.Lifecycle.Status != "security_only" || r.Basis != BasisNone {
		t.Errorf("%+v", r)
	}
	// No supported later line recorded.
	r = Recommend(Input{PurlType: "generic", Installed: "18.1.0", Product: "nodejs", Cycles: cycles[2:], Now: now,
		Findings: []Finding{{Kind: "end_of_life", Key: "nodejs:18"}}})
	if r.Recommended != "" || len(r.Unfixed) != 1 || !strings.Contains(strings.Join(r.Rationale, " "), "no supported later line") {
		t.Errorf("%+v", r)
	}
}

func TestOldReleaseDataFallsBackToDatedVersions(t *testing.T) {
	r := Recommend(Input{PurlType: "npm", Installed: "1.0.0", Now: now, Findings: []Finding{vuln("G", "1.0.2")},
		Release: &store.Release{LatestStable: "2.0.0", VersionDates: map[string]string{"1.0.2": "x", "1.0.3": "y", "1.1.0-beta": "z"}, CheckedAt: now}})
	if r.Recommended != "1.0.3" || r.Basis != BasisLatestInLine {
		t.Errorf("%+v", r)
	}
}
