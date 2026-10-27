package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The matching corpus (testdata/corpus, see its README) freezes real
// advisory records per ecosystem, trimmed to the entries that matter, with
// installed versions and the verdict each must get. TestCorpus serves the
// records from a fake upstream, syncs them with the real Syncer, ingests each
// case as its own asset and evaluates everything with the real Evaluator, so
// the whole pipeline is tested: download, storage, ecosystem and release
// selection, version comparison, grouping, fixed version, subscription
// labels and coverage.

type corpusFile struct {
	Ecosystem string       `json:"ecosystem"`
	Feed      string       `json:"feed"`
	Cases     []corpusCase `json:"cases"`
}

type corpusPackage struct {
	Purl     string            `json:"purl"`
	Evidence map[string]string `json:"evidence,omitempty"`
}

type corpusCase struct {
	Name     string            `json:"name"`
	Purl     string            `json:"purl"`
	Version  string            `json:"version,omitempty"` // inventory version when it differs from the purl's
	Evidence map[string]string `json:"evidence,omitempty"`
	// Affected maps each advisory group expected to match (the lowest CVE,
	// else the advisory id) to the fixed version recommended ("" for none).
	// Every other group must not match.
	Affected map[string]string `json:"affected"`
	// Subscription names the paid channel for groups whose only fix needs one.
	Subscription map[string]string `json:"subscription,omitempty"`
	// Coverage is the expected row coverage: evaluated (the default),
	// not_evaluated or unsupported. Reason must appear in the row's reason.
	Coverage string `json:"coverage,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Note     string `json:"note"`
	// Also lists more packages reported on the same asset, for cases that
	// need them together (a kernel is several packages from several
	// source packages). Findings and coverage are checked on purl's row.
	Also []corpusPackage `json:"also,omitempty"`
}

func TestCorpus(t *testing.T) {
	dirs, err := os.ReadDir(filepath.Join("testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		n++
		dir := filepath.Join("testdata", "corpus", d.Name())
		t.Run(d.Name(), func(t *testing.T) { runCorpus(t, dir) })
	}
	if n < 18 {
		t.Errorf("expected a corpus for each of the 18 supported ecosystems, found %d", n)
	}
	sc := corpusSecondCheck
	t.Logf("second check over the corpus: %d findings, %d agreed, %d could not check, %d disagreed",
		sc.Checked, sc.Agreed, sc.CouldNotCheck, sc.Disagreed)
}

func runCorpus(t *testing.T, dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cf corpusFile
	if err := json.Unmarshal(b, &cf); err != nil {
		t.Fatalf("cases.json: %v", err)
	}
	if len(cf.Cases) == 0 {
		t.Fatal("no cases")
	}
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)

	assets := make([]int64, len(cf.Cases))
	names := map[string]bool{}
	for i, c := range cf.Cases {
		if c.Name == "" || names[c.Name] || c.Note == "" {
			t.Fatalf("case %d needs a unique name and a note: %+v", i, c)
		}
		names[c.Name] = true
		kind := model.AssetRepository
		switch {
		case strings.HasPrefix(c.Purl, "pkg:deb/"), strings.HasPrefix(c.Purl, "pkg:rpm/"), strings.HasPrefix(c.Purl, "pkg:apk/"):
			kind = model.AssetHost
		}
		obs := confirmed(c.Purl, c.Evidence)
		obs.Version = c.Version
		all := []model.Observation{obs}
		for _, p := range c.Also {
			all = append(all, confirmed(p.Purl, p.Evidence))
		}
		assets[i] = ingest(t, st, kind, c.Name, true, all...)
	}
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	serveCorpus(t, dir, cf.Feed, sy, up)
	if _, err := sy.Sync(ctx, cf.Feed); err != nil {
		t.Fatalf("sync %s: %v", cf.Feed, err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}

	for i, c := range cf.Cases {
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: assets[i], Kind: "vulnerability"})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, f := range fs {
			got[f.Key] = f.FixedVersion
			var ev map[string]any
			_ = json.Unmarshal(f.Evidence, &ev)
			// The rule that matched is stored with the finding (evidence
			// "match"), naming one of its sources.
			m, _ := ev["match"].(map[string]any)
			if rule, _ := m["rule"].(string); rule == "" || !slices.Contains(f.Sources, fmt.Sprint(m["record"])) {
				t.Errorf("%s: %s match explanation %v does not name its rule and one of %v", c.Name, f.Key, m, f.Sources)
			}
			sub, _ := ev["requires_subscription"].(string)
			if want := c.Subscription[f.Key]; sub != want {
				t.Errorf("%s: %s subscription = %q, want %q", c.Name, f.Key, sub, want)
			}
		}
		if !sameMap(got, c.Affected) {
			t.Errorf("%s (%s): findings %s, want %s\n  note: %s", c.Name, c.Purl, showMap(got), showMap(c.Affected), c.Note)
		}
		rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: assets[i]})
		if err != nil || len(rows) != 1+len(c.Also) {
			t.Fatalf("%s: inventory %+v %v", c.Name, rows, err)
		}
		want := c.Coverage
		if want == "" {
			want = store.CoverageEvaluated
		}
		r := rows[0]
		for _, row := range rows {
			if row.Purl == c.Purl {
				r = row
			}
		}
		if r.Coverage != want || !strings.Contains(r.CoverageReason, c.Reason) {
			t.Errorf("%s (%s): coverage %s %q, want %s %q", c.Name, c.Purl, r.Coverage, r.CoverageReason, want, c.Reason)
		}
		if want != store.CoverageEvaluated && c.Reason == "" {
			t.Errorf("%s: a case that is not evaluated must say why (reason)", c.Name)
		}
	}

	// The independent second check re-derives every corpus finding from the
	// stored records. It may be unable to read some (pre-releases, SUSE
	// channels), but it must never disagree with a verdict the corpus pins.
	sc := &secondcheck.Runner{Store: st, All: true, Batch: 100_000}
	stats, err := sc.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Disagreed > 0 {
		sum, _ := st.SummarizeSecondChecks(ctx)
		for _, d := range sum.Recent {
			t.Errorf("second check disagrees on %s %s@%s: %+v", d.Key, d.Purl, d.Version, d.Differences)
		}
	}
	corpusSecondCheck.Checked += stats.Checked
	corpusSecondCheck.Agreed += stats.Agreed
	corpusSecondCheck.CouldNotCheck += stats.CouldNotCheck
	corpusSecondCheck.Disagreed += stats.Disagreed
}

// corpusSecondCheck adds up the second check over every corpus.
var corpusSecondCheck secondcheck.Stats

// serveCorpus publishes the corpus records the way the real source does:
// an OSV all.zip, or Amazon Linux repositories with updateinfo.
func serveCorpus(t *testing.T, dir, feed string, sy *Syncer, up *upstream) {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if feed == FeedAmazonLinux {
		base := strings.TrimSuffix(sy.f.cfg.AmazonLinuxURL, "/al")
		read := func(name string) string {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			body := string(b)
			_, after, _ := strings.Cut(body, "<updates>")
			inner, _, _ := strings.Cut(after, "</updates>")
			return inner
		}
		amazonRepo(t, up, base, "/al/al2023/core/mirrors/latest/x86_64/mirror.list", "/al/al2023/core/guids/a/x86_64/", read("al2023-core.xml"))
		amazonRepo(t, up, base, "/al/2/core/latest/x86_64/mirror.list", "/al/2/core/2.0/x86_64/b/", read("al2-core.xml"))
		up.set("/al/2/extras-catalog-x86_64-v2.json", `{"topics":[{"n":"kernel-5.10"},{"n":"docker"}]}`)
		amazonRepo(t, up, base, "/al/2/extras/kernel-5.10/latest/x86_64/mirror.list", "/al/2/extras/kernel-5.10/stable/x86_64/c/",
			read("al2-extras-kernel-5.10.xml"))
		return
	}
	eco, ok := strings.CutPrefix(feed, "osv:")
	if !ok {
		t.Fatalf("unknown corpus feed %q", feed)
	}
	records := map[string]string{}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") || f.Name() == "cases.json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		records[f.Name()] = string(b)
	}
	if len(records) == 0 {
		t.Fatal("no advisory records")
	}
	up.set("/osv/"+url.PathEscape(eco)+"/all.zip", zipOf(t, records))
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}

func showMap(m map[string]string) string {
	if len(m) == 0 {
		return "{none}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(" " + k + "=" + m[k])
	}
	return "{" + b.String() + " }"
}
