// Package prometheus holds the recommended alert rules. promtool tests their
// behaviour (stackurity-alerts_test.yml, run by CI); these tests keep the
// rules consistent with the code, the runbook and the Helm chart.
package prometheus

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const (
	rulesFile  = "stackurity-alerts.yml"
	chartCopy  = "../helm/stackurity/files/stackurity-alerts.yml"
	testsFile  = "stackurity-alerts_test.yml"
	runbook    = "../../docs/operations.md"
	runbookURL = "https://github.com/stackurity/stackurity/blob/main/docs/operations.md#"
)

type rule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

func loadRules(t *testing.T) []rule {
	t.Helper()
	b, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []rule `yaml:"rules"`
		} `yaml:"groups"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var out []rule
	for _, g := range doc.Groups {
		out = append(out, g.Rules...)
	}
	if len(out) == 0 {
		t.Fatal("no rules")
	}
	return out
}

// The chart renders its own copy (Helm cannot read files outside the
// chart). There is one source: edit deploy/prometheus and copy it over.
func TestChartCopyIsIdentical(t *testing.T) {
	want, err := os.ReadFile(rulesFile)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(chartCopy)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from %s; run: cp deploy/prometheus/%s deploy/helm/stackurity/files/", chartCopy, rulesFile, rulesFile)
	}
	tpl, err := os.ReadFile("../helm/stackurity/templates/prometheusrule.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tpl), `.Files.Get "files/stackurity-alerts.yml"`) {
		t.Error("the PrometheusRule template no longer renders files/stackurity-alerts.yml")
	}
}

// Every alert has a severity people can route on, a summary, a description
// and a runbook section in docs/operations.md.
func TestEveryAlertHasARunbook(t *testing.T) {
	doc, err := os.ReadFile(runbook)
	if err != nil {
		t.Fatal(err)
	}
	headings := map[string]bool{}
	for _, line := range strings.Split(string(doc), "\n") {
		if h, ok := strings.CutPrefix(line, "### "); ok {
			headings[strings.TrimSpace(h)] = true
		}
	}
	seen := map[string]bool{}
	for _, r := range loadRules(t) {
		if r.Alert == "" {
			t.Errorf("recording rules belong elsewhere; every rule here is an alert: %q", r.Expr)
			continue
		}
		if seen[r.Alert] {
			t.Errorf("%s: defined twice", r.Alert)
		}
		seen[r.Alert] = true
		switch r.Labels["severity"] {
		case "critical", "warning", "info":
		default:
			t.Errorf("%s: severity %q, want critical, warning or info", r.Alert, r.Labels["severity"])
		}
		for _, a := range []string{"summary", "description", "runbook_url"} {
			if strings.TrimSpace(r.Annotations[a]) == "" {
				t.Errorf("%s: no %s", r.Alert, a)
			}
		}
		if want := runbookURL + strings.ToLower(r.Alert); r.Annotations["runbook_url"] != want {
			t.Errorf("%s: runbook_url %q, want %q", r.Alert, r.Annotations["runbook_url"], want)
		}
		if !headings[r.Alert] {
			t.Errorf("%s: docs/operations.md has no \"### %s\" section", r.Alert, r.Alert)
		}
		if strings.Contains(r.Annotations["description"]+r.Annotations["summary"], "—") {
			t.Errorf("%s: no em dashes", r.Alert)
		}
	}
}

var metricName = regexp.MustCompile(`\bstackurity_[a-z_]+\b`)

// Every metric a rule uses is one the server exports, so a renamed metric
// cannot silently disable an alert.
func TestRulesUseExportedMetrics(t *testing.T) {
	var src strings.Builder
	files, _ := filepath.Glob("../../internal/metrics/*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(b)
	}
	exported := src.String()
	for _, r := range loadRules(t) {
		for _, m := range metricName.FindAllString(r.Expr, -1) {
			if !strings.Contains(exported, `"`+m+`"`) {
				t.Errorf("%s uses %s, which internal/metrics does not export", r.Alert, m)
			}
		}
	}
}

// Every alert is shown to fire in the promtool tests.
func TestEveryAlertIsTested(t *testing.T) {
	b, err := os.ReadFile(testsFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		RuleFiles []string `yaml:"rule_files"`
		Tests     []struct {
			Name  string `yaml:"name"`
			Cases []struct {
				Alert     string `yaml:"alertname"`
				ExpAlerts []any  `yaml:"exp_alerts"`
			} `yaml:"alert_rule_test"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.RuleFiles) != 1 || doc.RuleFiles[0] != rulesFile {
		t.Errorf("rule_files = %v, want [%s]", doc.RuleFiles, rulesFile)
	}
	fires := map[string]bool{}
	for _, tc := range doc.Tests {
		for _, c := range tc.Cases {
			if len(c.ExpAlerts) > 0 {
				fires[c.Alert] = true
			}
		}
	}
	for _, r := range loadRules(t) {
		if !fires[r.Alert] {
			t.Errorf("%s: no promtool test case where it fires", r.Alert)
		}
	}
}
