package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// curlIncident is the v0.19.0 demo's CVE-2026-18924 in curl: two Ubuntu
// packages fixed in an Ubuntu version, the Debian one with no fix yet.
func curlIncident(t *testing.T, fixes []map[string]any) store.Incident {
	t.Helper()
	det := map[string]any{"assets": []string{"demo-tools-1", "demo-web-1", "demo-web-2"},
		"components":     []string{"debian/curl", "ubuntu/curl", "ubuntu/libcurl4"},
		"fixed_versions": []string{"7.81.0-1ubuntu1.29"}}
	if fixes != nil {
		det["component_fixes"], det["component_count"] = fixes, len(fixes)
	}
	b, err := json.Marshal(det)
	if err != nil {
		t.Fatal(err)
	}
	return store.Incident{ID: 9, Kind: "vulnerability", Key: "CVE-2026-18924", Title: "CVE-2026-18924 in curl", Priority: "P2",
		Status: "open", FindingCount: 4, AssetCount: 3, Detail: b}
}

var curlFixes = []map[string]any{
	{"component": "ubuntu/curl", "type": "deb", "fixed_versions": []string{"7.81.0-1ubuntu1.29"}, "assets": 2, "unfixed": 0},
	{"component": "debian/curl", "type": "deb", "fixed_versions": []string{}, "assets": 1, "unfixed": 1},
	{"component": "ubuntu/libcurl4", "type": "deb", "fixed_versions": []string{"7.81.0-1ubuntu1.29"}, "assets": 1, "unfixed": 0},
}

func TestIncidentActionPerComponent(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	m := d.message(curlIncident(t, curlFixes), "opened")
	want := "ubuntu/curl (2 assets), ubuntu/libcurl4 (1 asset): upgrade to 7.81.0-1ubuntu1.29 or later; " +
		"debian/curl: no fixed version is published yet for Debian, watch the advisory and consider mitigations (1 asset)"
	if m.Action != want {
		t.Errorf("action\n %q\nwant\n %q", m.Action, want)
	}
	if strings.HasPrefix(m.Action, "Upgrade to") {
		t.Error("a single upgrade for a mixed Debian and Ubuntu group")
	}

	// Old incidents (not correlated since) keep the flat text.
	if m := d.message(curlIncident(t, nil), "opened"); m.Action != "Upgrade to 7.81.0-1ubuntu1.29 or later" {
		t.Errorf("fallback %q", m.Action)
	}
}

func TestComponentFixAction(t *testing.T) {
	for _, c := range []struct {
		name  string
		fixes []map[string]any
		count int
		want  string
	}{
		{"one fix", []map[string]any{{"component": "lodash", "type": "npm", "fixed_versions": []string{"4.17.21"}, "assets": 3, "unfixed": 0}}, 1,
			"Upgrade lodash to 4.17.21 or later (3 assets)"},
		{"release lines", []map[string]any{{"component": "ubuntu/openssl", "type": "deb",
			"fixed_versions": []string{"3.0.13-0ubuntu3.4", "3.0.2-0ubuntu1.18"}, "assets": 4, "unfixed": 0}}, 1,
			"ubuntu/openssl: upgrade to the version for each asset's release: 3.0.13-0ubuntu3.4 / 3.0.2-0ubuntu1.18 or later " +
				"(each asset's fixed version is in Stackurity) (4 assets)"},
		{"partly fixed", []map[string]any{{"component": "debian/openssl", "type": "deb", "fixed_versions": []string{"3.0.15-1~deb12u1"},
			"assets": 3, "unfixed": 1}}, 1,
			"debian/openssl: upgrade to 3.0.15-1~deb12u1 or later where it is published (2 assets); no fixed version yet on the other 1 asset, watch the advisory"},
		{"no fix, application", []map[string]any{{"component": "left-pad", "type": "npm", "fixed_versions": []string{}, "assets": 1, "unfixed": 1}}, 1,
			"left-pad: no fixed version is published yet, watch the advisory and consider mitigations (1 asset)"},
		// Debian/Ubuntu binary packages whose fix is named by their source
		// package's version: apt has no telnet 2:2.5-3ubuntu4.1, so the
		// advice names the source build; a binary whose version is the
		// source's keeps its own line.
		{"source version", []map[string]any{{"component": "ubuntu/telnet", "type": "deb", "fixed_versions": []string{"2:2.5-3ubuntu4.1"},
			"assets": 2, "unfixed": 0, "source_package": "inetutils"}}, 1,
			"Upgrade ubuntu/telnet to a build from inetutils 2:2.5-3ubuntu4.1 or later (2 assets)"},
		{"source and binary versions", []map[string]any{
			{"component": "ubuntu/telnet", "type": "deb", "fixed_versions": []string{"2:2.5-3ubuntu4.1"}, "assets": 2, "unfixed": 0, "source_package": "inetutils"},
			{"component": "ubuntu/inetutils-telnetd", "type": "deb", "fixed_versions": []string{"2:2.5-3ubuntu4.1"}, "assets": 1, "unfixed": 0}}, 2,
			"ubuntu/telnet: upgrade to a build from inetutils 2:2.5-3ubuntu4.1 or later (2 assets); " +
				"ubuntu/inetutils-telnetd: upgrade to 2:2.5-3ubuntu4.1 or later (1 asset)"},
		{"source version, release lines", []map[string]any{{"component": "ubuntu/telnet", "type": "deb",
			"fixed_versions": []string{"2:2.4-2ubuntu0.1", "2:2.5-3ubuntu4.1"}, "assets": 3, "unfixed": 0, "source_package": "inetutils"}}, 1,
			"ubuntu/telnet: upgrade to a build from inetutils at the version for each asset's release: 2:2.4-2ubuntu0.1 / 2:2.5-3ubuntu4.1 or later " +
				"(each asset's fixed version is in Stackurity) (3 assets)"},
		{"source version, partly fixed", []map[string]any{{"component": "ubuntu/telnet", "type": "deb", "fixed_versions": []string{"2:2.5-3ubuntu4.1"},
			"assets": 3, "unfixed": 1, "source_package": "inetutils"}}, 1,
			"ubuntu/telnet: upgrade to a build from inetutils 2:2.5-3ubuntu4.1 or later where it is published (2 assets); no fixed version yet on the other 1 asset, watch the advisory"},
		{"more than shown", []map[string]any{{"component": "lodash", "type": "npm", "fixed_versions": []string{"4.17.21"}, "assets": 3, "unfixed": 0}}, 4,
			"lodash: upgrade to 4.17.21 or later (3 assets); 3 components more: see the incident"},
	} {
		b, _ := json.Marshal(map[string]any{"component_fixes": c.fixes, "component_count": c.count})
		got, ok := componentFixAction(b)
		if !ok || got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if _, ok := componentFixAction(json.RawMessage(`{"fixed_versions":["1.0"]}`)); ok {
		t.Error("no component_fixes must fall back")
	}
}

func docText(doc jiraDoc) string {
	var b strings.Builder
	for _, bl := range doc {
		b.WriteString(bl.Heading + "\n")
		for _, in := range bl.Para {
			b.WriteString(in.Text)
		}
		for _, it := range bl.List {
			for _, in := range it {
				b.WriteString(in.Text)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// Jira descriptions say the same per component; the action plan's
// upgrade target replaces it only when it covers every component.
func TestJiraFixPerComponent(t *testing.T) {
	d := &Dispatcher{BaseURL: "https://stk.example"}
	in := curlIncident(t, curlFixes)
	brief := &store.IncidentBrief{Upgrades: []store.UpgradeTarget{{Component: "ubuntu/curl", Target: "7.81.0-1ubuntu1.29", Minimum: "7.81.0-1ubuntu1.29"}}}
	text := docText(d.issueDescription(in, brief))
	if !strings.Contains(text, "debian/curl: no fixed version is published yet for Debian") || strings.Contains(text, "Upgrade to 7.81") {
		t.Errorf("mixed group:\n%s", text)
	}

	b, _ := json.Marshal(map[string]any{"component_fixes": []map[string]any{
		{"component": "lodash", "type": "npm", "fixed_versions": []string{"4.17.21"}, "assets": 1, "unfixed": 0}}, "component_count": 1})
	one := store.Incident{ID: 2, Kind: "vulnerability", Key: "CVE-1", Title: "CVE-1 in lodash", Status: "open", Detail: b}
	text = docText(d.issueDescription(one, &store.IncidentBrief{Upgrades: []store.UpgradeTarget{{Component: "lodash", Target: "4.17.23", Minimum: "4.17.21"}}}))
	if !strings.Contains(text, "Upgrade to 4.17.23 (fixes from 4.17.21).") {
		t.Errorf("one component:\n%s", text)
	}
}
