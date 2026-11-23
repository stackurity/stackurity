package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/threats"
)

// A disclosed vulnerability is not described as exploited or in use: the
// notice says it is not known to be exploited yet.
func TestThreatNoticeDisclosedVuln(t *testing.T) {
	n, ok := threats.Embedded().Get("nginx2root")
	if !ok {
		t.Fatal("nginx2root is not in the embedded catalogue")
	}
	at := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	for _, v := range []string{threats.Found, threats.Covered, threats.NeedsConnection, threats.Upgrade} {
		m := ThreatNoticeMessage("https://stk.example", n, NoticeFacts{Verdict: v, Findings: 2, Assets: 1,
			Connected: map[string]int{threats.ConnHostAgent: 3}, Missing: n.Needs[1:]}, at)
		text := strings.Join(m.Summary, "\n") + "\n" + m.Action
		if !strings.Contains(m.Summary[0], "not known to be exploited yet") {
			t.Errorf("%s: first line %q", v, m.Summary[0])
		}
		for _, bad := range []string{"is being exploited", "is being used against", "treat the asset as compromised"} {
			if strings.Contains(text, bad) {
				t.Errorf("%s: says %q:\n%s", v, bad, text)
			}
		}
	}
	m := ThreatNoticeMessage("https://stk.example", n, NoticeFacts{Verdict: threats.Found, Findings: 2, Assets: 1}, at)
	if !strings.Contains(m.Action, "internet-facing ones first") || m.Link != "https://stk.example/search?q=CVE-2026-123007" {
		t.Errorf("found: action %q, link %q", m.Action, m.Link)
	}
}
