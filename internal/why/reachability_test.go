package why

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/risk"
)

func TestReachabilityDetail(t *testing.T) {
	factors := func(names ...string) json.RawMessage {
		var fs []risk.Factor
		for _, n := range names {
			fs = append(fs, risk.Factor{Name: n})
		}
		b, _ := json.Marshal(fs)
		return b
	}
	stepped := risk.DefaultPolicy()
	stepped.Steps = []risk.Step{{Name: risk.StepReachability, Apply: func(Input2 risk.Input, r *risk.Result) {}}}
	plain := risk.DefaultPolicy()
	for _, tc := range []struct {
		name, status string
		factors      json.RawMessage
		policy       *risk.Policy
		want         string
		lowered      bool
	}{
		{"empty is unknown", "", nil, &plain, "Not assessed", false},
		{"junk is unknown", "safe", nil, &plain, "Not assessed", false},
		{"reachable", "reachable", nil, &plain, "Reachable:", false},
		{"community", "not_imported", nil, &plain, "does not change the priority", false},
		{"lowered", "not_running", factors(risk.FactorNotReached), &stepped, "one level lower because of it", true},
		{"kept", "not_imported", factors(risk.FactorNotReachedKept), &stepped, "known to be exploited", false},
		{"step on, not yet scored", "not_imported", nil, &stepped, "after the next prioritisation", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := vuln(npmEvidence())
			in.Finding.Reachability = tc.status
			in.Finding.ReachabilityEvidence = []string{"no import of nodemailer in 12 source files"}
			in.Finding.PriorityFactors = tc.factors
			in.Policy = tc.policy
			d := Build(in, now).Reachability
			if d == nil || !strings.Contains(d.Text, tc.want) || d.Lowered != tc.lowered {
				t.Fatalf("detail = %+v, want text containing %q, lowered=%v", d, tc.want, tc.lowered)
			}
			if (tc.status == "" || tc.status == "safe") && d.Status != "unknown" {
				t.Errorf("status = %q, want unknown", d.Status)
			}
		})
	}
}
