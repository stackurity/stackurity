package api_test

import (
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// Why it matched, in one sentence, on the finding, in explain, and the
// second check where it disagreed.
func TestFindingWhyAndSecondCheck(t *testing.T) {
	l := newLoopEnv(t)
	id := l.findings["CVE-E"]
	var detail struct {
		Why struct {
			Sentence      string   `json:"sentence"`
			Type          string   `json:"type"`
			EvidenceState string   `json:"evidence_state"`
			Missing       []string `json:"missing_information"`
			SecondCheck   *struct {
				Result string `json:"result"`
			} `json:"second_check"`
			SecondCheckText string `json:"second_check_text"`
		} `json:"why"`
	}
	if code := l.view.do("GET", "/api/v1/findings/"+itoa(id), nil, &detail); code != 200 {
		t.Fatalf("finding: %d", code)
	}
	if !strings.HasPrefix(detail.Why.Sentence, "Installed 4.0.0 (from ") || detail.Why.Type != "package_advisory" ||
		detail.Why.EvidenceState != "confirmed" || detail.Why.SecondCheck != nil || len(detail.Why.Missing) != 0 {
		t.Fatalf("why: %+v", detail.Why)
	}

	recordDisagreement(t, l.st, l.ctx, id)
	if code := l.view.do("GET", "/api/v1/findings/"+itoa(id), nil, &detail); code != 200 {
		t.Fatalf("finding: %d", code)
	}
	if detail.Why.EvidenceState != "needs_validation" || detail.Why.SecondCheck == nil || detail.Why.SecondCheck.Result != "disagreed" ||
		len(detail.Why.Missing) != 1 || !strings.Contains(detail.Why.Missing[0], "disagreed") {
		t.Fatalf("after a disagreement: %+v", detail.Why)
	}
	var explain struct {
		Why struct {
			Sentence string `json:"sentence"`
		} `json:"why"`
	}
	if code := l.view.do("GET", "/api/v1/findings/"+itoa(id)+"/explain", nil, &explain); code != 200 || explain.Why.Sentence == "" {
		t.Fatalf("explain: %d %+v", code, explain)
	}
	var sum store.SecondCheckSummary
	if code := l.view.do("GET", "/api/v1/second-checks", nil, &sum); code != 200 || sum.Disagreed != 1 || len(sum.Recent) != 1 {
		t.Fatalf("second checks: %d %+v", code, sum)
	}
	var list struct {
		Items []store.Finding `json:"items"`
	}
	if code := l.view.do("GET", "/api/v1/findings?second_check=disagreed", nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].ID != id {
		t.Fatalf("filter: %d %+v", code, list)
	}
	if code := l.view.do("GET", "/api/v1/findings?second_check=maybe", nil, nil); code != 400 {
		t.Errorf("bad filter: %d", code)
	}
}
