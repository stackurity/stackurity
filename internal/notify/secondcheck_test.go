package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The second check is deliberately simple, so a defect in it must never
// hide a real issue: a known exploited P1 with SOS that the second check
// disagrees with stays P1 and SOS, confirmed, and still raises the urgent
// alert. The disagreement is shown for a person to review instead.
func TestSecondCheckDisagreementKeepsUrgentAlerts(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	f := setup(t)
	f.addAsset("web-1", "production", true)
	f.findingsOn(map[string][]string{"web-1": {"CVE-2021-23337"}})

	cands, err := f.st.SecondCheckCandidates(ctx, 100, false)
	if err != nil || len(cands) != 1 {
		t.Fatalf("candidates: %+v %v", cands, err)
	}
	c := cands[0]
	if _, err := f.st.RecordSecondChecks(ctx, []store.SecondCheckResult{{FindingID: c.FindingID, AssetID: c.AssetID, Basis: c.Basis,
		Result: store.SecondCheckDisagreed, Reason: "affected: the matcher says affected, the second check finds not affected",
		Differences: []store.SecondCheckDifference{{Field: "affected", Matcher: "affected", Independent: "not affected"}},
		Kind:        c.Kind, Key: c.Key, Purl: c.Purl, Version: c.Version}}); err != nil {
		t.Fatal(err)
	}

	f.tick() // prioritises, then alerts
	fd, err := f.st.GetFinding(ctx, c.FindingID)
	if err != nil {
		t.Fatal(err)
	}
	if fd.Priority != "P1" || !fd.SOS || fd.Verification != "confirmed" || fd.SecondCheck != store.SecondCheckDisagreed ||
		!strings.Contains(fd.SecondCheckReason, "not affected") {
		t.Fatalf("after a disagreement: priority %s sos %v verification %s second check %q", fd.Priority, fd.SOS, fd.Verification, fd.SecondCheck)
	}
	ev := f.hook.events()
	if len(ev) == 0 || ev[0] != "urgent:P1" || !f.hook.got[0].SOS {
		t.Fatalf("want the urgent SOS alert: %v", ev)
	}
	sum, err := f.st.SummarizeFindings(ctx)
	if err != nil || sum.SecondCheckDisagreed != 1 || sum.SOS != 1 {
		t.Fatalf("summary: %+v %v", sum, err)
	}
}
