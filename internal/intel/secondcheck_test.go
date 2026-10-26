package intel

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// End to end: a real advisory matched by the real matcher, then the stored
// record is corrupted so it no longer covers the installed version. The
// second check reads the raw record and disagrees; the finding shows the
// disagreement and keeps its verification (so its priority and SOS), and
// the disagreement is logged.
func TestSecondCheckCatchesACorruptedRecord(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	asset := ingest(t, st, model.AssetRepository, "shop", true, confirmed("pkg:npm/lodash@4.17.20", nil))
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	serveCorpus(t, filepath.Join("testdata", "corpus", "npm"), "osv:npm", sy, up)
	if _, err := sy.Sync(ctx, "osv:npm"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Key: "CVE-2021-23337"})
	if err != nil || len(fs) != 1 || fs[0].Verification != "confirmed" {
		t.Fatalf("finding: %+v %v", fs, err)
	}
	run := &secondcheck.Runner{Store: st, All: true}
	if s, err := run.Run(ctx); err != nil || s.Agreed != 1 {
		t.Fatalf("before corruption: %+v %v", s, err)
	}

	// Corrupt the stored range: fixed 4.17.21 becomes 4.17.10.
	sys := tenant.System(context.Background())
	tag, err := st.Pool.Exec(sys, `UPDATE advisory_packages SET affected = replace(affected::text, '"4.17.21"', '"4.17.10"')::jsonb
		WHERE name = 'lodash' AND affected::text LIKE '%4.17.21%'`)
	if err != nil || tag.RowsAffected() == 0 {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `DELETE FROM second_checks`); err != nil {
		t.Fatal(err)
	}
	s, err := run.Run(ctx)
	if err != nil || s.Disagreed != 1 {
		t.Fatalf("after corruption: %+v %v", s, err)
	}
	fs, _, _ = st.ListFindings(ctx, store.FindingFilter{AssetID: asset, Key: "CVE-2021-23337"})
	if fs[0].Verification != "confirmed" || fs[0].SecondCheck != store.SecondCheckDisagreed || !strings.Contains(fs[0].SecondCheckReason, "4.17.10") {
		t.Fatalf("after the disagreement: %s %q %q", fs[0].Verification, fs[0].SecondCheck, fs[0].SecondCheckReason)
	}
	sum, err := st.SummarizeSecondChecks(ctx)
	if err != nil || len(sum.Recent) != 1 || !strings.Contains(string(sum.Recent[0].Inputs), "4.17.10") {
		t.Fatalf("logged: %+v %v", sum, err)
	}
	// The matcher's next pass reads the same (corrupted) record and closes
	// the finding; the disagreement stays in the log for corpus work.
	if _, err := ev.Evaluate(ctx, nil, asset); err != nil {
		t.Fatal(err)
	}
	fs, _, _ = st.ListFindings(ctx, store.FindingFilter{Status: "all", AssetID: asset, Key: "CVE-2021-23337"})
	if len(fs) != 1 || fs[0].Status != "resolved" {
		t.Fatalf("after re-evaluation: %+v", fs)
	}
	if sum, _ := st.SummarizeSecondChecks(ctx); sum.Logged30d != 1 || sum.Disagreed != 0 {
		t.Fatalf("after re-evaluation: %+v", sum)
	}
}
