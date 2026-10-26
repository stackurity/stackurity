package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/risk"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type loopEnv struct {
	*env
	ctx                   context.Context
	admin, sec, eng, view *session
	collector             string
	asset                 int64
	findings              map[string]int64
	group                 string
}

// newLoopEnv: a host with two lodash issues (one fix) and one express issue,
// a session per role and a collector token.
func newLoopEnv(t *testing.T) *loopEnv {
	e := newEnv(t)
	l := &loopEnv{env: e, ctx: tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), findings: map[string]int64{}}
	for _, u := range []struct {
		email string
		role  auth.Role
	}{{"admin@x.io", auth.RoleAdmin}, {"sec@x.io", auth.RoleSecurity}, {"eng@x.io", auth.RoleEngineer}, {"view@x.io", auth.RoleViewer}} {
		e.user(u.email, u.role)
	}
	l.admin, l.sec, l.eng, l.view = e.login("admin@x.io"), e.login("sec@x.io"), e.login("eng@x.io"), e.login("view@x.io")
	var tok struct {
		Secret string `json:"secret"`
	}
	if code := l.admin.do("POST", "/api/v1/tokens", map[string]string{"name": "agent", "role": "collector"}, &tok); code != 201 {
		t.Fatalf("collector token: %d", code)
	}
	l.collector = tok.Secret
	l.asset = l.ingest("pkg:npm/lodash@4.17.15", "pkg:npm/express@4.0.0")
	rows, _, err := e.st.ListInventory(l.ctx, store.InventoryFilter{AssetID: l.asset})
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	var in []store.FindingInput
	for _, r := range rows {
		ids = append(ids, r.ID)
		keys := map[string][]string{"lodash": {"CVE-L1", "CVE-L2"}, "express": {"CVE-E"}}[r.Name]
		for _, k := range keys {
			fixed := "4.17.21"
			if k == "CVE-E" {
				fixed = "" // no fix yet
			}
			in = append(in, store.FindingInput{Kind: "vulnerability", Key: k, InventoryID: r.ID, AssetID: l.asset, ComponentID: r.ComponentID,
				Verification: "confirmed", Severity: "high", FixedVersion: fixed, Sources: []string{"GHSA-" + k}, Evidence: map[string]any{}})
		}
	}
	if _, _, err := e.st.SyncFindings(l.ctx, []string{"vulnerability"}, ids, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.Prioritize(l.ctx, risk.DefaultPolicy(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := planner.Rebuild(l.ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	fs, _, err := e.st.ListFindings(l.ctx, store.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fs {
		l.findings[f.Key] = f.ID
		if f.Key == "CVE-L1" {
			l.group = f.FixGroup
		}
	}
	if len(l.findings) != 3 || l.group == "" {
		t.Fatalf("fixture: %v group %q", l.findings, l.group)
	}
	return l
}

// ingest sends a complete host batch with the collector token.
func (l *loopEnv) ingest(purls ...string) int64 {
	b := model.NewBatch(model.Collector{ID: "agent", Version: "0.7.0", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: "web-1", Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "web-1"}}})
	for _, p := range purls {
		b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
	}
	b.Complete = true
	raw, _ := json.Marshal(b)
	req, _ := http.NewRequest("POST", l.srv.URL+"/api/v1/ingest", strings.NewReader(string(raw)))
	req.Header.Set("Authorization", "Bearer "+l.collector)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	var r store.IngestResult
	if resp.StatusCode != 201 || json.NewDecoder(resp.Body).Decode(&r) != nil {
		l.t.Fatalf("ingest: %d", resp.StatusCode)
	}
	return r.AssetID
}

func (l *loopEnv) poll(assets ...int64) (bool, int) {
	q := make([]string, len(assets))
	for i, a := range assets {
		q[i] = fmt.Sprint(a)
	}
	req, _ := http.NewRequest("GET", l.srv.URL+"/api/v1/agent/check?asset_id="+strings.Join(q, ","), nil)
	req.Header.Set("Authorization", "Bearer "+l.collector)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Check       bool `json:"check"`
		PollSeconds int  `json:"poll_seconds"`
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || json.Unmarshal(body, &out) != nil {
		l.t.Fatalf("poll: %d %s", resp.StatusCode, body)
	}
	return out.Check, out.PollSeconds
}

func (l *loopEnv) finding(key string) store.Finding {
	var out struct{ Finding store.Finding }
	if code := l.admin.do("GET", fmt.Sprintf("/api/v1/findings/%d", l.findings[key]), nil, &out); code != 200 {
		l.t.Fatalf("finding %s: %d", key, code)
	}
	return out.Finding
}

// Who may ignore, request, decide and end rules.
func TestIgnorePermissionsAndApprovals(t *testing.T) {
	l := newLoopEnv(t)
	ignore := map[string]any{"action": "ignore", "reason": "mitigated", "note": "WAF", "scope": "asset", "expiry": "until_fix"}
	for name, s := range map[string]*session{"engineer": l.eng, "viewer": l.view} {
		var e struct{ Error struct{ Message string } }
		code := s.do("POST", fmt.Sprintf("/api/v1/findings/%d/actions", l.findings["CVE-E"]), ignore, &e)
		if code != 403 || name == "engineer" && !strings.Contains(e.Error.Message, "ignore-requests") {
			t.Errorf("%s ignores: %d %q", name, code, e.Error.Message)
		}
		if code := s.do("POST", "/api/v1/findings/actions", map[string]any{"action": "ignore", "ids": []int64{l.findings["CVE-E"]},
			"reason": "mitigated", "note": "x", "expiry": "until_fix"}, nil); code != 403 {
			t.Errorf("%s bulk ignore: %d", name, code)
		}
	}

	// Engineers and viewers ask; a request with a bad expiry is refused.
	if code := l.eng.do("POST", "/api/v1/ignore-requests", map[string]any{"finding_ids": []int64{l.findings["CVE-E"]},
		"reason": "accepted_risk", "note": "x", "scope": "asset", "expiry": "never"}, nil); code != 400 {
		t.Errorf("accepted risk with no expiry: %d", code)
	}
	var engReq, viewReq store.IgnoreRequest
	if code := l.eng.do("POST", "/api/v1/ignore-requests", map[string]any{"finding_ids": []int64{l.findings["CVE-E"]},
		"reason": "no_fix", "note": "no fix upstream; not exposed", "scope": "everywhere", "expiry": "until_fix"}, &engReq); code != 201 {
		t.Fatalf("engineer request: %d", code)
	}
	if code := l.view.do("POST", "/api/v1/ignore-requests", map[string]any{"fix_group": l.group,
		"reason": "accepted_risk", "note": "dev box", "expiry": "date", "until": time.Now().AddDate(0, 0, 14)}, &viewReq); code != 201 {
		t.Fatalf("viewer request for a fix: %d", code)
	}
	if len(viewReq.FindingIDs) != 2 || viewReq.FixGroup != l.group || viewReq.RequestedByName != "view@x.io" || viewReq.Scope != "asset" {
		t.Errorf("fix request: %+v", viewReq)
	}

	type inbox struct {
		Items     []store.IgnoreRequest
		Total     int64
		CanDecide bool `json:"can_decide"`
	}
	var mine, all inbox
	l.eng.do("GET", "/api/v1/ignore-requests", nil, &mine)
	if mine.Total != 1 || mine.Items[0].ID != engReq.ID || mine.CanDecide {
		t.Errorf("engineer sees %+v", mine)
	}
	if code := l.eng.do("GET", fmt.Sprintf("/api/v1/ignore-requests/%d", viewReq.ID), nil, nil); code != 404 {
		t.Errorf("engineer reads another person's request: %d", code)
	}
	l.sec.do("GET", "/api/v1/ignore-requests", nil, &all)
	if all.Total != 2 || !all.CanDecide {
		t.Errorf("security inbox: %+v", all)
	}

	for name, s := range map[string]*session{"engineer": l.eng, "viewer": l.view} {
		if code := s.do("POST", fmt.Sprintf("/api/v1/ignore-requests/%d/decision", engReq.ID), map[string]string{"decision": "approve"}, nil); code != 403 {
			t.Errorf("%s decides: %d", name, code)
		}
	}
	var decided store.IgnoreRequest
	if code := l.sec.do("POST", fmt.Sprintf("/api/v1/ignore-requests/%d/decision", engReq.ID), map[string]string{"decision": "approve", "note": "ok"}, &decided); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	if decided.Status != "approved" || decided.Applied != 1 || decided.DecidedByName != "sec@x.io" {
		t.Errorf("approved: %+v", decided)
	}
	if f := l.finding("CVE-E"); f.State != "risk_accepted" || f.IgnoreReason != "no_fix" || !f.UntilFix {
		t.Errorf("CVE-E after approval: %s %s %v", f.State, f.IgnoreReason, f.UntilFix)
	}
	if code := l.admin.do("POST", fmt.Sprintf("/api/v1/ignore-requests/%d/decision", engReq.ID), map[string]string{"decision": "decline"}, nil); code != 409 {
		t.Errorf("decided twice: %d", code)
	}
	if code := l.admin.do("POST", fmt.Sprintf("/api/v1/ignore-requests/%d/decision", viewReq.ID), map[string]string{"decision": "maybe"}, nil); code != 400 {
		t.Errorf("bad decision: %d", code)
	}
	if code := l.admin.do("POST", fmt.Sprintf("/api/v1/ignore-requests/%d/decision", viewReq.ID), map[string]string{"decision": "decline", "note": "fix it"}, &decided); code != 200 || decided.Status != "declined" {
		t.Errorf("decline: %d %+v", code, decided)
	}
	var audit struct{ Items []store.AuditEvent }
	l.admin.do("GET", "/api/v1/audit?object_type=ignore_request", nil, &audit)
	got := map[string]bool{}
	for _, a := range audit.Items {
		got[a.Action] = true
	}
	for _, want := range []string{"ignore_request.create", "ignore_request.approve", "ignore_request.decline"} {
		if !got[want] {
			t.Errorf("audit has no %s: %v", want, got)
		}
	}

	// Security ignores directly; invalid input says why.
	var bad struct {
		Error struct{ Code, Message string }
	}
	if code := l.sec.do("POST", fmt.Sprintf("/api/v1/findings/%d/actions", l.findings["CVE-L1"]), map[string]any{"action": "ignore",
		"reason": "accepted_risk", "note": "x", "expiry": "never"}, &bad); code != 400 || bad.Error.Code != "invalid_action" {
		t.Errorf("never for accepted risk: %d %+v", code, bad)
	}
	if code := l.sec.do("POST", fmt.Sprintf("/api/v1/findings/%d/actions", l.findings["CVE-L1"]), map[string]any{"action": "ignore",
		"reason": "false_positive", "note": "not our code path", "scope": "everywhere", "expiry": "never"}, nil); code != 200 {
		t.Fatalf("security ignores: %d", code)
	}
	if f := l.finding("CVE-L1"); f.Verification != "rejected" || f.DisplayState != "accepted" {
		t.Errorf("false positive: %s %s", f.Verification, f.DisplayState)
	}
	var rules struct{ Items []store.IgnoreRule }
	l.view.do("GET", "/api/v1/ignore-rules", nil, &rules)
	if len(rules.Items) != 2 {
		t.Fatalf("rules: %+v", rules)
	}
	for _, r := range rules.Items {
		if code := l.eng.do("DELETE", fmt.Sprintf("/api/v1/ignore-rules/%d", r.ID), nil, nil); code != 403 {
			t.Errorf("engineer ends a rule: %d", code)
		}
		var out struct{ Reopened int64 }
		if code := l.sec.do("DELETE", fmt.Sprintf("/api/v1/ignore-rules/%d", r.ID), nil, &out); code != 200 || out.Reopened != 1 {
			t.Errorf("end rule %d: %d %+v", r.ID, code, out)
		}
	}
	if f := l.finding("CVE-L1"); f.State != "new" || f.Verification != "confirmed" {
		t.Errorf("after the rule ended: %s %s", f.State, f.Verification)
	}
	// Snooze until a fix ships, and its refusal when a fix exists.
	if code := l.sec.do("POST", fmt.Sprintf("/api/v1/findings/%d/actions", l.findings["CVE-L1"]), map[string]any{"action": "suppress",
		"note": "later", "until_fix": true}, nil); code != 400 {
		t.Errorf("snooze until a fix that exists: %d", code)
	}
	if code := l.sec.do("POST", fmt.Sprintf("/api/v1/findings/%d/actions", l.findings["CVE-E"]), map[string]any{"action": "suppress",
		"note": "waiting for upstream", "until_fix": true}, nil); code != 200 {
		t.Errorf("snooze until a fix: %d", code)
	}
	if f := l.finding("CVE-E"); f.DisplayState != "snoozed" || !f.UntilFix {
		t.Errorf("snoozed: %s %v", f.DisplayState, f.UntilFix)
	}
}

// Check again: request, agent poll and pickup, the report, the outcome.
func TestCheckAgainAPI(t *testing.T) {
	l := newLoopEnv(t)
	if due, every := l.poll(l.asset); due || every < 15 {
		t.Fatalf("nothing requested: %v %d", due, every)
	}
	if code := l.view.do("POST", fmt.Sprintf("/api/v1/assets/%d/check", l.asset), nil, nil); code != 403 {
		t.Errorf("viewer checks: %d", code)
	}
	var c store.Check
	if code := l.eng.do("POST", fmt.Sprintf("/api/v1/fix-groups/%s/check", l.group), nil, &c); code != 201 {
		t.Fatalf("check a fix: %d", code)
	}
	if c.Method != "agent" || c.Status != "waiting" || c.AgentPolledAt == nil {
		t.Errorf("check: %+v (the agent has polled once)", c)
	}
	var again store.Check
	if code := l.eng.do("POST", fmt.Sprintf("/api/v1/fix-groups/%s/check", l.group), nil, &again); code != 200 || again.ID != c.ID {
		t.Errorf("second press: %d %d", code, again.ID)
	}
	if code := l.eng.do("POST", "/api/v1/fix-groups/no-such-fix/check", nil, nil); code != 404 {
		t.Errorf("unknown fix: %d", code)
	}
	if due, _ := l.poll(l.asset); !due {
		t.Fatal("agent not asked to report")
	}
	var asset struct{ Asset store.Asset }
	l.view.do("GET", fmt.Sprintf("/api/v1/assets/%d", l.asset), nil, &asset)
	if asset.Asset.AgentPolledAt == nil {
		t.Error("asset does not say its agent polls")
	}

	// "I applied this": in progress, nothing resolved.
	var applied struct {
		Updated int64
		Check   store.Check
	}
	if code := l.eng.do("POST", fmt.Sprintf("/api/v1/fix-groups/%s/applied", l.group), nil, &applied); code != 200 || applied.Updated != 2 || applied.Check.ID != c.ID {
		t.Fatalf("applied: %d %+v", code, applied)
	}
	var regressed struct{ Total int64 }
	if code := l.view.do("GET", "/api/v1/findings?state=regressed", nil, &regressed); code != 200 || regressed.Total != 0 {
		t.Errorf("state=regressed: %d %d", code, regressed.Total)
	}
	if f := l.finding("CVE-L1"); f.Status != "open" || f.State != "in_progress" || f.StateReason != "applied, waiting for a check" {
		t.Errorf("applied issue: %s %s %q", f.Status, f.State, f.StateReason)
	}

	// The agent reports: the poll stops asking.
	l.ingest("pkg:npm/lodash@4.17.21", "pkg:npm/express@4.0.0")
	if due, _ := l.poll(l.asset); due {
		t.Error("agent asked again after it reported")
	}
	var got store.Check
	l.view.do("GET", fmt.Sprintf("/api/v1/checks/%d", c.ID), nil, &got)
	if got.Status != "evaluating" || got.PickedUpAt == nil {
		t.Errorf("after the report: %+v", got)
	}
	// The evaluation: lodash's findings go, the check passes.
	if _, err := l.st.ResolveRemovedFindings(l.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := l.st.Pool.Exec(l.ctx, `UPDATE jobs SET done_at = now() WHERE done_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	if err := l.st.MarkEvaluated(l.ctx, l.asset, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, err := l.st.CompleteChecks(tenant.System(context.Background())); err != nil || n != 1 {
		t.Fatalf("complete: %d %v", n, err)
	}
	var list struct {
		Items []store.Check
		Total int64
	}
	l.view.do("GET", "/api/v1/checks?fix_group="+l.group, nil, &list)
	if list.Total != 1 || list.Items[0].Outcome != "passed" || list.Items[0].Fixed != 2 || list.Items[0].Reason != "check" {
		t.Errorf("fix's checks: %+v", list)
	}
	var audit struct{ Items []store.AuditEvent }
	l.admin.do("GET", "/api/v1/audit?action=check.request", nil, &audit)
	l.admin.do("GET", "/api/v1/audit?object_type=fix_group", nil, &audit)
	if len(audit.Items) == 0 || audit.Items[0].Action != "fix.applied" {
		t.Errorf("audit: %+v", audit.Items)
	}

	// A repository scanned by the server: check again queues the scan.
	var integ store.Integration
	if code := l.admin.do("POST", "/api/v1/integrations", map[string]any{"kind": "git_repository",
		"config": map[string]string{"url": "https://github.com/x/app"}}, &integ); code != 201 {
		t.Fatalf("integration: %d", code)
	}
	b := model.NewBatch(model.Collector{ID: "git", Version: "1", Method: "lockfile"}, model.AssetRef{Kind: model.AssetRepository,
		Name: "github.com/x/app", Identifiers: []model.Identifier{{Scheme: "repo-url", Value: "https://github.com/x/app"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.15", Confidence: model.ConfidenceConfirmed}}
	b.Complete = true
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := l.st.Ingest(l.ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.st.IntegrationResult(l.ctx, integ.ID, r.AssetID, nil); err != nil {
		t.Fatal(err)
	}
	var repo store.Check
	if code := l.eng.do("POST", fmt.Sprintf("/api/v1/assets/%d/check", r.AssetID), nil, &repo); code != 201 || repo.Method != "integration" {
		t.Fatalf("repository check: %d %+v", code, repo)
	}
	var queued bool
	if err := l.st.Pool.QueryRow(l.ctx, `SELECT EXISTS (SELECT 1 FROM jobs WHERE kind = 'integration.run' AND dedupe_key = $1 AND done_at IS NULL)`,
		fmt.Sprintf("integration:%d", integ.ID)).Scan(&queued); err != nil || !queued {
		t.Errorf("scan queued: %v %v", queued, err)
	}
}
