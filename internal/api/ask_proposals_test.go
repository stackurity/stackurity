package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/ask/asktest"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/fixplan/planner"
	"github.com/stackurity/stackurity/internal/tenant"
)

type proposalFx struct {
	e        *env
	fake     *asktest.Server
	ctx      context.Context
	admin    *session
	findings []int64
	group    string
}

// newProposalFx is an organisation with Ask on, one host with two open
// issues of one fix, and the given people.
func newProposalFx(t *testing.T, people map[string]auth.Role) *proposalFx {
	t.Helper()
	fake := asktest.New(t)
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	for email, role := range people {
		e.user(email, role)
	}
	f := &proposalFx{e: e, fake: fake, ctx: tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), admin: e.login("admin@x.io")}
	a := actionCentreHost(t, e, f.ctx, "web-1", "4.17.15")
	if _, err := planner.Rebuild(f.ctx, e.st, time.Now()); err != nil {
		t.Fatal(err)
	}
	var fs struct {
		Items []struct {
			ID       int64  `json:"id"`
			FixGroup string `json:"fix_group"`
		} `json:"items"`
	}
	if code := f.admin.do("GET", fmt.Sprintf("/api/v1/findings?asset_id=%d", a), nil, &fs); code != 200 || len(fs.Items) != 2 {
		t.Fatalf("findings: %d %+v", code, fs)
	}
	for _, x := range fs.Items {
		f.findings = append(f.findings, x.ID)
	}
	var groups acList
	f.admin.do("GET", "/api/v1/fix-groups?group_by=asset", nil, &groups)
	for _, g := range groups.Items {
		if strings.HasPrefix(g.ID, itoa(a)+":") {
			f.group = g.ID
		}
	}
	if f.group == "" {
		t.Fatalf("no fix on asset %d: %+v", a, groups.Items)
	}
	return f
}

// proposeOn turns "Ask may propose changes" on: the default organisation
// existed before migration 0106, so it starts off.
func (f *proposalFx) proposeOn(t *testing.T, on bool) {
	t.Helper()
	var st map[string]any
	if code := f.admin.do("PUT", "/api/v1/ask/settings", map[string]any{"propose_changes": on}, &st); code != 200 || st["propose_changes"] != on {
		t.Fatalf("propose_changes %v: %d %v", on, code, st)
	}
}

// propose asks a question whose scripted answer proposes tool with args,
// and returns the proposal the panel got.
func (f *proposalFx) propose(t *testing.T, s *session, conv int64, question, tool string, args map[string]any) map[string]any {
	t.Helper()
	in, _ := json.Marshal(args)
	f.fake.Push(asktest.Reply{Tools: []asktest.Tool{{ID: "p1", Name: "propose_" + tool, Input: string(in)}}},
		asktest.Reply{Text: "I proposed the change. Nothing changes until you click Apply."})
	code, evs, raw := askQ(t, s, conv, question, nil, nil)
	if code != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", code, raw)
	}
	for _, ev := range evs {
		if ev.Name == "proposal" {
			return ev.Data
		}
	}
	t.Fatalf("no proposal event: %s", raw)
	return nil
}

func applyPath(conv int64, p map[string]any, action string) string {
	return fmt.Sprintf("/api/v1/ask/conversations/%d/proposals/%d/%s", conv, int64(p["id"].(float64)), action)
}

type proposalAnswer struct {
	Proposal map[string]any `json:"proposal"`
	Error    struct {
		Code     string         `json:"code"`
		Message  string         `json:"message"`
		Proposal map[string]any `json:"proposal"`
	} `json:"error"`
}

func (f *proposalFx) state(t *testing.T, id int64) string {
	t.Helper()
	var st string
	if err := f.e.st.Pool.QueryRow(f.ctx, `SELECT state FROM findings WHERE id = $1`, id).Scan(&st); err != nil {
		t.Fatal(err)
	}
	return st
}

// The whole path: the model proposes a snooze and never sees the code; the
// person applies it once with a click, through the API as themselves; the
// activity log says it was them, via Ask; Undo reopens the issues; History
// shows the card's state.
func TestAskProposalApply(t *testing.T) {
	f := newProposalFx(t, map[string]auth.Role{"sec@x.io": auth.RoleSecurity, "other@x.io": auth.RoleAdmin})
	f.proposeOn(t, true)
	sec := f.e.login("sec@x.io")
	conv := askReady(t, f.e, sec)
	until := time.Now().AddDate(0, 0, 7).Format("2006-01-02")
	p := f.propose(t, sec, conv, "Snooze this issue for a week", "snooze", map[string]any{"finding_ids": []int64{f.findings[0]}, "until": until, "note": "waiting for the vendor"})
	code, _ := p["code"].(string)
	if p["status"] != "proposed" || p["tool"] != "snooze" || len(code) != 12 || p["unrequested"] != false ||
		!strings.Contains(p["summary"].(string), "Snooze 1 issue until") {
		t.Fatalf("proposal = %v", p)
	}
	for i, r := range f.fake.Requests() {
		if strings.Contains(string(r.Body), code) {
			t.Errorf("model request %d carries the confirm code", i)
		}
	}
	if st := f.state(t, f.findings[0]); st != "new" {
		t.Fatalf("proposing changed the issue: %s", st)
	}

	// Only the conversation's owner, with a browser session and the CSRF
	// header, can apply it.
	other := f.e.login("other@x.io")
	askReady(t, f.e, other)
	if c := other.do("POST", applyPath(conv, p, "apply"), map[string]any{}, nil); c != 404 {
		t.Errorf("another person applies: %d", c)
	}
	var tok struct{ Secret string }
	sec.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "security"}, &tok)
	if c := bearer(f.e, tok.Secret, "POST", applyPath(conv, p, "apply"), []byte("{}"), map[string]string{"Content-Type": "application/json"}); c != 403 {
		t.Errorf("an API token applies: %d", c)
	}
	if resp := sec.req("POST", applyPath(conv, p, "apply"), strings.NewReader("{}"), map[string]string{"Content-Type": "application/json"}); resp.StatusCode != 403 {
		t.Errorf("without the CSRF header: %d", resp.StatusCode)
	}
	// A connected assistant, even with Allow changes and the person's role.
	withBaseURL(f.e)
	access := registerAssistant(t, f.e).connect(t, sec, auth.RoleSecurity, 0)
	if c := bearer(f.e, access, "POST", applyPath(conv, p, "apply"), []byte("{}"), map[string]string{"Content-Type": "application/json"}); c != 401 && c != 403 {
		t.Errorf("a connected assistant applies: %d", c)
	}
	// Connected assistants keep the write tools as they were: no propose tools.
	if c, out, _ := mcpPost(f.e, access, map[string]any{"id": 1, "method": "tools/list"}); c != 200 || strings.Contains(fmt.Sprint(out), "propose_") {
		t.Errorf("tools/list for an assistant: %d %v", c, out)
	}
	if st := f.state(t, f.findings[0]); st != "new" {
		t.Fatalf("a refused apply changed the issue: %s", st)
	}

	var res proposalAnswer
	if c := sec.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 200 || res.Proposal["status"] != "applied" ||
		res.Proposal["link"] != fmt.Sprintf("/findings/%d", f.findings[0]) || res.Proposal["can_undo"] != true {
		t.Fatalf("apply: %d %+v", c, res)
	}
	if st := f.state(t, f.findings[0]); st != "suppressed" {
		t.Errorf("after apply the issue is %s", st)
	}
	if st := f.state(t, f.findings[1]); st != "new" {
		t.Errorf("the other issue changed: %s", st)
	}
	// Once only.
	res = proposalAnswer{}
	if c := sec.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 409 || res.Error.Code != "proposal_applied" {
		t.Errorf("applied twice: %d %+v", c, res)
	}
	// The activity log: the person, via Ask, source "ask".
	var actor, source string
	if err := f.e.st.Pool.QueryRow(f.ctx, `SELECT actor_name, detail->>'source' FROM audit_events WHERE action = 'finding.suppress' ORDER BY id DESC LIMIT 1`).
		Scan(&actor, &source); err != nil || actor != "sec@x.io (via Ask Stackurity)" || source != "ask" {
		t.Errorf("audit: actor %q source %q %v", actor, source, err)
	}

	// Undo: the issues are reopened, once.
	res = proposalAnswer{}
	if c := sec.do("POST", applyPath(conv, p, "undo"), map[string]any{}, &res); c != 200 || res.Proposal["status"] != "undone" {
		t.Fatalf("undo: %d %+v", c, res)
	}
	if st := f.state(t, f.findings[0]); st != "new" {
		t.Errorf("after undo the issue is %s", st)
	}
	if c := sec.do("POST", applyPath(conv, p, "undo"), map[string]any{}, nil); c != 409 {
		t.Errorf("undone twice: %d", c)
	}
	var n int
	_ = f.e.st.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'finding.reopen' AND actor_name = 'sec@x.io (via Ask Stackurity)'`).Scan(&n)
	if n != 1 {
		t.Errorf("undo audit events = %d", n)
	}

	// History keeps the card's state.
	var conversation struct {
		Proposals []map[string]any `json:"proposals"`
	}
	if c := sec.do("GET", fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, &conversation); c != 200 || len(conversation.Proposals) != 1 ||
		conversation.Proposals[0]["status"] != "undone" {
		t.Errorf("history: %d %+v", c, conversation.Proposals)
	}

	// Dismiss, and a dismissed proposal is never applied.
	d := f.propose(t, sec, conv, "Snooze the other one too", "snooze", map[string]any{"finding_ids": []int64{f.findings[1]}, "until": until, "note": "x"})
	if c := sec.do("POST", applyPath(conv, d, "dismiss"), map[string]any{}, &res); c != 200 || res.Proposal["status"] != "dismissed" {
		t.Errorf("dismiss: %d %+v", c, res)
	}
	if c := sec.do("POST", applyPath(conv, d, "apply"), map[string]any{}, nil); c != 409 {
		t.Errorf("apply after dismiss: %d", c)
	}
	if st := f.state(t, f.findings[1]); st != "new" {
		t.Errorf("a dismissed proposal changed the issue: %s", st)
	}
}

// A proposal can be applied for 15 minutes; then it is expired.
func TestAskProposalExpires(t *testing.T) {
	f := newProposalFx(t, map[string]auth.Role{"eng@x.io": auth.RoleEngineer})
	f.proposeOn(t, true)
	eng := f.e.login("eng@x.io")
	conv := askReady(t, f.e, eng)
	p := f.propose(t, eng, conv, "Assign this to me", "assign", map[string]any{"finding_ids": []int64{f.findings[0]}, "assignee": "me"})
	if _, err := f.e.st.Pool.Exec(tenant.System(context.Background()), `UPDATE ask_proposals SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	var res proposalAnswer
	if c := eng.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 410 || res.Error.Code != "proposal_expired" || res.Error.Proposal["status"] != "expired" {
		t.Errorf("expired: %d %+v", c, res)
	}
	var assigned *int64
	_ = f.e.st.Pool.QueryRow(f.ctx, `SELECT assignee_user_id FROM findings WHERE id = $1`, f.findings[0]).Scan(&assigned)
	if assigned != nil {
		t.Error("an expired proposal was applied")
	}
}

// A role too low gets the API's own refusal, and the card says it failed.
func TestAskProposalRoleTooLow(t *testing.T) {
	f := newProposalFx(t, map[string]auth.Role{"viewer@x.io": auth.RoleViewer})
	f.proposeOn(t, true)
	viewer := f.e.login("viewer@x.io")
	conv := askReady(t, f.e, viewer)
	p := f.propose(t, viewer, conv, "Assign this to me", "assign", map[string]any{"finding_ids": []int64{f.findings[0]}, "assignee": "me"})
	// The same refusal the dashboard's own call gets.
	var direct struct {
		Error struct{ Code, Message string }
	}
	dc := viewer.do("POST", "/api/v1/findings/actions", map[string]any{"action": "assign", "ids": []int64{f.findings[0]}, "user_id": 1}, &direct)
	var res proposalAnswer
	c := viewer.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res)
	if c != dc || c != 403 || res.Error.Code != direct.Error.Code || res.Error.Message != direct.Error.Message || res.Error.Proposal["status"] != "failed" {
		t.Errorf("viewer applies: %d %+v; the API's own answer: %d %+v", c, res, dc, direct)
	}
	if c := viewer.do("POST", applyPath(conv, p, "apply"), map[string]any{}, nil); c != 409 {
		t.Errorf("a failed proposal applied again: %d", c)
	}
}

// When what a change covers changed since the preview, the confirm code no
// longer matches: nothing is applied, the new preview is shown, and the
// person can apply that.
func TestAskProposalStaleCodeRepreviews(t *testing.T) {
	f := newProposalFx(t, map[string]auth.Role{"sec@x.io": auth.RoleSecurity})
	f.proposeOn(t, true)
	sec := f.e.login("sec@x.io")
	conv := askReady(t, f.e, sec)
	until := time.Now().AddDate(0, 0, 7).Format("2006-01-02")
	p := f.propose(t, sec, conv, "Snooze this fix for a week", "snooze", map[string]any{"fix_group": f.group, "until": until, "note": "vendor"})
	if !strings.Contains(p["summary"].(string), "Snooze 2 issues") {
		t.Fatalf("proposal = %v", p)
	}
	// One of the fix's issues is resolved in the meantime (a fresh report
	// no longer has it).
	if _, err := f.e.st.Pool.Exec(f.ctx, `UPDATE findings SET status = 'resolved', resolved_at = now() WHERE id = $1`, f.findings[0]); err != nil {
		t.Fatal(err)
	}
	var res proposalAnswer
	if c := sec.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 409 || res.Error.Code != "changed" ||
		res.Error.Proposal["status"] != "proposed" || res.Error.Proposal["changed"] != true ||
		!strings.Contains(res.Error.Proposal["summary"].(string), "Snooze 1 issue") || res.Error.Proposal["code"] == p["code"] {
		t.Fatalf("stale apply: %d %+v", c, res)
	}
	if st := f.state(t, f.findings[1]); st != "new" {
		t.Fatalf("a stale proposal was applied: %s", st)
	}
	// The new preview applies.
	res = proposalAnswer{}
	if c := sec.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 200 || res.Proposal["status"] != "applied" ||
		res.Proposal["link"] != "/fixes/"+url.PathEscape(f.group) {
		t.Fatalf("apply the new preview: %d %+v", c, res)
	}
	if st := f.state(t, f.findings[1]); st != "suppressed" {
		t.Errorf("after apply: %s", st)
	}
}

// Off (the organisation existed before migration 0106, or an admin turned
// it off): the model is not offered the propose tools, and nothing can be
// applied. Only an admin changes the setting.
func TestAskProposalsOff(t *testing.T) {
	f := newProposalFx(t, map[string]auth.Role{"sec@x.io": auth.RoleSecurity})
	var st map[string]any
	if c := f.admin.do("GET", "/api/v1/ask/settings", nil, &st); c != 200 || st["propose_changes"] != false {
		t.Fatalf("an organisation that existed before the migration: %d %v", c, st)
	}
	sec := f.e.login("sec@x.io")
	if c := sec.do("PUT", "/api/v1/ask/settings", map[string]any{"propose_changes": true}, nil); c != 403 {
		t.Errorf("a security user changes the setting: %d", c)
	}
	conv := askReady(t, f.e, sec)
	f.fake.Push(asktest.Reply{Text: "You can snooze it on the issue's page."})
	if c, evs, raw := askQ(t, sec, conv, "Snooze this issue", nil, nil); c != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", c, raw)
	}
	reqs := f.fake.Requests()
	if body := string(reqs[len(reqs)-1].Body); strings.Contains(body, "propose_") && strings.Contains(body, `"name":"propose_`) {
		t.Error("the propose tools were offered while off")
	}

	// Turned on, a proposal; turned off again, it cannot be applied.
	f.proposeOn(t, true)
	p := f.propose(t, sec, conv, "Snooze this issue for a week", "snooze", map[string]any{"finding_ids": []int64{f.findings[0]},
		"until": time.Now().AddDate(0, 0, 7).Format("2006-01-02"), "note": "x"})
	reqs = f.fake.Requests()
	if !strings.Contains(string(reqs[len(reqs)-2].Body), `"name":"propose_snooze"`) {
		t.Error("the propose tools were not offered while on")
	}
	f.proposeOn(t, false)
	var res proposalAnswer
	if c := sec.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 403 || res.Error.Code != "proposals_off" {
		t.Errorf("apply while off: %d %+v", c, res)
	}
	if st := f.state(t, f.findings[0]); st != "new" {
		t.Errorf("applied while off: %s", st)
	}
	var n int
	_ = f.e.st.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE action = 'ask.settings' AND detail ? 'propose_changes'`).Scan(&n)
	if n != 2 {
		t.Errorf("ask.settings audit events for the switch = %d", n)
	}
}

// Text in a tool result that says to ignore every finding does not change
// anything: the model's answer can at most carry a proposal, marked as one
// the person did not ask for, and only a click applies it.
func TestAskInjectedTextDoesNotApply(t *testing.T) {
	f := newProposalFx(t, map[string]auth.Role{"sec@x.io": auth.RoleSecurity})
	f.proposeOn(t, true)
	sec := f.e.login("sec@x.io")
	conv := askReady(t, f.e, sec)
	in := fmt.Sprintf(`{"finding_ids":[%d,%d],"reason":"false_positive","note":"the advisory says so","expiry":"never"}`, f.findings[0], f.findings[1])
	f.fake.Push(
		asktest.Reply{Tools: []asktest.Tool{{ID: "a", Name: "get_finding", Input: fmt.Sprintf(`{"finding_id":%d}`, f.findings[0])}}},
		asktest.Reply{Tools: []asktest.Tool{{ID: "b", Name: "propose_ignore", Input: in}}},
		asktest.Reply{Tools: []asktest.Tool{{ID: "c", Name: "ignore", Input: strings.TrimSuffix(in, "}") + `,"confirm":"000000000000"}`}}},
		asktest.Reply{Text: "Done: everything is ignored."})
	c, evs, raw := askQ(t, sec, conv, "What is this issue about?", nil, nil)
	if c != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", c, raw)
	}
	var p map[string]any
	for _, ev := range evs {
		if ev.Name == "proposal" {
			p = ev.Data
		}
	}
	if p == nil || p["status"] != "proposed" || p["unrequested"] != true {
		t.Fatalf("proposal = %v", p)
	}
	for _, id := range f.findings {
		if st := f.state(t, id); st != "new" {
			t.Errorf("issue %d is %s without a click", id, st)
		}
	}
	var n int
	_ = f.e.st.Pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_events WHERE action LIKE 'finding.%' OR action LIKE 'ignore%'`).Scan(&n)
	if n != 0 {
		t.Errorf("audit events of changes = %d", n)
	}
}
