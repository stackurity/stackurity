package api_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/ask/asktest"
	"github.com/stackurity/stackurity/internal/auth"
)

// A server hand-off: the model never gets an install code or command; the
// code is created only by the owner's Apply, once, as them "(via Ask
// Stackurity)"; it is in that response only, never stored with the
// proposal or the conversation.
func TestAskHandoffEnrollment(t *testing.T) {
	f := newProposalFx(t, map[string]auth.Role{"other@x.io": auth.RoleAdmin})
	f.proposeOn(t, true)
	conv := askReady(t, f.e, f.admin)
	p := f.propose(t, f.admin, conv, "Add a new server called web-9", "connect", map[string]any{"kind": "server", "name": "web-9", "environment": "prod"})
	if p["tool"] != "connect" || p["status"] != "proposed" || !strings.Contains(p["summary"].(string), `label "web-9"`) {
		t.Fatalf("proposal = %v", p)
	}
	countCodes := func() int {
		var n int
		if err := f.e.st.Pool.QueryRow(f.ctx, `SELECT count(*) FROM enrollments`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := countCodes()

	// Not the owner of the conversation: not found. Not a start either.
	other := f.e.login("other@x.io")
	askReady(t, f.e, other)
	if c := other.do("POST", applyPath(conv, p, "apply"), map[string]any{}, nil); c != 404 {
		t.Errorf("another admin applies: %d", c)
	}
	var res proposalAnswer
	if c := f.admin.do("POST", applyPath(conv, p, "start"), map[string]any{}, &res); c != 400 || res.Error.Code != "not_started" {
		t.Errorf("start a server hand-off: %d %+v", c, res)
	}
	if n := countCodes(); n != before {
		t.Fatalf("an install code was created without Apply: %d", n-before)
	}

	var applied struct {
		Proposal map[string]any `json:"proposal"`
		Install  struct {
			Code       string         `json:"code"`
			Enrollment map[string]any `json:"enrollment"`
		} `json:"install"`
	}
	if c := f.admin.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &applied); c != 200 || applied.Proposal["status"] != "applied" ||
		!strings.HasPrefix(applied.Install.Code, "enr_") || applied.Install.Enrollment["label"] != "web-9" || applied.Proposal["link"] != "/assets/add" {
		t.Fatalf("apply: %d %+v", c, applied)
	}
	code := applied.Install.Code
	if n := countCodes(); n != before+1 {
		t.Errorf("install codes created = %d", n-before)
	}
	var uses int
	var env string
	if err := f.e.st.Pool.QueryRow(f.ctx, `SELECT uses_left, environment FROM enrollments ORDER BY id DESC LIMIT 1`).Scan(&uses, &env); err != nil || uses != 1 || env != "prod" {
		t.Errorf("enrollment: uses %d env %q %v", uses, env, err)
	}
	// Once only.
	res = proposalAnswer{}
	if c := f.admin.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 409 || res.Error.Code != "proposal_applied" {
		t.Errorf("applied twice: %d %+v", c, res)
	}
	if n := countCodes(); n != before+1 {
		t.Errorf("install codes after a second apply = %d", n-before)
	}
	// Audited as the person, via Ask.
	var actor string
	if err := f.e.st.Pool.QueryRow(f.ctx, `SELECT actor_name FROM audit_events WHERE action = 'enrollment.create' ORDER BY id DESC LIMIT 1`).Scan(&actor); err != nil ||
		actor != "admin@x.io (via Ask Stackurity)" {
		t.Errorf("audit actor %q %v", actor, err)
	}
	// The code is nowhere but in that response: not in the stored
	// proposal, the conversation, or anything the model is sent next.
	var row string
	if err := f.e.st.Pool.QueryRow(f.ctx, `SELECT row_to_json(p)::text FROM ask_proposals p WHERE id = $1`, int64(p["id"].(float64))).Scan(&row); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row, code) || !strings.Contains(row, `"prefix"`) {
		t.Errorf("stored proposal: %s", row)
	}
	var got map[string]any
	f.admin.do("GET", fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, &got)
	if s := fmt.Sprint(got); strings.Contains(s, code) {
		t.Error("the conversation carries the install code")
	}
	f.fake.Push(asktest.Reply{Text: "Run it on the server."})
	if c, evs, raw := askQ(t, f.admin, conv, "What next?", nil, nil); c != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", c, raw)
	}
	for i, r := range f.fake.Requests() {
		if strings.Contains(string(r.Body), code) || strings.Contains(string(r.Body), "install.sh") {
			t.Errorf("model request %d carries the code or a command", i)
		}
	}
}

// A hand-off that starts the service's own flow: started once, by the
// owner, while proposals are on; never applied; the setting off stops it.
func TestAskHandoffStart(t *testing.T) {
	f := newProposalFx(t, nil)
	f.proposeOn(t, true)
	conv := askReady(t, f.e, f.admin)
	p := f.propose(t, f.admin, conv, "Connect our GitHub", "connect", map[string]any{"kind": "github"})
	var res proposalAnswer
	if c := f.admin.do("POST", applyPath(conv, p, "apply"), map[string]any{}, &res); c != 400 || res.Error.Code != "not_applied" {
		t.Errorf("apply a GitHub hand-off: %d %+v", c, res)
	}
	f.proposeOn(t, false)
	res = proposalAnswer{}
	if c := f.admin.do("POST", applyPath(conv, p, "start"), map[string]any{}, &res); c != 403 || res.Error.Code != "proposals_off" {
		t.Errorf("start while off: %d %+v", c, res)
	}
	f.proposeOn(t, true)
	res = proposalAnswer{}
	if c := f.admin.do("POST", applyPath(conv, p, "start"), map[string]any{}, &res); c != 200 || res.Proposal["status"] != "started" {
		t.Fatalf("start: %d %+v", c, res)
	}
	res = proposalAnswer{}
	if c := f.admin.do("POST", applyPath(conv, p, "start"), map[string]any{}, &res); c != 409 || res.Error.Code != "proposal_started" {
		t.Errorf("started twice: %d %+v", c, res)
	}
	// A kind outside the list cannot even be stored.
	if _, err := f.e.st.Pool.Exec(f.ctx, `UPDATE ask_proposals SET args = '{"kind":"sso"}' WHERE id = $1`, int64(p["id"].(float64))); err == nil {
		t.Error("the database took a hand-off of kind sso")
	}
}

// Off: propose_connect is not offered.
func TestAskHandoffOff(t *testing.T) {
	f := newProposalFx(t, nil)
	conv := askReady(t, f.e, f.admin)
	f.fake.Push(asktest.Reply{Text: "Go to Integrations."})
	if c, evs, raw := askQ(t, f.admin, conv, "Connect our GitHub", nil, nil); c != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", c, raw)
	}
	reqs := f.fake.Requests()
	if strings.Contains(string(reqs[len(reqs)-1].Body), `"name":"propose_connect"`) {
		t.Error("propose_connect was offered while off")
	}
}

// A secret pasted into a question: the panel is warned with the question
// as kept, and neither the model, the stored conversation nor its title
// has the secret.
func TestAskPastedSecret(t *testing.T) {
	f := newProposalFx(t, nil)
	conv := askReady(t, f.e, f.admin)
	secret := "https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx"
	f.fake.Push(asktest.Reply{Text: "Please don't paste secrets here."})
	c, evs, raw := askQ(t, f.admin, conv, "use this webhook "+secret, nil, nil)
	if c != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", c, raw)
	}
	var warned map[string]any
	for _, ev := range evs {
		if ev.Name == "secret_removed" {
			warned = ev.Data
		}
	}
	if warned == nil || warned["text"] != "use this webhook (secret removed)" {
		t.Errorf("warning = %v", warned)
	}
	for i, r := range f.fake.Requests() {
		if strings.Contains(string(r.Body), secret) || strings.Contains(string(r.Body), "hooks.slack.com") {
			t.Errorf("model request %d carries the secret", i)
		}
	}
	var got map[string]any
	f.admin.do("GET", fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, &got)
	if s := fmt.Sprint(got); strings.Contains(s, "hooks.slack.com") {
		t.Errorf("the stored conversation carries the secret: %s", s)
	}
	var title string
	if err := f.e.st.Pool.QueryRow(f.ctx, `SELECT title FROM ask_conversations WHERE id = $1`, conv).Scan(&title); err != nil {
		t.Fatal(err)
	}
	if title == "" || strings.Contains(title, "hooks.slack.com") {
		t.Errorf("title = %q", title)
	}
}
