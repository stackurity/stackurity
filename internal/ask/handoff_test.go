package ask_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/ask/asktest"
)

// adminReplies makes the fake API answer what a hand-off reads: the
// person is an organisation admin, and project 4 exists.
func adminReplies(r *rig) {
	r.api.reply["/api/v1/auth/me"] = `{"user":{"id":7,"email":"alice@example.com"},"role":"admin"}`
	r.api.reply["/api/v1/projects/4"] = `{"project":{"id":4,"name":"Shop"}}`
}

// A hand-off: the model gets a short description, the panel a card, and
// nothing but reads reach the API. For a server, no install code exists
// yet: it is created only by the person's Apply (the API's tests).
func TestConnectHandsOff(t *testing.T) {
	r := newRig(t,
		asktest.Reply{Tools: []asktest.Tool{{ID: "c", Name: ask.ConnectTool, Input: `{"kind":"server","name":"web-9","environment":"prod","project_id":4}`}}},
		asktest.Reply{Text: "Click Apply on the card."})
	adminReplies(r)
	if _, err := r.askProposing("Add a new server called web-9 to Shop", true); err != nil {
		t.Fatal(err)
	}
	ps := r.proposals()
	if len(ps) != 1 || ps[0].Tool != ask.ConnectProposal || ps[0].Status != "proposed" || ps[0].Unrequested ||
		!strings.Contains(ps[0].Summary, `Create an install command for one new server (label "web-9", environment "prod", project "Shop")`) {
		t.Fatalf("proposals = %+v", ps)
	}
	var args ask.Connect
	if err := json.Unmarshal(ps[0].Args, &args); err != nil || args != (ask.Connect{Kind: "server", Name: "web-9", Environment: "prod", ProjectID: 4}) {
		t.Errorf("args = %s %v", ps[0].Args, err)
	}
	var label string
	for _, e := range r.events {
		if e.Kind == "tool" {
			label = e.Tool
		}
	}
	if label != "Preparing a connection" {
		t.Errorf("tool label = %q", label)
	}
	reqs := r.fake.Requests()
	if names := toolNames(t, reqs[0].Body); !strings.Contains(strings.Join(names, ","), ask.ConnectTool) {
		t.Errorf("tools offered = %v", names)
	}
	b := string(reqs[1].Body)
	if !strings.Contains(b, "handed_off") || !strings.Contains(b, "never write an install command yourself") {
		t.Errorf("the model's result: %s", b)
	}
	// The model never gets an install code or command: there is none yet,
	// and nothing it called could create one.
	for i, q := range reqs {
		for _, bad := range []string{"enr_", "install.sh", "curl ", "STACKURITY_ENROLL"} {
			if strings.Contains(string(q.Body), bad) {
				t.Errorf("request %d carries %q", i, bad)
			}
		}
	}
	for _, c := range r.api.calls {
		if !strings.HasPrefix(c, "GET ") {
			t.Errorf("non-read call: %s", c)
		}
	}
}

// Off: propose_connect is not offered, and a model that calls it anyway
// stores nothing.
func TestConnectOffNotOffered(t *testing.T) {
	r := newRig(t,
		asktest.Reply{Tools: []asktest.Tool{{ID: "c", Name: ask.ConnectTool, Input: `{"kind":"github"}`}}},
		asktest.Reply{Text: "Go to Integrations."})
	adminReplies(r)
	if _, err := r.askProposing("Connect our GitHub", false); err != nil {
		t.Fatal(err)
	}
	for i, q := range r.fake.Requests() {
		if strings.Contains(strings.Join(toolNames(t, q.Body), ","), ask.ConnectTool) {
			t.Errorf("request %d offers %s", i, ask.ConnectTool)
		}
	}
	if !strings.Contains(string(r.fake.Requests()[1].Body), `There is no tool \"propose_connect\"`) {
		t.Error("the invented call was not refused")
	}
	if ps := r.proposals(); len(ps) != 0 {
		t.Errorf("proposals = %+v", ps)
	}
	if len(r.api.calls) != 0 {
		t.Errorf("API calls = %v", r.api.calls)
	}
}

// The kind is one of a fixed list: a disconnect, a token, SSO, users or
// billing are not kinds, fields a kind does not take are refused, and a
// name shaped like a secret or an address is refused.
func TestConnectKindEnforced(t *testing.T) {
	for in, want := range map[string]string{
		`{"kind":"github"}`:                         "",
		`{"kind":"slack","name":"security-alerts"}`: "",
		`{"kind":"server","environment":"prod"}`:    "",
		`{"kind":"sso"}`:                            "not something Ask can hand off",
		`{"kind":"disconnect_github"}`:              "not something Ask can hand off",
		`{"kind":"billing"}`:                        "not something Ask can hand off",
		`{"kind":"users"}`:                          "not something Ask can hand off",
		`{"kind":"tokens"}`:                         "not something Ask can hand off",
		`{}`:                                        "kind is required",
		`{"kind":"github","name":"x"}`:              "github does not take name",
		`{"kind":"digitalocean","token":"x"}`:       "digitalocean does not take token",
		`{"kind":"slack","webhook_url":"x"}`:        "slack does not take webhook_url",
		`{"kind":"slack","name":"https://hooks.slack.com/services/T000/B000/XXXXXXXX"}`: "plain name",
		`{"kind":"server","name":"dop_v1_` + strings.Repeat("a", 64) + `"}`:             "plain name",
		`{"kind":"webhook","name":"see www.example.com"}`:                               "plain name",
		`{"kind":"server","environment":"prod; rm -rf /"}`:                              "environment may have",
		`{"kind":"server","project_id":-1}`:                                             "project_id",
	} {
		_, err := ask.ParseConnect(json.RawMessage(in))
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", in, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: err = %v, want %q", in, err, want)
		}
	}
	// Through the engine: refused, nothing stored, the model told why.
	r := newRig(t,
		asktest.Reply{Tools: []asktest.Tool{{ID: "c", Name: ask.ConnectTool, Input: `{"kind":"sso"}`}}},
		asktest.Reply{Text: "I can't."})
	adminReplies(r)
	if _, err := r.askProposing("Set up SSO", true); err != nil {
		t.Fatal(err)
	}
	if ps := r.proposals(); len(ps) != 0 {
		t.Errorf("proposals = %+v", ps)
	}
	if !strings.Contains(string(r.fake.Requests()[1].Body), "not something Ask can hand off") {
		t.Error("the model was not told the kind is refused")
	}
	// The tool's schema lists exactly the kinds.
	var kinds []string
	for _, k := range ask.ConnectKinds() {
		kinds = append(kinds, k.Kind)
	}
	if got := strings.Join(kinds, ","); got != "github,gitlab,jira,pagerduty,slack,teams,email,webhook,server,digitalocean" {
		t.Errorf("kinds = %s", got)
	}
}

// Only an organisation admin can connect anything: for anyone else nothing
// is stored and the model is told to send them to an admin.
func TestConnectNeedsAdmin(t *testing.T) {
	r := newRig(t,
		asktest.Reply{Tools: []asktest.Tool{{ID: "c", Name: ask.ConnectTool, Input: `{"kind":"github"}`}}},
		asktest.Reply{Text: "Ask an admin."})
	r.api.reply["/api/v1/auth/me"] = `{"user":{"id":7},"role":"security"}`
	if _, err := r.askProposing("Connect our GitHub", true); err != nil {
		t.Fatal(err)
	}
	if ps := r.proposals(); len(ps) != 0 {
		t.Errorf("proposals = %+v", ps)
	}
	if !strings.Contains(string(r.fake.Requests()[1].Body), "only an organisation admin can connect GitHub") {
		t.Error("the model was not told")
	}
}

// One proposal per answer, hand-offs included: a hand-off after a change,
// or a second hand-off, gets "not run".
func TestConnectOnePerAnswer(t *testing.T) {
	r := newRig(t,
		asktest.Reply{Tools: []asktest.Tool{
			{ID: "a", Name: ask.ConnectTool, Input: `{"kind":"github"}`},
			{ID: "b", Name: ask.ConnectTool, Input: `{"kind":"gitlab"}`},
			{ID: "c", Name: "propose_assign", Input: `{"finding_ids":[5],"assignee":"me"}`},
		}},
		asktest.Reply{Tools: []asktest.Tool{{ID: "d", Name: ask.ConnectTool, Input: `{"kind":"jira"}`}}},
		asktest.Reply{Text: "One card."})
	adminReplies(r)
	if _, err := r.askProposing("Connect our GitHub and GitLab and Jira", true); err != nil {
		t.Fatal(err)
	}
	ps := r.proposals()
	if len(ps) != 1 || !strings.Contains(string(ps[0].Args), `"github"`) {
		t.Fatalf("proposals = %+v", ps)
	}
	reqs := r.fake.Requests()
	if n := strings.Count(string(reqs[1].Body), "an answer may propose at most one change"); n != 2 {
		t.Errorf("round 1: %d not-run results, want 2", n)
	}
	// Round 2's request repeats round 1's results, plus its own not-run.
	if n := strings.Count(string(reqs[2].Body), "an answer may propose at most one change"); n != 3 {
		t.Errorf("round 2: %d not-run results, want 3: the extra hand-off ran", n)
	}
}

// A secret pasted into a question: removed before the model, the stored
// conversation and the step-up triage see it; the panel is warned (an
// event with the question as kept), and the model is told to point the
// person to the setup page.
func TestPastedSecretNotEchoed(t *testing.T) {
	secrets := []string{
		"ghp_" + strings.Repeat("A1b2", 9),
		"https://hooks.slack.com/services/T0000000/B0000000/abcdefghijklmnopqrstuvwx",
		"dop_v1_" + strings.Repeat("0f", 32),
		"xoxb-1234567890-abcdefghijkl",
	}
	for _, sec := range secrets {
		r := newRig(t, asktest.Reply{Text: "Please don't paste secrets here; enter it on the setup page."})
		if _, err := r.askProposing("Connect Slack with this: "+sec+" thanks", true); err != nil {
			t.Fatal(err)
		}
		var warned *ask.Event
		for i, e := range r.events {
			if e.Kind == "secret_removed" {
				warned = &r.events[i]
			}
		}
		if warned == nil || strings.Contains(warned.Text, sec) || !strings.Contains(warned.Text, "(secret removed)") {
			t.Errorf("%s: warning event = %+v", sec[:8], warned)
		}
		for i, q := range r.fake.Requests() {
			if strings.Contains(string(q.Body), sec) {
				t.Errorf("%s: model request %d carries the secret", sec[:8], i)
			}
			if !strings.Contains(string(q.Body), "removed text that looked like a secret") {
				t.Errorf("%s: model request %d is not told", sec[:8], i)
			}
		}
		ms, _ := r.st.AskMessages(r.ctx, r.user, r.conv.ID)
		for _, m := range ms {
			if strings.Contains(string(m.Content), sec) || strings.Contains(m.VisibleText, sec) {
				t.Errorf("%s: stored message %d carries the secret", sec[:8], m.Seq)
			}
		}
	}
	// A question without one: no warning, no note.
	r := newRig(t, asktest.Reply{Text: "ok"})
	if _, err := r.askProposing("Connect our GitHub", false); err != nil {
		t.Fatal(err)
	}
	for _, e := range r.events {
		if e.Kind == "secret_removed" {
			t.Error("warned without a secret")
		}
	}
	if strings.Contains(string(r.fake.Requests()[0].Body), "looked like a secret") {
		t.Error("note without a secret")
	}
}

// The words of a connection request count as asking for a change.
func TestAskedForConnect(t *testing.T) {
	for _, s := range []string{"connect our GitHub", "set up Jira", "add a Slack channel for critical alerts", "add a new server", "install the agent"} {
		if !ask.AskedForChange(s) {
			t.Errorf("AskedForChange(%q) = false", s)
		}
	}
}
