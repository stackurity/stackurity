package ask_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/ask/asktest"
	"github.com/stackurity/stackurity/internal/tenant"
)

const (
	haiku  = "claude-haiku-5-5"
	sonnet = "claude-sonnet-5-5"
	opus   = "claude-opus-5-5"
)

// tierRig is a conversation that starts on model, under a plan whose model
// (the ceiling) is ceiling.
func tierRig(t *testing.T, model string, replies ...asktest.Reply) *rig {
	t.Helper()
	r := newRig(t, replies...)
	c, err := r.st.CreateAskConversation(r.ctx, r.user, nil, model, "tiers")
	if err != nil {
		t.Fatal(err)
	}
	r.conv = c
	return r
}

func (r *rig) askUnder(ceiling, text string) (ask.Outcome, error) {
	r.t.Helper()
	c, err := r.st.AskConversation(r.ctx, r.user, r.conv.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return r.eng.Ask(r.ctx, ask.Question{Conversation: c, UserID: r.user, Text: text, Model: c.Model, Ceiling: ceiling, API: r.api},
		func(e ask.Event) { r.events = append(r.events, e) })
}

// requestModels are the models of every request so far, and whether each
// asked for server-side fallback.
func (r *rig) requestModels() []string {
	var out []string
	for _, b := range r.fake.Bodies() {
		m, _ := b["model"].(string)
		if _, fb := b["fallbacks"]; fb {
			m += "+fallbacks"
		}
		out = append(out, m)
	}
	return out
}

func (r *rig) convModel() string {
	c, err := r.st.AskConversation(r.ctx, r.user, r.conv.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return c.Model
}

// stepRecords are (kind, model, step_up_reason, stepped_from) of every call.
func (r *rig) stepRecords() []string {
	rows, err := r.st.Pool.Query(tenant.System(context.Background()), `SELECT kind, model, step_up_reason, stepped_from FROM ask_api_calls ORDER BY id`)
	if err != nil {
		r.t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k, m, reason, from string
		_ = rows.Scan(&k, &m, &reason, &from)
		out = append(out, strings.Join([]string{k, m, reason, from}, " "))
	}
	return out
}

func TestStartModelAndSteps(t *testing.T) {
	for _, c := range []struct{ start, ceiling, want string }{
		{"", sonnet, sonnet}, {haiku, sonnet, haiku}, {haiku, opus, haiku}, {haiku, haiku, haiku},
		{"plan", opus, opus}, {haiku, "claude-fable-5-1", "claude-fable-5-1"},
		{haiku, "anthropic.claude-sonnet-5-5", "anthropic.claude-haiku-5-5"},
	} {
		if got := ask.StartModel(c.start, c.ceiling); got != c.want {
			t.Errorf("StartModel(%q, %q) = %q, want %q", c.start, c.ceiling, got, c.want)
		}
	}
	for _, c := range []struct {
		cur, ceiling, want string
		ok                 bool
	}{{haiku, sonnet, sonnet, true}, {sonnet, sonnet, sonnet, false}, {sonnet, opus, opus, true}, {opus, opus, opus, false}, {haiku, "custom", haiku, false}} {
		if got, ok := ask.StepUp(c.cur, c.ceiling); got != c.want || ok != c.ok {
			t.Errorf("StepUp(%q, %q) = %q %v", c.cur, c.ceiling, got, ok)
		}
	}
	for q, want := range map[string]bool{
		"What runs on web-1?": false, "Make an upgrade plan for all our servers": true,
		"Compare project Shop and project Blog": true, "Which teams own the most findings across projects?": true,
		"Is CVE-2024-3094 fixed?": false,
	} {
		if ask.IsComplex(q) != want {
			t.Errorf("IsComplex(%q) = %v", q, !want)
		}
	}
	for q, want := range map[string]bool{"No, that's not what I asked": true, "that's wrong": true, "Not what I meant.": true,
		"And db-1?": false, "Now the same for db-1": false, "Thanks!": false} {
		if ask.SaysDissatisfied(q) != want {
			t.Errorf("SaysDissatisfied(%q) = %v", q, !want)
		}
	}
}

// A simple question stays on Claude Haiku 5.5, without server-side
// fallback (Haiku has none) and without the small triage call.
func TestTierSimpleStaysOnHaiku(t *testing.T) {
	r := tierRig(t, haiku, asktest.Reply{Text: "web-1 runs openssl 3.0.2."}, asktest.Reply{Text: "db-1 runs 3.0.13."})
	if _, err := r.askUnder(sonnet, "What runs on web-1?"); err != nil {
		t.Fatal(err)
	}
	// A follow-up the phrase list settles as a new question still asks
	// the small model whether it says the answer was wrong: no.
	r.fake.Push(asktest.Reply{Text: "no"})
	r.fake.Push(asktest.Reply{Text: "db-1 runs 3.0.13."})
	if _, err := r.askUnder(sonnet, "And db-1?"); err != nil {
		t.Fatal(err)
	}
	got := r.requestModels()
	if strings.Join(got, ",") != haiku+","+haiku+","+haiku {
		t.Errorf("requests = %v, want haiku answer, haiku triage, haiku answer", got)
	}
	if r.convModel() != haiku {
		t.Errorf("conversation moved to %s", r.convModel())
	}
	// The triage call: no tools, thinking off, one word.
	triage := r.fake.Bodies()[1]
	if _, tools := triage["tools"]; tools {
		t.Error("the triage call sent tools")
	}
	if th, _ := triage["thinking"].(map[string]any); th["type"] != "disabled" {
		t.Errorf("triage thinking = %v", triage["thinking"])
	}
}

// Asking the same question again moves the conversation to Claude Sonnet
// 5.5, for the rest of it.
func TestTierRephraseStepsUpAndStays(t *testing.T) {
	r := tierRig(t, haiku,
		asktest.Reply{Text: "Some hosts run openssl."},
		asktest.Reply{Text: "web-1 and db-1 run openssl 3.0."},
		asktest.Reply{Text: "Upgrade to 3.0.15."})
	if _, err := r.askUnder(sonnet, "Which hosts run openssl version 3.0?"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.askUnder(sonnet, "Which of my hosts run openssl version 3.0 exactly?"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.askUnder(sonnet, "What should I upgrade it to?"); err != nil {
		t.Fatal(err)
	}
	got := r.requestModels()
	want := []string{haiku, sonnet + "+fallbacks", sonnet + "+fallbacks"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("requests = %v, want %v", got, want)
	}
	if r.convModel() != sonnet {
		t.Errorf("conversation model = %s", r.convModel())
	}
	recs := r.stepRecords()
	if len(recs) < 2 || recs[1] != "answer "+sonnet+" rephrased "+haiku {
		t.Errorf("call records = %v", recs)
	}
}

// "No, that's not what I asked" steps up without asking the small model.
func TestTierDissatisfiedStepsUp(t *testing.T) {
	r := tierRig(t, haiku, asktest.Reply{Text: "web-1 runs openssl."}, asktest.Reply{Text: "You asked about db-1: it runs 3.0.13."})
	_, _ = r.askUnder(sonnet, "What runs on db-1?")
	if _, err := r.askUnder(sonnet, "No, that's not what I asked"); err != nil {
		t.Fatal(err)
	}
	if got := r.requestModels(); len(got) != 2 || got[1] != sonnet+"+fallbacks" {
		t.Errorf("requests = %v", got)
	}
}

// The answer says it could not find something: that turn is tried again
// on the next model, once, without the failed answer in its history.
func TestTierRetryOnNotFound(t *testing.T) {
	r := tierRig(t, haiku, asktest.Reply{Text: "I couldn't find that asset."}, asktest.Reply{Text: "web-1 is asset 3."})
	out, err := r.askUnder(opus, "Which asset is web-1?")
	if err != nil || out.Text != "web-1 is asset 3." || out.Retried != ask.StepNotFound {
		t.Fatalf("outcome = %+v %v", out, err)
	}
	got := r.requestModels()
	if len(got) != 2 || got[0] != haiku || got[1] != sonnet+"+fallbacks" {
		t.Fatalf("requests = %v", got)
	}
	if bytes.Contains(r.fake.Requests()[1].Body, []byte("couldn't find")) {
		t.Error("the retry sent the failed answer")
	}
	stored, _ := r.st.AskMessages(r.ctx, r.user, r.conv.ID)
	for _, m := range stored {
		if strings.Contains(m.VisibleText, "couldn't find") {
			t.Error("the failed answer is still in the conversation")
		}
	}
	reset := false
	for _, e := range r.events {
		reset = reset || e.Kind == "reset"
	}
	if !reset {
		t.Error("the panel was not told to drop the first answer")
	}
	if r.convModel() != sonnet {
		t.Errorf("conversation model = %s", r.convModel())
	}
}

// The plan's model is the ceiling: on a Starter or Team plan (Sonnet), a
// struggling Sonnet answer is not retried; on Business (Opus) it is,
// once, on Opus.
func TestTierCeiling(t *testing.T) {
	r := tierRig(t, sonnet, asktest.Reply{Text: "I could not find any such host."})
	if out, err := r.askUnder(sonnet, "Which hosts run nginx 1.18?"); err != nil || out.Retried != "" {
		t.Fatalf("outcome = %+v %v", out, err)
	}
	if got := r.requestModels(); len(got) != 1 {
		t.Errorf("requests over the ceiling: %v", got)
	}
	// A clearly complex request goes no further than Sonnet up front,
	// however high the ceiling.
	r = tierRig(t, haiku, asktest.Reply{Text: "Here is the plan."})
	if _, err := r.askUnder(opus, "Make an upgrade plan for all our servers"); err != nil {
		t.Fatal(err)
	}
	if got := r.requestModels(); len(got) != 1 || got[0] != sonnet+"+fallbacks" {
		t.Errorf("complex request: %v", got)
	}
	// Sonnet struggles too on a Business plan: Opus, once.
	// (A short follow-up first asks the small model whether it says the
	// last answer was wrong: no.)
	r.fake.Push(asktest.Reply{Text: "no"}, asktest.Reply{Text: "I couldn't find those assets."}, asktest.Reply{Text: "The plan, with assets."})
	if out, err := r.askUnder(opus, "List the assets in it"); err != nil || out.Retried != ask.StepNotFound {
		t.Fatalf("outcome = %+v %v", out, err)
	}
	if got := r.requestModels(); len(got) != 4 || got[1] != haiku || got[3] != opus+"+fallbacks" {
		t.Errorf("requests = %v", got)
	}
	// Never above the ceiling, whatever happens next.
	r.fake.Push(asktest.Reply{Text: "I couldn't find it."})
	if out, err := r.askUnder(opus, "And the next step?"); err != nil || out.Retried != "" {
		t.Fatalf("outcome = %+v %v", out, err)
	}
	if got := r.requestModels(); got[len(got)-1] != opus+"+fallbacks" || len(got) != 5 {
		t.Errorf("requests = %v", got)
	}
}

// A thumbs-down or a stopped answer between questions moves the
// conversation up; the next answer's call record says why.
func TestTierStepUpBetween(t *testing.T) {
	r := tierRig(t, haiku, asktest.Reply{Text: "web-1 runs openssl."})
	_, _ = r.askUnder(sonnet, "What runs on web-1?")
	c, _ := r.st.AskConversation(r.ctx, r.user, r.conv.ID)
	if m, ok, err := r.eng.StepUpBetween(r.ctx, r.user, c, sonnet, ask.StepThumbsDown); err != nil || !ok || m != sonnet {
		t.Fatalf("step up = %s %v %v", m, ok, err)
	}
	c, _ = r.st.AskConversation(r.ctx, r.user, r.conv.ID)
	if _, ok, _ := r.eng.StepUpBetween(r.ctx, r.user, c, sonnet, ask.StepStopped); ok {
		t.Error("stepped above the ceiling")
	}
	r.fake.Push(asktest.Reply{Text: "Sorry: web-1 runs openssl 3.0.2."})
	if _, err := r.askUnder(sonnet, "Which version exactly is installed there?"); err != nil {
		t.Fatal(err)
	}
	recs := r.stepRecords()
	if last := recs[len(recs)-1]; last != "answer "+sonnet+" thumbs_down "+haiku {
		t.Errorf("call records = %v", recs)
	}
}
