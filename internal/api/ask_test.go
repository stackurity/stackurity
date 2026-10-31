package api_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/ask/asktest"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// syncBuf is a log sink tests can read.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// withAsk configures Ask Stackurity against a fake model API and sends the
// server's log to logs.
func withAsk(t *testing.T, fake *asktest.Server, logs io.Writer) func(*api.Server) {
	return func(s *api.Server) {
		cfg := ask.Config{Provider: ask.ProviderAnthropic, APIKey: "sk-ant-test-not-real", BaseURL: fake.URL, Model: ask.DefaultModel, Effort: "low"}
		cl, err := ask.NewClient(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		s.Ask = &ask.Engine{Model: cl, Store: s.Store, Config: cfg}
		if logs != nil {
			s.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		}
	}
}

type sseEvent struct {
	Name string
	Data map[string]any
}

// askQ asks a question and returns the status and the events.
func askQ(t *testing.T, s *session, conv int64, text string, page map[string]string, hdr map[string]string) (int, []sseEvent, string) {
	t.Helper()
	body := map[string]any{"text": text}
	if page != nil {
		body["page"] = page
	}
	b, _ := json.Marshal(body)
	h := map[string]string{"X-Stackurity-CSRF": "1", "Content-Type": "application/json"}
	for k, v := range hdr {
		h[k] = v
	}
	resp := s.req("POST", fmt.Sprintf("/api/v1/ask/conversations/%d/messages", conv), bytes.NewReader(b), h)
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var evs []sseEvent
	var name string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			name = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			var d map[string]any
			_ = json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d)
			evs = append(evs, sseEvent{name, d})
		}
	}
	return resp.StatusCode, evs, string(raw)
}

// askReady turns Ask on for the workspace, accepts the notice for s and
// starts a conversation.
func askReady(t *testing.T, e *env, s *session) int64 {
	t.Helper()
	if err := e.st.SetAskEnabled(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), true); err != nil {
		t.Fatal(err)
	}
	if code := s.do("POST", "/api/v1/ask/notice", map[string]string{"version": api.AskNoticeVersion}, nil); code != 204 {
		t.Fatalf("notice: %d", code)
	}
	var c store.AskConversation
	if code := s.do("POST", "/api/v1/ask/conversations", map[string]any{}, &c); code != 201 {
		t.Fatalf("conversation: %d", code)
	}
	return c.ID
}

func lastEvent(evs []sseEvent) sseEvent {
	if len(evs) == 0 {
		return sseEvent{}
	}
	return evs[len(evs)-1]
}

// Off unless the server has a provider; then off for organisations that
// existed before (opt-in), and each person accepts the notice first.
func TestAskOptIn(t *testing.T) {
	e := newEnv(t)
	e.user("admin@x.io", auth.RoleAdmin)
	s := e.login("admin@x.io")
	var st map[string]any
	if code := s.do("GET", "/api/v1/ask/status", nil, &st); code != 200 || st["available"] != false || st["reason"] != "not_configured" {
		t.Fatalf("no provider: %d %v", code, st)
	}
	if code := s.do("POST", "/api/v1/ask/conversations", map[string]any{}, nil); code != 404 {
		t.Errorf("start without a provider: %d", code)
	}

	fake := asktest.New(t, asktest.Reply{Text: "Hello."})
	e = newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	s = e.login("admin@x.io")
	if code := s.do("GET", "/api/v1/ask/status", nil, &st); code != 200 || st["reason"] != "ask_disabled" || st["notice_accepted"] != false {
		t.Fatalf("existing organisation: %v", st)
	}
	if code := s.do("POST", "/api/v1/ask/conversations", map[string]any{}, nil); code != 403 {
		t.Errorf("start while off: %d", code)
	}
	if code := s.do("PUT", "/api/v1/ask/settings", map[string]bool{"enabled": true}, &st); code != 200 || st["enabled"] != true {
		t.Fatalf("turn on: %d %v", code, st)
	}
	var c store.AskConversation
	if code := s.do("POST", "/api/v1/ask/conversations", map[string]any{}, &c); code != 201 || c.Model != ask.DefaultModel {
		t.Fatalf("start: %d %+v", code, c)
	}
	if code, _, _ := askQ(t, s, c.ID, "hi", nil, nil); code != 409 {
		t.Errorf("before the notice: %d", code)
	}
	if code := s.do("POST", "/api/v1/ask/notice", map[string]string{"version": "2000-01"}, nil); code != 409 {
		t.Errorf("an old notice version: %d", code)
	}
	if code := s.do("POST", "/api/v1/ask/notice", map[string]string{"version": api.AskNoticeVersion}, nil); code != 204 {
		t.Fatal("notice")
	}
	code, evs, raw := askQ(t, s, c.ID, "hi", nil, nil)
	if code != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", code, raw)
	}
	var text string
	for _, ev := range evs {
		if ev.Name == "text" {
			text += ev.Data["text"].(string)
		}
	}
	if text != "Hello." {
		t.Errorf("answer = %q", text)
	}
	// Turned off again: no question reaches the model.
	if code := s.do("PUT", "/api/v1/ask/settings", map[string]bool{"enabled": false}, nil); code != 200 {
		t.Fatal("turn off")
	}
	if code, _, _ := askQ(t, s, c.ID, "again", nil, nil); code != 403 {
		t.Errorf("question while off: %d", code)
	}
	if n := len(fake.Requests()); n != 1 {
		t.Errorf("model requests = %d, want 1", n)
	}
	// API tokens cannot ask.
	var tok struct{ Secret string }
	s.do("POST", "/api/v1/tokens", map[string]any{"name": "t", "role": "admin"}, &tok)
	if code := bearer(e, tok.Secret, "GET", "/api/v1/ask/status", nil, nil); code != 403 {
		t.Errorf("token: %d", code)
	}
}

// A member with access to one project gets nothing of another project
// through the assistant: every tool, given the other project's ids and
// names, answers without them, and its page is ignored. The same holds for
// an organisation-wide member who chose the project in the switcher.
func TestAskProjectScoping(t *testing.T) {
	var replies []asktest.Reply
	var o *org
	fake := asktest.New(t)
	o = newOrgWith(t, withAsk(t, fake, nil))
	args := map[string]any{"query": "beta", "asset_id": o.id("beta-asset"), "finding_id": o.id("beta-finding"),
		"component_id": o.id("beta-component"), "name": "beta-private-lib", "since": "2000-01-01"}
	in, _ := json.Marshal(args)
	var tools []asktest.Tool
	for i, rt := range []string{"search", "list_assets", "action_plan", "asset_stack", "list_findings", "get_finding", "find_component",
		"explain_finding", "upgrade_recommendation", "remediation_plan", "verify_since", "updates_available"} {
		tools = append(tools, asktest.Tool{ID: fmt.Sprintf("t%d", i), Name: rt, Input: string(in)},
			asktest.Tool{ID: fmt.Sprintf("p%d", i), Name: rt, Input: `{"since":"2000-01-01"}`})
	}
	for range 2 {
		replies = append(replies, asktest.Reply{Tools: tools}, asktest.Reply{Text: "done"})
	}
	fake.Push(replies...)

	o.grant(t, "ask-member@x.io", o.id("alpha-project"), 0, auth.RoleEngineer)
	member := o.e.signIn("ask-member@x.io")
	o.e.user("ask-orgwide@x.io", auth.RoleEngineer)
	orgwide := o.e.login("ask-orgwide@x.io")
	// Teams belong to the organisation, not to a project: an
	// organisation-wide member sees them whatever project is chosen.
	for i, who := range []struct {
		s      *session
		hdr    map[string]string
		echoes []string
	}{{member, nil, nil}, {orgwide, map[string]string{"X-Stackurity-Project": o.s("alpha-project")}, []string{"team-beta-ops"}}} {
		conv := askReady(t, o.e, who.s)
		code, evs, raw := askQ(t, who.s, conv, "What about beta?", map[string]string{"kind": "finding", "id": o.s("beta-finding")}, who.hdr)
		if code != 200 || lastEvent(evs).Name != "done" {
			t.Fatalf("%d: %d %s", i, code, raw)
		}
		bodies := fake.Requests()
		q := string(bodies[2*i].Body)
		if strings.Contains(q, "has finding") {
			t.Errorf("%d: another project's finding was named as the open page", i)
		}
		results := string(bodies[2*i+1].Body)
		if !strings.Contains(results, "tool_result") {
			t.Fatalf("%d: no tool results", i)
		}
		if low := strings.ToLower(withoutBetaEchoes(results, append([]string{"beta-private-lib", "beta", "What about beta?"}, who.echoes...)...)); strings.Contains(low, "beta") {
			t.Errorf("%d: the assistant read Project Beta: %s", i, results)
		}
		if !strings.Contains(results, "alpha") {
			t.Errorf("%d: the assistant did not read Project Alpha either: the test proves nothing", i)
		}
	}
}

// Admins can delete people's conversations but never read them. The
// session the tools use is never written to the log, sent to the model or
// shown in an error.
func TestAskPrivacy(t *testing.T) {
	fake := asktest.New(t,
		asktest.Reply{Tools: []asktest.Tool{{ID: "a", Name: "get_finding", Input: `{"finding_id":999999}`}, {ID: "b", Name: "list_assets"}}},
		asktest.Reply{Text: "There is no finding 999999."})
	logs := &syncBuf{}
	e := newEnvWith(t, withAsk(t, fake, logs))
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("viewer@x.io", auth.RoleViewer)
	admin, viewer := e.login("admin@x.io"), e.login("viewer@x.io")
	conv := askReady(t, e, viewer)
	code, evs, raw := askQ(t, viewer, conv, "Explain finding 999999", nil, nil)
	if code != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("question: %d %s", code, raw)
	}
	u, _ := url.Parse(e.srv.URL)
	var cookie string
	for _, c := range viewer.http.Jar.Cookies(u) {
		if c.Name == "stackurity_session" {
			cookie = c.Value
		}
	}
	if len(cookie) < 16 {
		t.Fatal("no session cookie")
	}
	var everything strings.Builder
	everything.WriteString(logs.String())
	everything.WriteString(raw)
	for _, r := range fake.Requests() {
		everything.Write(r.Body)
		for k, v := range r.Header {
			everything.WriteString(k + strings.Join(v, ","))
		}
	}
	var mine map[string]any
	viewer.do("GET", fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, &mine)
	b, _ := json.Marshal(mine)
	everything.Write(b)
	if strings.Contains(everything.String(), cookie) {
		t.Error("the session reached the log, the model, an error or the conversation")
	}
	if !strings.Contains(everything.String(), "tool_result") || !strings.Contains(logs.String(), "/api/v1/findings/999999") {
		t.Error("the check saw nothing: the tools did not run")
	}

	// The admin cannot read it, list it or delete it one by one...
	var list struct{ Items []store.AskConversation }
	admin.do("GET", "/api/v1/ask/conversations", nil, &list)
	if len(list.Items) != 0 {
		t.Errorf("the admin lists others' conversations: %+v", list.Items)
	}
	for _, m := range []string{"GET", "DELETE"} {
		if code := admin.do(m, fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, nil); code != 404 {
			t.Errorf("admin %s another's conversation: %d", m, code)
		}
	}
	var settings map[string]any
	admin.do("GET", "/api/v1/ask/settings", nil, &settings)
	if b, _ := json.Marshal(settings); strings.Contains(string(b), "999999") {
		t.Errorf("settings show a question: %s", b)
	}
	// ...the viewer cannot see the settings or delete everyone's...
	if code := viewer.do("DELETE", "/api/v1/ask/settings/conversations", nil, nil); code != 403 {
		t.Errorf("viewer deletes everyone's: %d", code)
	}
	// ...and the admin deletes them all, learning only how many.
	var del map[string]any
	if code := admin.do("DELETE", "/api/v1/ask/settings/conversations", nil, &del); code != 200 || del["deleted"] != float64(1) {
		t.Errorf("delete all: %d %v", code, del)
	}
	if code := viewer.do("GET", fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, nil); code != 404 {
		t.Errorf("after delete all: %d", code)
	}
}

// The quota counts questions; a question that never reached the model is
// given back; the spend cap stops questions before the model is called.
func TestAskQuotaAndSpendCap(t *testing.T) {
	fake := asktest.New(t, asktest.Reply{Text: "one", Usage: asktest.Usage{Output: 10}}, asktest.Reply{Status: 401})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	s := e.login("admin@x.io")
	conv := askReady(t, e, s)
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	two := int64(2)
	if err := e.st.SetAskLimits(ctx, tenant.DefaultWorkspace, store.AskLimits{QuestionLimit: &two}); err != nil {
		t.Fatal(err)
	}
	if _, evs, raw := askQ(t, s, conv, "first", nil, nil); lastEvent(evs).Name != "done" || lastEvent(evs).Data["questions_used"] != float64(1) {
		t.Fatalf("first: %s", raw)
	}
	// The provider refuses the call: an error, and the question is given back.
	if _, evs, raw := askQ(t, s, conv, "second", nil, nil); lastEvent(evs).Name != "error" || lastEvent(evs).Data["code"] != "unavailable" {
		t.Fatalf("second: %s", raw)
	}
	var st map[string]any
	if s.do("GET", "/api/v1/ask/status", nil, &st); st["questions_used"] != float64(1) {
		t.Errorf("after a failed question: %v", st["questions_used"])
	}
	// A spend cap below what a call could cost: refused before the model.
	tiny := int64(1)
	if err := e.st.SetAskLimits(ctx, tenant.DefaultWorkspace, store.AskLimits{QuestionLimit: &two, SpendCapMicros: &tiny}); err != nil {
		t.Fatal(err)
	}
	before := len(fake.Requests())
	if _, evs, raw := askQ(t, s, conv, "third", nil, nil); lastEvent(evs).Name != "error" || lastEvent(evs).Data["code"] != "spend_cap" {
		t.Fatalf("over the cap: %s", raw)
	}
	if len(fake.Requests()) != before {
		t.Error("the model was called over the spend cap")
	}
	if err := e.st.SetAskLimits(ctx, tenant.DefaultWorkspace, store.AskLimits{QuestionLimit: &two}); err != nil {
		t.Fatal(err)
	}
	fake.Push(asktest.Reply{Text: "two"})
	if _, evs, raw := askQ(t, s, conv, "fourth", nil, nil); lastEvent(evs).Name != "done" {
		t.Fatalf("fourth: %s", raw)
	}
	if code, _, _ := askQ(t, s, conv, "fifth", nil, nil); code != 429 {
		t.Errorf("over the quota: %d", code)
	}
	// A plan without questions.
	zero := int64(0)
	_ = e.st.SetAskLimits(ctx, tenant.DefaultWorkspace, store.AskLimits{QuestionLimit: &zero})
	if code := s.do("GET", "/api/v1/ask/status", nil, &st); code != 200 || st["reason"] != "plan_required" {
		t.Errorf("not in the plan: %v", st)
	}
}

// A read-only organisation cannot ask.
func TestAskReadOnly(t *testing.T) {
	fake := asktest.New(t)
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	s := e.login("admin@x.io")
	conv := askReady(t, e, s)
	if err := e.st.SetReadOnly(context.Background(), tenant.DefaultWorkspace, ptrNow(), "trial ended"); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := askQ(t, s, conv, "hi", nil, nil); code != 402 {
		t.Errorf("read-only: %d", code)
	}
	if len(fake.Requests()) != 0 {
		t.Error("the model was called")
	}
}

func ptrNow() *time.Time { t := time.Now(); return &t }

// Row-level security keeps conversations in their workspace; inside it,
// every conversation and message endpoint matches the asking person's
// user id. A second person of the same organisation, whatever their role,
// gets 404 on each, never sees it listed, and their delete-mine leaves it.
func TestAskOtherPersonGets404(t *testing.T) {
	fake := asktest.New(t, asktest.Reply{Text: "Owner's answer."})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("owner@x.io", auth.RoleViewer)
	e.user("peer@x.io", auth.RoleViewer)
	e.user("boss@x.io", auth.RoleAdmin)
	owner := e.login("owner@x.io")
	conv := askReady(t, e, owner)
	if code, evs, raw := askQ(t, owner, conv, "secret question", nil, nil); code != 200 || lastEvent(evs).Name != "done" {
		t.Fatalf("owner's question: %d %s", code, raw)
	}
	for _, who := range []string{"peer@x.io", "boss@x.io"} {
		s := e.login(who)
		if code := s.do("POST", "/api/v1/ask/notice", map[string]string{"version": api.AskNoticeVersion}, nil); code != 204 {
			t.Fatalf("%s notice: %d", who, code)
		}
		path := fmt.Sprintf("/api/v1/ask/conversations/%d", conv)
		var body map[string]any
		if code := s.do("GET", path, nil, &body); code != 404 {
			t.Errorf("%s GET %s: %d %v", who, path, code, body)
		}
		if code, _, raw := askQ(t, s, conv, "append to it", nil, nil); code != 404 {
			t.Errorf("%s POST %s/messages: %d %s", who, path, code, raw)
		}
		if code := s.do("DELETE", path, nil, nil); code != 404 {
			t.Errorf("%s DELETE %s: %d", who, path, code)
		}
		var list struct{ Items []store.AskConversation }
		if code := s.do("GET", "/api/v1/ask/conversations", nil, &list); code != 200 || len(list.Items) != 0 {
			t.Errorf("%s list: %d %+v", who, code, list.Items)
		}
		var del map[string]any
		if code := s.do("DELETE", "/api/v1/ask/conversations", nil, &del); code != 200 || del["deleted"] != float64(0) {
			t.Errorf("%s delete mine: %d %v", who, code, del)
		}
	}
	if n := len(fake.Requests()); n != 1 {
		t.Errorf("model requests = %d: another person's question reached the model", n)
	}
	var mine struct {
		Messages []store.AskMessage
	}
	if code := owner.do("GET", fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, &mine); code != 200 || len(mine.Messages) != 2 ||
		mine.Messages[0].VisibleText != "secret question" {
		t.Errorf("the owner's conversation changed: %d %+v", code, mine.Messages)
	}
}
