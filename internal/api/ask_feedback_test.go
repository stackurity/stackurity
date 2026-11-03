package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/ask/asktest"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

type feedbackList struct {
	Items      []store.AskFeedback `json:"items"`
	NextBefore int64               `json:"next_before"`
}

// A person rates an answer and says what was wrong; with consent the
// operators see a snapshot of the question and the answer, without
// credentials or email addresses. Nobody else can leave feedback on the
// conversation, and organisation admins have no way to read feedback.
func TestAskFeedbackFromPerson(t *testing.T) {
	fake := asktest.New(t, asktest.Reply{Text: "web-1 runs openssl 3.0.2. Its deploy key is ghp_abcdefghijklmnopqrstuvwxyz0123456789."})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	e.instanceAdmin("admin@x.io")
	e.user("eve@x.io", auth.RoleAdmin)
	admin, eve := e.login("admin@x.io"), e.login("eve@x.io")
	conv := askReady(t, e, admin)
	_, evs, raw := askQ(t, admin, conv, "Which hosts run openssl 3.0? Ask bob@example.com.", nil, nil)
	done := lastEvent(evs)
	if done.Name != "done" || done.Data["answer_seq"] != float64(2) {
		t.Fatalf("done event: %s", raw)
	}
	path := fmt.Sprintf("/api/v1/ask/conversations/%d/feedback", conv)
	in := map[string]any{"seq": 2, "rating": "down", "category": "wrong", "text": "db-1 also runs it", "consent": true,
		"page_path": "/assets/3?tab=stack", "viewport": "390x844"}
	var created map[string]any
	if code := admin.do("POST", path, in, &created); code != 201 || created["consent"] != true {
		t.Fatalf("feedback: %d %v", code, created)
	}
	// Someone else in the organisation: 404 on the conversation.
	if code := eve.do("POST", path, in, nil); code != 404 {
		t.Errorf("another person's conversation: %d", code)
	}
	// Without the CSRF header: refused.
	b, _ := json.Marshal(in)
	if resp := admin.req("POST", path, bytes.NewReader(b), map[string]string{"Content-Type": "application/json"}); resp.StatusCode != 403 {
		t.Errorf("no CSRF header: %d", resp.StatusCode)
	}
	// A thumbs up, no consent; feedback on the panel with no conversation;
	// and a bad one.
	if code := admin.do("POST", path, map[string]any{"seq": 2, "rating": "up"}, nil); code != 201 {
		t.Errorf("thumbs up: %d", code)
	}
	if code := admin.do("POST", "/api/v1/ask/feedback", map[string]any{"scope": "ui", "category": "formatting", "text": "panel covers the menu"}, nil); code != 201 {
		t.Errorf("panel feedback: %d", code)
	}
	if code := admin.do("POST", "/api/v1/ask/feedback", map[string]any{"scope": "chat", "rating": "down"}, nil); code != 400 {
		t.Errorf("chat feedback without a conversation: %d", code)
	}
	if code := admin.do("POST", path, map[string]any{"seq": 2, "rating": "sideways"}, nil); code != 400 {
		t.Errorf("bad rating: %d", code)
	}

	// The operator's review.
	var list feedbackList
	if code := admin.do("GET", "/api/v1/admin/ask/feedback?kind=explicit&rating=down", nil, &list); code != 200 || len(list.Items) != 1 {
		t.Fatalf("review list: %d %+v", code, list)
	}
	fb := list.Items[0]
	snap := string(fb.Snapshot)
	if !strings.Contains(snap, "web-1 runs openssl") || strings.Contains(snap, "ghp_") || strings.Contains(snap, "bob@example.com") {
		t.Errorf("snapshot = %s", snap)
	}
	if fb.PagePath != "/assets/3" || fb.Viewport != "390x844" || fb.Model == "" || fb.PromptVersion == "" {
		t.Errorf("metadata = %+v", fb)
	}
	if code := admin.do("PATCH", fmt.Sprintf("/api/v1/admin/ask/feedback/%d", fb.ID), map[string]any{"status": "triaged", "resolution_notes": "checking"}, nil); code != 200 {
		t.Errorf("review: %d", code)
	}
	// An organisation admin who is not an operator: no access.
	if code := eve.do("GET", "/api/v1/admin/ask/feedback", nil, nil); code != 403 {
		t.Errorf("organisation admin reads feedback: %d", code)
	}
	if code := e.anon().do("GET", "/api/v1/admin/ask/feedback", nil, nil); code != 401 {
		t.Errorf("anonymous: %d", code)
	}
	// Deleting the conversation keeps the shared snapshot.
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/ask/conversations/%d", conv), nil, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
	var got store.AskFeedback
	if code := admin.do("GET", fmt.Sprintf("/api/v1/admin/ask/feedback/%d", fb.ID), nil, &got); code != 200 || got.Snapshot == nil || got.Status != "triaged" {
		t.Errorf("after deleting the conversation: %d %+v", code, got)
	}
}

// Signals recorded without the person doing anything: an answer that says
// it could not find something, the same question asked again, a tool that
// failed. Metadata only.
func TestAskFeedbackSignals(t *testing.T) {
	fake := asktest.New(t,
		asktest.Reply{Text: "I couldn't find any asset named web-9 in your inventory."},
		asktest.Reply{Tools: []asktest.Tool{{ID: "t1", Name: "get_finding", Input: `{"finding_id": 987654}`}}},
		asktest.Reply{Text: "Still nothing for web-9."})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	s := e.login("admin@x.io")
	conv := askReady(t, e, s)
	if _, evs, raw := askQ(t, s, conv, "Which packages does web-9 run right now?", nil, nil); lastEvent(evs).Name != "done" {
		t.Fatalf("first: %s", raw)
	}
	if _, evs, raw := askQ(t, s, conv, "What packages does web-9 run right now", nil, nil); lastEvent(evs).Name != "done" {
		t.Fatalf("second: %s", raw)
	}
	rows, err := e.st.ListAskFeedback(context.Background(), store.AskFeedbackFilter{Kind: "implicit"})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range rows {
		got[r.Category]++
		if r.Text != "" || r.Snapshot != nil || r.Rating != nil || r.PromptVersion == "" {
			t.Errorf("implicit row: %+v", r)
		}
	}
	// The second answer ("Still nothing...") uses no phrase on the list.
	if got[store.AskSignalNotFound] != 1 || got[store.AskSignalRephrased] != 1 || got[store.AskSignalToolError] != 1 {
		t.Errorf("signals = %v", got)
	}
}

// Feedback review tokens: made by an operator, they read and triage
// feedback and nothing else.
func TestAskFeedbackReviewToken(t *testing.T) {
	fake := asktest.New(t, asktest.Reply{Text: "ok"})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	e.user("eve@x.io", auth.RoleAdmin)
	e.instanceAdmin("admin@x.io")
	admin, eve := e.login("admin@x.io"), e.login("eve@x.io")
	conv := askReady(t, e, admin)
	askQ(t, admin, conv, "hello there friend", nil, nil)
	if code := admin.do("POST", fmt.Sprintf("/api/v1/ask/conversations/%d/feedback", conv), map[string]any{"seq": 2, "rating": "down", "category": "slow"}, nil); code != 201 {
		t.Fatalf("feedback: %d", code)
	}
	var made struct {
		Token  store.AskFeedbackReviewToken `json:"token"`
		Secret string                       `json:"secret"`
	}
	if code := eve.do("POST", "/api/v1/admin/ask/review-tokens", map[string]any{"name": "bot"}, nil); code != 403 {
		t.Errorf("organisation admin makes a review token: %d", code)
	}
	if code := admin.do("POST", "/api/v1/admin/ask/review-tokens", map[string]any{"name": "triage bot", "expires_in_days": 30}, &made); code != 201 || made.Secret == "" {
		t.Fatalf("make token: %d %+v", code, made)
	}
	tok := made.Secret
	get := func(path string) (int, string) {
		req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	code, body := get("/api/v1/admin/ask/feedback?status=new")
	var list feedbackList
	_ = json.Unmarshal([]byte(body), &list)
	if code != 200 || len(list.Items) != 1 {
		t.Fatalf("token lists feedback: %d %s", code, body)
	}
	id := list.Items[0].ID
	if code, _ := get(fmt.Sprintf("/api/v1/admin/ask/feedback/%d", id)); code != 200 {
		t.Errorf("token reads one: %d", code)
	}
	patch, _ := json.Marshal(map[string]any{"status": "wontfix", "resolution_notes": "expected latency"})
	if code := bearer(e, tok, "PATCH", fmt.Sprintf("/api/v1/admin/ask/feedback/%d", id), patch, map[string]string{"Content-Type": "application/json"}); code != 200 {
		t.Errorf("token triages: %d", code)
	}
	// Everything else is refused, organisation data included (404: a route
	// not mounted in this test server, such as /mcp without a base URL; a
	// principal without a user is refused there too).
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/v1/auth/me"}, {"GET", "/api/v1/assets"}, {"GET", "/api/v1/findings"}, {"GET", "/api/v1/ask/conversations"},
		{"GET", "/api/v1/admin/ask"}, {"GET", "/api/v1/admin/ask/review-tokens"}, {"POST", "/api/v1/admin/ask/review-tokens"},
		{"GET", "/api/v1/admin/workspaces"}, {"POST", "/api/v1/admin/ask/feedback"}, {"DELETE", fmt.Sprintf("/api/v1/admin/ask/feedback/%d", id)},
		{"GET", "/api/v1/admin/ask/feedback-tokens"}, {"POST", "/mcp"},
	} {
		if code := bearer(e, tok, c.method, c.path, []byte(`{"name":"x"}`), map[string]string{"Content-Type": "application/json"}); code != 403 && code != 401 && code != 404 && code != 405 {
			t.Errorf("token on %s %s: %d", c.method, c.path, code)
		}
	}
	// Revoked: 401.
	if code := admin.do("DELETE", fmt.Sprintf("/api/v1/admin/ask/review-tokens/%d", made.Token.ID), nil, nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _ := get("/api/v1/admin/ask/feedback"); code != 401 {
		t.Errorf("revoked token: %d", code)
	}
}

// While Ask is off for the organisation, feedback keeps only what the
// person chose and wrote: no conversation snapshot, even with the box
// ticked; the person's own words are redacted like a snapshot.
func TestAskFeedbackWhileOff(t *testing.T) {
	fake := asktest.New(t, asktest.Reply{Text: "web-1 runs openssl 3.0.2."})
	e := newEnvWith(t, withAsk(t, fake, nil))
	e.user("admin@x.io", auth.RoleAdmin)
	admin := e.login("admin@x.io")
	conv := askReady(t, e, admin)
	if _, evs, raw := askQ(t, admin, conv, "Which hosts run openssl?", nil, nil); lastEvent(evs).Name != "done" {
		t.Fatalf("ask: %s", raw)
	}
	if code := admin.do("PUT", "/api/v1/ask/settings", map[string]bool{"enabled": false}, nil); code != 200 {
		t.Fatal("turn off")
	}
	in := map[string]any{"seq": 2, "rating": "down", "category": "wrong", "consent": true,
		"text": "my token stka_abcdefghijklmnopqrstuvwxyz234567 and password=hunter2hunter"}
	var created map[string]any
	if code := admin.do("POST", fmt.Sprintf("/api/v1/ask/conversations/%d/feedback", conv), in, &created); code != 201 || created["consent"] != false {
		t.Fatalf("feedback while off: %d %v", code, created)
	}
	var snap *string
	var text string
	if err := e.st.Pool.QueryRow(tenant.System(context.Background()), `SELECT snapshot::text, text FROM ask_feedback ORDER BY id DESC LIMIT 1`).Scan(&snap, &text); err != nil {
		t.Fatal(err)
	}
	if snap != nil {
		t.Errorf("snapshot stored while Ask was off: %s", *snap)
	}
	if strings.Contains(text, "abcdefghijklmnop") || strings.Contains(text, "hunter2") {
		t.Errorf("credentials kept in the feedback text: %s", text)
	}
}
