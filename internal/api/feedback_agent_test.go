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
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/tenant"
)

type fbComment struct {
	AuthorKind string `json:"author_kind"`
	Author     string
	Kind       string
	Body       string
}

type fbItem struct {
	Item struct {
		Status       string
		OwnerReason  string  `json:"owner_reason"`
		ApprovedAt   *string `json:"approved_at"`
		ApprovedBy   string  `json:"approved_by"`
		ApprovalNote string  `json:"approval_note"`
		Resolution   string
	} `json:"item"`
	Events []struct {
		Action, Actor, Detail string
		ToStatus              string `json:"to_status"`
	} `json:"events"`
	Comments []fbComment `json:"comments"`
}

type mineThread struct {
	Items []struct {
		Ref, Status string
		Thread      []struct{ From, Kind, Body string } `json:"thread"`
	} `json:"items"`
}

// triageToken creates a triage token as the instance administrator.
func triageToken(t *testing.T, ops *session) string {
	t.Helper()
	var created struct{ Token string }
	if code := ops.do("POST", "/api/v1/admin/feedback-tokens", map[string]any{"name": "feedback-agent", "days": 7}, &created); code != 201 {
		t.Fatalf("token: %d", code)
	}
	return created.Token
}

// The whole loop: the agent asks, the sender answers from My feedback on
// their installation (through the relay), the item goes back to new, the
// agent holds it for the owner, the owner approves it in the dashboard.
func TestFeedbackAgentLoop(t *testing.T) {
	queue, _ := queueEnv(t, 0)
	mail := &fakeMailer{}
	queue.api.AccountMail = mail
	queue.api.FeedbackQueue.Approvers = []string{"owner@stackurity.test"}
	rl := relay(t, queue)
	inst := newEnv(t)
	inst.api.FeedbackURL = rl.URL + "/feedback"
	inst.user("viewer@x.io", auth.RoleViewer)
	s := inst.login("viewer@x.io")
	var sent map[string]any
	if code := s.do("POST", "/api/v1/feedback", map[string]any{"kind": "issue", "message": "The filter is lost", "email": "me@example.com"}, &sent); code != 202 {
		t.Fatalf("send: %d %v", code, sent)
	}
	ref := sent["ref"].(string)

	queue.user("ops@x.io", auth.RoleAdmin)
	queue.instanceAdmin("ops@x.io")
	ops := queue.login("ops@x.io")
	tok := triageToken(t, ops)
	var me map[string]any
	ops.do("GET", "/api/v1/auth/me", nil, &me)
	if me["feedback_queue"] != true {
		t.Fatalf("instance admin: feedback_queue %v", me["feedback_queue"])
	}

	// needs_info is set by asking, never by PATCH.
	if code := bearerJSON(t, queue, tok, "PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "needs_info"}, nil); code != 400 {
		t.Fatalf("patch needs_info: %d", code)
	}
	var item fbItem
	q := "1. Which page: Fixes or Issues?\n2. See https://evil.example/x"
	if code := bearerJSON(t, queue, tok, "POST", "/api/v1/admin/feedback/"+ref+"/comments", map[string]any{"body": q, "ask": true}, &item); code != 201 {
		t.Fatalf("ask: %d", code)
	}
	if item.Item.Status != "needs_info" || len(item.Comments) != 1 || item.Comments[0].AuthorKind != "agent" || item.Comments[0].Kind != "question" {
		t.Fatalf("after ask: %+v", item)
	}
	// Agent emails are off: nothing was sent.
	if mail.count() != 0 {
		t.Fatalf("emailed with agent emails off")
	}

	// The sender sees the question in My feedback.
	resetChecked := func() {
		if _, err := inst.st.Pool.Exec(tenant.System(context.Background()), `UPDATE feedback_sent SET checked_at = now() - interval '1 hour'`); err != nil {
			t.Fatal(err)
		}
	}
	resetChecked()
	var mine mineThread
	s.do("GET", "/api/v1/feedback/mine", nil, &mine)
	if len(mine.Items) != 1 || mine.Items[0].Status != "needs_info" || len(mine.Items[0].Thread) != 1 || mine.Items[0].Thread[0].From != "agent" ||
		!strings.Contains(mine.Items[0].Thread[0].Body, "Which page") {
		t.Fatalf("mine: %+v", mine)
	}
	// The thread never names who wrote it.
	if strings.Contains(fmt.Sprint(mine), "feedback-agent") {
		t.Fatalf("author leaked: %+v", mine)
	}

	// Another user cannot reply to it; an empty reply is refused.
	inst.user("other@x.io", auth.RoleAdmin)
	if code := inst.login("other@x.io").do("POST", "/api/v1/feedback/mine/"+ref+"/reply", map[string]any{"message": "hi"}, nil); code != 404 {
		t.Fatalf("other user's reply: %d", code)
	}
	if code := s.do("POST", "/api/v1/feedback/mine/"+ref+"/reply", map[string]any{"message": "  "}, nil); code != 400 {
		t.Fatalf("empty reply: %d", code)
	}
	var replied struct {
		Status string
		Thread []struct{ From, Body string } `json:"thread"`
	}
	if code := s.do("POST", "/api/v1/feedback/mine/"+ref+"/reply", map[string]any{"message": "The Fixes page."}, &replied); code != 200 {
		t.Fatalf("reply: %d", code)
	}
	if replied.Status != "received" || len(replied.Thread) != 2 || replied.Thread[1].From != "sender" {
		t.Fatalf("after reply: %+v", replied)
	}
	bearerJSON(t, queue, tok, "GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	if item.Item.Status != "new" || len(item.Comments) != 2 || item.Comments[1].Body != "The Fixes page." {
		t.Fatalf("queue after reply: %+v", item)
	}

	// The agent holds it for the owner: the approvers are emailed.
	if code := bearerJSON(t, queue, tok, "PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "needs_owner",
		"owner_reason": "It changes the wording of an email customers receive."}, nil); code != 200 {
		t.Fatalf("needs_owner: %d", code)
	}
	if mail.count() != 1 || mail.to[0] != "owner@stackurity.test" || !strings.Contains(mail.sent[0].Link, "/admin/feedback?item="+ref) {
		t.Fatalf("approval email: %d %v", mail.count(), mail.to)
	}

	// Only an instance administrator signed in to the dashboard decides:
	// not the triage token, not their API token, not a customer admin.
	var adminTok map[string]any
	if code := ops.do("POST", "/api/v1/tokens", map[string]any{"name": "ci", "role": "admin"}, &adminTok); code != 201 {
		t.Fatalf("api token: %d", code)
	}
	queue.user("customer@x.io", auth.RoleAdmin)
	customer := queue.login("customer@x.io")
	me = nil
	customer.do("GET", "/api/v1/auth/me", nil, &me)
	if _, ok := me["feedback_queue"]; ok {
		t.Fatal("a customer admin is told about the queue")
	}
	for _, path := range []string{"/approve", "/decline"} {
		body := map[string]any{"note": "go", "resolution": "no"}
		if code := bearerJSON(t, queue, tok, "POST", "/api/v1/admin/feedback/"+ref+path, body, nil); code != 403 {
			t.Errorf("triage token %s: %d", path, code)
		}
		if code := bearerJSON(t, queue, adminTok["secret"].(string), "POST", "/api/v1/admin/feedback/"+ref+path, body, nil); code != 403 {
			t.Errorf("admin API token %s: %d", path, code)
		}
		if code := customer.do("POST", "/api/v1/admin/feedback/"+ref+path, body, nil); code != 403 {
			t.Errorf("customer admin %s: %d", path, code)
		}
	}
	// Declining needs a resolution.
	if code := ops.do("POST", "/api/v1/admin/feedback/"+ref+"/decline", map[string]any{}, nil); code != 400 {
		t.Fatalf("decline without resolution: %d", code)
	}
	if code := ops.do("POST", "/api/v1/admin/feedback/"+ref+"/approve", map[string]any{"note": "Go ahead, keep the subject line."}, nil); code != 200 {
		t.Fatalf("approve: %d", code)
	}
	bearerJSON(t, queue, tok, "GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	if item.Item.Status != "triaged" || item.Item.ApprovedAt == nil || item.Item.ApprovedBy != "ops@x.io" || item.Item.ApprovalNote != "Go ahead, keep the subject line." {
		t.Fatalf("after approve: %+v", item.Item)
	}
	approved := false
	for _, ev := range item.Events {
		if ev.Action == "approved" && ev.Actor == "ops@x.io" && ev.ToStatus == "triaged" {
			approved = true
		}
	}
	if !approved {
		t.Fatalf("no approved event: %+v", item.Events)
	}
	// Approving twice: it no longer waits for the owner.
	if code := ops.do("POST", "/api/v1/admin/feedback/"+ref+"/approve", map[string]any{}, nil); code != 409 {
		t.Fatalf("approve again: %d", code)
	}
	// The approved items the agent picks up are listed first by attention.
	var list struct {
		Items []struct {
			Ref, Status string
			ApprovedAt  *string `json:"approved_at"`
		}
	}
	bearerJSON(t, queue, tok, "GET", "/api/v1/admin/feedback?status=new,triaged&order=attention", nil, &list)
	if len(list.Items) != 1 || list.Items[0].ApprovedAt == nil {
		t.Fatalf("list: %+v", list)
	}
}

func TestFeedbackDeclineClosesAndEmails(t *testing.T) {
	e, _ := queueEnv(t, 0)
	mail := &fakeMailer{}
	e.api.AccountMail = mail
	e.api.FeedbackQueue.Emails = true
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	_, res := postIntake(t, e, intakeKey, validItem())
	ref := res["ref"].(string)
	// Not waiting for the owner: refused.
	if code := ops.do("POST", "/api/v1/admin/feedback/"+ref+"/decline", map[string]any{"resolution": "No."}, nil); code != 409 {
		t.Fatalf("decline new: %d", code)
	}
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "needs_owner"}, nil)
	if code := ops.do("POST", "/api/v1/admin/feedback/"+ref+"/decline", map[string]any{"resolution": "Prices stay as they are."}, nil); code != 200 {
		t.Fatalf("decline: %d", code)
	}
	var item fbItem
	ops.do("GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	if item.Item.Status != "wont_fix" || item.Item.Resolution != "Prices stay as they are." {
		t.Fatalf("after decline: %+v", item.Item)
	}
	if mail.count() != 1 || !strings.Contains(strings.Join(mail.sent[0].Summary, "\n"), "Prices stay as they are.") {
		t.Fatalf("won't fix email: %d", mail.count())
	}
	// A closed item takes no questions and no replies.
	if code := ops.do("POST", "/api/v1/admin/feedback/"+ref+"/comments", map[string]any{"body": "Which plan?", "ask": true}, nil); code != 409 {
		t.Fatalf("ask on closed: %d", code)
	}
	var st struct {
		Items []struct {
			Status     string
			ReplyError string `json:"reply_error"`
			Replied    bool
		}
	}
	code := postStatus(t, e, map[string]any{"items": []any{map[string]any{"ref": ref, "token": res["token"], "reply": "But why?"}}}, &st)
	if code != 200 || len(st.Items) != 1 || st.Items[0].Replied || !strings.Contains(st.Items[0].ReplyError, "closed") {
		t.Fatalf("reply on closed: %d %+v", code, st)
	}
}

// statusRaw posts a status request as the website relay does.
func statusRaw(t *testing.T, e *env, body any) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/v1/feedback-queue/status", bytes.NewReader(b))
	req.Header.Set("X-Stackurity-Feedback-Key", intakeKey)
	req.Header.Set("X-Stackurity-Feedback-Client-IP", "203.0.113.9")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func postStatus(t *testing.T, e *env, body any, out any) int {
	t.Helper()
	code, raw := statusRaw(t, e, body)
	if out != nil {
		_ = json.Unmarshal(raw, out)
	}
	return code
}

func TestFeedbackStatusReplies(t *testing.T) {
	e, _ := queueEnv(t, 0)
	_, res := postIntake(t, e, intakeKey, validItem())
	ref, token := res["ref"].(string), res["token"].(string)
	_, res2 := postIntake(t, e, intakeKey, validItem())
	// A wrong token: unknown, nothing stored.
	var st struct {
		Items []struct {
			Ref, Status string
			Replied     bool
			Comments    []struct{ From, Body string }
		}
	}
	postStatus(t, e, map[string]any{"items": []any{map[string]any{"ref": ref, "token": res2["token"], "reply": "hello"}}}, &st)
	if st.Items[0].Status != "unknown" || st.Items[0].Replied {
		t.Fatalf("wrong token: %+v", st)
	}
	// Two replies in one request are refused.
	two := map[string]any{"items": []any{map[string]any{"ref": ref, "token": token, "reply": "a"}, map[string]any{"ref": res2["ref"], "token": res2["token"], "reply": "b"}}}
	if code := postStatus(t, e, two, nil); code != 400 {
		t.Fatalf("two replies: %d", code)
	}
	if code := postStatus(t, e, map[string]any{"items": []any{map[string]any{"ref": ref, "token": token, "reply": strings.Repeat("x", 2001)}}}, &st); code != 200 || st.Items[0].Replied {
		t.Fatalf("long reply: %d %+v", code, st)
	}
	postStatus(t, e, map[string]any{"items": []any{map[string]any{"ref": ref, "token": token, "reply": "More detail"}}}, &st)
	if !st.Items[0].Replied || st.Items[0].Status != "received" || len(st.Items[0].Comments) != 1 || st.Items[0].Comments[0].From != "sender" {
		t.Fatalf("reply: %+v", st)
	}
	// Large threads are cut to fit the relay's answer size.
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	for i := 0; i < 25; i++ {
		ops.do("POST", "/api/v1/admin/feedback/"+ref+"/comments", map[string]any{"body": fmt.Sprintf("%02d ", i) + strings.Repeat("é", 4990)}, nil)
	}
	_, raw := statusRaw(t, e, map[string]any{"items": []any{map[string]any{"ref": ref, "token": token}}})
	b := string(raw)
	if len(b) > 64<<10 {
		t.Fatalf("status answer %d bytes", len(b))
	}
	if !strings.Contains(b, "24 ") {
		t.Fatalf("newest comment missing")
	}
}

func TestFeedbackAgentEmails(t *testing.T) {
	e, _ := queueEnv(t, 0)
	mail := &fakeMailer{}
	e.api.AccountMail = mail
	e.api.FeedbackQueue.AgentEmails = true
	item := validItem()
	item["description"] = "Click https://phish.example/login and mail boss@corp.example"
	item["hosting"] = "cloud"
	_, res := postIntake(t, e, intakeKey, item)
	ref := res["ref"].(string)
	// The received email goes after the answer.
	waitMail := func(n int) {
		t.Helper()
		for i := 0; i < 100 && mail.count() < n; i++ {
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
	}
	waitMail(1)
	if mail.count() != 1 {
		t.Fatalf("received: %d", mail.count())
	}
	mail.mu.Lock()
	body := mail.sent[0].Title + "\n" + strings.Join(mail.sent[0].Summary, "\n")
	mail.mu.Unlock()
	if !strings.Contains(body, ref) || !strings.Contains(body, "phish[.]example") || strings.Contains(body, "phish.example") ||
		strings.Contains(body, "https://") || strings.Contains(body, "boss@") {
		t.Fatalf("received email: %s", body)
	}
	// Five a day to one address.
	for i := 0; i < 6; i++ {
		postIntake(t, e, intakeKey, item)
		waitMail(min(1+i+1, 5))
	}
	if mail.count() != 5 {
		t.Fatalf("received emails to one address: %d", mail.count())
	}
	// Questions: emailed, with a link to My feedback for Cloud senders. The
	// released email still goes once (the received email is not it).
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	ops.do("POST", "/api/v1/admin/feedback/"+ref+"/comments", map[string]any{"body": "Which page were you on?", "ask": true}, nil)
	m := mail.sent[len(mail.sent)-1]
	if mail.count() != 6 || !strings.Contains(strings.Join(m.Summary, "\n"), "Which page were you on?") || m.Link != "https://app.example.test/feedback" {
		t.Fatalf("needs_info email: %d %+v", mail.count(), m)
	}
	e.api.FeedbackQueue.Emails = true
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "released"}, nil)
	if mail.count() != 7 {
		t.Fatalf("released after agent emails: %d", mail.count())
	}
	// The preview marks the new templates as not approved.
	var tpl struct {
		AgentEnabled bool `json:"agent_enabled"`
		Templates    []struct {
			Name     string
			Approved bool
		}
	}
	ops.do("GET", "/api/v1/admin/feedback/email-templates", nil, &tpl)
	if !tpl.AgentEnabled || len(tpl.Templates) != 4 || !tpl.Templates[0].Approved || tpl.Templates[2].Approved || tpl.Templates[3].Approved {
		t.Fatalf("preview: %+v", tpl)
	}
}
