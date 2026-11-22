package api_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/notify"
)

type fakeMailer struct {
	mu   sync.Mutex
	sent []notify.Message
	to   []string
}

func (m *fakeMailer) SendMail(_ context.Context, to []string, msg notify.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sent = append(m.sent, msg)
	m.to = append(m.to, to...)
	return nil
}

func (m *fakeMailer) From() string { return "no-reply@example.test" }

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func TestFeedbackSenderEmail(t *testing.T) {
	e, _ := queueEnv(t, 0)
	mail := &fakeMailer{}
	e.api.AccountMail = mail
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	item := validItem()
	item["description"] = "Click here: https://phish.example/login to claim your refund"
	_, res := postIntake(t, e, intakeKey, item)
	ref := res["ref"].(string)

	// Off by default: no email, whatever the status.
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "released", "fixed_in": "0.15.0"}, nil)
	if mail.count() != 0 {
		t.Fatalf("emailed with emails off")
	}

	e.api.FeedbackQueue.Emails = true
	_, res = postIntake(t, e, intakeKey, item)
	ref = res["ref"].(string)
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "fixed"}, nil)
	if mail.count() != 0 {
		t.Fatalf("emailed for fixed")
	}
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "released", "fixed_in": "0.15.0"}, nil)
	if mail.count() != 1 || mail.to[0] != "me@example.com" {
		t.Fatalf("released: %d %v", mail.count(), mail.to)
	}
	m := mail.sent[0]
	body := m.Title + "\n" + strings.Join(m.Summary, "\n")
	if !strings.Contains(body, ref) || !strings.Contains(body, "0.15.0") || strings.Contains(body, "phish.example") {
		t.Fatalf("email: %s", body)
	}
	// Once only, even if it is changed again.
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "fixed"}, nil)
	ops.do("PATCH", "/api/v1/admin/feedback/"+ref, map[string]any{"status": "released"}, nil)
	if mail.count() != 1 {
		t.Fatalf("emailed twice: %d", mail.count())
	}
	// Won't fix carries the team's reason; no address, no email.
	_, res = postIntake(t, e, intakeKey, item)
	ops.do("PATCH", "/api/v1/admin/feedback/"+res["ref"].(string), map[string]any{"status": "wont_fix", "resolution": "Exports stay in the API."}, nil)
	if mail.count() != 2 || !strings.Contains(strings.Join(mail.sent[1].Summary, "\n"), "Exports stay in the API.") {
		t.Fatalf("won't fix: %d", mail.count())
	}
	noEmail := validItem()
	delete(noEmail, "email")
	_, res = postIntake(t, e, intakeKey, noEmail)
	ops.do("PATCH", "/api/v1/admin/feedback/"+res["ref"].(string), map[string]any{"status": "released"}, nil)
	if mail.count() != 2 {
		t.Fatalf("emailed without an address")
	}

	// The templates can be previewed by operators, not customers.
	var tpl struct {
		Enabled   bool
		Templates []struct{ Name, Subject, Body string }
	}
	if code := ops.do("GET", "/api/v1/admin/feedback/email-templates", nil, &tpl); code != 200 || len(tpl.Templates) != 4 || !tpl.Enabled {
		t.Fatalf("preview: %d %+v", code, tpl)
	}
	e.user("admin@x.io", auth.RoleAdmin)
	if code := e.login("admin@x.io").do("GET", "/api/v1/admin/feedback/email-templates", nil, nil); code != 403 {
		t.Fatalf("customer preview: %d", code)
	}
}

func TestFeedbackScanOnDemand(t *testing.T) {
	e, dir := queueEnv(t, 200)
	e.api.FeedbackQueue.ScanRequired = true
	e.user("ops@x.io", auth.RoleAdmin)
	e.instanceAdmin("ops@x.io")
	ops := e.login("ops@x.io")
	var triage, scanner struct{ Token string }
	ops.do("POST", "/api/v1/admin/feedback-tokens", map[string]any{"name": "agent"}, &triage)
	if code := ops.do("POST", "/api/v1/admin/feedback-tokens", map[string]any{"name": "scanner", "scope": "scanner"}, &scanner); code != 201 {
		t.Fatalf("scanner token: %d", code)
	}
	if code := ops.do("POST", "/api/v1/admin/feedback-tokens", map[string]any{"name": "x", "scope": "admin"}, nil); code != 400 {
		t.Fatalf("bad scope: %d", code)
	}

	code, res := postIntake(t, e, intakeKey, validItem(), upload{"a.pdf", []byte("%PDF-1.4 clean" + strings.Repeat("x", 100))}, upload{"b.pdf", []byte("%PDF-1.4 X5O EICAR" + strings.Repeat("x", 60))})
	if code != 201 || !strings.Contains(res["storage_warning"].(string), "%") {
		t.Fatalf("intake: %d %v", code, res)
	}
	ref := res["ref"].(string)
	// Pending: invisible to operators and the triage agent.
	var item struct {
		Item struct {
			Status      string
			TriageNotes string `json:"triage_notes"`
			Count       int    `json:"attachment_count"`
		} `json:"item"`
		Attachments []struct {
			ID   int64
			Scan string
		} `json:"attachments"`
	}
	bearerJSON(t, e, triage.Token, "GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	if len(item.Attachments) != 0 || item.Item.Count != 0 {
		t.Fatalf("pending attachments visible: %+v", item)
	}
	// Scopes do not mix.
	if code := bearerJSON(t, e, triage.Token, "GET", "/api/v1/admin/feedback/scan/pending", nil, nil); code != 403 {
		t.Fatalf("triage token on the scan queue: %d", code)
	}
	for _, p := range []string{"/api/v1/admin/feedback", "/api/v1/admin/feedback/" + ref, "/api/v1/auth/me"} {
		if code := bearerJSON(t, e, scanner.Token, "GET", p, nil, nil); code != 403 && code != 401 {
			t.Fatalf("scanner token on %s: %d", p, code)
		}
	}
	var pending struct {
		Attachments []struct {
			ID         int64  `json:"id"`
			StorageKey string `json:"storage_key"`
		} `json:"attachments"`
	}
	if code := bearerJSON(t, e, scanner.Token, "GET", "/api/v1/admin/feedback/scan/pending", nil, &pending); code != 200 || len(pending.Attachments) != 2 {
		t.Fatalf("scan queue: %d %+v", code, pending)
	}
	clean, bad := pending.Attachments[0], pending.Attachments[1]
	// A link for a pending attachment is refused.
	if code := ops.do("POST", fmt.Sprintf("/api/v1/admin/feedback/%s/attachments/%d/link", ref, clean.ID), nil, nil); code != 404 {
		t.Fatalf("link while pending: %d", code)
	}
	if code := bearerJSON(t, e, scanner.Token, "POST", fmt.Sprintf("/api/v1/admin/feedback/scan/%d", bad.ID), map[string]any{"result": "infected", "signature": "x<script>"}, nil); code != 400 {
		t.Fatalf("bad signature: %d", code)
	}
	for id, body := range map[int64]map[string]any{clean.ID: {"result": "clean"}, bad.ID: {"result": "infected", "signature": "Eicar-Test-Signature"}} {
		if code := bearerJSON(t, e, scanner.Token, "POST", fmt.Sprintf("/api/v1/admin/feedback/scan/%d", id), body, nil); code != 204 {
			t.Fatalf("scan result %d: %d", id, code)
		}
	}
	// Again: no longer pending.
	if code := bearerJSON(t, e, scanner.Token, "POST", fmt.Sprintf("/api/v1/admin/feedback/scan/%d", clean.ID), map[string]any{"result": "infected", "signature": "X"}, nil); code != 404 {
		t.Fatalf("second verdict: %d", code)
	}
	if _, err := os.Stat(dir + "/" + bad.StorageKey); !os.IsNotExist(err) {
		t.Fatalf("infected file kept: %v", err)
	}
	if _, err := os.Stat(dir + "/" + clean.StorageKey); err != nil {
		t.Fatalf("clean file: %v", err)
	}
	bearerJSON(t, e, triage.Token, "GET", "/api/v1/admin/feedback/"+ref, nil, &item)
	if item.Item.Status != "needs_owner" || !strings.Contains(item.Item.TriageNotes, "Eicar-Test-Signature") || len(item.Attachments) != 2 {
		t.Fatalf("after scan: %+v", item)
	}
	if code := ops.do("POST", fmt.Sprintf("/api/v1/admin/feedback/%s/attachments/%d/link", ref, clean.ID), nil, nil); code != 200 {
		t.Fatalf("link when clean: %d", code)
	}
	if code := ops.do("POST", fmt.Sprintf("/api/v1/admin/feedback/%s/attachments/%d/link", ref, bad.ID), nil, nil); code != 410 {
		t.Fatalf("link when infected: %d", code)
	}
}
