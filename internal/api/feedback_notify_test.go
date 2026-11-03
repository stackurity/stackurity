package api_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/feedback"
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
	if code := ops.do("GET", "/api/v1/admin/feedback/email-templates", nil, &tpl); code != 200 || len(tpl.Templates) != 2 || !tpl.Enabled {
		t.Fatalf("preview: %d %+v", code, tpl)
	}
	e.user("admin@x.io", auth.RoleAdmin)
	if code := e.login("admin@x.io").do("GET", "/api/v1/admin/feedback/email-templates", nil, nil); code != 403 {
		t.Fatalf("customer preview: %d", code)
	}
}

// fakeClamd answers INSTREAM: FOUND for data containing EICAR.
func fakeClamd(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				if cmd, _ := r.ReadString(0); cmd != "zINSTREAM\x00" {
					return
				}
				var data []byte
				for {
					var n uint32
					if binary.Read(r, binary.BigEndian, &n) != nil {
						return
					}
					if n == 0 {
						break
					}
					chunk := make([]byte, n)
					if _, err := io.ReadFull(r, chunk); err != nil {
						return
					}
					data = append(data, chunk...)
				}
				if strings.Contains(string(data), "EICAR") {
					c.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
				} else {
					c.Write([]byte("stream: OK\x00"))
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestFeedbackClamdAndStorageWarning(t *testing.T) {
	e, dir := queueEnv(t, 200)
	e.api.FeedbackQueue.Clamd = &feedback.Clamd{Addr: fakeClamd(t)}
	if code, res := postIntake(t, e, intakeKey, validItem(), upload{"a.pdf", []byte("%PDF-1.4 X5O!P%@AP EICAR-STANDARD-ANTIVIRUS")}); code != 422 {
		t.Fatalf("infected: %d %v", code, res)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("infected file kept")
	}
	// Clean, and past 80% of the cap: the reply carries the warning.
	code, res := postIntake(t, e, intakeKey, validItem(), upload{"b.pdf", []byte("%PDF-1.4 " + strings.Repeat("x", 160))})
	if code != 201 || !strings.Contains(res["storage_warning"].(string), "84%") {
		t.Fatalf("clean: %d %v", code, res)
	}
	// A scanner that is down refuses attachments (fails closed).
	e.api.FeedbackQueue.Clamd = &feedback.Clamd{Addr: "127.0.0.1:1"}
	e.api.FeedbackQueue.StorageMax = 1 << 30
	if code, res := postIntake(t, e, intakeKey, validItem(), upload{"c.pdf", []byte("%PDF-1.4 c")}); code != 503 {
		t.Fatalf("scanner down: %d %v", code, res)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("%d files", len(entries))
	}
}
