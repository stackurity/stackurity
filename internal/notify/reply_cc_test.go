package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"strings"
	"testing"
)

// fakeSMTP is a mail server on a pipe that records the envelope recipients
// and the message.
type fakeSMTP struct {
	rcpts []string
	data  string
	dials int
}

func (f *fakeSMTP) sender() *Sender {
	return &Sender{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		f.dials++
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			r := bufio.NewReader(server)
			say := func(l string) { server.Write([]byte(l + "\r\n")) }
			say("220 test")
			inData := false
			var b strings.Builder
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				line = strings.TrimRight(line, "\r\n")
				if inData {
					if line == "." {
						inData = false
						f.data = b.String()
						say("250 queued")
						continue
					}
					b.WriteString(line + "\r\n")
					continue
				}
				switch cmd := strings.ToUpper(line); {
				case strings.HasPrefix(cmd, "RCPT TO:"):
					f.rcpts = append(f.rcpts, strings.Trim(line[len("RCPT TO:"):], "<> "))
					say("250 ok")
				case cmd == "DATA":
					inData = true
					say("354 go")
				case cmd == "QUIT":
					say("221 bye")
					return
				default:
					say("250 ok")
				}
			}
		}()
		return client, nil
	}}
}

func TestEmailReplyToAndCc(t *testing.T) {
	f := &fakeSMTP{}
	c := ChannelConfig{Host: "smtp.test", Port: 587, TLS: "none", From: "Stackurity <no-reply@stackurity.dev>", To: []string{"dana@example.org"}}
	m := Message{Event: "billing", Title: "Your trial ends in 3 days", ReplyTo: "Stackurity sales <sales@stackurity.dev>",
		Cc: []string{"sales@stackurity.dev", "DANA@example.org"}}
	if err := f.sender().sendEmail(context.Background(), c, "", m); err != nil {
		t.Fatal(err)
	}
	// The Cc is in the envelope once; an address already in To is not
	// sent a second copy.
	if got := strings.Join(f.rcpts, ","); got != "dana@example.org,sales@stackurity.dev" {
		t.Errorf("RCPT TO %s", got)
	}
	msg, err := mail.ReadMessage(strings.NewReader(f.data))
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.Header.Get("Reply-To"); got != `"Stackurity sales" <sales@stackurity.dev>` {
		t.Errorf("Reply-To %q", got)
	}
	if got := msg.Header.Get("Cc"); got != "sales@stackurity.dev, DANA@example.org" {
		t.Errorf("Cc %q", got)
	}
	if got := msg.Header.Get("To"); got != "dana@example.org" {
		t.Errorf("To %q", got)
	}
}

func TestEmailWithoutReplyToHasNoSuchHeaders(t *testing.T) {
	raw := string(RenderEmail("no-reply@stackurity.dev", []string{"dana@example.org"}, Message{Event: "test", Title: "Test"}))
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	if strings.Contains(head, "Reply-To:") || strings.Contains(head, "\r\nCc:") {
		t.Errorf("headers:\n%s", head)
	}
}

// A line break in Reply-To or Cc would add headers of the caller's
// choosing: the send is refused for good, before anything is dialled.
func TestEmailReplyToAndCcRefuseHeaderInjection(t *testing.T) {
	c := ChannelConfig{Host: "smtp.test", Port: 587, TLS: "none", From: "no-reply@stackurity.dev", To: []string{"dana@example.org"}}
	for name, m := range map[string]Message{
		"reply-to crlf": {Title: "x", ReplyTo: "sales@stackurity.dev\r\nBcc: victim@example.org"},
		"reply-to lf":   {Title: "x", ReplyTo: "sales@stackurity.dev\nX-Evil: 1"},
		"reply-to bad":  {Title: "x", ReplyTo: "not an address"},
		"cc crlf":       {Title: "x", Cc: []string{"sales@stackurity.dev\r\nBcc: victim@example.org"}},
		"cc bad":        {Title: "x", Cc: []string{"sales@"}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeSMTP{}
			err := f.sender().sendEmail(context.Background(), c, "", m)
			var pe *PermanentError
			if !errors.As(err, &pe) {
				t.Fatalf("err %v, want a PermanentError", err)
			}
			if f.dials != 0 {
				t.Error("dialled the mail server")
			}
			// Rendering (previews) leaves the bad address out instead.
			raw := string(RenderEmail("no-reply@stackurity.dev", []string{"dana@example.org"}, m))
			head, _, _ := strings.Cut(raw, "\r\n\r\n")
			for _, l := range strings.Split(head, "\r\n") {
				if strings.HasPrefix(l, "Bcc:") || strings.HasPrefix(l, "X-Evil:") {
					t.Errorf("injected header %q", l)
				}
			}
		})
	}
}

// Cc counts towards the recipients of one email.
func TestEmailCcCountsTowardsRecipients(t *testing.T) {
	to := make([]string, MaxEmailRecipients-1)
	for i := range to {
		to[i] = fmt.Sprintf("p%d@example.org", i)
	}
	c := ChannelConfig{Host: "smtp.test", Port: 587, TLS: "none", From: "no-reply@stackurity.dev", To: to}
	f := &fakeSMTP{}
	if err := f.sender().sendEmail(context.Background(), c, "", Message{Title: "x", Cc: []string{"sales@stackurity.dev"}}); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	f = &fakeSMTP{}
	err := f.sender().sendEmail(context.Background(), c, "", Message{Title: "x", Cc: []string{"sales@stackurity.dev", "ops@stackurity.dev"}})
	var pe *PermanentError
	if !errors.As(err, &pe) || f.dials != 0 {
		t.Fatalf("over the limit: err %v, dials %d", err, f.dials)
	}
}

// Email sent by Stackurity hides its recipients from each other; a Cc is
// shown, as the sender asked for it.
func TestPlatformMailerSendsCc(t *testing.T) {
	f := &fakeSMTP{}
	pm := &SMTPMailer{Sender: f.sender(), Config: ChannelConfig{Host: "smtp.test", Port: 587, TLS: "none", From: "no-reply@stackurity.dev"}}
	m := Message{Event: "inactive_pause", Title: "Sign in", ReplyTo: "sales@stackurity.dev", Cc: []string{"sales@stackurity.dev"}}
	if err := pm.SendMail(context.Background(), []string{"a@example.org", "b@example.org"}, m); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.rcpts, ","); got != "a@example.org,b@example.org,sales@stackurity.dev" {
		t.Errorf("RCPT TO %s", got)
	}
	msg, err := mail.ReadMessage(strings.NewReader(f.data))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Cc") != "sales@stackurity.dev" || msg.Header.Get("Reply-To") != "sales@stackurity.dev" ||
		strings.Contains(msg.Header.Get("To"), "a@example.org") {
		t.Errorf("headers To %q Cc %q Reply-To %q", msg.Header.Get("To"), msg.Header.Get("Cc"), msg.Header.Get("Reply-To"))
	}
}

// Reply-To and Cc are email headers, never part of a webhook's payload.
func TestReplyToAndCcNotInWebhookPayload(t *testing.T) {
	b, _ := json.Marshal(Message{Title: "x", ReplyTo: "sales@stackurity.dev", Cc: []string{"sales@stackurity.dev"}})
	if strings.Contains(string(b), "sales@") {
		t.Errorf("payload %s", b)
	}
}

func TestCheckEmailReplyToAndCc(t *testing.T) {
	m := Message{Event: "billing", Title: "Your trial ends in 3 days", Summary: []string{"Choose a plan to keep everything."},
		Link: "https://app.stackurity.dev/settings/billing", LinkLabel: "Choose a plan",
		ReplyTo: "sales@stackurity.dev", Cc: []string{"sales@stackurity.dev"}}
	raw := RenderEmail("Stackurity <no-reply@stackurity.dev>", []string{"dana@example.org"}, m)
	if p := CheckEmail(raw, m, EmailCheck{Base: "https://app.stackurity.dev", FromName: "Stackurity"}); len(p) > 0 {
		t.Errorf("problems: %v", p)
	}
	other := m
	other.ReplyTo = "support@stackurity.dev"
	if p := CheckEmail(raw, other, EmailCheck{Base: "https://app.stackurity.dev", FromName: "Stackurity"}); len(p) == 0 {
		t.Error("a different Reply-To passed the check")
	}
}
