package notify

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
)

// A From with a display name is sent as the bare address in MAIL FROM and
// kept whole in the From header. ZeptoMail answered the whole string in MAIL
// FROM with 501, so every Cloud sign-up email failed.
func TestSendEmailEnvelopeFromIsBareAddress(t *testing.T) {
	var mailFrom, data string
	s := &Sender{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
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
						data = b.String()
						say("250 queued")
						continue
					}
					b.WriteString(line + "\n")
					continue
				}
				switch cmd := strings.ToUpper(line); {
				case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
					say("250 test")
				case strings.HasPrefix(cmd, "MAIL FROM:"):
					mailFrom = line[len("MAIL FROM:"):]
					if strings.Count(mailFrom, "<") != 1 {
						say(`501 5.5.2 Syntax error in MAIL command`)
						continue
					}
					say("250 ok")
				case strings.HasPrefix(cmd, "RCPT TO:"):
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
	c := ChannelConfig{Host: "smtp.test", Port: 587, TLS: "none",
		From: "Stackurity <no-reply@stackurity.dev>", To: []string{"person@example.com"}}
	if err := s.sendEmail(context.Background(), c, "", Message{Event: "test", Title: "Confirm your sign-up"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !strings.HasPrefix(mailFrom, "<no-reply@stackurity.dev>") {
		t.Errorf("MAIL FROM = %q, want the bare address", mailFrom)
	}
	if !strings.Contains(data, "Stackurity <no-reply@stackurity.dev>") && !strings.Contains(data, `"Stackurity" <no-reply@stackurity.dev>`) {
		t.Errorf("From header lost its display name:\n%s", data)
	}
	if got := envelopeAddress("no-reply@stackurity.dev"); got != "no-reply@stackurity.dev" {
		t.Errorf("bare address changed: %q", got)
	}
}
