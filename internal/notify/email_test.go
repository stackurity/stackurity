package notify

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/store"
)

// The email checks: every kind of email the server sends is rendered from
// its sample (email_samples.go) for Stackurity Cloud and for a self-hosted
// installation, and must pass CheckEmail. The Cloud rendering is also kept
// in testdata/email (subject and text, and HTML), so a change to any email
// shows in review:
//
//	go test ./internal/notify -run TestEmailGolden -update
//
// rewrites them after a deliberate change. make email-preview writes them
// all as .html files to look at in a browser.

type emailInstall struct {
	name  string
	brand EmailBrand
	from  string
}

var emailInstalls = []emailInstall{
	{"cloud", EmailBrand{Product: "Stackurity Cloud", Home: "https://app.stackurity.dev",
		PrivacyURL: "https://stackurity.ai/privacy.html", SupportURL: "mailto:info@stackurity.ai"}, "Stackurity <no-reply@stackurity.dev>"},
	{"self-hosted", EmailBrand{Home: "https://stackurity.northwind-traders.com"}, "Northwind Stackurity <stackurity@northwind-traders.com>"},
}

// emailParts decodes a rendered email into its subject, text and HTML.
func emailParts(t *testing.T, raw []byte) (subject, text, page string) {
	t.Helper()
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	subject, _ = new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(p)
		if strings.HasPrefix(p.Header.Get("Content-Type"), "text/html") {
			page = string(b)
		} else {
			text = string(b)
		}
	}
	return subject, strings.ReplaceAll(text, "\r\n", "\n"), strings.ReplaceAll(page, "\r\n", "\n")
}

func TestEmailSamplesPassChecks(t *testing.T) {
	for _, in := range emailInstalls {
		for _, s := range EmailSamples(in.brand.Home) {
			t.Run(in.name+"/"+s.Name, func(t *testing.T) {
				from, _ := mail.ParseAddress(in.from)
				raw := renderEmail(in.from, []string{"dana@northwind-traders.com"}, s.Message, in.brand.normal(), EmailSampleTime)
				for _, p := range CheckEmail(raw, s.Message, EmailCheck{Base: in.brand.Home, FromName: from.Name,
					Notification: s.Notification, Secrets: s.Secrets}) {
					t.Error(p)
				}
				// The From header keeps the display name (CheckEmail); SMTP's
				// envelope sender is the bare address (#257).
				if got := envelopeAddress(in.from); got != from.Address {
					t.Errorf("envelope sender %q, want the bare address %q", got, from.Address)
				}
				if s.Notification != (s.Message.oneClick != "") {
					t.Errorf("notification %v, but one-click unsubscribe %q", s.Notification, s.Message.oneClick)
				}
				if in.name == "self-hosted" {
					// The installation's own address, never the hosted service's.
					for _, other := range []string{"app.stackurity.dev", "stackurity.ai/privacy", "info@stackurity.ai"} {
						if bytes.Contains(raw, []byte(other)) {
							t.Errorf("a self-hosted email mentions %s", other)
						}
					}
				}
			})
		}
	}
}

func TestEmailGolden(t *testing.T) {
	in := emailInstalls[0]
	dir := filepath.Join("testdata", "email")
	want := map[string]bool{}
	for _, s := range EmailSamples(in.brand.Home) {
		want[s.Name+".txt"], want[s.Name+".html"] = true, true
		raw := renderEmail(in.from, []string{"dana@northwind-traders.com"}, s.Message, in.brand.normal(), EmailSampleTime)
		subject, text, page := emailParts(t, raw)
		files := map[string]string{s.Name + ".txt": "Subject: " + subject + "\n\n" + text, s.Name + ".html": page}
		for name, got := range files {
			golden := filepath.Join(dir, name)
			if *updateGolden {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			b, err := os.ReadFile(golden)
			if err != nil {
				t.Errorf("%v (run go test ./internal/notify -run TestEmailGolden -update)", err)
				continue
			}
			if string(b) != got {
				t.Errorf("%s differs from the rendering (run with -update after a deliberate change, and review the diff):\n%s", golden, got)
			}
		}
	}
	// No golden file of an email that no longer exists.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !want[e.Name()] {
			if *updateGolden {
				_ = os.Remove(filepath.Join(dir, e.Name()))
				continue
			}
			t.Errorf("%s has no sample any more; delete it (or run with -update)", filepath.Join(dir, e.Name()))
		}
	}
}

// Every kind of email has a sample: the events of accountEvents, the
// alerts, and every literal Message{Event: "…"} in the code. A new email
// fails here until it is added to EmailSamples (or, for Stackurity
// Cloud's, to the pro repository's samples).
func TestEveryEmailHasASample(t *testing.T) {
	have := map[string]bool{}
	for _, s := range EmailSamples("https://app.stackurity.dev") {
		have[s.Message.Event] = true
	}
	cloud := map[string]bool{"signup": true, "deletion_warning": true, "trial_summary": true, "community_key": true} // pro's samples
	need := map[string]bool{"opened": true, "escalated": true, "resolved": true, EventUrgent: true, EventSummary: true,
		EventOverdue: true, EventConnected: true, EventDigest: true, store.CategoryMarketing: true, store.CategoryVulnerabilityNews: true}
	for e := range accountEvents {
		need[e] = true
	}
	lit := regexp.MustCompile(`Message\{Event:\s*"([a-z_]+)"`)
	for _, root := range []string{"../../internal", "../../cmd"} {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, m := range lit.FindAllSubmatch(b, -1) {
				need[string(m[1])] = true
			}
			return nil
		})
	}
	var missing []string
	for e := range need {
		if !have[e] && !cloud[e] {
			missing = append(missing, e)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("emails without a sample in EmailSamples: %v", missing)
	}
}

func TestSubjectTags(t *testing.T) {
	for _, c := range []struct {
		m    Message
		want string
	}{
		{Message{Event: "signup", Title: "Confirm your email for Stackurity Cloud"}, "Confirm your email for Stackurity Cloud"},
		{Message{Event: "some_new_kind", Title: "Hello"}, "Hello"}, // no priority: no "[]"
		{Message{Event: "opened", Priority: "P1", Title: "CVE-1 in x"}, "[P1] CVE-1 in x"},
		{Message{Event: "opened", Priority: "P1", SOS: true, Title: "CVE-1 in x"}, "[SOS] [P1] CVE-1 in x"},
		{Message{Event: "escalated", Priority: "P2", Title: "t"}, "[P2 escalated] t"},
		{Message{Event: "escalated", Title: "t"}, "[escalated] t"},
		{Message{Event: "resolved", Priority: "P1", Title: "t"}, "[resolved] t"},
		{Message{Event: EventUrgent, Priority: "P1", SOS: true, Title: "web-1: 3 new urgent issues"}, "[SOS] web-1: 3 new urgent issues"},
		{Message{Event: EventOverdue, Priority: "P1", Title: "1 urgent issue past its deadline"}, "1 urgent issue past its deadline"},
		{Message{Event: "invitation", Title: "  You are invited to  Acme \n on Stackurity: "}, "You are invited to Acme on Stackurity"},
		{Message{Event: "opened", Title: ""}, "Stackurity notification"},
	} {
		if got := c.m.Subject(); got != c.want {
			t.Errorf("Subject(%+v) = %q, want %q", c.m, got, c.want)
		}
		if p := CheckSubject(c.m.Subject(), nil); len(p) > 0 {
			t.Errorf("%q: %v", c.m.Subject(), p)
		}
	}
	for _, bad := range []string{"[] Confirm your email", "Hello ()", " Hello", "Hello -", "Hello  world", "Code {{.Code}}",
		"%!s(MISSING)", "<nil>", "Sign-in from 203.0.113.42", "Reset pwr_Zq7Kx2mN4pR8sT1vW6yB3cD9", strings.Repeat("a ", 50)} {
		if len(CheckSubject(bad, nil)) == 0 {
			t.Errorf("CheckSubject(%q) found nothing wrong", bad)
		}
	}
	// A long subject is cut in the email.
	m := Message{Event: "invitation", Title: "You are invited to " + strings.Repeat("Very Long Organisation Name ", 6) + "on Stackurity"}
	subject, _, _ := emailParts(t, renderEmail("a@b.c", []string{"d@e.f"}, m, EmailBrand{}.normal(), EmailSampleTime))
	if p := CheckSubject(subject, nil); len(p) > 0 {
		t.Errorf("long subject %q: %v", subject, p)
	}
}

// The checks catch what the 4 Nov sign-up email had: an empty tag, the
// subject repeated as the first line, plain text only, no button.
func TestCheckEmailCatchesTheOldEmail(t *testing.T) {
	old := "From: no-reply@stackurity.dev\r\nTo: a@northwind-traders.com\r\nSubject: [] Confirm your email for Stackurity Cloud\r\n" +
		"Date: Wed, 04 Nov 2026 09:30:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		"[] Confirm your email for Stackurity Cloud\r\n\r\n• Open the link\r\n\r\nhttps://app.stackurity.dev/signup/verify#sup_x\r\n"
	m := Message{Event: "signup", Title: "Confirm your email for Stackurity Cloud", Link: "https://app.stackurity.dev/signup/verify#sup_x"}
	p := strings.Join(CheckEmail([]byte(old), m, EmailCheck{Base: "https://app.stackurity.dev", FromName: "Stackurity"}), "\n")
	for _, want := range []string{`contains "[]"`, "Message-ID", "display name", "multipart/alternative"} {
		if !strings.Contains(p, want) {
			t.Errorf("CheckEmail did not report %q:\n%s", want, p)
		}
	}
}

// Text and HTML of a sign-in code, a button email and a notification.
func TestEmailLayout(t *testing.T) {
	br := EmailBrand{Home: "https://stk.northwind-traders.com"}.normal()
	m := EmailCodeEmail(br.Home, "dana@northwind-traders.com", "signing in", "482915", "203.0.113.42", EmailSampleTime)
	_, text, page := emailParts(t, renderEmail("Stackurity <s@northwind-traders.com>", []string{"d@e.f"}, m, br, EmailSampleTime))
	if !strings.Contains(text, "\n    482915\n") || !strings.Contains(page, `letter-spacing:0.18em`) || strings.Contains(text, "•") {
		t.Errorf("code not shown on its own:\n%s", text)
	}
	if !strings.Contains(page, `src="https://stk.northwind-traders.com/favicon-64.png"`) || !strings.Contains(page, `alt="Stackurity logo"`) ||
		!strings.Contains(page, ">Stackurity</span>") || !strings.Contains(page, "prefers-color-scheme:dark") || !strings.Contains(page, "max-width:600px") {
		t.Errorf("layout:\n%s", page)
	}
	raw := renderEmail("Stackurity <s@northwind-traders.com>", []string{"d@e.f"}, m, br, EmailSampleTime)
	for _, l := range strings.Split(string(raw), "\r\n") {
		if len(l) > 78 && !strings.HasPrefix(l, "Subject:") && !strings.HasPrefix(l, "Content-Type:") {
			t.Errorf("line longer than 78 characters: %q", l)
		}
	}
	if !bytes.Contains(raw, []byte("From: \"Stackurity\" <s@northwind-traders.com>\r\n")) {
		t.Errorf("From lost its display name:\n%s", raw)
	}
}

// readableEmail is raw with its subject and parts decoded, for tests that
// look for text in an email: the headers as sent (the Subject decoded),
// then each part's content type and decoded body, with CRLF line endings.
func readableEmail(raw []byte) string {
	head, _, _ := strings.Cut(string(raw), "\r\n\r\n")
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return string(raw)
	}
	subject, _ := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	var b strings.Builder
	for _, l := range strings.Split(head, "\r\n") {
		if strings.HasPrefix(l, "Subject: ") {
			l = "Subject: " + subject
		}
		b.WriteString(l + "\r\n")
	}
	b.WriteString("\r\n")
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		body, _ := io.ReadAll(p)
		b.WriteString("Content-Type: " + p.Header.Get("Content-Type") + "\r\n\r\n" + string(body) + "\r\n")
	}
	return b.String()
}
