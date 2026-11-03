package feedback

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// The two emails the queue sends to the person who sent an item, when they
// left an address: when it is released, and when the team decided not to
// change anything (with the reason). Plain text, no tracking, no links but
// the changelog. They are sent only with STACKURITY_FEEDBACK_EMAILS=on; the
// owner approves the wording before that is turned on.

// EmailData fills a template.
type EmailData struct {
	Ref        string // FB-123
	Summary    string // what they wrote; not put in the email (see RenderEmail)
	Resolution string // the team's note (required for won't fix)
	Version    string // the release that has the change
}

// Email is a rendered message.
type Email struct {
	Subject string
	Body    string
}

var emailTemplates = map[string]struct{ subject, body string }{
	"released": {
		subject: "Your Stackurity feedback {{.Ref}} is fixed",
		body: `Hello,

Thank you for your feedback {{.Ref}}.

{{if .Version}}The change is in Stackurity {{.Version}}, released today.{{else}}The change has been released.{{end}}{{if .Resolution}}

{{.Resolution}}{{end}}

On Stackurity Cloud you have it already. If you run Stackurity yourself, it arrives when you upgrade; the changelog is at https://stackurity.ai/changelog.html.

You can see this and anything else you sent under Feedback -> My feedback in Stackurity.

The Stackurity team
`,
	},
	"wont_fix": {
		subject: "About your Stackurity feedback {{.Ref}}",
		body: `Hello,

Thank you for your feedback {{.Ref}}.

We looked at it carefully and decided not to make this change for now:

{{.Resolution}}

If something about it is different from what we understood, reply to this email or send new feedback from Stackurity, and we will look again.

The Stackurity team
`,
	},
}

// EmailTemplates names the templates, for the preview.
func EmailTemplates() []string { return []string{"released", "wont_fix"} }

// RenderEmail renders one template. Nothing the sender wrote is quoted:
// the address they left is not verified, so the email must not carry text
// a stranger chose to someone else's inbox. Nothing is HTML.
func RenderEmail(name string, d EmailData) (Email, error) {
	t, ok := emailTemplates[name]
	if !ok {
		return Email{}, fmt.Errorf("feedback: no email template %q", name)
	}
	d.Summary = Summarise(d.Summary, 140)
	var subj, body bytes.Buffer
	if err := template.Must(template.New("s").Parse(t.subject)).Execute(&subj, d); err != nil {
		return Email{}, err
	}
	if err := template.Must(template.New("b").Parse(t.body)).Execute(&body, d); err != nil {
		return Email{}, err
	}
	return Email{Subject: strings.TrimSpace(subj.String()), Body: body.String()}, nil
}

// Summarise returns the first line of s, at most n characters.
func Summarise(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	r := []rune(s)
	if len(r) > n {
		return strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}
