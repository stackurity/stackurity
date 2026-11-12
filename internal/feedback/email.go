package feedback

import (
	"bytes"
	"fmt"
	"regexp"
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
	Summary    string // what they wrote; not put in the released and won't-fix emails (see RenderEmail)
	Resolution string // the team's note (required for won't fix)
	Version    string // the release that has the change
	// For the feedback agent's emails (received, needs_info), which are
	// sent only with STACKURITY_FEEDBACK_AGENT_EMAILS=on once the owner has
	// approved their wording.
	Source      string // cloud, self_hosted or website: where they can answer
	Attachments int    // how many files they attached
	Questions   string // needs_info: what the agent or the team asks
	Link        string // needs_info on Stackurity Cloud: My feedback
	Quote       string // received: what they sent, shortened and defanged (set by RenderEmail from Summary)
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

{{if .Version}}The change is in Stackurity {{.Version}}.{{else}}The change has been released.{{end}}{{if .Resolution}}

{{.Resolution}}{{end}}

On Stackurity Cloud you have it already. If you run Stackurity yourself, it arrives when you upgrade; the changelog is at https://stackurity.ai/changelog.html.

You can see this and anything else you sent under My feedback, in your account menu in Stackurity.

The Stackurity team
`,
	},
	"wont_fix": {
		subject: "About your Stackurity feedback {{.Ref}}",
		body: `Hello,

Thank you for your feedback {{.Ref}}.

We looked at it carefully and decided not to make this change for now:

{{.Resolution}}

If something about it is different from what we understood, send new feedback from Stackurity or write to info@stackurity.ai, and we will look again.

The Stackurity team
`,
	},
}

// agentEmailTemplates are the feedback agent's emails. Their wording is
// NOT approved yet: they are sent only with STACKURITY_FEEDBACK_AGENT_EMAILS=on,
// which stays off until the owner approves them in the preview.
var agentEmailTemplates = map[string]struct{ subject, body string }{
	"received": {
		subject: "We received your Stackurity feedback {{.Ref}}",
		body: `Hello,

Thank you for your feedback {{.Ref}}. It is with the Stackurity team now. We will email you when it is done, or if we need more details from you.

You sent:

{{.Quote}}{{if .Attachments}}

With {{.Attachments}} attachment{{if gt .Attachments 1}}s{{end}}.{{end}}

{{if eq .Source "website"}}If you want to add something, write to info@stackurity.ai and mention {{.Ref}}.{{else}}You can follow it under My feedback, in your account menu in Stackurity.{{end}}

The Stackurity team
`,
	},
	"needs_info": {
		subject: "Your Stackurity feedback {{.Ref}}: a few questions",
		body: `Hello,

Thank you for your feedback {{.Ref}}. To work on it, we need a few more details:

{{.Questions}}

{{if .Link}}Please answer under My feedback (the button below).{{else if eq .Source "website"}}Please write your answer to info@stackurity.ai and mention {{.Ref}}.{{else}}Please answer under My feedback, in your account menu in Stackurity.{{end}}

The Stackurity team
`,
	},
}

// EmailTemplates names the templates, for the preview.
func EmailTemplates() []string { return []string{"released", "wont_fix", "received", "needs_info"} }

// EmailApproved reports whether the owner approved a template's wording
// (released and won't fix, 6 November 2026). The others wait for approval.
func EmailApproved(name string) bool { return name == "released" || name == "wont_fix" }

var (
	defangDomain = regexp.MustCompile(`([A-Za-z0-9-])\.([A-Za-z]{2,})`)
	defangScheme = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*)://`)
)

// QuoteMax is how much of what the sender wrote the received email quotes.
const QuoteMax = 600

// Defang makes text a stranger chose safe to quote in an email: links and
// addresses stop being clickable ("example[.]com", "hxxps", "[at]") and it
// is cut to n characters.
func Defang(s string, n int) string {
	s = strings.TrimSpace(strings.ToValidUTF8(s, ""))
	if r := []rune(s); len(r) > n {
		s = strings.TrimSpace(string(r[:n-1])) + "…"
	}
	s = defangScheme.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Replace(strings.Replace(strings.ToLower(m), "http", "hxxp", 1), "://", "[:]//", 1)
	})
	s = strings.ReplaceAll(s, "@", " [at] ")
	for i := 0; i < 3; i++ { // overlapping matches (a.b.c)
		s = defangDomain.ReplaceAllString(s, "$1[.]$2")
	}
	return s
}

// RenderEmail renders one template. The released and won't-fix emails
// quote nothing the sender wrote: the address they left is not verified, so
// the email must not carry text a stranger chose to someone else's inbox.
// The received email (not approved yet) quotes it shortened to QuoteMax
// characters with links and addresses defanged. Nothing is HTML.
func RenderEmail(name string, d EmailData) (Email, error) {
	t, ok := emailTemplates[name]
	if !ok {
		t, ok = agentEmailTemplates[name]
	}
	if !ok {
		return Email{}, fmt.Errorf("feedback: no email template %q", name)
	}
	if name == "received" {
		d.Quote = Defang(d.Summary, QuoteMax)
	} else {
		d.Quote = ""
	}
	// The questions are the agent's words, but it read the sender's text
	// to write them.
	d.Questions = Defang(d.Questions, 2000)
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
