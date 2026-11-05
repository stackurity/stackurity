package notify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// The checks every email passes before it can ship (email_test.go runs
// them on a sample of every kind of email, and the pro repository on its
// own). CheckEmail lists what is wrong with one rendered email; nothing
// means it is fine.

// EmailExternalHosts are the only hosts outside the installation an email
// may link to: the project's website and code, and the sources the
// vulnerability news cites (docs/install.md, "How email looks").
var EmailExternalHosts = []string{
	"stackurity.ai", "www.stackurity.ai", "github.com",
	"nvd.nist.gov", "www.cisa.gov", "www.first.org", "api.first.org", "endoflife.date",
}

// EmailCheck is what CheckEmail expects of an email.
type EmailCheck struct {
	// Base is the installation's address: every link is on it or on one
	// of EmailExternalHosts.
	Base string
	// FromName is the display name the From header must have ("" none
	// expected).
	FromName string
	// Notification: an organisation's notification (or bulk) email, which
	// must have one-click unsubscribe headers (RFC 8058).
	Notification bool
	// Secrets must not be in the subject: tokens, codes, IP addresses.
	Secrets []string
}

// EmailSubjectMax is the longest subject CheckEmail accepts (in
// characters, exclusive).
const EmailSubjectMax = 100

var (
	subjectIPv4  = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	subjectIPv6  = regexp.MustCompile(`\b[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{0,4}){3,7}\b`)
	subjectToken = regexp.MustCompile(`[A-Za-z0-9_\-]{24,}`)
	textURL      = regexp.MustCompile(`https?://[^\s<>"]+`)
	messageIDRE  = regexp.MustCompile(`^<[^<>@\s]+@[^<>@\s]+>$`)
	placeholders = []string{"{{", "}}", "%!", "<nil>", "<no value>", "[]", "()"}
)

// CheckSubject lists what is wrong with a subject line.
func CheckSubject(s string, secrets []string) []string {
	var p []string
	if strings.TrimSpace(s) == "" {
		return []string{"subject is empty"}
	}
	for _, bad := range placeholders {
		if strings.Contains(s, bad) {
			p = append(p, fmt.Sprintf("subject %q contains %q", s, bad))
		}
	}
	if strings.Contains(s, "[ ]") || strings.Contains(s, "( )") {
		p = append(p, fmt.Sprintf("subject %q has an empty tag", s))
	}
	if strings.Contains(s, "  ") || strings.ContainsAny(s, "\r\n\t") {
		p = append(p, fmt.Sprintf("subject %q has double spaces or line breaks", s))
	}
	if t := strings.Trim(s, " -–—:|·,;/"); t != s {
		p = append(p, fmt.Sprintf("subject %q starts or ends with a separator or space", s))
	}
	if n := utf8.RuneCountInString(s); n >= EmailSubjectMax {
		p = append(p, fmt.Sprintf("subject is %d characters (at most %d)", n, EmailSubjectMax-1))
	}
	for _, sec := range secrets {
		if sec != "" && strings.Contains(s, sec) {
			p = append(p, fmt.Sprintf("subject %q contains the secret %q", s, sec))
		}
	}
	if subjectIPv4.MatchString(s) || subjectIPv6.MatchString(s) {
		p = append(p, fmt.Sprintf("subject %q contains an IP address", s))
	}
	for _, w := range subjectToken.FindAllString(s, -1) {
		// A token mixes digits and both cases; a long asset name does not.
		if strings.ContainsAny(w, "0123456789") && strings.ToLower(w) != w && strings.ToUpper(w) != w {
			p = append(p, fmt.Sprintf("subject %q contains something like a token (%s)", s, w))
		}
	}
	return p
}

// CheckEmail lists what is wrong with raw, the email m was rendered as.
func CheckEmail(raw []byte, m Message, c EmailCheck) []string {
	var p []string
	bad := func(f string, a ...any) { p = append(p, fmt.Sprintf(f, a...)) }
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return []string{"not an email: " + err.Error()}
	}
	h := msg.Header
	for _, k := range []string{"From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"} {
		if h.Get(k) == "" {
			bad("no %s header", k)
		}
	}
	if _, err := mail.ParseDate(h.Get("Date")); err != nil {
		bad("Date header %q: %v", h.Get("Date"), err)
	}
	if !messageIDRE.MatchString(h.Get("Message-ID")) {
		bad("Message-ID %q is not <id@domain>", h.Get("Message-ID"))
	}
	if h.Get("MIME-Version") != "1.0" {
		bad("MIME-Version %q", h.Get("MIME-Version"))
	}
	subject, err := new(mime.WordDecoder).DecodeHeader(h.Get("Subject"))
	if err != nil {
		bad("Subject header %q: %v", h.Get("Subject"), err)
	}
	p = append(p, CheckSubject(subject, c.Secrets)...)
	if from, err := mail.ParseAddress(h.Get("From")); err != nil {
		bad("From %q: %v", h.Get("From"), err)
	} else if c.FromName != "" && from.Name != c.FromName {
		bad("From %q: display name %q, want %q", h.Get("From"), from.Name, c.FromName)
	}
	if c.Notification {
		if lu := h.Get("List-Unsubscribe"); !strings.HasPrefix(lu, "<https://") || !strings.HasSuffix(lu, ">") {
			bad("List-Unsubscribe %q, want <https://…>", lu)
		} else {
			checkLink(strings.Trim(lu, "<>"), c.Base, bad)
		}
		if h.Get("List-Unsubscribe-Post") != "List-Unsubscribe=One-Click" {
			bad("List-Unsubscribe-Post %q", h.Get("List-Unsubscribe-Post"))
		}
	}

	mt, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		return append(p, fmt.Sprintf("Content-Type %q, want multipart/alternative", h.Get("Content-Type")))
	}
	parts := map[string]string{}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return append(p, "multipart: "+err.Error())
		}
		pt, pp, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			bad("part Content-Type %q: %v", part.Header.Get("Content-Type"), err)
			continue
		}
		if !strings.EqualFold(pp["charset"], "utf-8") {
			bad("%s part has charset %q, want utf-8", pt, pp["charset"])
		}
		body, _ := io.ReadAll(part)
		parts[pt] = string(body)
	}
	text, okText := parts["text/plain"]
	page, okHTML := parts["text/html"]
	if !okText || !okHTML {
		return append(p, fmt.Sprintf("parts %v, want text/plain and text/html", keys(parts)))
	}
	if !utf8.ValidString(text) || !utf8.ValidString(page) {
		bad("a part is not valid UTF-8")
	}
	for _, ph := range []string{"{{", "%!", "<nil>", "<no value>"} {
		if strings.Contains(text, ph) || strings.Contains(page, ph) {
			bad("the body contains the placeholder %q", ph)
		}
	}

	// The text part: does not open with the subject; its links.
	first := ""
	for _, l := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(l) != "" {
			first = strings.TrimSpace(l)
			break
		}
	}
	if first == subject || strings.TrimLeft(first, "•-* ") == subject {
		bad("the text part repeats the subject as its first line")
	}
	for _, l := range textURL.FindAllString(text, -1) {
		checkLink(strings.TrimRight(l, ".,;:)"), c.Base, bad)
	}

	checkEmailHTML(page, text, m, c, bad)
	return p
}

// checkEmailHTML checks the HTML part.
func checkEmailHTML(page, text string, m Message, c EmailCheck, bad func(string, ...any)) {
	// The HTML part: it parses, has no scripts or outside style sheets,
	// every image has alt text, every link is allowed, and the main
	// action is one button whose link is also in the text.
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		bad("HTML does not parse: %v", err)
		return
	}
	var buttons []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			attr := func(k string) (string, bool) {
				for _, a := range n.Attr {
					if a.Key == k {
						return a.Val, true
					}
				}
				return "", false
			}
			switch n.Data {
			case "script", "iframe", "form", "object", "embed":
				bad("HTML has a <%s>", n.Data)
			case "link":
				bad("HTML loads an outside resource (<link>)")
			case "a":
				href, _ := attr("href")
				switch {
				case strings.HasPrefix(href, "mailto:"):
				default:
					checkLink(href, c.Base, bad)
				}
				if cls, _ := attr("class"); strings.Contains(" "+cls+" ", " stk-btn ") {
					buttons = append(buttons, href)
				}
			case "img":
				src, _ := attr("src")
				checkLink(src, c.Base, bad)
				if alt, ok := attr("alt"); !ok || strings.TrimSpace(alt) == "" {
					bad("image %q has no alt text", src)
				}
			case "style":
				if n.FirstChild != nil && strings.Contains(n.FirstChild.Data, "@import") {
					bad("HTML style imports an outside style sheet")
				}
			}
		}
		for ch := n.FirstChild; ch != nil; ch = ch.NextSibling {
			walk(ch)
		}
	}
	walk(doc)
	switch {
	case m.Link == "" && len(buttons) > 0:
		bad("buttons %v, but the message has no link", buttons)
	case m.Link != "" && len(buttons) != 1:
		bad("%d buttons, want one, to %s", len(buttons), m.Link)
	case m.Link != "" && buttons[0] != m.Link:
		bad("the button links to %s, want %s", buttons[0], m.Link)
	case m.Link != "" && !strings.Contains(text, m.Link):
		bad("the text part lacks the button's link %s", m.Link)
	}
	if m.Link != "" && !strings.Contains(page, "If the button doesn't work") {
		bad("the HTML lacks the button's link written out")
	}
}

// checkLink: absolute https, on the installation or an allowed outside
// host, never a local or example address.
func checkLink(link, base string, bad func(string, ...any)) {
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		bad("link %q is not an absolute https link", link)
		return
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasPrefix(host, "127.") || host == "::1" ||
		host == "example.com" || strings.HasSuffix(host, ".example.com") || strings.HasSuffix(host, ".example") ||
		strings.HasSuffix(host, ".test") || strings.HasSuffix(host, ".invalid") || strings.HasSuffix(host, ".localhost") {
		bad("link %q is on a local or example host", link)
		return
	}
	if b, err := url.Parse(base); err == nil && b.Host != "" && strings.EqualFold(b.Host, u.Host) {
		return
	}
	for _, h := range EmailExternalHosts {
		if host == h {
			return
		}
	}
	bad("link %q is neither on %s nor on an allowed outside host", link, base)
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
