package notify

import (
	"fmt"
	"html"
	"net/mail"
	"strings"
)

// The layout of bulk email (release notes, vulnerability news) is the one
// of every email (email_layout.go), with the bulk footer: why the person
// gets it, the links to unsubscribe from its category and to the
// preference page, the sender and the postal address.

// bulkWhy is the footer's first line.
func bulkWhy(f *bulkFooter) string {
	return fmt.Sprintf("You are receiving this because you are subscribed to %s emails from Stackurity.", BulkCategoryLabel(f.category))
}

// bulkSender is the footer's sender line: "Sent by Stackurity
// (news@stackurity.dev)".
func bulkSender(from string) string {
	if from == "" {
		return ""
	}
	a, err := mail.ParseAddress(from)
	switch {
	case err != nil:
		return "Sent by " + from
	case a.Name == "":
		return "Sent by " + a.Address
	}
	return "Sent by " + a.Name + " (" + a.Address + ")"
}

// webLink: only http and https links are made links in bulk email.
func webLink(href string) bool {
	h := strings.ToLower(href)
	return strings.HasPrefix(h, "https://") || strings.HasPrefix(h, "http://")
}

func bulkText(m Message) string {
	var b strings.Builder
	for _, l := range m.Summary {
		b.WriteString(l + "\n\n")
	}
	for _, s := range m.Sections {
		if s.Title != "" {
			b.WriteString(s.Title + "\n")
		}
		writeItems(&b, s.Items, "")
		b.WriteString("\n")
	}
	if m.Link != "" {
		b.WriteString(bulkLinkLabel(m) + ":\n" + m.Link + "\n")
	}
	if f := m.bulk; f != nil {
		b.WriteString("\n--\n" + bulkWhy(f) + "\n")
		b.WriteString("Unsubscribe from " + BulkCategoryLabel(f.category) + ": " + f.unsubscribe + "\n")
		b.WriteString("Manage email preferences: " + f.preferences + "\n")
		if s := bulkSender(f.sender); s != "" {
			b.WriteString(s + "\n")
		}
		if f.postalAddress != "" {
			b.WriteString(f.postalAddress + "\n")
		}
	}
	return b.String()
}

func bulkLinkLabel(m Message) string {
	if m.LinkLabel != "" {
		return m.LinkLabel
	}
	return "Read more"
}

func bulkHTML(m Message) string {
	var b strings.Builder
	esc := html.EscapeString
	w := func(s ...string) {
		for _, p := range s {
			b.WriteString(p)
		}
	}
	link := func(text, href string) string {
		if !webLink(href) {
			return esc(text)
		}
		return `<a href="` + esc(href) + `" style="color:` + emailLink + `;text-decoration:underline">` + esc(text) + `</a>`
	}
	f := m.bulk
	if f == nil {
		f = &bulkFooter{category: m.Event}
	}
	w(`<h1 class="stk-ink" style="margin:0 0 16px;font-size:22px;line-height:1.3;font-weight:700;color:`, emailNavy, `">`, esc(cleanSubject(m.Title)), "</h1>\n")
	for _, l := range m.Summary {
		w(`<p style="margin:0 0 14px">`, esc(l), "</p>\n")
	}
	var items func(list []Item, depth int)
	items = func(list []Item, depth int) {
		if depth == 0 {
			w(`<ul style="margin:0 0 8px 20px;padding:0">`, "\n")
		} else {
			w(`<ul class="stk-ink2" style="margin:4px 0 0 18px;padding:0;font-size:14px;line-height:1.5;color:`, emailInk2, `">`, "\n")
		}
		for _, it := range list {
			w(`<li style="margin:0 0 6px">`, link(it.Text, it.Link))
			if len(it.Items) > 0 {
				items(it.Items, depth+1)
			}
			w("</li>\n")
		}
		w("</ul>\n")
	}
	for _, s := range m.Sections {
		if s.Title != "" {
			w(`<h2 class="stk-ink" style="margin:24px 0 8px;font-size:17px;line-height:1.35;font-weight:700;color:`, emailNavy, `">`, esc(s.Title), "</h2>\n")
		}
		items(s.Items, 0)
	}
	if webLink(m.Link) {
		w(emailButton(bulkLinkLabel(m), m.Link), emailFallback(m.Link))
	}
	var foot strings.Builder
	if m.bulk != nil {
		foot.WriteString(`<p style="margin:0 0 8px">` + esc(emailAbout) + " " + esc(bulkWhy(f)) + "</p>\n")
		foot.WriteString(`<p style="margin:0 0 8px">` + link("Unsubscribe from "+BulkCategoryLabel(f.category), f.unsubscribe) + " &middot; " +
			link("Manage email preferences", f.preferences) + "</p>\n")
		if s := bulkSender(f.sender); s != "" {
			foot.WriteString(`<p style="margin:0">` + esc(s) + "</p>\n")
		}
		if f.postalAddress != "" {
			foot.WriteString(`<p style="margin:0">` + esc(f.postalAddress) + "</p>\n")
		}
	}
	pre := ""
	if len(m.Summary) > 0 {
		pre = m.Summary[0]
	}
	return emailShell(m.Subject(), pre, strings.TrimRight(f.home, "/"), b.String(), foot.String())
}
