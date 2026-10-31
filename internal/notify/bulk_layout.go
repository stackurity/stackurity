package notify

import (
	"fmt"
	"html"
	"net/mail"
	"strings"
)

// The layout of bulk email (release notes, vulnerability news): one
// column at most 600px wide, the Stackurity wordmark as text on the
// dashboard's navy (no remote images), the content on a white card, and
// the footer below it. Tables and inline styles, so Outlook and Gmail show
// it as other clients do; a <style> block only adds what clients that read
// it can use: narrow-screen padding and dark colours. The colours are the
// dashboard's (web/src/styles.css); text and links keep at least 4.5:1
// contrast in light and dark.
const (
	bulkFont   = `system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif`
	bulkNavy   = "#0b1f4d"
	bulkCyan   = "#19c3ff"
	bulkBg     = "#f4f6fb"
	bulkBorder = "#dde3ee"
	bulkInk    = "#0f1b33"
	bulkInk2   = "#3d4a63"
	bulkMuted  = "#5a6780"
	bulkLink   = "#0758c9"
)

const bulkHead = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<style>
:root{color-scheme:light dark;supported-color-schemes:light dark}
@media (max-width:620px){.stk-pad{padding-left:16px!important;padding-right:16px!important}}
@media (prefers-color-scheme:dark){
.stk-bg{background:#070f1f!important}
.stk-card{background:#0f1a2e!important;border-color:#22345a!important}
.stk-ink{color:#e8eef9!important}
.stk-ink2{color:#bccae3!important}
.stk-muted{color:#93a4c3!important}
.stk-card a,.stk-foot a{color:#74b8ff!important}
.stk-card a.stk-btn{color:#ffffff!important}
}
</style>
<!--[if mso]><style>body,table,td,a,h1,h2,p,li{font-family:Arial,sans-serif!important}</style><![endif]-->
`

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
	b.WriteString(m.Subject() + "\n\n")
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
		label := m.LinkLabel
		if label == "" {
			label = "Read more"
		}
		b.WriteString(label + ": " + m.Link + "\n")
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

func bulkHTML(m Message) string {
	var b strings.Builder
	esc := html.EscapeString
	w := func(s ...string) {
		for _, p := range s {
			b.WriteString(p)
		}
	}
	link := func(text, href, color string) string {
		if !webLink(href) {
			return esc(text)
		}
		return `<a href="` + esc(href) + `" style="color:` + color + `;text-decoration:underline">` + esc(text) + `</a>`
	}
	f := m.bulk
	if f == nil {
		f = &bulkFooter{category: m.Event}
	}

	w("<!doctype html>\n", `<html lang="en">`, "\n<head>\n", bulkHead, "<title>", esc(m.Subject()), "</title>\n</head>\n")
	w(`<body class="stk-bg" style="margin:0;padding:0;background:`, bulkBg, `;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%">`, "\n")
	if len(m.Summary) > 0 {
		// The preheader: the line inboxes show after the subject.
		w(`<div style="display:none;max-height:0;overflow:hidden;mso-hide:all">`, esc(m.Summary[0]), "</div>\n")
	}
	w(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="stk-bg" style="background:`, bulkBg, `">`)
	w(`<tr><td align="center" style="padding:24px 12px">`, "\n")
	w(`<!--[if mso]><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->`, "\n")
	w(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;font-family:`, bulkFont, `">`, "\n")

	// Header: the wordmark, as the dashboard's sidebar shows it.
	w(`<tr><td class="stk-pad" bgcolor="`, bulkNavy, `" style="background:`, bulkNavy, `;border-bottom:3px solid `, bulkCyan, `;border-radius:8px 8px 0 0;padding:18px 32px">`)
	brand := `<span style="font-family:` + bulkFont + `;font-size:20px;line-height:28px;font-weight:700;letter-spacing:-0.01em;color:#ffffff;text-decoration:none">Stackurity</span>`
	if webLink(f.home) {
		brand = `<a href="` + esc(f.home) + `" style="text-decoration:none">` + brand + `</a>`
	}
	w(brand, "</td></tr>\n")

	// Content.
	w(`<tr><td class="stk-card stk-pad stk-ink" bgcolor="#ffffff" style="background:#ffffff;border:1px solid `, bulkBorder, `;border-top:0;border-radius:0 0 8px 8px;padding:28px 32px 32px;font-family:`, bulkFont, `;font-size:15px;line-height:1.6;color:`, bulkInk, `">`, "\n")
	w(`<h1 class="stk-ink" style="margin:0 0 16px;font-size:22px;line-height:1.3;font-weight:700;color:`, bulkNavy, `">`, esc(m.Subject()), "</h1>\n")
	for _, l := range m.Summary {
		w(`<p style="margin:0 0 12px">`, esc(l), "</p>\n")
	}
	var items func(list []Item, depth int)
	items = func(list []Item, depth int) {
		if depth == 0 {
			w(`<ul style="margin:0 0 8px 20px;padding:0">`, "\n")
		} else {
			w(`<ul class="stk-ink2" style="margin:4px 0 0 18px;padding:0;font-size:14px;line-height:1.5;color:`, bulkInk2, `">`, "\n")
		}
		for _, it := range list {
			w(`<li style="margin:0 0 6px">`, link(it.Text, it.Link, bulkLink))
			if len(it.Items) > 0 {
				items(it.Items, depth+1)
			}
			w("</li>\n")
		}
		w("</ul>\n")
	}
	for _, s := range m.Sections {
		if s.Title != "" {
			w(`<h2 class="stk-ink" style="margin:24px 0 8px;font-size:17px;line-height:1.35;font-weight:700;color:`, bulkNavy, `">`, esc(s.Title), "</h2>\n")
		}
		items(s.Items, 0)
	}
	if webLink(m.Link) {
		label := m.LinkLabel
		if label == "" {
			label = "Read more"
		}
		// A button made of a table cell, which Outlook draws too.
		w(`<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:24px 0 0"><tr>`)
		w(`<td bgcolor="`, bulkLink, `" style="background:`, bulkLink, `;border-radius:6px">`)
		w(`<a class="stk-btn" href="`, esc(m.Link), `" style="display:inline-block;padding:11px 22px;font-family:`, bulkFont, `;font-size:15px;font-weight:600;line-height:1.2;color:#ffffff;text-decoration:none;border-radius:6px">`, esc(label), "</a>")
		w("</td></tr></table>\n")
	}
	w("</td></tr>\n")

	// Footer.
	if m.bulk != nil {
		w(`<tr><td class="stk-pad stk-foot stk-muted" style="padding:20px 32px;font-family:`, bulkFont, `;font-size:12px;line-height:1.6;color:`, bulkMuted, `">`, "\n")
		w(`<p style="margin:0 0 8px">`, esc(bulkWhy(f)), "</p>\n")
		w(`<p style="margin:0 0 8px">`, link("Unsubscribe from "+BulkCategoryLabel(f.category), f.unsubscribe, bulkLink), " &middot; ",
			link("Manage email preferences", f.preferences, bulkLink), "</p>\n")
		if s := bulkSender(f.sender); s != "" {
			w(`<p style="margin:0">`, esc(s), "</p>\n")
		}
		if f.postalAddress != "" {
			w(`<p style="margin:0">`, esc(f.postalAddress), "</p>\n")
		}
		w("</td></tr>\n")
	}
	w("</table>\n", `<!--[if mso]></td></tr></table><![endif]-->`, "\n", "</td></tr></table>\n</body>\n</html>\n")
	return b.String()
}
