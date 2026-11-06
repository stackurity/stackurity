package notify

import (
	"html"
	"net/url"
	"strings"
	"sync/atomic"
)

// The layout of every email Stackurity sends, after the website and the
// dashboard (web/src/styles.css): a centred white card at most 600px wide on
// the light band, the logo mark and wordmark at the top, a heading, short
// paragraphs, one button for the main action with its link written out
// below it, and a footer that says what Stackurity is, why the email came
// and where to change or stop it. Tables and inline styles only, so Outlook
// and Gmail show it as other clients do; the <style> block only adds what
// clients that read it can use (narrow screens, dark colours). No web
// fonts and no scripts; the one image (the logo, from the installation's
// own address) has alt text, and the wordmark next to it is text, so the
// email reads the same with images blocked.

// EmailBrand is what an installation's email names in its header and
// footer. Self-hosted installations use the same templates with their own
// address.
type EmailBrand struct {
	// Product is the product name in the footer ("Stackurity" by default;
	// "Stackurity Cloud" on the hosted service).
	Product string
	// Home is the installation's dashboard address (STACKURITY_BASE_URL).
	// Empty: taken from the email's own links.
	Home string
	// PrivacyURL and SupportURL are optional footer links (https or
	// mailto).
	PrivacyURL string
	SupportURL string
}

var emailBrand atomic.Pointer[EmailBrand]

// SetEmailBrand sets the installation's EmailBrand; the server calls it once
// at start.
func SetEmailBrand(b EmailBrand) { emailBrand.Store(&b) }

// brandFor is the brand an email is rendered with.
func brandFor(m Message) EmailBrand {
	var b EmailBrand
	if p := emailBrand.Load(); p != nil {
		b = *p
	}
	if m.bulk != nil && m.bulk.home != "" && b.Home == "" {
		b.Home = m.bulk.home
	}
	if b.Home == "" {
		b.Home = originOf(m.Link, m.SettingsLink, m.oneClick, m.unsubscribe)
	}
	return b.normal()
}

func (b EmailBrand) normal() EmailBrand {
	if b.Product == "" {
		b.Product = "Stackurity"
	}
	b.Home = strings.TrimRight(b.Home, "/")
	return b
}

// originOf is the scheme and host of the first of links that has them.
func originOf(links ...string) string {
	for _, l := range links {
		u, err := url.Parse(l)
		if err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

func hostOfURL(s string) string {
	if u, err := url.Parse(s); err == nil {
		return u.Host
	}
	return ""
}

func isHTTPS(s string) bool { return strings.HasPrefix(strings.ToLower(s), "https://") }

// emailAbout is the footer's first line: what Stackurity is.
const emailAbout = "Stackurity lists the software on your servers and code, and tells you which fixes matter."

// emailWhy is the footer line saying why the email came.
func emailWhy(m Message, host string) string {
	on := ""
	if host != "" {
		on = " on " + host
	}
	switch m.Event {
	case "invitation":
		return "You received this email because someone invited this address to an organisation" + on + "."
	case "confirm_email":
		return "You received this email because an organisation" + on + " asked to send its alerts to this address."
	case "password_reset", "mfa_email_code", "mfa_email_sign_in", "mfa_changed":
		return "You received this email because it is the address of a Stackurity account" + on + "."
	case "signup":
		return "You received this email because this address was used to sign up or sign in" + on + "."
	case "ask_spend", "deletion_warning", "inactive_pause":
		return "You received this email because you are an administrator of an organisation" + on + "."
	case "community_key":
		return "You received this email because this address asked for a free Stackurity key" + on + "."
	case "trial_summary":
		return "You received this email because you are an administrator of this installation" + on + "."
	case "feedback_update":
		return "You received this email because you left this address when you sent feedback to the Stackurity team."
	}
	if m.unsubscribe != "" {
		return "You received this email because an organisation" + on + " sends its notifications to this address."
	}
	return "You received this email because this address is a recipient of a notification channel" + on + "."
}

// listStyle: the Summary lines are facts to list (alerts, digests,
// figures), not paragraphs to read.
func (m Message) listStyle() bool {
	return m.IncidentID > 0 || m.Kind != "" || m.Event == EventDigest || m.Event == "trial_summary"
}

// linkLabel is the label of the email's button.
func (m Message) linkLabel() string {
	if m.LinkLabel != "" {
		return m.LinkLabel
	}
	return "Open in Stackurity"
}

// emailSections are m's sections for email. An item that only repeats
// the heading (a single connected asset's line is also the title) is
// shown as "Details", so the body does not open with the subject.
func emailSections(m Message) []Section {
	if len(m.Sections) == 0 || len(m.Sections[0].Items) == 0 || m.Sections[0].Title != "" ||
		cleanSubject(m.Sections[0].Items[0].Text) != cleanSubject(m.Title) {
		return m.Sections
	}
	out := append([]Section(nil), m.Sections...)
	items := append([]Item(nil), out[0].Items...)
	items[0].Text = "Details"
	out[0].Items = items
	return out
}

// emailText is the text/plain part: the body, the main link, and the
// footer. The subject is not repeated: it is the email's subject.
func emailText(m Message, br EmailBrand) string {
	var b strings.Builder
	switch {
	case len(m.Sections) > 0:
		for _, s := range emailSections(m) {
			if s.Title != "" {
				b.WriteString(s.Title + "\n")
			}
			writeItems(&b, s.Items, "")
			b.WriteString("\n")
		}
	case m.listStyle():
		for _, l := range m.Summary {
			b.WriteString("- " + l + "\n")
		}
		if len(m.Summary) > 0 {
			b.WriteString("\n")
		}
	default:
		for i, l := range m.Summary {
			b.WriteString(l + "\n\n")
			if i == 0 && m.Code != "" {
				b.WriteString("    " + m.Code + "\n\n")
			}
		}
		if len(m.Summary) == 0 && m.Code != "" {
			b.WriteString("    " + m.Code + "\n\n")
		}
	}
	if m.Action != "" {
		b.WriteString("Recommended action: " + m.Action + "\n")
	}
	if m.OwnerTeam != "" {
		b.WriteString("Owner: " + m.OwnerTeam + "\n")
	}
	if m.Action != "" || m.OwnerTeam != "" {
		b.WriteString("\n")
	}
	if m.Link != "" {
		b.WriteString(m.linkLabel() + ":\n" + m.Link + "\n\n")
	}
	b.WriteString("--\n" + emailAbout + "\n" + emailWhy(m, hostOfURL(br.Home)) + "\n")
	if m.SettingsLink != "" {
		b.WriteString("Change these notifications: " + m.SettingsLink + "\n")
	}
	if m.unsubscribe != "" {
		b.WriteString(m.footerLabel() + ": " + m.unsubscribe + "\n")
	}
	if br.Home != "" {
		b.WriteString(br.Product + ": " + br.Home + "/\n")
	}
	if br.PrivacyURL != "" {
		b.WriteString("Privacy: " + br.PrivacyURL + "\n")
	}
	if br.SupportURL != "" {
		b.WriteString("Support: " + strings.TrimPrefix(br.SupportURL, "mailto:") + "\n")
	}
	return b.String()
}

// Colours of the website and dashboard; text and links keep at least
// 4.5:1 contrast in light and dark.
const (
	emailFont   = `system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif`
	emailMono   = `ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace`
	emailNavy   = "#0b1f4d"
	emailBlue   = "#0a6cf5" // buttons: white text on it is 4.6:1
	emailBand   = "#f4f6fb"
	emailBorder = "#dde3ee"
	emailInk    = "#0f1b33"
	emailInk2   = "#3d4a63"
	emailMuted  = "#5a6780"
	emailLink   = "#0758c9"
)

const emailHead = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="supported-color-schemes" content="light dark">
<style>
:root{color-scheme:light dark;supported-color-schemes:light dark}
@media (max-width:620px){.stk-pad{padding-left:20px!important;padding-right:20px!important}.stk-outer{padding:12px 6px!important}}
@media (prefers-color-scheme:dark){
.stk-bg{background:#0a1430!important}
.stk-card{background:#102049!important;border-left-color:#22356a!important;border-right-color:#22356a!important;border-bottom-color:#22356a!important}
.stk-ink{color:#e8eefc!important}
.stk-ink2{color:#c2cde6!important}
.stk-muted{color:#98a7c9!important}
.stk-code{background:#0d1a3c!important;border-color:#22356a!important;color:#e8eefc!important}
.stk-card a,.stk-foot a{color:#74b8ff!important}
.stk-card a.stk-btn{color:#ffffff!important}
}
</style>
<!--[if mso]><style>body,table,td,a,h1,h2,p,li,span{font-family:Arial,sans-serif!important}</style><![endif]-->
`

// emailShell wraps content (the card's body) and footer in the layout.
func emailShell(subject, preheader, home, content, footer string) string {
	var b strings.Builder
	esc := html.EscapeString
	w := func(s ...string) {
		for _, p := range s {
			b.WriteString(p)
		}
	}
	w("<!doctype html>\n", `<html lang="en">`, "\n<head>\n", emailHead, "<title>", esc(subject), "</title>\n</head>\n")
	w(`<body class="stk-bg" style="margin:0;padding:0;background:`, emailBand, `;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%">`, "\n")
	if preheader != "" {
		// The preheader: the line inboxes show after the subject.
		w(`<div style="display:none;max-height:0;overflow:hidden;mso-hide:all">`, esc(preheader), "</div>\n")
	}
	w(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" class="stk-bg" bgcolor="`, emailBand, `" style="background:`, emailBand, `">`)
	w(`<tr><td class="stk-outer" align="center" style="padding:32px 12px">`, "\n")
	w(`<!--[if mso]><table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0"><tr><td><![endif]-->`, "\n")
	w(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;font-family:`, emailFont, `">`, "\n")
	w(`<tr><td class="stk-card" bgcolor="#ffffff" style="background:#ffffff;border:1px solid `, emailBorder, `;border-top:4px solid `, emailBlue, `;border-radius:12px">`, "\n")
	w(`<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">`, "\n")
	w(`<tr><td class="stk-pad" style="padding:24px 32px 0;font-family:`, emailFont, `">`, emailMark(home), "</td></tr>\n")
	w(`<tr><td class="stk-pad stk-ink" style="padding:20px 32px 32px;font-family:`, emailFont, `;font-size:16px;line-height:1.6;color:`, emailInk, `">`, "\n")
	w(content)
	w("</td></tr>\n</table>\n</td></tr>\n")
	if footer != "" {
		w(`<tr><td class="stk-pad stk-foot stk-muted" style="padding:20px 32px 8px;font-family:`, emailFont, `;font-size:13px;line-height:1.6;color:`, emailMuted, `">`, "\n", footer, "</td></tr>\n")
	}
	w("</table>\n", `<!--[if mso]></td></tr></table><![endif]-->`, "\n", "</td></tr></table>\n</body>\n</html>\n")
	return b.String()
}

// emailMark is the header: the logo mark (from the installation's own
// address, so no other server learns when an email is opened) and the
// wordmark as text.
func emailMark(home string) string {
	esc := html.EscapeString
	word := `<span class="stk-ink" style="display:inline-block;vertical-align:middle;font-family:` + emailFont +
		`;font-size:19px;line-height:32px;font-weight:700;letter-spacing:-0.01em;color:` + emailNavy + `">Stackurity</span>`
	if !isHTTPS(home) {
		return word
	}
	img := `<img src="` + esc(home+"/favicon-64.png") + `" width="32" height="32" alt="Stackurity logo" style="display:inline-block;vertical-align:middle;border:0;outline:none;text-decoration:none;border-radius:8px;margin-right:10px;font-size:11px;color:` + emailMuted + `">`
	return `<a href="` + esc(home+"/") + `" style="text-decoration:none">` + img + word + `</a>`
}

// emailButton is the main action: a table cell, which Outlook draws too.
func emailButton(label, href string) string {
	esc := html.EscapeString
	return `<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="margin:28px 0 0"><tr>` +
		`<td bgcolor="` + emailBlue + `" style="background:` + emailBlue + `;border-radius:8px">` +
		`<a class="stk-btn" href="` + esc(href) + `" target="_blank" style="display:inline-block;padding:13px 26px;font-family:` + emailFont +
		`;font-size:16px;font-weight:600;line-height:1.2;color:#ffffff;text-decoration:none;border-radius:8px">` + esc(label) + "</a></td></tr></table>\n"
}

// emailFallback writes the button's link out, for clients that do not
// show the button.
func emailFallback(href string) string {
	esc := html.EscapeString
	return `<p class="stk-muted" style="margin:20px 0 0;font-size:13px;line-height:1.5;color:` + emailMuted + `">If the button doesn't work, copy this link into your browser:<br>` +
		`<a href="` + esc(href) + `" style="color:` + emailLink + `;word-break:break-all">` + esc(href) + "</a></p>\n"
}

// emailBadge is the tag above an alert's heading (P1, SOS, resolved).
func emailBadge(m Message) string {
	if accountEvents[m.Event] || m.Event == EventDigest || m.bulk != nil {
		return ""
	}
	type tag struct{ text, fg, bg string }
	var tags []tag
	if m.SOS {
		tags = append(tags, tag{"SOS", "#b4123a", "#ffe3ea"})
	}
	switch {
	case m.Event == "resolved":
		tags = append(tags, tag{"Resolved", "#157a3f", "#e5f5ec"})
	case m.Event == "escalated":
		tags = append(tags, tag{strings.TrimSpace(m.Priority + " escalated"), "#b4123a", "#ffe3ea"})
	case m.Priority == "P1":
		tags = append(tags, tag{"P1", "#b4123a", "#ffe3ea"})
	case m.Priority == "P2":
		tags = append(tags, tag{"P2", "#b33a00", "#ffe8dc"})
	case m.Priority == "P3":
		tags = append(tags, tag{"P3", "#8a5a00", "#fff3d6"})
	case m.Priority != "":
		tags = append(tags, tag{m.Priority, emailInk2, emailBand})
	}
	if len(tags) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<p style="margin:0 0 10px">`)
	for _, t := range tags {
		b.WriteString(`<span style="display:inline-block;margin-right:6px;padding:2px 10px;border-radius:999px;font-size:12px;line-height:20px;font-weight:700;letter-spacing:0.02em;color:` +
			t.fg + `;background:` + t.bg + `">` + html.EscapeString(t.text) + "</span>")
	}
	b.WriteString("</p>\n")
	return b.String()
}

// emailHTML is the text/html part.
func emailHTML(m Message, br EmailBrand) string {
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
	para := `<p style="margin:0 0 14px">`
	w(emailBadge(m))
	w(`<h1 class="stk-ink" style="margin:0 0 16px;font-size:22px;line-height:1.3;font-weight:700;color:`, emailNavy, `">`, esc(cleanSubject(m.Title)), "</h1>\n")
	var items func(list []Item, depth int)
	items = func(list []Item, depth int) {
		if depth == 0 {
			w(`<ul style="margin:0 0 12px 20px;padding:0">`, "\n")
		} else {
			w(`<ul class="stk-ink2" style="margin:4px 0 0 18px;padding:0;font-size:14px;line-height:1.5;color:`, emailInk2, `">`, "\n")
		}
		for _, it := range list {
			w(`<li style="margin:0 0 6px">`, link(it.Text, it.Link))
			var acts []string
			for _, a := range it.Actions {
				if a.Kind != "open" { // the item's own link opens it
					acts = append(acts, link(a.Label, a.Link))
				}
			}
			if len(acts) > 0 {
				w(` <span class="stk-muted" style="white-space:nowrap;font-size:13px;color:`, emailMuted, `">(`, strings.Join(acts, " &middot; "), ")</span>")
			}
			if len(it.Items) > 0 {
				items(it.Items, depth+1)
			}
			w("</li>\n")
		}
		w("</ul>\n")
	}
	switch {
	case len(m.Sections) > 0:
		for _, s := range emailSections(m) {
			if s.Title != "" {
				w(`<h2 class="stk-ink" style="margin:20px 0 8px;font-size:17px;line-height:1.35;font-weight:700;color:`, emailNavy, `">`, esc(s.Title), "</h2>\n")
			}
			items(s.Items, 0)
		}
	case m.listStyle():
		if len(m.Summary) > 0 {
			w(`<ul style="margin:0 0 14px 20px;padding:0">`, "\n")
			for _, l := range m.Summary {
				w(`<li style="margin:0 0 6px">`, esc(l), "</li>\n")
			}
			w("</ul>\n")
		}
	default:
		code := func() {
			// A short code (sign-in) large and spaced; a long one (a
			// licence key) small, wrapping anywhere.
			size := "font-size:28px;line-height:1.2;font-weight:700;letter-spacing:0.18em"
			if len(m.Code) > 16 {
				size = "font-size:13px;line-height:1.5;font-weight:400;word-break:break-all"
			}
			w(`<p style="margin:4px 0 18px"><span class="stk-code" style="display:inline-block;padding:12px 20px;font-family:`, emailMono,
				`;`, size, `;color:`, emailNavy, `;background:`, emailBand,
				`;border:1px solid `, emailBorder, `;border-radius:8px">`, esc(m.Code), "</span></p>\n")
		}
		for i, l := range m.Summary {
			w(para, esc(l), "</p>\n")
			if i == 0 && m.Code != "" {
				code()
			}
		}
		if len(m.Summary) == 0 && m.Code != "" {
			code()
		}
	}
	if m.Action != "" {
		w(para, "<strong>Recommended action:</strong> ", esc(m.Action), "</p>\n")
	}
	if m.OwnerTeam != "" {
		w(para, "<strong>Owner:</strong> ", esc(m.OwnerTeam), "</p>\n")
	}
	if webLink(m.Link) {
		w(emailButton(m.linkLabel(), m.Link), emailFallback(m.Link))
	}

	var f strings.Builder
	f.WriteString(`<p style="margin:0 0 8px">` + esc(emailAbout) + " " + esc(emailWhy(m, hostOfURL(br.Home))) + "</p>\n")
	var links []string
	if m.SettingsLink != "" {
		links = append(links, link("Change these notifications", m.SettingsLink))
	}
	if m.unsubscribe != "" {
		links = append(links, link(m.footerLabel(), m.unsubscribe))
	}
	if br.Home != "" {
		links = append(links, link(br.Product+" ("+hostOfURL(br.Home)+")", br.Home+"/"))
	}
	if br.PrivacyURL != "" {
		links = append(links, link("Privacy", br.PrivacyURL))
	}
	if br.SupportURL != "" {
		if strings.HasPrefix(br.SupportURL, "mailto:") {
			links = append(links, `<a href="`+esc(br.SupportURL)+`" style="color:`+emailLink+`;text-decoration:underline">Support</a>`)
		} else {
			links = append(links, link("Support", br.SupportURL))
		}
	}
	if len(links) > 0 {
		f.WriteString(`<p style="margin:0">` + strings.Join(links, " &middot; ") + "</p>\n")
	}
	pre := ""
	if len(m.Summary) > 0 {
		pre = m.Summary[0]
	}
	return emailShell(m.Subject(), pre, br.Home, b.String(), f.String())
}
