package notify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits of Slack's Block Kit: a header's text, a section's text and the
// blocks in one message. Grouped messages stay well inside them by
// listing a few items with a "+N more" link, so nothing is cut off; the
// checks here only keep a malformed message from being rejected.
const (
	slackHeaderMax  = 150
	slackSectionMax = 3000
	slackBlocksMax  = 50
	// slackActionItems is how many items of one message get buttons; the
	// rest keep their links. Each takes two blocks.
	slackActionItems = 8
)

func buildEmail(from string, to []string, m Message) []byte {
	var b bytes.Buffer
	hdr := func(k, v string) {
		b.WriteString(k + ": " + strings.NewReplacer("\r", " ", "\n", " ").Replace(v) + "\r\n")
	}
	crlf := func(s string) string {
		// Normalise every line ending to CRLF; bare CR or LF is not allowed in SMTP.
		return strings.ReplaceAll(strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s), "\n", "\r\n")
	}
	hdr("From", from)
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", m.Subject())
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("MIME-Version", "1.0")
	if m.IncidentID > 0 {
		hdr("X-Stackurity-Incident", strconv.FormatInt(m.IncidentID, 10))
	}
	if m.Event != "" {
		hdr("X-Stackurity-Event", m.Event)
	}
	if len(m.Sections) == 0 {
		hdr("Content-Type", "text/plain; charset=utf-8")
		hdr("Content-Transfer-Encoding", "8bit")
		b.WriteString("\r\n")
		b.WriteString(crlf(m.Text()))
		return b.Bytes()
	}
	// Grouped messages: plain text and HTML, so every item is a link.
	text, page := crlf(m.Text()), crlf(emailHTML(m))
	sum := sha256.Sum256([]byte(text + page))
	boundary := "stackurity-" + hex.EncodeToString(sum[:12])
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	for _, part := range []struct{ typ, body string }{{"text/plain", text}, {"text/html", page}} {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + part.typ + "; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
		b.WriteString(part.body + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

func emailHTML(m Message) string {
	var b strings.Builder
	esc := html.EscapeString
	link := func(text, href string) string {
		if href == "" {
			return esc(text)
		}
		return `<a href="` + esc(href) + `">` + esc(text) + `</a>`
	}
	b.WriteString(`<!doctype html><html><body style="font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;font-size:14px;line-height:1.5;color:#1f2933">` + "\n")
	b.WriteString("<h2 style=\"font-size:17px;margin:0 0 12px\">" + link(m.Subject(), m.Link) + "</h2>\n")
	var items func([]Item)
	items = func(list []Item) {
		b.WriteString("<ul style=\"margin:4px 0 4px 18px;padding:0\">\n")
		for _, it := range list {
			b.WriteString("<li>" + link(it.Text, it.Link))
			if len(it.Actions) > 0 {
				var acts []string
				for _, a := range it.Actions {
					acts = append(acts, link(a.Label, a.Link))
				}
				b.WriteString(` <span style="white-space:nowrap">(` + strings.Join(acts, " &middot; ") + `)</span>`)
			}
			if len(it.Items) > 0 {
				items(it.Items)
			}
			b.WriteString("</li>\n")
		}
		b.WriteString("</ul>\n")
	}
	for _, s := range m.Sections {
		if s.Title != "" {
			b.WriteString("<h3 style=\"font-size:15px;margin:16px 0 4px\">" + esc(s.Title) + "</h3>\n")
		}
		items(s.Items)
	}
	b.WriteString("<p style=\"margin-top:20px;color:#52606d\">")
	if m.Link != "" {
		b.WriteString(link("Open in Stackurity", m.Link))
	}
	if m.SettingsLink != "" {
		b.WriteString(" &middot; " + link("Change these notifications", m.SettingsLink))
	}
	b.WriteString("</p>\n</body></html>\n")
	return b.String()
}

func escapeSlack(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// slackLink is a mrkdwn link; the text cannot contain the separator.
func slackLink(text, href string) string {
	t := escapeSlack(strings.ReplaceAll(text, "|", "/"))
	if href == "" {
		return t
	}
	return "<" + href + "|" + t + ">"
}

// slackPayload renders a message as Block Kit blocks at the top level of
// the message (not an attachment, which Slack folds away behind "Show
// more").
func slackPayload(m Message) map[string]any {
	// Items with actions (fixes) get URL buttons: Assign to me, Snooze,
	// Open. They open the dashboard, which asks to confirm; they work with
	// a plain incoming webhook, no Slack app needed. Each takes two more
	// blocks (its own section and the buttons), so they go to the first
	// items while the message stays inside Slack's block limit.
	plain := slackBlocks(m, 0)
	budget := min(slackActionItems, (slackBlocksMax-len(plain))/2)
	blocks := plain
	if budget > 0 {
		blocks = slackBlocks(m, budget)
	}
	return map[string]any{"text": m.Subject(), "blocks": blocks}
}

// slackBlocks renders a message, giving buttons to at most buttons items.
func slackBlocks(m Message, buttons int) []map[string]any {
	var blocks []map[string]any
	section := func(text string) {
		for _, part := range splitLines(text, slackSectionMax) {
			blocks = append(blocks, map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": part}})
		}
	}
	blocks = append(blocks, map[string]any{"type": "header",
		"text": map[string]any{"type": "plain_text", "text": shorten(m.Subject(), slackHeaderMax), "emoji": false}})
	if len(m.Sections) > 0 {
		given := 0
		for _, s := range m.Sections {
			var lines []string
			if s.Title != "" {
				lines = append(lines, "*"+escapeSlack(s.Title)+"*")
			}
			flush := func() {
				if len(lines) > 0 {
					section(strings.Join(lines, "\n"))
					lines = nil
				}
			}
			var walk func([]Item, string)
			walk = func(items []Item, indent string) {
				for _, it := range items {
					bullet := "• "
					if indent != "" {
						bullet = "◦ "
					}
					lines = append(lines, indent+bullet+slackLink(it.Text, it.Link))
					if len(it.Actions) > 0 && given < buttons {
						flush()
						blocks = append(blocks, slackButtons(it.Actions, given))
						given++
					}
					walk(it.Items, indent+"      ")
				}
			}
			walk(s.Items, "")
			flush()
		}
	} else {
		var lines []string
		for _, l := range m.Summary {
			lines = append(lines, "• "+escapeSlack(l))
		}
		if m.Action != "" {
			lines = append(lines, "*Recommended action:* "+escapeSlack(m.Action))
		}
		if len(lines) > 0 {
			section(strings.Join(lines, "\n"))
		}
	}
	var foot []string
	if m.Link != "" {
		foot = append(foot, slackLink("Open in Stackurity", m.Link))
	}
	if m.SettingsLink != "" {
		foot = append(foot, slackLink("Change these notifications", m.SettingsLink))
	}
	if len(foot) > 0 {
		if len(blocks) >= slackBlocksMax {
			blocks = blocks[:slackBlocksMax-1]
		}
		blocks = append(blocks, map[string]any{"type": "context",
			"elements": []map[string]any{{"type": "mrkdwn", "text": strings.Join(foot, "  ·  ")}}})
	}
	if len(blocks) > slackBlocksMax {
		blocks = blocks[:slackBlocksMax]
	}
	return blocks
}

// teamsPayload is an Adaptive Card message accepted by Teams Workflows
// ("Post to a channel when a webhook request is received").
func teamsPayload(m Message) map[string]any {
	attention := m.SOS || m.Priority == "P1"
	body := []map[string]any{
		{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "text": m.Subject(),
			"color": map[bool]string{true: "Attention", false: "Default"}[attention]},
	}
	text := func(s string, extra map[string]any) {
		b := map[string]any{"type": "TextBlock", "wrap": true, "spacing": "Small", "text": s}
		for k, v := range extra {
			b[k] = v
		}
		body = append(body, b)
	}
	mdLink := func(t, href string) string {
		t = strings.NewReplacer("[", "(", "]", ")").Replace(t)
		if href == "" {
			return t
		}
		return "[" + t + "](" + href + ")"
	}
	if len(m.Sections) > 0 {
		for _, s := range m.Sections {
			if s.Title != "" {
				text("**"+s.Title+"**", map[string]any{"spacing": "Medium"})
			}
			var walk func([]Item, int)
			walk = func(items []Item, depth int) {
				for _, it := range items {
					prefix := "• "
					extra := map[string]any{}
					if depth > 0 {
						prefix = strings.Repeat(" ", 4*depth) + "◦ "
						extra["isSubtle"] = true
						extra["spacing"] = "None"
					}
					line := prefix + mdLink(it.Text, it.Link)
					for _, a := range it.Actions {
						if a.Kind != "open" {
							line += " · " + mdLink(a.Label, a.Link)
						}
					}
					text(line, extra)
					walk(it.Items, depth+1)
				}
			}
			walk(s.Items, 0)
		}
	} else {
		for _, l := range m.Summary {
			text("• "+l, nil)
		}
		if m.Action != "" {
			text("**Recommended action:** "+m.Action, nil)
		}
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4", "body": body,
	}
	var actions []map[string]any
	if m.Link != "" {
		actions = append(actions, map[string]any{"type": "Action.OpenUrl", "title": "Open in Stackurity", "url": m.Link})
	}
	if m.SettingsLink != "" {
		actions = append(actions, map[string]any{"type": "Action.OpenUrl", "title": "Change these notifications", "url": m.SettingsLink})
	}
	if len(actions) > 0 {
		card["actions"] = actions
	}
	return map[string]any{
		"type":        "message",
		"attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}},
	}
}

// slackButtons is an actions block of URL buttons; n numbers the item so
// every action_id in the message is unique.
func slackButtons(actions []Action, n int) map[string]any {
	var els []map[string]any
	for _, a := range actions {
		if len(a.Link) > 3000 {
			continue
		}
		b := map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": a.Label, "emoji": false},
			"url": a.Link, "action_id": "stk-" + strconv.Itoa(n) + "-" + a.Kind}
		if a.Kind == "assign" {
			b["style"] = "primary"
		}
		els = append(els, b)
	}
	return map[string]any{"type": "actions", "elements": els}
}

// shorten cuts s to at most n characters at a word boundary.
func shorten(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)[:n-3]
	cut := string(r)
	if i := strings.LastIndexByte(cut, ' '); i > n/2 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,.:;") + "..."
}

// splitLines splits text into parts of at most n bytes, between lines.
func splitLines(text string, n int) []string {
	if len(text) <= n {
		return []string{text}
	}
	var parts []string
	var cur strings.Builder
	for _, l := range strings.Split(text, "\n") {
		if len(l) > n {
			l = shorten(l, n/2)
		}
		if cur.Len() > 0 && cur.Len()+1+len(l) > n {
			parts = append(parts, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte('\n')
		}
		cur.WriteString(l)
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}
