package notify

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"mime/quotedprintable"
	"net/mail"
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

// emailSubjectMax is the longest subject an email gets; inboxes cut
// longer ones anyway.
const emailSubjectMax = 98

// buildEmail renders m as an email: headers, then a multipart/alternative
// body with a text/plain and a text/html part, both quoted-printable (no
// line is ever too long for SMTP).
func buildEmail(from string, to []string, m Message) []byte {
	return renderEmail(from, to, m, brandFor(m), time.Now())
}

// RenderEmail is the email m would be sent as, for previews and for the
// checks of email built elsewhere (CheckEmail).
func RenderEmail(from string, to []string, m Message) []byte { return buildEmail(from, to, m) }

func renderEmail(from string, to []string, m Message, br EmailBrand, now time.Time) []byte {
	var b bytes.Buffer
	hdr := func(k, v string) {
		b.WriteString(k + ": " + strings.NewReplacer("\r", " ", "\n", " ").Replace(v) + "\r\n")
	}
	crlf := func(s string) string {
		// Normalise every line ending to LF; the encoder writes CRLF.
		return strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(s)
	}
	hdr("From", headerAddress(from))
	hdr("To", strings.Join(to, ", "))
	if cc := headerAddresses(m.Cc); cc != "" {
		hdr("Cc", cc)
	}
	if rt := headerAddresses([]string{m.ReplyTo}); rt != "" {
		hdr("Reply-To", rt)
	}
	hdr("Subject", mime.QEncoding.Encode("utf-8", shorten(m.Subject(), emailSubjectMax)))
	hdr("Date", now.Format(time.RFC1123Z))
	hdr("Message-ID", messageID(from))
	hdr("MIME-Version", "1.0")
	if m.IncidentID > 0 {
		hdr("X-Stackurity-Incident", strconv.FormatInt(m.IncidentID, 10))
	}
	if m.Event != "" {
		hdr("X-Stackurity-Event", m.Event)
	}
	if m.oneClick != "" {
		// One-click unsubscribe (RFC 8058): mail clients POST to it.
		hdr("List-Unsubscribe", "<"+m.oneClick+">")
		hdr("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
	}
	if m.bulk != nil {
		hdr("X-Stackurity-Category", m.bulk.category)
		hdr("Precedence", "bulk")
		hdr("Auto-Submitted", "auto-generated")
	}
	text, page := emailText(m, br), emailHTML(m, br)
	if m.bulk != nil {
		text, page = bulkText(m), bulkHTML(m)
	}
	text, page = qp(crlf(text)), qp(crlf(page))
	sum := sha256.Sum256([]byte(text + page))
	boundary := "stackurity-" + hex.EncodeToString(sum[:12])
	hdr("Content-Type", `multipart/alternative; boundary="`+boundary+`"`)
	b.WriteString("\r\n")
	for _, part := range []struct{ typ, body string }{{"text/plain", text}, {"text/html", page}} {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + part.typ + "; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
		b.WriteString(part.body + "\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.Bytes()
}

// qp encodes s as quoted-printable with CRLF line endings.
func qp(s string) string {
	var b bytes.Buffer
	w := quotedprintable.NewWriter(&b)
	_, _ = w.Write([]byte(s))
	_ = w.Close()
	return b.String()
}

// headerAddress is a From value for the header: a display name is kept
// (and encoded when it is not ASCII); the envelope sender is the bare
// address (envelopeAddress).
func headerAddress(from string) string {
	a, err := mail.ParseAddress(from)
	if err != nil {
		return from
	}
	if a.Name == "" {
		return a.Address
	}
	return a.String()
}

// headerAddresses is a Cc or Reply-To value: the addresses that parse,
// display names kept (encoded when not ASCII), others left out (sending
// refuses them first: emailExtras).
func headerAddresses(list []string) string {
	var out []string
	for _, a := range list {
		if _, err := mail.ParseAddress(a); err == nil && !strings.ContainsAny(a, "\r\n") {
			out = append(out, headerAddress(a))
		}
	}
	return strings.Join(out, ", ")
}

// messageID is a new Message-ID on the sender's domain.
func messageID(from string) string {
	domain := "stackurity.invalid"
	if a, err := mail.ParseAddress(from); err == nil {
		if _, d, ok := strings.Cut(a.Address, "@"); ok && d != "" {
			domain = d
		}
	}
	var r [16]byte
	_, _ = rand.Read(r[:])
	return "<" + hex.EncodeToString(r[:]) + "@" + domain + ">"
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
func slackPayload(m Message) map[string]any { return slackPayloadFor(m, 0) }

// slackPayloadFor renders a message for a Slack channel. channel is the
// channel's id when it is set up with a Slack app's signing secret (0:
// not): Assign to me and Snooze are then interactive buttons that act from
// inside Slack, handled by POST /api/v1/integrations/slack/actions.
func slackPayloadFor(m Message, channel int64) map[string]any {
	// Items with actions (fixes) get buttons: Assign to me, Snooze, Open.
	// Without a Slack app they are URL buttons that open the dashboard,
	// which asks to confirm; they work with a plain incoming webhook. Each
	// takes two more blocks (its own section and the buttons), so they go
	// to the first items while the message stays inside Slack's block
	// limit.
	plain := slackBlocks(m, 0, channel)
	budget := min(slackActionItems, (slackBlocksMax-len(plain))/2)
	blocks := plain
	if budget > 0 {
		blocks = slackBlocks(m, budget, channel)
	}
	return map[string]any{"text": m.Subject(), "blocks": blocks}
}

// slackBlocks renders a message, giving buttons to at most buttons items.
func slackBlocks(m Message, buttons int, channel int64) []map[string]any {
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
						blocks = append(blocks, slackButtons(it.Actions, given, channel))
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

// slackButtons is an actions block of buttons; n numbers the item so
// every block_id and action_id in the message is unique. Without a channel
// they are URL buttons. With one (a Slack app is set up), Assign to me and
// Snooze are interactive and Open stays a URL button; each carries a value
// naming the channel, the action and the fix, which the interactivity
// endpoint reads after checking the request's signature with that
// channel's signing secret.
func slackButtons(actions []Action, n int, channel int64) map[string]any {
	var els []map[string]any
	for _, a := range actions {
		if len(a.Link) > 3000 {
			continue
		}
		label := a.Label
		value := ""
		if channel > 0 && a.Fix != "" {
			value = SlackActionValue(channel, a.Kind, a.Fix)
			if len(value) > slackValueMax {
				value = ""
			}
		}
		interactive := value != "" && a.Kind != "open"
		if interactive && a.Kind == "snooze" {
			label = "Snooze 1 week"
		}
		b := map[string]any{"type": "button", "text": map[string]any{"type": "plain_text", "text": label, "emoji": false},
			"action_id": "stk-" + strconv.Itoa(n) + "-" + a.Kind}
		if !interactive {
			b["url"] = a.Link
		}
		if value != "" {
			// Slack also reports clicks on URL buttons of an app's message;
			// the value lets the endpoint verify and ignore them.
			b["value"] = value
		}
		if a.Kind == "assign" {
			b["style"] = "primary"
		}
		els = append(els, b)
	}
	block := map[string]any{"type": "actions", "elements": els}
	if channel > 0 {
		// The endpoint puts what was done under the clicked buttons.
		block["block_id"] = "stk-" + strconv.Itoa(n)
	}
	return block
}

// slackValueMax is the longest value Slack accepts on a button.
const slackValueMax = 2000

// SlackActionValue is the value of an interactive button: a version, the
// channel whose signing secret must verify the click, the action and the
// fix.
func SlackActionValue(channel int64, kind, fix string) string {
	return "stk1|" + strconv.FormatInt(channel, 10) + "|" + kind + "|" + fix
}

// ParseSlackActionValue reads a button's value; ok is false for anything
// that is not one.
func ParseSlackActionValue(v string) (channel int64, kind, fix string, ok bool) {
	parts := strings.SplitN(v, "|", 4)
	if len(parts) != 4 || parts[0] != "stk1" || parts[3] == "" || len(v) > slackValueMax {
		return 0, "", "", false
	}
	channel, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || channel <= 0 {
		return 0, "", "", false
	}
	switch parts[2] {
	case "assign", "snooze", "open":
	default:
		return 0, "", "", false
	}
	return channel, parts[2], parts[3], true
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
