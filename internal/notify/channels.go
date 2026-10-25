// Package notify routes incidents to channels (email, Slack, Microsoft
// Teams, webhooks) with deduplication, quiet hours, rate limits, retries and
// escalation (FR-08, FR-09).
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stackurity/stackurity/internal/netguard"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Message is what every channel renders.
type Message struct {
	Event      string         `json:"event"` // opened, priority_raised, escalated, resolved, digest, test
	IncidentID int64          `json:"incident_id,omitempty"`
	Kind       string         `json:"kind,omitempty"`
	Key        string         `json:"key,omitempty"`
	Title      string         `json:"title"`
	Priority   string         `json:"priority,omitempty"`
	SOS        bool           `json:"sos"`
	Status     string         `json:"status,omitempty"`
	OwnerTeam  string         `json:"owner_team,omitempty"`
	Findings   int            `json:"finding_count,omitempty"`
	Assets     int            `json:"asset_count,omitempty"`
	Summary    []string       `json:"summary"` // short lines: assets, fix, exploitation
	Action     string         `json:"recommended_action,omitempty"`
	Link       string         `json:"link,omitempty"`
	Escalation int            `json:"escalation_level,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	At         time.Time      `json:"at"`
}

func (m Message) Subject() string {
	prefix := ""
	if m.SOS {
		prefix = "[SOS] "
	}
	switch m.Event {
	case "resolved":
		return fmt.Sprintf("%s[resolved] %s", prefix, m.Title)
	case "escalated":
		return fmt.Sprintf("%s[%s escalated] %s", prefix, m.Priority, m.Title)
	case "digest", "test":
		return m.Title
	}
	return fmt.Sprintf("%s[%s] %s", prefix, m.Priority, m.Title)
}

func (m Message) Text() string {
	var b strings.Builder
	b.WriteString(m.Subject() + "\n\n")
	for _, l := range m.Summary {
		b.WriteString("• " + l + "\n")
	}
	if m.Action != "" {
		b.WriteString("\nRecommended action: " + m.Action + "\n")
	}
	if m.OwnerTeam != "" {
		b.WriteString("Owner: " + m.OwnerTeam + "\n")
	}
	if m.Link != "" {
		b.WriteString("\n" + m.Link + "\n")
	}
	return b.String()
}

// Channel kinds.
const (
	KindEmail   = "email"
	KindSlack   = "slack"
	KindTeams   = "teams"
	KindWebhook = "webhook"
)

// ChannelConfig is the non-secret part of a channel. Secrets (SMTP password,
// Slack/Teams webhook URL, webhook HMAC key) come from a secret reference.
type ChannelConfig struct {
	// email
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Username string   `json:"username,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	TLS      string   `json:"tls,omitempty"` // starttls (default), tls, none
	// webhook
	URL string `json:"url,omitempty"`
}

// ValidateChannel checks configuration before it is stored.
func ValidateChannel(kind string, c ChannelConfig, hasSecret, allowHTTP bool) error {
	switch kind {
	case KindEmail:
		if c.Host == "" || c.Port <= 0 || c.Port > 65535 {
			return errors.New("email needs host and port")
		}
		if _, err := mail.ParseAddress(c.From); err != nil {
			return errors.New("email needs a valid from address")
		}
		if len(c.To) == 0 || len(c.To) > 50 {
			return errors.New("email needs 1-50 recipients")
		}
		for _, t := range c.To {
			if _, err := mail.ParseAddress(t); err != nil {
				return fmt.Errorf("invalid recipient %q", t)
			}
		}
		switch c.TLS {
		case "", "starttls", "tls", "none":
		default:
			return errors.New("tls must be starttls, tls or none")
		}
	case KindSlack, KindTeams:
		if !hasSecret {
			return errors.New("set secret_ref to the incoming webhook URL (it is a credential)")
		}
	case KindWebhook:
		if err := checkURL(c.URL, allowHTTP); err != nil {
			return err
		}
	default:
		return errors.New("kind must be email, slack, teams or webhook")
	}
	return nil
}

func checkURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("a valid URL is required")
	}
	if u.User != nil {
		return errors.New("do not put credentials in the URL; use secret_ref")
	}
	if u.Scheme != "https" && !(allowHTTP && u.Scheme == "http") {
		return errors.New("webhook URLs must use https (set STACKURITY_ALLOW_HTTP_WEBHOOKS=true to allow http)")
	}
	return nil
}

// Sender delivers messages.
type Sender struct {
	HTTP      *http.Client
	AllowHTTP bool
	Dial      func(ctx context.Context, network, addr string) (net.Conn, error)
}

func NewSender(allowHTTP bool) *Sender {
	return &Sender{
		AllowHTTP: allowHTTP,
		HTTP: &http.Client{
			Timeout: 15 * time.Second,
			// Connections are checked against the workspace's network policy
			// at dial time, and environment proxies are not used, so a
			// webhook cannot reach internal addresses.
			Transport: &http.Transport{
				DialContext:         netguard.DialContext,
				TLSHandshakeTimeout: 10 * time.Second,
				MaxIdleConns:        20,
				IdleConnTimeout:     90 * time.Second,
			},
			// Never follow redirects: a webhook URL must not be able to
			// bounce requests to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Send delivers one message. deliveryID is passed to webhooks for receiver
// deduplication.
func (s *Sender) Send(ctx context.Context, kind string, c ChannelConfig, secret string, deliveryID int64, m Message) error {
	switch kind {
	case KindEmail:
		return s.sendEmail(ctx, c, secret, m)
	case KindSlack:
		if err := checkURL(secret, false); err != nil {
			return fmt.Errorf("slack webhook: %w", err)
		}
		return s.postJSON(ctx, secret, slackPayload(m), nil)
	case KindTeams:
		if err := checkURL(secret, false); err != nil {
			return fmt.Errorf("teams webhook: %w", err)
		}
		return s.postJSON(ctx, secret, teamsPayload(m), nil)
	case KindWebhook:
		if err := checkURL(c.URL, s.AllowHTTP); err != nil {
			return err
		}
		body, _ := json.Marshal(m)
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		h := map[string]string{
			"X-Stackurity-Event":     m.Event,
			"X-Stackurity-Delivery":  strconv.FormatInt(deliveryID, 10),
			"X-Stackurity-Timestamp": ts,
		}
		if secret != "" {
			// Sign timestamp.body so receivers can reject replays.
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(ts + "." + string(body)))
			h["X-Stackurity-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
		return s.post(ctx, c.URL, body, h)
	}
	return fmt.Errorf("unknown channel kind %q", kind)
}

func (s *Sender) postJSON(ctx context.Context, u string, v any, h map[string]string) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.post(ctx, u, body, h)
}

func (s *Sender) post(ctx context.Context, u string, body []byte, h map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "stackurity-notify")
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return redactURL(err, u)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// redactURL keeps webhook URLs (which embed credentials for Slack/Teams) out
// of stored error messages.
func redactURL(err error, u string) error {
	msg := strings.ReplaceAll(err.Error(), u, "[webhook url]")
	if p, perr := url.Parse(u); perr == nil {
		msg = strings.ReplaceAll(msg, p.Path, "/[redacted]")
	}
	return errors.New(msg)
}

func (s *Sender) sendEmail(ctx context.Context, c ChannelConfig, password string, m Message) error {
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	dial := s.Dial
	if dial == nil {
		dial = netguard.DialContext
	}
	conn, err := dial(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(time.Minute))
	}
	tlsCfg := &tls.Config{ServerName: c.Host, MinVersion: tls.VersionTLS12}
	if c.TLS == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.TLS == "" || c.TLS == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS; refusing to send credentials in clear text (set tls to none to override)")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); err != nil {
			return err
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return err
	}
	for _, to := range c.To {
		if err := cl.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(buildEmail(c.From, c.To, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func buildEmail(from string, to []string, m Message) []byte {
	var b bytes.Buffer
	hdr := func(k, v string) {
		b.WriteString(k + ": " + strings.NewReplacer("\r", " ", "\n", " ").Replace(v) + "\r\n")
	}
	hdr("From", from)
	hdr("To", strings.Join(to, ", "))
	hdr("Subject", m.Subject())
	hdr("Date", time.Now().Format(time.RFC1123Z))
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "8bit")
	if m.IncidentID > 0 {
		hdr("X-Stackurity-Incident", strconv.FormatInt(m.IncidentID, 10))
	}
	b.WriteString("\r\n")
	// Normalise every line ending to CRLF; bare CR or LF is not allowed in SMTP.
	body := strings.NewReplacer("\r\n", "\n", "\r", "\n").Replace(m.Text())
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return b.Bytes()
}

func priorityColor(m Message) string {
	switch {
	case m.Event == "resolved":
		return "#2e7d32"
	case m.SOS || m.Priority == "P1":
		return "#c62828"
	case m.Priority == "P2":
		return "#ef6c00"
	}
	return "#546e7a"
}

func slackPayload(m Message) map[string]any {
	text := "*" + escapeSlack(m.Subject()) + "*"
	var lines []string
	for _, l := range m.Summary {
		lines = append(lines, "• "+escapeSlack(l))
	}
	if m.Action != "" {
		lines = append(lines, "*Recommended action:* "+escapeSlack(m.Action))
	}
	if m.Link != "" {
		lines = append(lines, "<"+m.Link+"|Open in Stackurity>")
	}
	return map[string]any{
		"text": m.Subject(),
		"attachments": []map[string]any{{
			"color":     priorityColor(m),
			"mrkdwn_in": []string{"text"},
			"text":      text + "\n" + strings.Join(lines, "\n"),
		}},
	}
}

func escapeSlack(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// teamsPayload is an Adaptive Card message accepted by Teams Workflows
// ("Post to a channel when a webhook request is received").
func teamsPayload(m Message) map[string]any {
	body := []map[string]any{
		{"type": "TextBlock", "size": "Medium", "weight": "Bolder", "wrap": true, "text": m.Subject(),
			"color": map[bool]string{true: "Attention", false: "Default"}[m.SOS || m.Priority == "P1"]},
	}
	for _, l := range m.Summary {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "spacing": "Small", "text": "• " + l})
	}
	if m.Action != "" {
		body = append(body, map[string]any{"type": "TextBlock", "wrap": true, "text": "**Recommended action:** " + m.Action})
	}
	card := map[string]any{
		"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
		"type":    "AdaptiveCard", "version": "1.4", "body": body,
	}
	if m.Link != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open in Stackurity", "url": m.Link}}
	}
	return map[string]any{
		"type":        "message",
		"attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}},
	}
}
