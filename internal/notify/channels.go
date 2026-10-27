// Package notify routes incidents to channels (email, Slack, Microsoft
// Teams, webhooks, Jira issues) with deduplication, quiet hours, rate limits, retries and
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

// Message is what every channel renders. Webhooks receive it as JSON; the
// shape only ever gains fields (see docs/api.md, "Notification messages").
type Message struct {
	// Event: urgent, summary, overdue, connected (grouped messages to
	// people), test; opened, priority_raised, escalated, resolved and
	// updated for Jira issues (one per incident).
	Event      string         `json:"event"`
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
	Summary    []string       `json:"summary"` // short lines; for grouped messages, the item texts of Sections
	Action     string         `json:"recommended_action,omitempty"`
	Link       string         `json:"link,omitempty"` // the dashboard page to open
	Escalation int            `json:"escalation_level,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
	At         time.Time      `json:"at"`
	// ProjectID marks a Jira delivery of a route limited to that project:
	// its issue describes only the project's part of the incident, built
	// when it is sent (see jira_projects.go). The payload carries nothing
	// else about the incident.
	ProjectID int64 `json:"project_id,omitempty"`
	// Grouped messages only.
	Route        string         `json:"route,omitempty"`  // the route that sent it
	Period       *Period        `json:"period,omitempty"` // summaries: what they cover
	Counts       map[string]int `json:"counts,omitempty"` // totals, e.g. new, urgent, fixed, overdue
	Sections     []Section      `json:"sections,omitempty"`
	SettingsLink string         `json:"settings_link,omitempty"` // where the route is changed
}

// Section is a titled list of items in a grouped message.
type Section struct {
	Title string `json:"title,omitempty"`
	Items []Item `json:"items"`
}

// Item is one line of a section, such as an asset and its new issues, with
// the dashboard page it is about. Items holds details, such as the top
// fixes for an asset.
type Item struct {
	Text  string `json:"text"`
	Link  string `json:"link,omitempty"`
	Items []Item `json:"items,omitempty"`
	// Actions are links that open the item in the dashboard with an action
	// ready (Assign to me, Snooze, Open a fix). The dashboard asks for one
	// tap to confirm after sign-in; following a link changes nothing.
	Actions []Action `json:"actions,omitempty"`
	// asset is the asset the item is about (0: none or several), used to
	// open links in the route's project.
	asset int64
}

// Action is a link to act on an item: assign, snooze or open.
type Action struct {
	Kind  string `json:"kind"`
	Label string `json:"label"`
	Link  string `json:"link"`
	// Fix is the fix group the action is about.
	Fix string `json:"fix,omitempty"`
}

// Period is the time a summary covers.
type Period struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Grouped reports whether the message is one of the grouped kinds.
func (m Message) Grouped() bool {
	switch m.Event {
	case EventUrgent, EventSummary, EventOverdue, EventConnected:
		return true
	}
	return false
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
	case "digest", "test", "invitation", "confirm_email", EventSummary, EventOverdue, EventConnected:
		return m.Title
	case EventUrgent:
		return prefix + m.Title
	}
	return fmt.Sprintf("%s[%s] %s", prefix, m.Priority, m.Title)
}

// Text is the plain-text rendering (email, and anything that shows text).
func (m Message) Text() string {
	var b strings.Builder
	b.WriteString(m.Subject() + "\n\n")
	if len(m.Sections) > 0 {
		for _, s := range m.Sections {
			if s.Title != "" {
				b.WriteString(s.Title + "\n")
			}
			writeItems(&b, s.Items, "")
			b.WriteString("\n")
		}
		if m.Link != "" {
			b.WriteString("Open in Stackurity: " + m.Link + "\n")
		}
		if m.SettingsLink != "" {
			b.WriteString("Change these notifications: " + m.SettingsLink + "\n")
		}
		return b.String()
	}
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

func writeItems(b *strings.Builder, items []Item, indent string) {
	for _, it := range items {
		b.WriteString(indent + "- " + it.Text + "\n")
		if it.Link != "" {
			b.WriteString(indent + "  " + it.Link + "\n")
		}
		for _, a := range it.Actions {
			if a.Kind != "open" { // the item's own link opens it
				b.WriteString(indent + "  " + a.Label + ": " + a.Link + "\n")
			}
		}
		writeItems(b, it.Items, indent+"  ")
	}
}

// itemTexts flattens sections into the Summary lines.
func itemTexts(sections []Section) []string {
	var out []string
	var walk func([]Item, string)
	walk = func(items []Item, indent string) {
		for _, it := range items {
			out = append(out, indent+it.Text)
			walk(it.Items, indent+"  ")
		}
	}
	for _, s := range sections {
		walk(s.Items, "")
	}
	return out
}

// Channel kinds.
const (
	KindEmail   = "email"
	KindSlack   = "slack"
	KindTeams   = "teams"
	KindWebhook = "webhook"
	KindJira    = "jira"
	// KindStackurityEmail is email sent by Stackurity through the
	// platform's own mail server (Dispatcher.PlatformMail), to members and
	// to addresses that confirmed; hosted installations only.
	KindStackurityEmail = "stackurity_email"
)

// ChannelConfig is the non-secret part of a channel. Secrets (SMTP password,
// Slack/Teams webhook URL, webhook HMAC key, Jira token) come from a secret
// reference.
type ChannelConfig struct {
	// email
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Username string   `json:"username,omitempty"` // also the Jira Cloud account email
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	TLS      string   `json:"tls,omitempty"` // starttls (default), tls, none
	// webhook; the site's base URL for Jira
	URL string `json:"url,omitempty"`
	// jira
	Deployment        string            `json:"deployment,omitempty"` // cloud (default) or datacenter
	Project           string            `json:"project,omitempty"`    // project key
	IssueType         string            `json:"issue_type,omitempty"` // default Task
	Labels            []string          `json:"labels,omitempty"`
	Priorities        map[string]string `json:"priorities,omitempty"`         // P1..P4 -> Jira priority name
	ResolveTransition string            `json:"resolve_transition,omitempty"` // e.g. Done; empty only comments
	// slack: a reference to the Slack app's signing secret. When set,
	// messages carry interactive Assign to me and Snooze buttons, and
	// clicks are verified with it (internal/api/slack.go).
	SigningSecretRef string `json:"signing_secret_ref,omitempty"`

	// stackurity_email: members of the organisation (user ids) who get
	// the messages; To holds the other addresses, which must confirm first.
	UserIDs []int64 `json:"user_ids,omitempty"`
	// slack, added with the Stackurity Slack app ("Add to Slack"): the
	// Slack workspace and channel the app's webhook posts to. Clicks are
	// verified with the app's signing secret.
	SlackApp         bool   `json:"slack_app,omitempty"`
	TeamID           string `json:"team_id,omitempty"`
	TeamName         string `json:"team_name,omitempty"`
	SlackChannel     string `json:"slack_channel,omitempty"`
	ConfigurationURL string `json:"configuration_url,omitempty"`

	// interactive is the channel's id when its messages get interactive
	// buttons; set by the dispatcher, never stored.
	interactive int64
	// headerTo replaces the To header (the envelope still names every
	// recipient), so recipients of email sent by Stackurity do not see
	// each other's addresses.
	headerTo string
}

// ValidateChannel checks configuration before it is stored.
func ValidateChannel(kind string, c ChannelConfig, hasSecret, allowHTTP bool) error {
	if c.SigningSecretRef != "" && kind != KindSlack {
		return errors.New("signing_secret_ref is for Slack channels")
	}
	if c.SlackApp && kind != KindSlack {
		return errors.New("slack_app is for Slack channels")
	}
	switch kind {
	case KindStackurityEmail:
		if len(c.UserIDs)+len(c.To) == 0 {
			return errors.New("pick at least one member or address")
		}
		for _, t := range c.To {
			if a, err := mail.ParseAddress(t); err != nil || a.Address != t {
				return fmt.Errorf("invalid address %q", t)
			}
		}
		if c.Host != "" || c.Username != "" || c.From != "" {
			return errors.New("email sent by Stackurity takes no mail server settings")
		}
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
	case KindJira:
		return validateJira(c, hasSecret, allowHTTP)
	default:
		return errors.New("kind must be email, stackurity_email, slack, teams, webhook or jira")
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
			Transport: &guardedTransport{private: guardedPool(), public: guardedPool()},
			// Never follow redirects: a webhook URL must not be able to
			// bounce requests to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func guardedPool() *http.Transport {
	return &http.Transport{
		DialContext:         netguard.DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        20,
		IdleConnTimeout:     90 * time.Second,
	}
}

// guardedTransport keeps connections opened for workspaces that may reach
// private networks apart from the others. The network policy is checked when
// a connection is dialled, so a shared pool would let one workspace reuse a
// connection to an internal address that another workspace opened.
type guardedTransport struct{ private, public *http.Transport }

func (g *guardedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if netguard.AllowsPrivate(r.Context()) {
		return g.private.RoundTrip(r)
	}
	return g.public.RoundTrip(r)
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
		return s.postJSON(ctx, secret, slackPayloadFor(m, c.interactive), nil)
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
	case KindJira:
		// Issues are kept per incident, which needs the store; see
		// Dispatcher.syncJira.
		return errors.New("jira channels are delivered by the dispatcher")
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

// redactURL keeps webhook URLs (which embed credentials for Slack/Teams, in
// the path or a sig= query parameter) out of stored error messages. The
// result still wraps the underlying cause (without the URL), so callers can
// tell a blocked destination from other failures.
func redactURL(err error, u string) error {
	msg := err.Error()
	forms := []string{u}
	if p, perr := url.Parse(u); perr == nil {
		forms = append(forms, p.String(), p.Redacted())
		for _, part := range []string{p.EscapedPath(), p.Path, p.RawQuery} {
			if strings.Trim(part, "/") != "" {
				forms = append(forms, part)
			}
		}
	}
	for i, f := range forms {
		if f == "" {
			continue
		}
		repl := "/[redacted]"
		if i < 3 {
			repl = "[webhook url]"
		}
		msg = strings.ReplaceAll(msg, f, repl)
	}
	cause := err
	var ue *url.Error
	if errors.As(err, &ue) {
		cause = ue.Err
	}
	return &redactedError{msg: msg, cause: cause}
}

type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

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
	to := c.To
	if c.headerTo != "" {
		to = []string{c.headerTo}
	}
	if _, err := w.Write(buildEmail(c.From, to, m)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
