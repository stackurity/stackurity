package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// PagerDuty channels keep one alert per incident through the Events API
// v2: triggered when the incident is announced, acknowledged when it is
// acknowledged in Stackurity (no new findings left), triggered again when
// its priority rises or it escalates, and resolved when it resolves. The
// dedup key names the workspace and the incident (IncidentLabel), so every
// event about one incident lands on the same alert, retries included: the
// Events API itself makes them idempotent.

// PagerDuty's Events API v2 endpoints per service region.
const (
	PagerDutyUS = "https://events.pagerduty.com/v2/enqueue"
	PagerDutyEU = "https://events.eu.pagerduty.com/v2/enqueue"
)

var pagerDutySeverities = map[string]bool{"critical": true, "error": true, "warning": true, "info": true}

// defaultSeverity maps a priority to a PagerDuty severity.
var defaultSeverity = map[string]string{"P1": "critical", "P2": "error", "P3": "warning", "P4": "info"}

func validatePagerDuty(c ChannelConfig, hasSecret bool) error {
	switch c.Region {
	case "", "us", "eu":
	default:
		return errors.New("region must be us or eu")
	}
	if !hasSecret {
		return errors.New("set secret_ref to the PagerDuty integration key (routing key) of an Events API v2 integration")
	}
	for p, sev := range c.Severities {
		if !priorityNames[p] {
			return fmt.Errorf("severities maps P1-P4 to PagerDuty severities, not %q", p)
		}
		if !pagerDutySeverities[sev] {
			return fmt.Errorf("severity for %s must be critical, error, warning or info", p)
		}
	}
	if c.URL != "" || c.Project != "" || c.Auth != "" {
		return errors.New("pagerduty takes region, severities and the routing key only")
	}
	return nil
}

// pagerDutyEvent is an Events API v2 event.
type pagerDutyEvent struct {
	RoutingKey  string            `json:"routing_key"`
	EventAction string            `json:"event_action"` // trigger, acknowledge, resolve
	DedupKey    string            `json:"dedup_key"`
	Payload     *pagerDutyPayload `json:"payload,omitempty"`
	Client      string            `json:"client,omitempty"`
	ClientURL   string            `json:"client_url,omitempty"`
	Links       []pagerDutyLink   `json:"links,omitempty"`
}

type pagerDutyPayload struct {
	Summary       string         `json:"summary"`
	Source        string         `json:"source"`
	Severity      string         `json:"severity"`
	Component     string         `json:"component,omitempty"`
	Group         string         `json:"group,omitempty"`
	Class         string         `json:"class,omitempty"`
	CustomDetails map[string]any `json:"custom_details,omitempty"`
}

type pagerDutyLink struct {
	Href string `json:"href"`
	Text string `json:"text"`
}

func (s *Sender) pagerDutyURL(c ChannelConfig) string {
	if s.PagerDutyURL != "" {
		return s.PagerDutyURL
	}
	if c.Region == "eu" {
		return PagerDutyEU
	}
	return PagerDutyUS
}

// pagerDuty sends one event and reads the reply.
func (s *Sender) pagerDuty(ctx context.Context, c ChannelConfig, ev pagerDutyEvent) error {
	if strings.TrimSpace(ev.RoutingKey) == "" {
		return &PermanentError{errors.New("pagerduty channel has no routing key: set secret_ref")}
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	u := s.pagerDutyURL(c)
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity-notify")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("pagerduty %s: %w", ev.EventAction, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	err = fmt.Errorf("pagerduty %s: HTTP %d%s", ev.EventAction, resp.StatusCode, pagerDutyErrorText(raw))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return &RetryAfterError{Wait: retryAfter(resp.Header.Get("Retry-After"), time.Now(), time.Minute), Err: fmt.Errorf("rate limited by PagerDuty: %w", err)}
	case resp.StatusCode == http.StatusBadRequest:
		// An unknown or disabled routing key is also a 400 ("Invalid
		// routing key").
		return &PermanentError{fmt.Errorf("PagerDuty refused the event (check the integration key is an Events API v2 key of an enabled service, and the region): %w", err)}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusNotFound:
		return &PermanentError{err}
	}
	return err
}

// pagerDutyErrorText extracts PagerDuty's message and errors from a reply.
func pagerDutyErrorText(raw []byte) string {
	var e struct {
		Status  string   `json:"status"`
		Message string   `json:"message"`
		Errors  []string `json:"errors"`
	}
	if json.Unmarshal(raw, &e) != nil || (e.Message == "" && len(e.Errors) == 0) {
		return "" // not PagerDuty's JSON: do not store the body
	}
	parts := []string{}
	if e.Message != "" {
		parts = append(parts, e.Message)
	}
	parts = append(parts, e.Errors...)
	return ": " + clip(strings.Join(parts, "; "), 300)
}

// pagerDutySeverity is the severity of an incident's alert.
func pagerDutySeverity(c ChannelConfig, priority string, sos bool) string {
	if sos {
		return "critical"
	}
	if s := c.Severities[priority]; s != "" {
		return s
	}
	if s := defaultSeverity[priority]; s != "" {
		return s
	}
	return "warning"
}
