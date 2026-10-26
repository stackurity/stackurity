package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Feedback lets a signed-in user send a message to the Stackurity team from
// the dashboard. The server forwards it to STACKURITY_FEEDBACK_URL (the
// project's website by default). Only what the user typed (kind, message,
// email if given) is sent, plus the path of the page they were on, the
// version and the edition: never workspace or asset names, findings,
// hostnames or this installation's URL. Nothing is sent unless a user
// presses Send, and an empty STACKURITY_FEEDBACK_URL turns the feature off.

// DefaultFeedbackURL receives feedback unless STACKURITY_FEEDBACK_URL says
// otherwise.
const DefaultFeedbackURL = "https://stackurity.dev/feedback"

const (
	feedbackMaxMessage = 5000
	feedbackTimeout    = 10 * time.Second
)

// limitFeedback caps what one user can send.
var limitFeedback = rateLimit{10, time.Hour}

// FeedbackURLFromEnv reads STACKURITY_FEEDBACK_URL. Unset means the default;
// set to an empty string (or off) turns feedback off and returns "".
func FeedbackURLFromEnv() (string, error) {
	v, ok := os.LookupEnv("STACKURITY_FEEDBACK_URL")
	if !ok {
		return DefaultFeedbackURL, nil
	}
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "off") {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("STACKURITY_FEEDBACK_URL must be an http(s) URL or empty, not %q", v)
	}
	return v, nil
}

type feedbackRequest struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Email   string `json:"email"`
	Page    string `json:"page"`
}

// feedbackPayload is exactly what leaves the installation.
type feedbackPayload struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
	Email   string `json:"email,omitempty"`
	Page    string `json:"page,omitempty"`
	Version string `json:"version"`
	Edition string `json:"edition"`
	Source  string `json:"source"`
}

var feedbackSegment = regexp.MustCompile(`^[a-z0-9-]+$`)

// feedbackPage reduces a dashboard location to its path, and replaces any
// segment that is not a plain route word or number with "_", so a name
// that ends up in a future route is not sent.
func feedbackPage(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) > 300 {
		return ""
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range segs {
		if s != "" && !feedbackSegment.MatchString(s) {
			segs[i] = "_"
		}
	}
	return "/" + strings.Join(segs, "/")
}

func validateFeedback(req feedbackRequest) (feedbackPayload, error) {
	out := feedbackPayload{Source: "app"}
	switch k := strings.TrimSpace(req.Kind); k {
	case "bug", "idea", "question":
		out.Kind = k
	default:
		return out, badRequest("kind must be bug, idea or question")
	}
	out.Message = strings.TrimSpace(req.Message)
	if out.Message == "" {
		return out, badRequest("write a message")
	}
	if !utf8.ValidString(out.Message) {
		return out, badRequest("the message is not valid text")
	}
	if utf8.RuneCountInString(out.Message) > feedbackMaxMessage {
		return out, badRequest(fmt.Sprintf("keep the message under %d characters", feedbackMaxMessage))
	}
	if e := strings.TrimSpace(req.Email); e != "" {
		addr, err := mail.ParseAddress(e)
		if err != nil || addr.Address != e || len(e) > 200 {
			return out, badRequest("the email address is not valid; leave it empty to send without one")
		}
		out.Email = e
	}
	out.Page = feedbackPage(req.Page)
	return out, nil
}

var errFeedbackUpstream = errors.New("feedback service")

func (s *Server) sendFeedback(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if s.FeedbackURL == "" {
		writeError(w, 404, "not_found", "feedback is turned off on this server")
		return
	}
	if p.User == nil {
		writeError(w, 403, "forbidden", "feedback needs a signed-in user")
		return
	}
	var req feedbackRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := validateFeedback(req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.limited(w, r, "you have sent a lot of feedback; try again in an hour", limitHit{"feedback", itoa(p.User.ID), limitFeedback}) {
		return
	}
	out.Version = s.Version
	out.Edition = string(s.Gate.Edition(r.Context()))
	if status, err := s.forwardFeedback(r.Context(), out); err != nil {
		s.Log.Warn("feedback not delivered", "err", err, "upstream_status", status)
		if status == http.StatusTooManyRequests {
			writeError(w, 429, "rate_limited", "the feedback service is busy; try again later")
			return
		}
		writeError(w, 502, "feedback_unavailable", "the feedback could not be delivered; try again later, or email info@stackurity.dev")
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "feedback.send", "feedback", "", map[string]any{"kind": out.Kind})
	writeJSON(w, 202, map[string]string{"status": "sent"})
}

func (s *Server) forwardFeedback(ctx context.Context, out feedbackPayload) (int, error) {
	body, err := json.Marshal(out)
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, feedbackTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", s.FeedbackURL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity")
	hc := s.FeedbackHTTP
	if hc == nil {
		hc = &http.Client{Timeout: feedbackTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errFeedbackUpstream, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode/100 != 2 {
		return resp.StatusCode, fmt.Errorf("%w answered %s", errFeedbackUpstream, resp.Status)
	}
	return resp.StatusCode, nil
}
