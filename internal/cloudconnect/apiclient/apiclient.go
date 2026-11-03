// Package apiclient is the small HTTP client the gcp-managed and
// azure-managed plugins share: JSON over HTTPS through the run's network
// policy, without keep-alives (a reused connection would skip the policy's
// check, which runs when a connection is dialled), without redirects, with
// bounded responses and errors that keep the cloud's reason.
package apiclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/stackurity/stackurity/pkg/plugin"
)

// MaxResponse bounds one response body.
const MaxResponse = 32 << 20

// NewHTTP returns the client every request of a plugin run uses.
func NewHTTP(ctx context.Context) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:         plugin.Dialer(ctx),
			DisableKeepAlives:   true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 15 * time.Second,
			ForceAttemptHTTP2:   false,
		},
		Timeout: 2 * time.Minute,
		// Cloud APIs answer list calls directly; a redirect could take a
		// bearer token somewhere unexpected.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Error is a non-2xx answer.
type Error struct {
	Status  int
	Code    string // PERMISSION_DENIED, AuthorizationFailed, invalid_client, ...
	Reason  string // Google's ErrorInfo reason, e.g. SERVICE_DISABLED
	Message string
}

func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d", e.Status)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Reason != "" && e.Reason != e.Code {
		b.WriteString(" (" + e.Reason + ")")
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	s := b.String()
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}

// StatusOf returns the HTTP status of an *Error, or 0.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

// AsError returns err as an *Error.
func AsError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}

// Do sends one request and decodes a JSON answer into out (when not nil).
func Do(ctx context.Context, c *http.Client, method, url, token, contentType string, body io.Reader, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity-plugin")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > MaxResponse {
		return fmt.Errorf("response larger than %d MiB", MaxResponse>>20)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseError(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("unexpected answer: %w", err)
	}
	return nil
}

// parseError reads the error shapes of Google APIs, Azure Resource Manager
// and OAuth token endpoints.
func parseError(status int, data []byte) *Error {
	e := &Error{Status: status}
	var env struct {
		Error            json.RawMessage `json:"error"`
		ErrorDescription string          `json:"error_description"`
		Message          string          `json:"message"`
	}
	if json.Unmarshal(data, &env) != nil {
		return e
	}
	var s string
	if json.Unmarshal(env.Error, &s) == nil {
		e.Code, e.Message = s, firstLine(env.ErrorDescription) // OAuth
		return e
	}
	var obj struct {
		Code    any    `json:"code"`
		Status  string `json:"status"`
		Message string `json:"message"`
		Details []struct {
			Reason string `json:"reason"`
		} `json:"details"`
	}
	if json.Unmarshal(env.Error, &obj) == nil {
		e.Message = obj.Message
		if c, ok := obj.Code.(string); ok {
			e.Code = c // Azure
		}
		if obj.Status != "" {
			e.Code = obj.Status // Google
		}
		for _, d := range obj.Details {
			if d.Reason != "" {
				e.Reason = d.Reason
				break
			}
		}
	}
	if e.Message == "" {
		e.Message = env.Message
	}
	e.Message = firstLine(e.Message)
	return e
}

// firstLine drops the trace lines token endpoints add to a description.
func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return s[:i]
	}
	return s
}
