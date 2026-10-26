// Package client is the HTTP client the CLI and agent use to talk to a
// Stackurity server.
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/model"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	UA      string
}

func New(base, token, version string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid server url %q", base)
	}
	return &Client{
		BaseURL: strings.TrimSuffix(base, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 5 * time.Minute},
		UA:      "stackurity/" + version,
	}, nil
}

type APIError struct {
	Status  int
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details"`
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("server returned %d %s: %s", e.Status, e.Code, e.Message)
	if len(e.Details) > 0 {
		msg += " (" + strings.Join(e.Details, "; ") + ")"
	}
	return msg
}

func (c *Client) Do(ctx context.Context, method, path string, body io.Reader, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("User-Agent", c.UA)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error APIError `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&e)
		e.Error.Status = resp.StatusCode
		return &e.Error
	}
	if out == nil {
		return nil
	}
	if w, ok := out.(io.Writer); ok {
		_, err = io.Copy(w, resp.Body)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func gz(v any) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

type IngestResult struct {
	AssetID      int64   `json:"asset_id"`
	CollectionID int64   `json:"collection_id"`
	Observations int     `json:"observations"`
	Removed      int64   `json:"removed"`
	NewAsset     bool    `json:"new_asset"`
	Conflict     []int64 `json:"identity_conflict"`
}

// Ingest submits a batch, gzip-compressed, retrying transient failures.
func (c *Client) Ingest(ctx context.Context, b *model.ObservationBatch) (*IngestResult, error) {
	var res IngestResult
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var buf *bytes.Buffer
		buf, err = gz(b)
		if err != nil {
			return nil, err
		}
		err = c.Do(ctx, "POST", "/api/v1/ingest", buf, map[string]string{
			"Content-Type": "application/json", "Content-Encoding": "gzip",
		}, &res)
		if err == nil {
			return &res, nil
		}
		if ae, ok := err.(*APIError); ok && ae.Status < 500 && ae.Status != 429 {
			return nil, err // client errors are not retried
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 2 * time.Second):
		}
	}
	return nil, err
}

func (c *Client) ImportSBOM(ctx context.Context, doc io.Reader, assetName, assetKind, env string) (*IngestResult, error) {
	q := url.Values{}
	if assetName != "" {
		q.Set("asset_name", assetName)
		q.Set("asset_kind", assetKind)
	}
	if env != "" {
		q.Set("environment", env)
	}
	var res IngestResult
	err := c.Do(ctx, "POST", "/api/v1/sbom/import?"+q.Encode(), doc, map[string]string{"Content-Type": "application/json"}, &res)
	return &res, err
}

// AgentAction is a remediation action dispatched to this host.
type AgentAction struct {
	ID          int64    `json:"id"`
	Kind        string   `json:"kind"`
	Package     string   `json:"package"`
	Manager     string   `json:"manager"`
	FromVersion string   `json:"from_version"`
	ToVersion   string   `json:"to_version"`
	HealthUnits []string `json:"health_units"`
}

func (c *Client) AgentActions(ctx context.Context) ([]AgentAction, error) {
	var out struct {
		Items []AgentAction `json:"items"`
	}
	err := c.Do(ctx, "GET", "/api/v1/agent/actions", nil, nil, &out)
	return out.Items, err
}

// reportRetryWait is the first pause between report attempts; it doubles.
var reportRetryWait = 2 * time.Second

// ReportAction sends the result of a remediation action. A change has
// already been made, so the result is worth retrying through a brief network
// interruption or server restart; the server accepts the same result twice
// without recording it twice. Client errors (such as a 409 because the
// server already timed the action out) are not retried. If every attempt
// fails, the inventory the agent collects next lets the server settle it.
func (c *Client) ReportAction(ctx context.Context, id int64, report any) error {
	b, err := json.Marshal(report)
	if err != nil {
		return err
	}
	wait := reportRetryWait
	for attempt := 0; ; attempt++ {
		err = c.Do(ctx, "POST", fmt.Sprintf("/api/v1/agent/actions/%d/report", id), bytes.NewReader(b),
			map[string]string{"Content-Type": "application/json"}, nil)
		if err == nil || attempt == 3 {
			return err
		}
		if ae, ok := err.(*APIError); ok && ae.Status < 500 && ae.Status != 429 {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// ResultFinding is the part of a finding a CI gate needs.
type ResultFinding struct {
	ID             int64  `json:"id"`
	Kind           string `json:"kind"`
	Key            string `json:"key"`
	ComponentName  string `json:"component_name"`
	Version        string `json:"version"`
	Location       string `json:"location"`
	Verification   string `json:"verification"`
	Severity       string `json:"severity"`
	Priority       string `json:"priority"`
	State          string `json:"state"`
	FixedVersion   string `json:"fixed_version"`
	Title          string `json:"title"`
	KnownExploited bool   `json:"known_exploited"`
	// PriorityPolicy is the risk policy version that scored the finding;
	// "" until the server has prioritised it.
	PriorityPolicy string `json:"priority_policy_version"`
}

type CollectionResult struct {
	CollectionID int64           `json:"collection_id"`
	AssetID      int64           `json:"asset_id"`
	Status       string          `json:"status"` // pending, scoring, evaluated, failed
	Error        string          `json:"error"`
	Findings     []ResultFinding `json:"findings"`
	Gaps         int64           `json:"evaluation_gaps"`
}

// CollectionResult fetches the evaluation of a submitted collection.
func (c *Client) CollectionResult(ctx context.Context, id int64) (*CollectionResult, error) {
	var res CollectionResult
	if err := c.Do(ctx, "GET", fmt.Sprintf("/api/v1/collections/%d/result", id), nil, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Enrollment is what the server returns for a redeemed enrollment code.
type Enrollment struct {
	Token        string   `json:"token"`
	Environment  string   `json:"environment"`
	AppDirs      []string `json:"app_dirs"`
	DiscoverApps bool     `json:"discover_apps"`
}

// Enroll exchanges a one-time enrollment code for a collector token. The
// client needs no token of its own.
func (c *Client) Enroll(ctx context.Context, code, hostname string) (*Enrollment, error) {
	body, _ := json.Marshal(map[string]string{"code": code, "hostname": hostname})
	var e Enrollment
	err := c.Do(ctx, "POST", "/api/v1/enroll", bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json", "X-Stackurity-CSRF": "1"}, &e)
	return &e, err
}
