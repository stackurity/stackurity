package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"
)

// item is what the agent reads of a queue item.
type item struct {
	ID           int64      `json:"id"`
	Ref          string     `json:"ref"`
	Kind         string     `json:"kind"`
	Description  string     `json:"description"`
	Source       string     `json:"source"`
	Version      string     `json:"version"`
	Edition      string     `json:"edition"`
	Page         string     `json:"page"`
	Browser      string     `json:"browser"`
	Viewport     string     `json:"viewport"`
	Status       string     `json:"status"`
	Link         string     `json:"link"`
	OwnerReason  string     `json:"owner_reason"`
	ApprovedAt   *time.Time `json:"approved_at"`
	ApprovedBy   string     `json:"approved_by"`
	ApprovalNote string     `json:"approval_note"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	Comments     int        `json:"comment_count"`
}

// approved: the owner approved it and no pull request was opened since.
func (it item) approved() bool {
	return it.Status == "triaged" && it.ApprovedAt != nil && it.Link == ""
}

type attachment struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	ContentType string     `json:"content_type"`
	Size        int64      `json:"size"`
	PurgedAt    *time.Time `json:"purged_at"`
}

type comment struct {
	At         time.Time `json:"at"`
	AuthorKind string    `json:"author_kind"`
	Kind       string    `json:"kind"`
	Body       string    `json:"body"`
}

type detail struct {
	Item        item         `json:"item"`
	Attachments []attachment `json:"attachments"`
	Comments    []comment    `json:"comments"`
}

// queue talks to /api/v1/admin/feedback with the triage token.
type queue struct {
	base  string
	token string
	http  *http.Client
}

func (q *queue) client() *http.Client {
	if q.http != nil {
		return q.http
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (q *queue) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, q.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+q.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "stackurity-feedback-agent")
	resp, err := q.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(raw[:min(len(raw), 300)]))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (q *queue) list(ctx context.Context) ([]item, error) {
	var out struct {
		Items []item `json:"items"`
	}
	err := q.do(ctx, "GET", "?status=new,triaged&order=attention&limit=100", nil, &out)
	return out.Items, err
}

func (q *queue) get(ctx context.Context, ref string) (*detail, error) {
	var d detail
	if err := q.do(ctx, "GET", "/"+url.PathEscape(ref), nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (q *queue) patch(ctx context.Context, ref string, p map[string]any) error {
	return q.do(ctx, "PATCH", "/"+url.PathEscape(ref), p, nil)
}

func (q *queue) comment(ctx context.Context, ref, body string, ask bool) error {
	return q.do(ctx, "POST", "/"+url.PathEscape(ref)+"/comments", map[string]any{"body": body, "ask": ask}, nil)
}

// download saves one attachment through its signed link (at most max bytes).
func (q *queue) download(ctx context.Context, ref string, aid int64, dst string, max int64) error {
	var link struct {
		URL string `json:"url"`
	}
	if err := q.do(ctx, "POST", fmt.Sprintf("/%s/attachments/%d/link", url.PathEscape(ref), aid), nil, &link); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", link.URL, nil)
	if err != nil {
		return err
	}
	resp, err := q.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("attachment %d: %s", aid, resp.Status)
	}
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, io.LimitReader(resp.Body, max))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
