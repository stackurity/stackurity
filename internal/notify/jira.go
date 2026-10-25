package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Jira channels keep one issue per incident: created when the incident is
// announced, commented on when findings join or leave and when its priority
// changes or it escalates, and commented on (and optionally transitioned)
// when it resolves. Jira Cloud uses REST API v3 with Atlassian Document
// Format and email + API token; Jira Data Center and Server use REST API v2
// with wiki markup and a personal access token.

const (
	JiraCloud      = "cloud"
	JiraDataCenter = "datacenter"
)

var (
	jiraProjectRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,49}$`)
	jiraLabelRe   = regexp.MustCompile(`^[^\s]{1,100}$`)
)

// jiraLabelPrefix starts the label that ties an issue to its incident.
const jiraLabelPrefix = "stackurity-incident-"

// IncidentLabel is the label on the issue of incident id in workspace ws. It
// is searched for before an issue is created, so a retry after a crash finds
// the issue instead of creating another.
func IncidentLabel(ws, id int64) string {
	return fmt.Sprintf("%s%d-%d", jiraLabelPrefix, ws, id)
}

func validateJira(c ChannelConfig, hasSecret, allowHTTP bool) error {
	if err := checkURL(c.URL, allowHTTP); err != nil {
		return fmt.Errorf("jira url: %w", err)
	}
	if u, _ := url.Parse(c.URL); u.RawQuery != "" || u.Fragment != "" {
		return errors.New("jira url must be the site's base URL, without a query")
	}
	switch c.Deployment {
	case "", JiraCloud:
		if _, err := mail.ParseAddress(c.Username); err != nil {
			return errors.New("jira cloud needs the account's email address as username (the API token goes in secret_ref)")
		}
	case JiraDataCenter:
	default:
		return errors.New("deployment must be cloud or datacenter")
	}
	if !hasSecret {
		return errors.New("set secret_ref to the Jira API token (cloud) or personal access token (datacenter)")
	}
	if !jiraProjectRe.MatchString(c.Project) {
		return errors.New("project must be a Jira project key such as SEC")
	}
	if len(c.IssueType) > 60 {
		return errors.New("issue_type is too long")
	}
	if len(c.Labels) > 10 {
		return errors.New("at most 10 labels")
	}
	for _, l := range c.Labels {
		if !jiraLabelRe.MatchString(l) || strings.HasPrefix(l, jiraLabelPrefix) {
			return fmt.Errorf("invalid label %q: labels cannot contain spaces or start with %s", l, jiraLabelPrefix)
		}
	}
	for p, name := range c.Priorities {
		if !priorityNames[p] {
			return fmt.Errorf("priorities maps P1-P4 to Jira priority names, not %q", p)
		}
		if strings.TrimSpace(name) == "" || len(name) > 60 {
			return fmt.Errorf("invalid Jira priority name for %s", p)
		}
	}
	if len(c.ResolveTransition) > 100 {
		return errors.New("resolve_transition is too long")
	}
	return nil
}

var priorityNames = map[string]bool{"P1": true, "P2": true, "P3": true, "P4": true}

// RetryAfterError asks for the delivery to be retried no sooner than Wait
// (an HTTP 429 or 503 with Retry-After).
type RetryAfterError struct {
	Wait time.Duration
	Err  error
}

func (e *RetryAfterError) Error() string { return e.Err.Error() }
func (e *RetryAfterError) Unwrap() error { return e.Err }

// PermanentError fails a delivery without further retries: retrying cannot
// help until someone changes the configuration (credentials, project,
// permissions). The delivery can be retried by hand afterwards.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// retryAfter reads a Retry-After header (seconds or an HTTP date), bounded to
// an hour; def applies when it is missing.
func retryAfter(h string, now time.Time, def time.Duration) time.Duration {
	d := def
	if s, err := strconv.Atoi(strings.TrimSpace(h)); err == nil && s >= 0 {
		d = time.Duration(s) * time.Second
	} else if t, err := http.ParseTime(h); err == nil {
		d = t.Sub(now)
	}
	return min(max(d, time.Second), time.Hour)
}

type jiraClient struct {
	http  *http.Client
	base  string
	cloud bool
	auth  string
	cfg   ChannelConfig
}

func (s *Sender) jira(c ChannelConfig, secret string) (*jiraClient, error) {
	if err := checkURL(c.URL, s.AllowHTTP); err != nil {
		return nil, &PermanentError{fmt.Errorf("jira url: %w", err)}
	}
	if secret == "" {
		return nil, &PermanentError{errors.New("jira channel has no token: set secret_ref")}
	}
	j := &jiraClient{http: s.HTTP, base: strings.TrimRight(c.URL, "/"), cloud: c.Deployment != JiraDataCenter, cfg: c}
	if j.cloud {
		j.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.Username+":"+secret))
	} else {
		j.auth = "Bearer " + secret
	}
	return j, nil
}

func (j *jiraClient) path(p string) string {
	v := "2"
	if j.cloud {
		v = "3"
	}
	return j.base + "/rest/api/" + v + p
}

// do sends one request to the Jira REST API and decodes a JSON reply into out.
func (j *jiraClient) do(ctx context.Context, method, p string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, j.path(p), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", j.auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity-notify")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := j.http.Do(req)
	if err != nil {
		return fmt.Errorf("jira %s %s: %w", method, p, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			return nil
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out); err != nil {
			return fmt.Errorf("jira %s %s: invalid reply: %w", method, p, err)
		}
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	err = fmt.Errorf("jira %s %s: HTTP %d%s", method, p, resp.StatusCode, jiraErrorText(raw))
	switch resp.StatusCode {
	case http.StatusTooManyRequests:
		return &RetryAfterError{Wait: retryAfter(resp.Header.Get("Retry-After"), time.Now(), time.Minute), Err: fmt.Errorf("rate limited by Jira: %w", err)}
	case http.StatusServiceUnavailable:
		if h := resp.Header.Get("Retry-After"); h != "" {
			return &RetryAfterError{Wait: retryAfter(h, time.Now(), time.Minute), Err: err}
		}
	case http.StatusUnauthorized:
		return &PermanentError{fmt.Errorf("Jira rejected the credentials (check the username and token): %w", err)}
	case http.StatusForbidden:
		return &PermanentError{fmt.Errorf("Jira refused access (check the account's permissions on the project): %w", err)}
	case http.StatusBadRequest, http.StatusNotFound:
		return &PermanentError{err}
	}
	return err
}

// jiraErrorText extracts Jira's error messages from a reply body.
func jiraErrorText(raw []byte) string {
	var e struct {
		ErrorMessages []string          `json:"errorMessages"`
		Errors        map[string]string `json:"errors"`
	}
	var parts []string
	if json.Unmarshal(raw, &e) == nil {
		parts = append(parts, e.ErrorMessages...)
		for k, v := range e.Errors {
			parts = append(parts, k+": "+v)
		}
	}
	if len(parts) == 0 {
		// Not Jira's JSON (a proxy or login page): do not store the body.
		return ""
	}
	return ": " + clip(strings.Join(parts, "; "), 300)
}

// Check verifies the credentials and access to the project and issue type
// without creating anything.
func (j *jiraClient) Check(ctx context.Context) error {
	var me struct {
		DisplayName string `json:"displayName"`
	}
	if err := j.do(ctx, "GET", "/myself", nil, &me); err != nil {
		return err
	}
	var proj struct {
		Key        string `json:"key"`
		IssueTypes []struct {
			Name string `json:"name"`
		} `json:"issueTypes"`
	}
	if err := j.do(ctx, "GET", "/project/"+url.PathEscape(j.cfg.Project), nil, &proj); err != nil {
		return fmt.Errorf("project %s: %w", j.cfg.Project, err)
	}
	want := j.issueType()
	var names []string
	for _, t := range proj.IssueTypes {
		if strings.EqualFold(t.Name, want) {
			return j.checkPriorities(ctx)
		}
		names = append(names, t.Name)
	}
	if len(proj.IssueTypes) == 0 {
		return j.checkPriorities(ctx) // the reply does not list them; creation will tell
	}
	return fmt.Errorf("project %s has no issue type %q (it has: %s)", j.cfg.Project, want, strings.Join(firstN(names, 10), ", "))
}

func (j *jiraClient) checkPriorities(ctx context.Context) error {
	if len(j.cfg.Priorities) == 0 {
		return nil
	}
	var list []struct {
		Name string `json:"name"`
	}
	if err := j.do(ctx, "GET", "/priority", nil, &list); err != nil {
		var pe *PermanentError
		if errors.As(err, &pe) && strings.Contains(err.Error(), "HTTP 404") {
			return nil // not offered by this Jira; creation will tell
		}
		return err
	}
	have := map[string]bool{}
	for _, p := range list {
		have[strings.ToLower(p.Name)] = true
	}
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		if n, ok := j.cfg.Priorities[p]; ok && !have[strings.ToLower(n)] {
			return fmt.Errorf("Jira has no priority %q (mapped from %s)", n, p)
		}
	}
	return nil
}

func (j *jiraClient) issueType() string {
	if t := strings.TrimSpace(j.cfg.IssueType); t != "" {
		return t
	}
	return "Task"
}

// findIssue returns the oldest issue in the project carrying label, or "".
func (j *jiraClient) findIssue(ctx context.Context, label string) (string, error) {
	q := map[string]any{
		"jql":        fmt.Sprintf(`project = "%s" AND labels = "%s" ORDER BY created ASC`, j.cfg.Project, label),
		"fields":     []string{"status"},
		"maxResults": 1,
	}
	p := "/search"
	if j.cloud {
		p = "/search/jql" // the enhanced search; /search is retired on Cloud
	}
	var res struct {
		Issues []struct {
			Key string `json:"key"`
		} `json:"issues"`
	}
	if err := j.do(ctx, "POST", p, q, &res); err != nil {
		return "", err
	}
	if len(res.Issues) == 0 {
		return "", nil
	}
	return res.Issues[0].Key, nil
}

func (j *jiraClient) createIssue(ctx context.Context, summary string, desc jiraDoc, labels []string, priority string) (string, error) {
	fields := map[string]any{
		"project":     map[string]string{"key": j.cfg.Project},
		"issuetype":   map[string]string{"name": j.issueType()},
		"summary":     summary,
		"description": j.render(desc),
		"labels":      labels,
	}
	if priority != "" {
		fields["priority"] = map[string]string{"name": priority}
	}
	var res struct {
		Key string `json:"key"`
	}
	if err := j.do(ctx, "POST", "/issue", map[string]any{"fields": fields}, &res); err != nil {
		return "", err
	}
	if res.Key == "" {
		return "", errors.New("jira created an issue but did not return its key")
	}
	return res.Key, nil
}

func (j *jiraClient) setPriority(ctx context.Context, key, priority string) error {
	return j.do(ctx, "PUT", "/issue/"+url.PathEscape(key), map[string]any{"fields": map[string]any{"priority": map[string]string{"name": priority}}}, nil)
}

func (j *jiraClient) comment(ctx context.Context, key string, doc jiraDoc) error {
	return j.do(ctx, "POST", "/issue/"+url.PathEscape(key)+"/comment", map[string]any{"body": j.render(doc)}, nil)
}

// hasComment reports whether one of the issue's latest comments contains
// marker, so a retried delivery does not comment twice.
func (j *jiraClient) hasComment(ctx context.Context, key, marker string) (bool, error) {
	var res struct {
		Comments []struct {
			Body json.RawMessage `json:"body"`
		} `json:"comments"`
	}
	if err := j.do(ctx, "GET", "/issue/"+url.PathEscape(key)+"/comment?orderBy=-created&maxResults=50", nil, &res); err != nil {
		return false, err
	}
	for _, c := range res.Comments {
		if bytes.Contains(c.Body, []byte(marker)) {
			return true, nil
		}
	}
	return false, nil
}

// transition moves the issue through the transition (or to the status) named
// name. An issue already in that status, or in any done status, is left alone.
func (j *jiraClient) transition(ctx context.Context, key, name string) error {
	var res struct {
		Transitions []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			To   struct {
				Name string `json:"name"`
			} `json:"to"`
		} `json:"transitions"`
	}
	if err := j.do(ctx, "GET", "/issue/"+url.PathEscape(key)+"/transitions", nil, &res); err != nil {
		return err
	}
	var avail []string
	for _, t := range res.Transitions {
		if strings.EqualFold(t.Name, name) || strings.EqualFold(t.To.Name, name) {
			return j.do(ctx, "POST", "/issue/"+url.PathEscape(key)+"/transitions", map[string]any{"transition": map[string]string{"id": t.ID}}, nil)
		}
		avail = append(avail, t.Name)
	}
	var issue struct {
		Fields struct {
			Status struct {
				Name           string `json:"name"`
				StatusCategory struct {
					Key string `json:"key"`
				} `json:"statusCategory"`
			} `json:"status"`
		} `json:"fields"`
	}
	if err := j.do(ctx, "GET", "/issue/"+url.PathEscape(key)+"?fields=status", nil, &issue); err != nil {
		return err
	}
	st := issue.Fields.Status
	if strings.EqualFold(st.Name, name) || st.StatusCategory.Key == "done" {
		return nil
	}
	return &PermanentError{fmt.Errorf("jira issue %s in status %q has no transition %q (available: %s)", key, st.Name, name, strings.Join(avail, ", "))}
}

// --- issue text

// jiraDoc is issue text in a form rendered as Atlassian Document Format
// (Cloud) or wiki markup (Data Center).
type jiraDoc []jiraBlock

// jiraBlock is a heading, a paragraph or a bullet list.
type jiraBlock struct {
	Heading string
	Para    []jiraInline
	List    [][]jiraInline
}

// jiraInline is text, linked when Href is set.
type jiraInline struct {
	Text string
	Href string
}

func plain(s string) []jiraInline { return []jiraInline{{Text: s}} }

// Limits that keep issue text bounded whatever the incident holds.
const (
	jiraMaxText     = 400
	jiraMaxListItem = 30
	jiraMaxSummary  = 250
)

// clip shortens s to n runes and removes control characters.
func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func (j *jiraClient) render(d jiraDoc) any {
	if j.cloud {
		return renderADF(d)
	}
	return renderWiki(d)
}

func renderADF(d jiraDoc) map[string]any {
	inl := func(xs []jiraInline) []map[string]any {
		var out []map[string]any
		for _, x := range xs {
			t := clip(x.Text, jiraMaxText)
			if t == "" {
				continue
			}
			n := map[string]any{"type": "text", "text": t}
			if x.Href != "" {
				n["marks"] = []map[string]any{{"type": "link", "attrs": map[string]string{"href": x.Href}}}
			}
			out = append(out, n)
		}
		return out
	}
	para := func(xs []jiraInline) map[string]any {
		p := map[string]any{"type": "paragraph"}
		if c := inl(xs); len(c) > 0 {
			p["content"] = c
		}
		return p
	}
	var content []map[string]any
	for _, b := range d {
		switch {
		case b.Heading != "":
			content = append(content, map[string]any{"type": "heading", "attrs": map[string]int{"level": 3}, "content": inl(plain(b.Heading))})
		case len(b.List) > 0:
			var items []map[string]any
			for _, it := range firstN(b.List, jiraMaxListItem) {
				items = append(items, map[string]any{"type": "listItem", "content": []map[string]any{para(it)}})
			}
			content = append(content, map[string]any{"type": "bulletList", "content": items})
		default:
			content = append(content, para(b.Para))
		}
	}
	return map[string]any{"type": "doc", "version": 1, "content": content}
}

// wikiEscape keeps text from being read as wiki markup (links, macros,
// formatting, images).
var wikiEscape = strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`, `{`, `\{`, `}`, `\}`, `|`, `\|`, `*`, `\*`, `_`, `\_`,
	`+`, `\+`, `^`, `\^`, `~`, `\~`, `!`, `\!`, `#`, `\#`, `-`, `\-`, `?`, `\?`)

func renderWiki(d jiraDoc) string {
	inl := func(xs []jiraInline) string {
		var b strings.Builder
		for _, x := range xs {
			t := wikiEscape.Replace(clip(x.Text, jiraMaxText))
			if x.Href != "" {
				b.WriteString("[" + t + "|" + strings.NewReplacer("|", "%7C", "]", "%5D", " ", "%20").Replace(x.Href) + "]")
			} else {
				b.WriteString(t)
			}
		}
		return b.String()
	}
	var parts []string
	for _, b := range d {
		switch {
		case b.Heading != "":
			parts = append(parts, "h3. "+inl(plain(b.Heading)))
		case len(b.List) > 0:
			var lines []string
			for _, it := range firstN(b.List, jiraMaxListItem) {
				lines = append(lines, "* "+inl(it))
			}
			parts = append(parts, strings.Join(lines, "\n"))
		default:
			parts = append(parts, inl(b.Para))
		}
	}
	return strings.Join(parts, "\n\n")
}
