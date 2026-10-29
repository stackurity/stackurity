package notify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// ServiceNow channels keep one record per incident (the incident table by
// default) through the Table API: created when the incident is announced,
// updated with a work note when findings join or leave, its priority
// changes (urgency and impact follow), it is acknowledged or escalates, and
// resolved when it resolves. The record's correlation_id names the
// workspace and incident (IncidentLabel); it is searched for before
// creating, so a retry after a lost reply finds the record instead of
// creating another. With sync_back, the record's state is read back, and a
// record closed in ServiceNow shows as such on the incident and is no
// longer updated.

const (
	SNAuthBasic = "basic"
	SNAuthOAuth = "oauth"
)

var (
	snNameRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,79}$`)
	snStateRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,40}$`)
	// snManaged are the fields Stackurity sets itself.
	snManaged = map[string]bool{
		"short_description": true, "description": true, "urgency": true, "impact": true, "priority": true, "state": true,
		"correlation_id": true, "correlation_display": true, "work_notes": true, "comments": true, "close_code": true,
		"close_notes": true, "sys_id": true, "number": true, "assignment_group": true, "category": true, "subcategory": true,
	}
	snLevels = map[string]bool{"1": true, "2": true, "3": true}
	// Defaults: with ServiceNow's default priority matrix, P1 1/1 is
	// priority 1, P2 1/2 is 2, P3 2/2 is 3 and P4 3/2 is 4.
	snDefaultUrgency = map[string]string{"P1": "1", "P2": "1", "P3": "2", "P4": "3"}
	snDefaultImpact  = map[string]string{"P1": "1", "P2": "2", "P3": "2", "P4": "2"}
)

// snMaxShort bounds short_description (160 characters by default).
const snMaxShort = 160

func validateServiceNow(c ChannelConfig, hasSecret, allowHTTP bool) error {
	if err := checkURL(c.URL, allowHTTP); err != nil {
		return fmt.Errorf("servicenow url: %w", err)
	}
	if u, _ := url.Parse(c.URL); u.RawQuery != "" || u.Fragment != "" || strings.Trim(u.Path, "/") != "" {
		return errors.New("servicenow url must be the instance's base URL, such as https://acme.service-now.com")
	}
	switch c.Auth {
	case "", SNAuthBasic:
		if strings.TrimSpace(c.Username) == "" {
			return errors.New("servicenow basic auth needs username (the password goes in secret_ref)")
		}
		if c.ClientID != "" {
			return errors.New("client_id is for auth oauth")
		}
	case SNAuthOAuth:
		if strings.TrimSpace(c.ClientID) == "" {
			return errors.New("servicenow oauth needs client_id (the client secret goes in secret_ref)")
		}
	default:
		return errors.New("auth must be basic or oauth")
	}
	if !hasSecret {
		return errors.New("set secret_ref to the ServiceNow password (basic) or OAuth client secret (oauth)")
	}
	if c.Table != "" && !snNameRe.MatchString(c.Table) {
		return errors.New("table must be a ServiceNow table name such as incident")
	}
	for name, v := range map[string]string{"assignment_group": c.AssignmentGroup, "category": c.Category, "subcategory": c.Subcategory, "close_code": c.CloseCode} {
		if len(v) > 100 || strings.ContainsAny(v, "^\r\n\t") {
			return fmt.Errorf("%s is too long or contains ^ or a line break", name)
		}
	}
	for label, m := range map[string]map[string]string{"urgency": c.Urgency, "impact": c.Impact} {
		for p, v := range m {
			if !priorityNames[p] {
				return fmt.Errorf("%s maps P1-P4, not %q", label, p)
			}
			if !snLevels[v] {
				return fmt.Errorf("%s for %s must be 1, 2 or 3", label, p)
			}
		}
	}
	if len(c.Fields) > 20 {
		return errors.New("at most 20 custom fields")
	}
	for k, v := range c.Fields {
		if !snNameRe.MatchString(k) {
			return fmt.Errorf("invalid field name %q: use the column name, such as u_business_service", k)
		}
		if snManaged[k] {
			return fmt.Errorf("field %s is set by Stackurity (use the mapping settings for assignment group, category, urgency and impact)", k)
		}
		if len(v) > 1000 {
			return fmt.Errorf("value of field %s is too long", k)
		}
	}
	if c.ResolveState != "" && !snStateRe.MatchString(c.ResolveState) {
		return errors.New("resolve_state must be a state value such as 6")
	}
	if len(c.ClosedStates) > 10 {
		return errors.New("at most 10 closed_states")
	}
	for _, st := range c.ClosedStates {
		if !snStateRe.MatchString(st) {
			return fmt.Errorf("invalid closed state %q", st)
		}
	}
	return nil
}

// tokenCache keeps OAuth access tokens per instance, client and secret.
type tokenCache struct {
	mu sync.Mutex
	m  map[string]cachedToken
}

type cachedToken struct {
	token string
	until time.Time
}

func (c *tokenCache) get(k string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.m[k]; ok && time.Now().Before(t.until) {
		return t.token
	}
	return ""
}

func (c *tokenCache) put(k, tok string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]cachedToken{}
	}
	c.m[k] = cachedToken{token: tok, until: time.Now().Add(ttl)}
}

func (c *tokenCache) drop(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, k)
}

type snClient struct {
	s      *Sender
	base   string
	cfg    ChannelConfig
	secret string
	table  string
	key    string // token cache key (oauth)
}

func (s *Sender) serviceNow(c ChannelConfig, secret string) (*snClient, error) {
	if err := checkURL(c.URL, s.AllowHTTP); err != nil {
		return nil, &PermanentError{fmt.Errorf("servicenow url: %w", err)}
	}
	if secret == "" {
		return nil, &PermanentError{errors.New("servicenow channel has no password or client secret: set secret_ref")}
	}
	sn := &snClient{s: s, base: strings.TrimRight(c.URL, "/"), cfg: c, secret: secret, table: c.Table}
	if sn.table == "" {
		sn.table = "incident"
	}
	if c.Auth == SNAuthOAuth {
		h := sha256.Sum256([]byte(secret))
		sn.key = sn.base + "\x00" + c.ClientID + "\x00" + hex.EncodeToString(h[:])
	}
	return sn, nil
}

// authorization returns the Authorization header, fetching an OAuth token
// when needed.
func (sn *snClient) authorization(ctx context.Context) (string, error) {
	if sn.cfg.Auth != SNAuthOAuth {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(sn.cfg.Username+":"+sn.secret)), nil
	}
	if t := sn.s.tokens.get(sn.key); t != "" {
		return "Bearer " + t, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {sn.cfg.ClientID}, "client_secret": {sn.secret}}
	req, err := http.NewRequestWithContext(ctx, "POST", sn.base+"/oauth_token.do", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity-notify")
	resp, err := sn.s.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("servicenow oauth token: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("servicenow oauth token: HTTP %d%s", resp.StatusCode, oauthErrorText(raw))
		switch {
		case resp.StatusCode == http.StatusTooManyRequests:
			return "", &RetryAfterError{Wait: retryAfter(resp.Header.Get("Retry-After"), time.Now(), time.Minute), Err: err}
		case resp.StatusCode >= 400 && resp.StatusCode < 500, resp.StatusCode >= 300 && resp.StatusCode < 400:
			return "", &PermanentError{fmt.Errorf("ServiceNow refused the OAuth client (check the client id and secret, and that its Application Registry entry allows the client credentials grant): %w", err)}
		}
		return "", err
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if json.Unmarshal(raw, &tok) != nil || tok.AccessToken == "" {
		return "", &PermanentError{errors.New("servicenow oauth token: the reply has no access_token")}
	}
	ttl := time.Duration(tok.ExpiresIn)*time.Second - time.Minute
	if ttl < time.Minute {
		ttl = time.Minute
	}
	sn.s.tokens.put(sn.key, tok.AccessToken, ttl)
	return "Bearer " + tok.AccessToken, nil
}

func oauthErrorText(raw []byte) string {
	var e struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Error == "" {
		return ""
	}
	s := e.Error
	if e.Description != "" && e.Description != e.Error {
		s += ": " + e.Description
	}
	return ": " + clip(s, 200)
}

// do sends one Table API request and decodes the reply's result into out.
func (sn *snClient) do(ctx context.Context, method, p string, q url.Values, body, out any) error {
	err := sn.once(ctx, method, p, q, body, out)
	var ae *snAuthError
	if errors.As(err, &ae) && sn.cfg.Auth == SNAuthOAuth && ae.cached {
		// The cached token may have been revoked or expired early.
		sn.s.tokens.drop(sn.key)
		err = sn.once(ctx, method, p, q, body, out)
	}
	return err
}

// snAuthError is a 401; cached says an OAuth token from the cache was used.
type snAuthError struct {
	err    error
	cached bool
}

func (e *snAuthError) Error() string { return e.err.Error() }
func (e *snAuthError) Unwrap() error { return e.err }

func (sn *snClient) once(ctx context.Context, method, p string, q url.Values, body, out any) error {
	cached := sn.cfg.Auth == SNAuthOAuth && sn.s.tokens.get(sn.key) != ""
	auth, err := sn.authorization(ctx)
	if err != nil {
		return err
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := sn.base + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity-notify")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := sn.s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("servicenow %s %s: %w", method, p, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
			return nil
		}
		var wrap struct {
			Result json.RawMessage `json:"result"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&wrap); err != nil || len(wrap.Result) == 0 {
			return fmt.Errorf("servicenow %s %s: invalid reply (is the URL the instance's base URL?)", method, p)
		}
		if err := json.Unmarshal(wrap.Result, out); err != nil {
			return fmt.Errorf("servicenow %s %s: invalid reply: %w", method, p, err)
		}
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	err = fmt.Errorf("servicenow %s %s: HTTP %d%s", method, p, resp.StatusCode, snErrorText(raw))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return &RetryAfterError{Wait: retryAfter(resp.Header.Get("Retry-After"), time.Now(), time.Minute), Err: fmt.Errorf("rate limited by ServiceNow: %w", err)}
	case resp.StatusCode == http.StatusServiceUnavailable:
		if h := resp.Header.Get("Retry-After"); h != "" {
			return &RetryAfterError{Wait: retryAfter(h, time.Now(), time.Minute), Err: err}
		}
	case resp.StatusCode == http.StatusUnauthorized:
		return &PermanentError{&snAuthError{err: fmt.Errorf("ServiceNow rejected the credentials (check the user name and password, or the OAuth client): %w", err), cached: cached}}
	case resp.StatusCode == http.StatusForbidden:
		table, _, _ := strings.Cut(strings.TrimPrefix(p, "/api/now/table/"), "/")
		return &PermanentError{fmt.Errorf("ServiceNow refused access: an access control rule (ACL) denies the account %s in table %s; give it a role that may read, create and update these records (such as itil): %w",
			verb(method), table, err)}
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return &PermanentError{fmt.Errorf("ServiceNow redirected the request (is the URL the instance's base URL, such as https://acme.service-now.com?): %w", err)}
	case resp.StatusCode == http.StatusBadRequest, resp.StatusCode == http.StatusNotFound:
		return &PermanentError{err}
	}
	return err
}

func verb(method string) string {
	switch method {
	case "POST":
		return "creating records"
	case "PATCH", "PUT":
		return "updating records"
	}
	return "reading records"
}

// snErrorText extracts ServiceNow's error message and detail.
func snErrorText(raw []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
			Detail  string `json:"detail"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil || e.Error.Message == "" {
		return "" // not ServiceNow's JSON (a proxy or login page): do not store the body
	}
	s := e.Error.Message
	if e.Error.Detail != "" {
		s += " (" + e.Error.Detail + ")"
	}
	return ": " + clip(s, 300)
}

func (sn *snClient) tablePath(sysID string) string {
	p := "/api/now/table/" + url.PathEscape(sn.table)
	if sysID != "" {
		p += "/" + url.PathEscape(sysID)
	}
	return p
}

// snRecord is a record as the Table API returns it with reference links
// excluded: field values are strings.
type snRecord map[string]any

func (r snRecord) str(k string) string {
	switch v := r[k].(type) {
	case string:
		return v
	case map[string]any: // a reference with its link
		s, _ := v["value"].(string)
		return s
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// Check verifies the credentials, read access to the table and, when set,
// that the assignment group exists, without creating anything.
func (sn *snClient) Check(ctx context.Context) error {
	var recs []snRecord
	if err := sn.do(ctx, "GET", sn.tablePath(""), url.Values{"sysparm_limit": {"1"}, "sysparm_fields": {"sys_id"}}, nil, &recs); err != nil {
		return err
	}
	if g := sn.cfg.AssignmentGroup; g != "" {
		var groups []snRecord
		q := url.Values{"sysparm_query": {"name=" + g + "^ORsys_id=" + g}, "sysparm_fields": {"sys_id,name"}, "sysparm_limit": {"1"}}
		if err := sn.do(ctx, "GET", "/api/now/table/sys_user_group", q, nil, &groups); err != nil {
			return fmt.Errorf("assignment group %q: %w", g, err)
		}
		if len(groups) == 0 {
			return fmt.Errorf("ServiceNow has no assignment group %q, or the account cannot read sys_user_group", g)
		}
	}
	return nil
}

// find returns the oldest record whose correlation_id is label.
func (sn *snClient) find(ctx context.Context, label string) (snRecord, error) {
	var recs []snRecord
	q := url.Values{"sysparm_query": {"correlation_id=" + label + "^ORDERBYsys_created_on"}, "sysparm_fields": {"sys_id,number,state"},
		"sysparm_limit": {"1"}, "sysparm_exclude_reference_link": {"true"}}
	if err := sn.do(ctx, "GET", sn.tablePath(""), q, nil, &recs); err != nil {
		return nil, err
	}
	if len(recs) == 0 {
		return nil, nil
	}
	return recs[0], nil
}

func (sn *snClient) create(ctx context.Context, fields map[string]any) (snRecord, error) {
	var rec snRecord
	q := url.Values{"sysparm_exclude_reference_link": {"true"}}
	if err := sn.do(ctx, "POST", sn.tablePath(""), q, fields, &rec); err != nil {
		return nil, err
	}
	if rec.str("sys_id") == "" {
		return nil, errors.New("servicenow created a record but did not return its sys_id")
	}
	return rec, nil
}

func (sn *snClient) update(ctx context.Context, sysID string, fields map[string]any) (snRecord, error) {
	var rec snRecord
	q := url.Values{"sysparm_exclude_reference_link": {"true"}}
	if err := sn.do(ctx, "PATCH", sn.tablePath(sysID), q, fields, &rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// hasNote reports whether the record's work notes contain marker, so a
// retried delivery does not add its note twice.
func (sn *snClient) hasNote(ctx context.Context, sysID, marker string) (bool, error) {
	var rec snRecord
	q := url.Values{"sysparm_fields": {"work_notes"}, "sysparm_display_value": {"true"}}
	if err := sn.do(ctx, "GET", sn.tablePath(sysID), q, nil, &rec); err != nil {
		return false, err
	}
	return strings.Contains(rec.str("work_notes"), marker), nil
}

// states reads the state of records by sys_id. Records missing from the
// reply were deleted or are hidden from the account.
func (sn *snClient) states(ctx context.Context, sysIDs []string) (map[string]string, error) {
	var recs []snRecord
	q := url.Values{"sysparm_query": {"sys_idIN" + strings.Join(sysIDs, ",")}, "sysparm_fields": {"sys_id,state"},
		"sysparm_limit": {fmt.Sprint(len(sysIDs))}, "sysparm_exclude_reference_link": {"true"}}
	if err := sn.do(ctx, "GET", sn.tablePath(""), q, nil, &recs); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, r := range recs {
		out[r.str("sys_id")] = r.str("state")
	}
	return out, nil
}

func (sn *snClient) recordURL(sysID string) string {
	return sn.base + "/" + url.PathEscape(sn.table) + ".do?sys_id=" + url.QueryEscape(sysID)
}

func (c ChannelConfig) snUrgency(p string) string {
	if v := c.Urgency[p]; v != "" {
		return v
	}
	return snDefaultUrgency[p]
}

func (c ChannelConfig) snImpact(p string) string {
	if v := c.Impact[p]; v != "" {
		return v
	}
	return snDefaultImpact[p]
}

func (c ChannelConfig) snResolveState() string {
	if c.ResolveState != "" {
		return c.ResolveState
	}
	return "6"
}

func (c ChannelConfig) snCloseCode() string {
	if c.CloseCode != "" {
		return c.CloseCode
	}
	return "Solution provided"
}

// snClosedState names a record's state when it counts as closed in
// ServiceNow, and "" otherwise.
func (c ChannelConfig) snClosedState(state string) string {
	closed := c.ClosedStates
	if len(closed) == 0 {
		closed = []string{"6", "7", "8"}
	}
	for _, s := range closed {
		if s == state {
			switch state {
			case "6":
				return "resolved"
			case "7":
				return "closed"
			case "8":
				return "canceled"
			}
			return "closed (state " + state + ")"
		}
	}
	return ""
}

// droppedFields lists the fields set on create that the created record
// does not have: ServiceNow ignores fields the account may not write (a
// field ACL) or that do not exist, without an error.
func droppedFields(sent map[string]any, rec snRecord) []string {
	var out []string
	for k, v := range sent {
		if snManaged[k] && k != "assignment_group" && k != "category" && k != "subcategory" && k != "correlation_id" {
			continue
		}
		if s, _ := v.(string); s != "" && rec.str(k) == "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// renderText renders issue text as plain text (ServiceNow descriptions and
// work notes).
func renderText(d jiraDoc) string {
	inl := func(xs []jiraInline) string {
		var b strings.Builder
		for _, x := range xs {
			b.WriteString(clip(x.Text, jiraMaxText))
			if x.Href != "" {
				b.WriteString(" (" + x.Href + ")")
			}
		}
		return b.String()
	}
	var parts []string
	for _, b := range d {
		switch {
		case b.Heading != "":
			parts = append(parts, strings.ToUpper(clip(b.Heading, jiraMaxText)))
		case len(b.List) > 0:
			var lines []string
			for _, it := range firstN(b.List, jiraMaxListItem) {
				lines = append(lines, "- "+inl(it))
			}
			parts = append(parts, strings.Join(lines, "\n"))
		default:
			parts = append(parts, inl(b.Para))
		}
	}
	return strings.Join(parts, "\n\n")
}
