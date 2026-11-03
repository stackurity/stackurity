package api

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/feedback"
	"github.com/stackurity/stackurity/internal/store"
)

// Feedback lets a signed-in user send a message to the Stackurity team from
// the dashboard. The server forwards it to STACKURITY_FEEDBACK_URL (the
// project's website by default), which hands it to the team's queue. Only
// what the user typed or attached (kind, message, email if given, up to
// three files) is sent, plus the path of the page they were on, the browser
// and window size, the version and the edition: never workspace or asset
// names, findings, hostnames or this installation's URL. Nothing is sent
// unless a user presses Send, and an empty STACKURITY_FEEDBACK_URL turns the
// feature off.
//
// Attachments are checked by content here first (type, size), and images
// lose their metadata (EXIF, location) before they leave the installation.
// The queue answers with a reference (FB-123) and a status token, kept in
// feedback_sent so "My feedback" can show the status.

// DefaultFeedbackURL receives feedback unless STACKURITY_FEEDBACK_URL says
// otherwise.
const DefaultFeedbackURL = "https://stackurity.dev/feedback"

const (
	feedbackMaxMessage = 5000
	feedbackTimeout    = 10 * time.Second
	// feedbackUploadTimeout bounds a send with attachments.
	feedbackUploadTimeout = 5 * time.Minute
	// feedbackStatusAge is how old a stored status may be before My
	// feedback asks the queue again.
	feedbackStatusAge = 5 * time.Minute
)

// limitFeedback caps what one user can send.
var limitFeedback = rateLimit{10, time.Hour}

// feedbackUploads bounds sends with attachments at once on this server
// (each holds up to 90 MB in memory); more are asked to try again.
var feedbackUploads = make(chan struct{}, 2)

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
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	Email    string `json:"email"`
	Page     string `json:"page"`
	Viewport string `json:"viewport"`
}

// feedbackPayload is exactly what leaves the installation (as JSON, or as
// the "item" part when there are attachments).
type feedbackPayload struct {
	Kind     string `json:"kind"`
	Message  string `json:"message"`
	Email    string `json:"email,omitempty"`
	Page     string `json:"page,omitempty"`
	Browser  string `json:"browser,omitempty"`
	Viewport string `json:"viewport,omitempty"`
	Version  string `json:"version"`
	Edition  string `json:"edition"`
	Hosting  string `json:"hosting"`
	Source   string `json:"source"`
}

// itemPart is the payload in the queue's field names.
func (p feedbackPayload) itemPart() intakeItem {
	return intakeItem{Kind: p.Kind, Description: p.Message, Email: p.Email, Page: p.Page, Browser: p.Browser,
		Viewport: p.Viewport, Version: p.Version, Edition: p.Edition, Hosting: p.Hosting, Source: p.Source}
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

var (
	uaBrowsers = []struct{ name, re string }{
		{"Edge", `Edg/([0-9]+)`}, {"Opera", `OPR/([0-9]+)`}, {"Firefox", `Firefox/([0-9]+)`},
		{"Chrome", `(?:Chrome|CriOS)/([0-9]+)`}, {"Safari", `Version/([0-9]+)[0-9.]* .*Safari/`},
	}
	uaOS = []struct{ name, re string }{
		{"Android", `Android`}, {"iOS", `iPhone|iPad|iPod`}, {"Windows", `Windows`}, {"macOS", `Macintosh|Mac OS X`},
		{"ChromeOS", `CrOS`}, {"Linux", `Linux`},
	}
)

// browserSummary reduces a User-Agent to "Chrome 131 on macOS": enough to
// reproduce a layout problem, not enough to tell people apart.
func browserSummary(ua string) string {
	name := ""
	for _, b := range uaBrowsers {
		if m := regexp.MustCompile(b.re).FindStringSubmatch(ua); m != nil {
			name = b.name + " " + m[1]
			break
		}
	}
	for _, o := range uaOS {
		if regexp.MustCompile(o.re).MatchString(ua) {
			if name == "" {
				return o.name
			}
			return name + " on " + o.name
		}
	}
	return name
}

func validateFeedback(req feedbackRequest) (feedbackPayload, error) {
	out := feedbackPayload{Source: "app"}
	var ok bool
	if out.Kind, ok = feedbackKind(req.Kind); !ok {
		return out, badRequest("kind must be issue, feature or question")
	}
	out.Message = strings.TrimSpace(req.Message)
	if out.Message == "" {
		return out, badRequest("write a description")
	}
	if !utf8.ValidString(out.Message) {
		return out, badRequest("the description is not valid text")
	}
	if utf8.RuneCountInString(out.Message) > feedbackMaxMessage {
		return out, badRequest(fmt.Sprintf("keep the description under %d characters", feedbackMaxMessage))
	}
	if e := strings.TrimSpace(req.Email); e != "" {
		addr, err := mail.ParseAddress(e)
		if err != nil || addr.Address != e || len(e) > 200 {
			return out, badRequest("the email address is not valid; leave it empty to send without one")
		}
		out.Email = e
	}
	out.Page = feedbackPage(req.Page)
	if feedbackViewport.MatchString(req.Viewport) {
		out.Viewport = req.Viewport
	}
	return out, nil
}

var errFeedbackUpstream = errors.New("feedback service")

// upstreamProblem is a refusal from the feedback service that the user can
// act on (an attachment too large, of the wrong type, storage full).
type upstreamProblem struct {
	status int
	msg    string
}

func (e *upstreamProblem) Error() string { return e.msg }

// feedbackAttachment is one checked file, ready to forward.
type feedbackAttachment struct {
	kind feedback.Kind
	name string
	data []byte
}

// readFeedbackForm reads the dashboard's multipart form: text fields first,
// then up to three files named attachment. Each file is checked by its
// content and size, and images are stripped of metadata, before anything
// is sent.
func readFeedbackForm(w http.ResponseWriter, r *http.Request) (feedbackRequest, []feedbackAttachment, error) {
	var req feedbackRequest
	var files []feedbackAttachment
	r.Body = http.MaxBytesReader(w, r.Body, feedback.MaxTotalBytes+64<<10)
	mr, err := r.MultipartReader()
	if err != nil {
		return req, nil, badRequest("send multipart/form-data")
	}
	var total int64
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			return req, files, nil
		}
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return req, nil, &feedback.TooLarge{Total: true}
			}
			return req, nil, badRequest("the form could not be read")
		}
		name := part.FormName()
		if name != "attachment" {
			if len(files) > 0 {
				return req, nil, badRequest("send the text fields before the files")
			}
			b, err := io.ReadAll(io.LimitReader(part, 32<<10))
			if err != nil {
				return req, nil, badRequest("the form could not be read")
			}
			v := string(b)
			switch name {
			case "kind":
				req.Kind = v
			case "message":
				req.Message = v
			case "email":
				req.Email = v
			case "page":
				req.Page = v
			case "viewport":
				req.Viewport = v
			default:
				return req, nil, badRequest("unexpected field " + oneLinePrintable(name, 40))
			}
			continue
		}
		if len(files) == feedback.MaxFiles {
			return req, nil, badRequest(fmt.Sprintf("attach at most %d files", feedback.MaxFiles))
		}
		br := bufio.NewReaderSize(part, 4096)
		head, _ := br.Peek(feedback.SniffBytes)
		k, err := feedback.Detect(head)
		if err != nil {
			return req, nil, badRequest(fmt.Sprintf("%s: %v", feedback.SafeName(part.FileName(), "bin"), err))
		}
		limit := min(k.MaxBytes(), feedback.MaxTotalBytes-total)
		data, err := io.ReadAll(io.LimitReader(br, limit+1))
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				return req, nil, &feedback.TooLarge{Total: true}
			}
			return req, nil, badRequest("the form could not be read")
		}
		if int64(len(data)) > limit {
			return req, nil, &feedback.TooLarge{Kind: k, Total: limit < k.MaxBytes()}
		}
		if k.Image() {
			if data, err = feedback.StripImage(k, data); err != nil {
				return req, nil, badRequest(feedback.SafeName(part.FileName(), k) + ": " + err.Error())
			}
		}
		total += int64(len(data))
		files = append(files, feedbackAttachment{kind: k, name: feedback.SafeName(part.FileName(), k), data: data})
	}
}

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
	// Counted before the body is read, so refused uploads cost the
	// sender their allowance too.
	if s.limited(w, r, "you have sent a lot of feedback; try again in an hour", limitHit{"feedback", itoa(p.User.ID), limitFeedback}) {
		return
	}
	var req feedbackRequest
	var files []feedbackAttachment
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		select {
		case feedbackUploads <- struct{}{}:
			defer func() { <-feedbackUploads }()
		default:
			writeError(w, 503, "busy", "another upload is being sent; try again in a minute")
			return
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(time.Now().Add(feedbackUploadTimeout))
		_ = rc.SetWriteDeadline(time.Now().Add(feedbackUploadTimeout + time.Minute))
		var err error
		if req, files, err = readFeedbackForm(w, r); err != nil {
			var tl *feedback.TooLarge
			if errors.As(err, &tl) {
				writeError(w, 413, "too_large", tl.Error())
				return
			}
			s.fail(w, r, err)
			return
		}
	} else if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := validateFeedback(req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.Version = s.Version
	out.Edition = string(s.Gate.Edition(r.Context()))
	out.Browser = browserSummary(r.UserAgent())
	out.Hosting = "self_hosted"
	if s.InviteOnly {
		// Stackurity Cloud (the hosted edition sets InviteOnly).
		out.Hosting = "cloud"
	}
	reply, status, err := s.forwardFeedback(r.Context(), out, files)
	if err != nil {
		var up *upstreamProblem
		switch {
		case errors.As(err, &up):
			writeError(w, up.status, "feedback_refused", up.msg)
		case status == http.StatusTooManyRequests:
			writeError(w, 429, "rate_limited", "the feedback service is busy; try again later")
		default:
			s.Log.Warn("feedback not delivered", "err", err, "upstream_status", status)
			msg := "the feedback could not be delivered; try again later, or email info@stackurity.ai"
			if len(files) > 0 {
				msg = "the feedback could not be delivered; try again later or send it without attachments"
			}
			writeError(w, 502, "feedback_unavailable", msg)
		}
		return
	}
	res := map[string]any{"status": "sent"}
	if reply.Ref != "" && feedbackRefPattern.MatchString(reply.Ref) && feedbackTokenPattern.MatchString(reply.Token) {
		if err := s.Store.AddFeedbackSent(r.Context(), p.User.ID, store.FeedbackSent{Ref: reply.Ref, Token: reply.Token,
			Kind: out.Kind, Summary: summarise(out.Message, 120), Attachments: len(files)}); err != nil {
			s.Log.Warn("feedback sent but not recorded for My feedback", "ref", reply.Ref, "err", err)
		}
		res["ref"] = reply.Ref
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "feedback.send", "feedback", reply.Ref, map[string]any{"kind": out.Kind, "attachments": len(files)})
	writeJSON(w, 202, res)
}

var (
	feedbackRefPattern   = regexp.MustCompile(`^FB-[0-9]{1,18}$`)
	feedbackTokenPattern = regexp.MustCompile(`^fbs_[a-z2-7]{52}$`)
)

// summarise returns the first line of s, at most n characters.
func summarise(s string, n int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if r := []rune(s); len(r) > n {
		return strings.TrimSpace(string(r[:n-1])) + "…"
	}
	return s
}

// feedbackReply is what the feedback service answers; ref and token are
// set when the queue stored the item.
type feedbackReply struct {
	Ref   string `json:"ref"`
	Token string `json:"token"`
}

func (s *Server) feedbackClient(timeout time.Duration) *http.Client {
	if s.FeedbackHTTP != nil {
		return s.FeedbackHTTP
	}
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// forwardFeedback sends the payload: JSON without attachments (what any
// receiver of the documented JSON accepts), multipart with them.
func (s *Server) forwardFeedback(ctx context.Context, out feedbackPayload, files []feedbackAttachment) (feedbackReply, int, error) {
	var body io.Reader
	contentType := "application/json"
	timeout := feedbackTimeout
	if len(files) == 0 {
		// The kinds' older names, which every version of the receiver
		// accepts (the queue maps them back).
		legacy := out
		legacy.Kind = map[string]string{"issue": "bug", "feature": "idea", "question": "question"}[out.Kind]
		b, err := json.Marshal(legacy)
		if err != nil {
			return feedbackReply{}, 0, err
		}
		body = bytes.NewReader(b)
	} else {
		// Streamed: the files are already in memory once, not twice.
		timeout = feedbackUploadTimeout
		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		contentType = mw.FormDataContentType()
		go func() { pw.CloseWithError(writeFeedbackParts(mw, out, files)) }()
		defer pr.Close()
		body = pr
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", s.FeedbackURL, body)
	if err != nil {
		return feedbackReply{}, 0, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackurity")
	resp, err := s.feedbackClient(timeout).Do(req)
	if err != nil {
		return feedbackReply{}, 0, fmt.Errorf("%w: %v", errFeedbackUpstream, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode/100 != 2 {
		// The queue's refusals of attachments (type, size, storage full)
		// are for the user; other failures are reported generically.
		switch resp.StatusCode {
		case 400, 413, 415, 507:
			if msg := upstreamMessage(raw); msg != "" {
				st := resp.StatusCode
				if st == 507 {
					st = 503
				}
				return feedbackReply{}, resp.StatusCode, &upstreamProblem{status: st, msg: msg}
			}
		}
		return feedbackReply{}, resp.StatusCode, fmt.Errorf("%w answered %s", errFeedbackUpstream, resp.Status)
	}
	var reply feedbackReply
	_ = json.Unmarshal(raw, &reply)
	return reply, resp.StatusCode, nil
}

// writeFeedbackParts writes the item part, then the files.
func writeFeedbackParts(mw *multipart.Writer, out feedbackPayload, files []feedbackAttachment) error {
	h := textproto.MIMEHeader{}
	h.Set("Content-Disposition", `form-data; name="item"`)
	h.Set("Content-Type", "application/json")
	pw, err := mw.CreatePart(h)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(pw).Encode(out.itemPart()); err != nil {
		return err
	}
	for _, f := range files {
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="attachment"; filename="%s"`, f.name))
		h.Set("Content-Type", f.kind.ContentType())
		pw, err := mw.CreatePart(h)
		if err != nil {
			return err
		}
		if _, err := pw.Write(f.data); err != nil {
			return err
		}
	}
	return mw.Close()
}

// upstreamMessage reads {"error":"..."} or {"error":{"message":"..."}},
// shortened to one line.
func upstreamMessage(raw []byte) string {
	var v struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(raw, &v) != nil || len(v.Error) == 0 {
		return ""
	}
	var msg string
	if json.Unmarshal(v.Error, &msg) != nil {
		var obj struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(v.Error, &obj)
		msg = obj.Message
	}
	return oneLinePrintable(msg, 200)
}

// feedbackStatusURL is where the status of sent items is asked:
// STACKURITY_FEEDBACK_URL followed by /status.
func (s *Server) feedbackStatusURL() string {
	u, err := url.Parse(s.FeedbackURL)
	if err != nil {
		return ""
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/status"
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

// myFeedback lists what the caller sent, with each item's status. Statuses
// older than five minutes of items still open are asked again (one request,
// with the items' tokens only).
func (s *Server) myFeedback(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p.User == nil || p.Workspace == 0 {
		writeJSON(w, 200, map[string]any{"items": []any{}})
		return
	}
	items, err := s.Store.ListFeedbackSent(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var stale []int
	for i, it := range items {
		closed := it.Status == "released" || it.Status == "wont_fix" || it.Status == "duplicate"
		if !closed && (it.CheckedAt == nil || time.Since(*it.CheckedAt) > feedbackStatusAge) {
			stale = append(stale, i)
		}
	}
	checkFailed := false
	if len(stale) > 0 && s.FeedbackURL != "" {
		if err := s.refreshFeedbackStatus(r.Context(), items, stale); err != nil {
			s.Log.Warn("feedback status not checked", "err", err)
			checkFailed = true
		}
	}
	if items == nil {
		items = []store.FeedbackSent{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "check_failed": checkFailed})
}

func (s *Server) refreshFeedbackStatus(ctx context.Context, items []store.FeedbackSent, idx []int) error {
	type ask struct {
		Ref   string `json:"ref"`
		Token string `json:"token"`
	}
	req := struct {
		Items []ask `json:"items"`
	}{}
	byRef := map[string]int{}
	for _, i := range idx {
		if len(req.Items) == 50 {
			break
		}
		req.Items = append(req.Items, ask{items[i].Ref, items[i].Token})
		byRef[items[i].Ref] = i
	}
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(ctx, feedbackTimeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, "POST", s.feedbackStatusURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("User-Agent", "stackurity")
	resp, err := s.feedbackClient(feedbackTimeout).Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%w answered %s", errFeedbackUpstream, resp.Status)
	}
	var res struct {
		Items []store.FeedbackPublic `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&res); err != nil {
		return err
	}
	for _, st := range res.Items {
		i, ok := byRef[st.Ref]
		if !ok {
			continue
		}
		it := &items[i]
		switch st.Status {
		case "received", "reviewing", "in_progress", "fixed", "released", "wont_fix", "duplicate", "unknown":
		default:
			continue
		}
		note := oneLineKeepBreaks(st.Resolution, 2000)
		fixed := ""
		if feedbackVersion.MatchString(st.FixedIn) {
			fixed = st.FixedIn
		}
		var at *time.Time
		if !st.UpdatedAt.IsZero() {
			t := st.UpdatedAt
			at = &t
		}
		if err := s.Store.SetFeedbackSentStatus(ctx, it.ID, st.Status, note, fixed, at); err != nil {
			return err
		}
		now := time.Now()
		it.Status, it.StatusNote, it.FixedIn, it.StatusAt, it.CheckedAt = st.Status, note, fixed, at, &now
	}
	return nil
}

// oneLineKeepBreaks keeps text from the queue at most n runes, valid UTF-8.
func oneLineKeepBreaks(s string, n int) string {
	s = strings.ToValidUTF8(s, "")
	if r := []rune(s); len(r) > n {
		s = string(r[:n])
	}
	return s
}
