package api

// The feedback queue: where feedback from every Stackurity installation,
// Stackurity Cloud and the website ends up, for the Stackurity team to
// triage. Only the team's own server runs it (STACKURITY_FEEDBACK_QUEUE_DIR).
//
//   - The website (stackurity.dev/feedback) relays what installations send
//     to POST /api/v1/feedback-queue/intake, with a shared key; status
//     lookups by the sender's token go to POST /api/v1/feedback-queue/status
//     the same way. Neither is reachable without the key.
//   - Operators (instance administrators) and the triage agent's token read
//     and update items under /api/v1/admin/feedback. A triage token works on
//     those routes only (authenticate refuses it everywhere else).
//   - Attachments are served only through signed links that expire after
//     ten minutes, as downloads, never rendered by the browser.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/feedback"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
)

// FeedbackQueue configures the queue; nil on a Server turns it off.
type FeedbackQueue struct {
	Disk *feedback.Disk
	// IntakeKey is shared with the website relay
	// (STACKURITY_FEEDBACK_INTAKE_KEY); it also derives the key that signs
	// attachment links.
	IntakeKey string
	// StorageMax caps the attachments kept, in bytes
	// (STACKURITY_FEEDBACK_STORAGE_MAX_MB).
	StorageMax int64
	// LinkKey signs attachment links (STACKURITY_FEEDBACK_LINK_KEY); the
	// website relay never holds it. Empty uses a random key per process,
	// so links work only on the replica that made them.
	LinkKey string
	// ScanRequired holds new attachments as pending until the on-demand
	// virus scanner (deploy/feedback-scan) reports them clean
	// (STACKURITY_FEEDBACK_SCAN=required); until then operators and the
	// triage agent do not see them.
	ScanRequired bool
	// Emails sends the sender one short email when their item is released
	// or will not be fixed (STACKURITY_FEEDBACK_EMAILS=on); off by default
	// until the owner approves the wording.
	Emails bool

	once     sync.Once
	linkKey  []byte
	inflight atomic.Int64 // bytes written by intakes not yet committed
	uploads  chan struct{}
}

func (q *FeedbackQueue) init() {
	q.once.Do(func() {
		if q.LinkKey != "" {
			k := sha256.Sum256([]byte("stackurity feedback attachment link\x00" + q.LinkKey))
			q.linkKey = k[:]
		} else {
			q.linkKey = make([]byte, 32)
			if _, err := rand.Read(q.linkKey); err != nil {
				panic(err)
			}
		}
		q.uploads = make(chan struct{}, feedbackIntakeConcurrency)
	})
}

const (
	// FeedbackTokenPrefix starts a triage agent's token.
	FeedbackTokenPrefix = "stkfb"
	// feedbackStatusPrefix starts the sender's status token.
	feedbackStatusPrefix = "fbs"
	feedbackLinkTTL      = 10 * time.Minute
	feedbackIntakeBody   = feedback.MaxTotalBytes + 2<<20
	feedbackItemJSON     = 16 << 10
	// feedbackIntakeConcurrency bounds intakes at once (each holds at most
	// one 10 MB image in memory); more get 503 and the sender retries.
	feedbackIntakeConcurrency = 8
)

var (
	limitFeedbackIntakeIP  = rateLimit{30, time.Hour}
	limitFeedbackIntakeAll = rateLimit{300, time.Hour}
	limitFeedbackStatus    = rateLimit{3000, time.Hour}
	limitFeedbackDownload  = rateLimit{120, time.Minute}
	// limitFeedbackIntakeFiles caps items with attachments per sender.
	limitFeedbackIntakeFiles = rateLimit{10, time.Hour}
	// limitFeedbackStatusIP caps status checks per sender address.
	limitFeedbackStatusIP = rateLimit{120, time.Hour}
)

// feedbackAgentPath reports whether a triage token may be used on path.
func feedbackAgentPath(path string) bool {
	return path == "/api/v1/admin/feedback" || strings.HasPrefix(path, "/api/v1/admin/feedback/")
}

func (q *FeedbackQueue) keyOK(r *http.Request) bool {
	got := r.Header.Get("X-Stackurity-Feedback-Key")
	return q != nil && q.IntakeKey != "" && got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(q.IntakeKey)) == 1
}

func (q *FeedbackQueue) linkSig(item, aid, exp int64) string {
	q.init()
	m := hmac.New(sha256.New, q.linkKey)
	fmt.Fprintf(m, "%d:%d:%d", item, aid, exp)
	return hex.EncodeToString(m.Sum(nil))
}

// feedbackQueueRoutes are outside the session and CSRF checks: the intake
// and status routes need the relay's key, the download a signed link.
func (s *Server) feedbackQueueRoutes(r chi.Router) {
	r.Post("/api/v1/feedback-queue/intake", s.feedbackIntake)
	r.Post("/api/v1/feedback-queue/status", s.feedbackQueueStatus)
	r.With(s.limitAddress("feedback-download", limitFeedbackDownload, "too many downloads; wait a minute")).
		Get("/feedback-attachments/{id}", s.feedbackDownload)
}

// feedbackOperatorRoutes are inside /api/v1 (authenticated).
func (s *Server) feedbackOperatorRoutes(r chi.Router) {
	r.Route("/admin/feedback", func(r chi.Router) {
		// The on-demand virus scanner (deploy/feedback-scan): its own token
		// scope, which reaches these two routes only.
		r.With(requireFeedbackScanner).Get("/scan/pending", s.feedbackScanPending)
		r.With(requireFeedbackScanner).Post("/scan/{aid}", s.feedbackScanResult)
		r.Group(func(r chi.Router) {
			r.Use(requireFeedbackOperator)
			s.feedbackTriageRoutes(r)
		})
	})
	r.Route("/admin/feedback-tokens", func(r chi.Router) {
		r.Use(requireInstanceAdmin)
		r.Get("/", s.listFeedbackTokens)
		r.Post("/", s.createFeedbackToken)
		r.Delete("/{id}", s.revokeFeedbackToken)
	})
}

// feedbackTriageRoutes are for instance administrators and triage tokens.
func (s *Server) feedbackTriageRoutes(r chi.Router) {
	r.Get("/", s.listFeedbackQueue)
	r.Get("/email-templates", s.feedbackEmailTemplates)
	r.Get("/{id}", s.getFeedbackQueueItem)
	r.Patch("/{id}", s.updateFeedbackQueueItem)
	r.Post("/{id}/attachments/{aid}/link", s.feedbackAttachmentLink)
	// Deleting (spam, abuse) is for instance administrators only.
	r.With(requireInstanceAdmin).Delete("/{id}", s.deleteFeedbackQueueItem)
}

// Feedback token scopes.
const (
	feedbackScopeTriage  = "triage"
	feedbackScopeScanner = "scanner"
)

// requireFeedbackScope allows instance administrators and feedback tokens
// of one scope; a token of the other scope gets 403.
func requireFeedbackScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		admin := requireInstanceAdmin(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p := principal(r); p != nil && p.FeedbackAgent != nil {
				if p.FeedbackAgent.Scope != scope {
					writeError(w, 403, "forbidden", "this feedback token's scope does not allow it")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			admin.ServeHTTP(w, r)
		})
	}
}

var (
	// requireFeedbackOperator: instance administrators and triage tokens.
	requireFeedbackOperator = requireFeedbackScope(feedbackScopeTriage)
	// requireFeedbackScanner: instance administrators and scanner tokens.
	requireFeedbackScanner = requireFeedbackScope(feedbackScopeScanner)
)

func (s *Server) queueOn(w http.ResponseWriter) bool {
	if s.FeedbackQueue == nil {
		writeError(w, 404, "not_found", "this server does not run the feedback queue")
		return false
	}
	return true
}

func feedbackActor(r *http.Request) string {
	p := principal(r)
	switch {
	case p == nil:
		return "unknown"
	case p.FeedbackAgent != nil:
		return "agent:" + p.FeedbackAgent.Name
	case p.User != nil:
		return p.User.Email
	}
	return "unknown"
}

// intakeItem is the "item" part the relay sends.
type intakeItem struct {
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Email       string `json:"email"`
	Page        string `json:"page"`
	Browser     string `json:"browser"`
	Viewport    string `json:"viewport"`
	Version     string `json:"version"`
	Edition     string `json:"edition"`
	Hosting     string `json:"hosting"`
	Source      string `json:"source"`
}

var (
	feedbackVersion  = regexp.MustCompile(`^(dev|test|v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?)$`)
	feedbackViewport = regexp.MustCompile(`^[0-9]{2,5}x[0-9]{2,5}$`)
)

// relaySender is the sender's address the relay reports (trusted only
// after the key was checked); "unknown" when it gives none.
func relaySender(r *http.Request) string {
	if a, err := netip.ParseAddr(r.Header.Get("X-Stackurity-Feedback-Client-IP")); err == nil {
		return a.String()
	}
	return "unknown"
}

// feedbackKind maps the form's kinds (and the older ones) to the queue's.
func feedbackKind(k string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "issue", "bug":
		return "issue", true
	case "feature", "idea":
		return "feature", true
	case "question":
		return "question", true
	}
	return "", false
}

// oneLinePrintable keeps printable characters on one line, at most n runes.
func oneLinePrintable(s string, n int) string {
	var b strings.Builder
	i := 0
	for _, r := range s {
		if i >= n {
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
			i++
		}
	}
	return strings.TrimSpace(b.String())
}

func validateIntake(in intakeItem) (store.NewFeedbackItem, error) {
	var out store.NewFeedbackItem
	var ok bool
	if out.Kind, ok = feedbackKind(in.Kind); !ok {
		return out, badRequest("kind must be issue, feature or question")
	}
	out.Description = strings.TrimSpace(in.Description)
	if out.Description == "" || !utf8.ValidString(out.Description) || utf8.RuneCountInString(out.Description) > feedbackMaxMessage {
		return out, badRequest(fmt.Sprintf("the description must be text of 1 to %d characters", feedbackMaxMessage))
	}
	if e := strings.TrimSpace(in.Email); e != "" {
		addr, err := mail.ParseAddress(e)
		if err != nil || addr.Address != e || len(e) > 200 {
			return out, badRequest("the email address is not valid")
		}
		out.ContactEmail = e
	}
	out.Page = feedbackPage(in.Page)
	out.Browser = oneLinePrintable(in.Browser, 80)
	if feedbackViewport.MatchString(in.Viewport) {
		out.Viewport = in.Viewport
	}
	if len(in.Version) <= 40 && feedbackVersion.MatchString(in.Version) {
		out.Version = in.Version
	}
	switch in.Edition {
	case "community", "pro", "enterprise":
		out.Edition = in.Edition
	}
	switch {
	case in.Source == "web":
		out.Source = "website"
	case in.Source == "app" && in.Hosting == "cloud":
		out.Source = "cloud"
	case in.Source == "app":
		out.Source = "self_hosted"
	default:
		return out, badRequest("source must be app or web")
	}
	return out, nil
}

// feedbackIntake stores one item from the relay: the "item" part, then up
// to three "attachment" parts, each checked by content, stripped of
// metadata (images) and written under a random name.
func (s *Server) feedbackIntake(w http.ResponseWriter, r *http.Request) {
	q := s.FeedbackQueue
	if !s.queueOn(w) {
		return
	}
	if !q.keyOK(r) {
		writeError(w, 401, "unauthorized", "missing or wrong intake key")
		return
	}
	sender := relaySender(r)
	if s.limited(w, r, "too much feedback; try again in an hour",
		limitHit{"feedback-intake-ip", sender, limitFeedbackIntakeIP}, limitHit{"feedback-intake", "all", limitFeedbackIntakeAll}) {
		return
	}
	q.init()
	select {
	case q.uploads <- struct{}{}:
		defer func() { <-q.uploads }()
	default:
		writeError(w, 503, "busy", "the feedback queue is busy; try again in a minute")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(10 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(11 * time.Minute))
	r.Body = http.MaxBytesReader(w, r.Body, feedbackIntakeBody)
	mr, err := r.MultipartReader()
	if err != nil {
		writeError(w, 400, "bad_request", "send multipart/form-data")
		return
	}
	var keys []string
	var reserved int64
	defer func() { q.inflight.Add(-reserved) }()
	cleanup := func() {
		for _, k := range keys {
			_ = q.Disk.Remove(k)
		}
	}
	fail := func(err error) {
		cleanup()
		var tl *feedback.TooLarge
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &tl):
			writeError(w, 413, "too_large", tl.Error())
		case errors.As(err, &mbe):
			writeError(w, 413, "too_large", (&feedback.TooLarge{Total: true}).Error())
		case errors.Is(err, errFeedbackStorageFull):
			writeError(w, 507, "storage_full", err.Error())
		case errors.Is(err, feedback.ErrUnsupported), errors.Is(err, feedback.ErrBadImage):
			writeError(w, 415, "unsupported", err.Error())
		case errors.Is(err, feedback.ErrTooManyPixels):
			writeError(w, 413, "too_large", err.Error())
		default:
			s.fail(w, r, err)
		}
	}

	part, err := mr.NextPart()
	if err != nil || part.FormName() != "item" {
		fail(badRequest("the first part must be item"))
		return
	}
	var in intakeItem
	dec := json.NewDecoder(io.LimitReader(part, feedbackItemJSON))
	if err := dec.Decode(&in); err != nil {
		fail(badRequest("the item is not valid JSON"))
		return
	}
	item, err := validateIntake(in)
	if err != nil {
		fail(err)
		return
	}
	var total int64
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fail(err)
			return
		}
		if part.FormName() != "attachment" {
			fail(badRequest("unexpected part " + strconv.Quote(oneLinePrintable(part.FormName(), 40))))
			return
		}
		if len(item.Attachments) == feedback.MaxFiles {
			fail(badRequest(fmt.Sprintf("at most %d attachments", feedback.MaxFiles)))
			return
		}
		if len(item.Attachments) == 0 {
			ok, err := s.limiter.check(r.Context(), limitHit{"feedback-intake-files", sender, limitFeedbackIntakeFiles})
			if err != nil {
				fail(err)
				return
			}
			if !ok {
				cleanup()
				writeError(w, 429, "rate_limited", "too many attachments from your address; send without them or try again in an hour")
				return
			}
		}
		a, err := q.storeAttachment(r, s, part, total, &reserved)
		if a != nil && a.StorageKey != "" {
			keys = append(keys, a.StorageKey)
		}
		if err != nil {
			fail(err)
			return
		}
		total += a.Size
		item.Attachments = append(item.Attachments, *a)
	}
	secret, _, err := auth.NewToken(feedbackStatusPrefix)
	if err != nil {
		fail(err)
		return
	}
	item.TokenHash = auth.HashToken(secret)
	id, err := s.Store.CreateFeedbackItem(r.Context(), item, "intake:"+item.Source)
	if err != nil {
		fail(err)
		return
	}
	s.Log.Info("feedback received", "ref", store.FeedbackRef(id), "kind", item.Kind, "source", item.Source, "attachments", len(item.Attachments))
	reply := map[string]any{
		"ref": store.FeedbackRef(id), "token": secret, "kind": item.Kind, "source": item.Source,
		"version": item.Version, "edition": item.Edition, "attachments": len(item.Attachments),
	}
	if len(item.Attachments) > 0 {
		if warn := s.feedbackStorageWarning(r.Context()); warn != "" {
			// The relay posts it to the team's Slack with the item.
			reply["storage_warning"] = warn
		}
	}
	writeJSON(w, 201, reply)
}

var errFeedbackStorageFull = errors.New("attachments cannot be stored right now; send the feedback without them")

// storeAttachment checks and writes one file. The returned attachment has
// its StorageKey set once something is on disk, so the caller can remove it.
func (q *FeedbackQueue) storeAttachment(r *http.Request, s *Server, part io.Reader, total int64, reserved *int64) (*store.FeedbackAttachment, error) {
	name := ""
	if p, ok := part.(interface{ FileName() string }); ok {
		name = p.FileName()
	}
	br := bufio.NewReaderSize(part, 4096)
	head, err := br.Peek(feedback.SniffBytes)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return nil, err
	}
	k, err := feedback.Detect(head)
	if err != nil {
		return nil, err
	}
	limit := min(k.MaxBytes(), feedback.MaxTotalBytes-total)
	used, err := s.Store.FeedbackStorageBytes(r.Context())
	if err != nil {
		return nil, err
	}
	if used+q.inflight.Load() >= q.StorageMax {
		return nil, errFeedbackStorageFull
	}
	h := sha256.New()
	var key string
	var n int64
	if k.Image() {
		b, err := io.ReadAll(io.LimitReader(br, limit+1))
		if err == nil && int64(len(b)) > limit {
			err = &feedback.TooLarge{Kind: k, Total: limit < k.MaxBytes()}
		}
		if err == nil {
			b, err = feedback.StripImage(k, b)
		}
		if err == nil {
			// Decoded and encoded again: only the pixels are kept.
			b, k, err = feedback.Reencode(k, b)
		}
		if err == nil {
			h.Write(b)
			key, n, err = q.Disk.Write(bytes.NewReader(b), k, int64(len(b)))
		}
		if err != nil {
			return nil, err
		}
	} else {
		key, n, err = q.Disk.Write(io.TeeReader(br, h), k, limit)
		if err != nil {
			var tl *feedback.TooLarge
			if errors.As(err, &tl) && limit < k.MaxBytes() {
				tl.Total = true
			}
			return nil, err
		}
	}
	a := &store.FeedbackAttachment{Name: feedback.SafeName(name, k), ContentType: k.ContentType(), Size: n,
		SHA256: h.Sum(nil), StorageKey: key, Scan: "checked"}
	if q.ScanRequired {
		a.Scan = "pending"
	}
	// Counts this request's earlier files and other intakes in flight.
	q.inflight.Add(n)
	*reserved += n
	if used+q.inflight.Load() > q.StorageMax {
		return a, errFeedbackStorageFull
	}
	return a, nil
}

// FeedbackStorageAlertPercent is the share of the attachment cap above
// which the team is warned.
const FeedbackStorageAlertPercent = 80

// feedbackStorageWarning says when attachment storage is above the alert
// share, and logs it as an error (the logs are watched).
func (s *Server) feedbackStorageWarning(ctx context.Context) string {
	q := s.FeedbackQueue
	used, err := s.Store.FeedbackStorageBytes(ctx)
	if err != nil || q.StorageMax <= 0 || used*100 < q.StorageMax*FeedbackStorageAlertPercent {
		return ""
	}
	msg := fmt.Sprintf("feedback attachment storage is at %d%% of %d MB; raise STACKURITY_FEEDBACK_STORAGE_MAX_MB or delete old items",
		used*100/q.StorageMax, q.StorageMax>>20)
	s.Log.Error(msg, "used_bytes", used, "max_bytes", q.StorageMax)
	return msg
}

// feedbackQueueStatus answers the sender's installation: the public status
// of each item whose token matches.
func (s *Server) feedbackQueueStatus(w http.ResponseWriter, r *http.Request) {
	q := s.FeedbackQueue
	if !s.queueOn(w) {
		return
	}
	if !q.keyOK(r) {
		writeError(w, 401, "unauthorized", "missing or wrong intake key")
		return
	}
	if s.limited(w, r, "too many status checks", limitHit{"feedback-status-ip", relaySender(r), limitFeedbackStatusIP},
		limitHit{"feedback-status", "all", limitFeedbackStatus}) {
		return
	}
	var req struct {
		Items []struct {
			Ref   string `json:"ref"`
			Token string `json:"token"`
		} `json:"items"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.Items) > 50 {
		writeError(w, 400, "bad_request", "at most 50 items")
		return
	}
	out := make([]any, 0, len(req.Items))
	for _, it := range req.Items {
		id, ok := store.ParseFeedbackRef(it.Ref)
		unknown := map[string]string{"ref": oneLinePrintable(it.Ref, 24), "status": "unknown"}
		if !ok || !strings.HasPrefix(it.Token, feedbackStatusPrefix+"_") {
			out = append(out, unknown)
			continue
		}
		st, err := s.Store.FeedbackStatusByToken(r.Context(), id, auth.HashToken(it.Token))
		if errors.Is(err, store.ErrNotFound) {
			out = append(out, unknown)
			continue
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, st)
	}
	writeJSON(w, 200, map[string]any{"items": out})
}

func (s *Server) listFeedbackQueue(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	f := store.FeedbackFilter{}
	if v := r.URL.Query().Get("status"); v != "" {
		for _, st := range strings.Split(v, ",") {
			if !validFeedbackStatus(st) {
				writeError(w, 400, "bad_request", "unknown status "+strconv.Quote(oneLinePrintable(st, 20)))
				return
			}
			f.Statuses = append(f.Statuses, st)
		}
	}
	if v := r.URL.Query().Get("before"); v != "" {
		id, ok := store.ParseFeedbackRef(v)
		if !ok {
			writeError(w, 400, "bad_request", "invalid before")
			return
		}
		f.BeforeID = id
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}
	items, err := s.Store.ListFeedbackItems(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	counts, err := s.Store.FeedbackItemCounts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	used, err := s.Store.FeedbackStorageBytes(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "counts": counts,
		"storage": map[string]int64{"used_bytes": used, "max_bytes": s.FeedbackQueue.StorageMax}})
}

func validFeedbackStatus(st string) bool {
	for _, v := range store.FeedbackStatuses {
		if v == st {
			return true
		}
	}
	return false
}

func feedbackIDParam(r *http.Request) (int64, error) {
	id, ok := store.ParseFeedbackRef(chi.URLParam(r, "id"))
	if !ok {
		return 0, badRequest("invalid feedback id; use FB-123")
	}
	return id, nil
}

func (s *Server) getFeedbackQueueItem(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	id, err := feedbackIDParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	it, atts, events, err := s.Store.GetFeedbackItem(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"item": it, "attachments": atts, "events": events})
}

// feedbackLink is a pull request or issue in one of the project's
// repositories.
var feedbackLink = regexp.MustCompile(`^https://github\.com/stackurity/[A-Za-z0-9._-]{1,100}/(pull|issues)/[0-9]{1,9}$`)

func (s *Server) updateFeedbackQueueItem(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	id, err := feedbackIDParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Status      *string `json:"status"`
		Resolution  *string `json:"resolution"`
		TriageNotes *string `json:"triage_notes"`
		Note        *string `json:"note"`
		Link        *string `json:"link"`
		DuplicateOf *string `json:"duplicate_of"`
		FixedIn     *string `json:"fixed_in"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	p := store.FeedbackPatch{Status: req.Status, Resolution: req.Resolution, TriageNotes: req.TriageNotes, AppendNote: req.Note,
		Link: req.Link, FixedIn: req.FixedIn}
	switch {
	case req.Status != nil && !validFeedbackStatus(*req.Status):
		err = badRequest("status must be one of " + strings.Join(store.FeedbackStatuses, ", "))
	case req.Resolution != nil && utf8.RuneCountInString(*req.Resolution) > 2000:
		err = badRequest("the resolution is limited to 2000 characters")
	case req.Note != nil && utf8.RuneCountInString(*req.Note) > 5000:
		err = badRequest("a note is limited to 5000 characters")
	case req.Link != nil && *req.Link != "" && !feedbackLink.MatchString(*req.Link):
		err = badRequest("link must be a pull request or issue at https://github.com/stackurity/...")
	case req.FixedIn != nil && *req.FixedIn != "" && !feedbackVersion.MatchString(*req.FixedIn):
		err = badRequest("fixed_in must be a version such as 0.15.0")
	}
	if err == nil && req.DuplicateOf != nil {
		var d int64
		if *req.DuplicateOf != "" {
			var ok bool
			if d, ok = store.ParseFeedbackRef(*req.DuplicateOf); !ok {
				err = badRequest("duplicate_of must be a reference such as FB-12")
			}
		}
		p.DuplicateOf = &d
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	before, after, err := s.Store.UpdateFeedbackItem(r.Context(), id, p, feedbackActor(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if before.Status != after.Status && (after.Status == store.FeedbackReleased || after.Status == store.FeedbackWontFix) {
		s.emailFeedbackSender(r.Context(), after)
	}
	writeJSON(w, 200, after)
}

// emailFeedbackSender sends the one email for a released or won't-fix
// item, when the sender left an address and emails are on. Off, it only
// logs that no email went.
func (s *Server) emailFeedbackSender(ctx context.Context, it *store.FeedbackItem) {
	if it.ContactEmail == "" || it.NotifiedAt != nil {
		return
	}
	tmpl := "released"
	if it.Status == store.FeedbackWontFix {
		tmpl = "wont_fix"
	}
	if !s.FeedbackQueue.Emails || s.AccountMail == nil {
		s.Log.Info("feedback sender not emailed: STACKURITY_FEEDBACK_EMAILS is off or no mail is configured", "ref", it.Ref, "template", tmpl)
		return
	}
	m, err := feedback.RenderEmail(tmpl, feedback.EmailData{Ref: it.Ref, Summary: it.Description, Resolution: it.Resolution, Version: it.FixedIn})
	if err != nil {
		s.Log.Error("feedback email", "err", err)
		return
	}
	lines := strings.Split(strings.TrimSpace(m.Body), "\n\n")
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	msg := notify.Message{Event: "feedback_update", Title: m.Subject, At: time.Now().UTC(), Summary: lines}
	if err := s.AccountMail.SendMail(ctx, []string{it.ContactEmail}, msg); err != nil {
		s.Log.Error("feedback email not sent", "ref", it.Ref, "err", err)
		return
	}
	if err := s.Store.MarkFeedbackNotified(ctx, it.ID, tmpl); err != nil {
		s.Log.Error("feedback email sent but not recorded", "ref", it.Ref, "err", err)
	}
}

// feedbackEmailTemplates renders the emails with sample text, for the
// owner to approve before STACKURITY_FEEDBACK_EMAILS is turned on.
func (s *Server) feedbackEmailTemplates(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	sample := feedback.EmailData{Ref: "FB-123", Summary: "The Fixes page loses the asset filter after I open a fix and go back",
		Resolution: "The filter is now kept when you go back.", Version: "0.15.0"}
	var out []map[string]string
	for _, name := range feedback.EmailTemplates() {
		d := sample
		if name == "wont_fix" {
			d.Resolution = "Exports stay in the API (GET /fixes?format=csv) so they follow your project access; the dashboard will not get a separate button."
		}
		m, err := feedback.RenderEmail(name, d)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, map[string]string{"name": name, "subject": m.Subject, "body": m.Body})
	}
	writeJSON(w, 200, map[string]any{"enabled": s.FeedbackQueue.Emails && s.AccountMail != nil, "templates": out})
}

func (s *Server) deleteFeedbackQueueItem(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	id, err := feedbackIDParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	keys, err := s.Store.DeleteFeedbackItem(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, k := range keys {
		if err := s.FeedbackQueue.Disk.Remove(k); err != nil {
			s.Log.Error("feedback attachment not deleted; the orphan sweep will retry", "key", k, "err", err)
		}
	}
	s.Log.Info("feedback item deleted", "ref", store.FeedbackRef(id), "by", feedbackActor(r), "files", len(keys))
	w.WriteHeader(204)
}

func (s *Server) feedbackAttachmentLink(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	id, err := feedbackIDParam(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	aid, err := idParam(r, "aid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.Store.GetFeedbackAttachment(r.Context(), aid)
	if err != nil || a.ItemID != id {
		writeError(w, 404, "not_found", "not found")
		return
	}
	switch {
	case a.Scan == "pending":
		// Not scanned yet: as if it did not exist.
		writeError(w, 404, "not_found", "not found")
		return
	case a.PurgedAt != nil:
		writeError(w, 410, "gone", "this attachment was deleted (retention rules, or the virus scanner flagged it)")
		return
	}
	exp := time.Now().Add(feedbackLinkTTL).Unix()
	u := fmt.Sprintf("%s/feedback-attachments/%d?exp=%d&sig=%s", strings.TrimRight(s.BaseURL, "/"), aid, exp, s.FeedbackQueue.linkSig(id, aid, exp))
	writeJSON(w, 200, map[string]any{"url": u, "expires_at": time.Unix(exp, 0).UTC(), "name": a.Name,
		"content_type": a.ContentType, "size": a.Size})
}

// feedbackDownload serves an attachment from a signed link, as a download:
// the browser never renders it in the dashboard's origin.
func (s *Server) feedbackDownload(w http.ResponseWriter, r *http.Request) {
	q := s.FeedbackQueue
	if !s.queueOn(w) {
		return
	}
	denied := func() { writeError(w, 403, "forbidden", "this link is invalid or has expired; ask for a new one") }
	aid, err := idParam(r, "id")
	exp, err2 := strconv.ParseInt(r.URL.Query().Get("exp"), 10, 64)
	now := time.Now().Unix()
	if err != nil || err2 != nil || exp < now || exp > now+int64(feedbackLinkTTL/time.Second)+60 {
		denied()
		return
	}
	a, err := s.Store.GetFeedbackAttachment(r.Context(), aid)
	if err != nil {
		denied()
		return
	}
	if !hmac.Equal([]byte(r.URL.Query().Get("sig")), []byte(q.linkSig(a.ItemID, aid, exp))) {
		denied()
		return
	}
	if !store.FeedbackAttachmentVisible(a) {
		writeError(w, 404, "not_found", "not found")
		return
	}
	k, ok := feedback.KindFromContentType(a.ContentType)
	if !ok {
		writeError(w, 404, "not_found", "not found")
		return
	}
	f, err := q.Disk.Open(a.StorageKey)
	if err != nil {
		s.Log.Error("feedback attachment missing", "attachment", aid, "err", err)
		writeError(w, 404, "not_found", "not found")
		return
	}
	defer f.Close()
	h := w.Header()
	h.Set("Content-Type", k.ContentType())
	h.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%d.%s"`, store.FeedbackRef(a.ItemID), a.ID, k.Ext()))
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	http.ServeContent(w, r, "", a.CreatedAt, f)
}

// feedbackScanPending lists attachments waiting for the virus scan: id,
// storage key (the file name in the queue's directory) and size.
func (s *Server) feedbackScanPending(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	list, err := s.Store.FeedbackScanQueue(r.Context(), 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, a := range list {
		out = append(out, map[string]any{"id": a.ID, "storage_key": a.StorageKey, "size": a.Size, "sha256": hex.EncodeToString(a.SHA256)})
	}
	writeJSON(w, 200, map[string]any{"attachments": out, "required": s.FeedbackQueue.ScanRequired})
}

var feedbackSignature = regexp.MustCompile(`^[A-Za-z0-9._:/+-]{1,200}$`)

// feedbackScanResult records a verdict: {"result":"clean"} or
// {"result":"infected","signature":"Eicar-Test-Signature"}. An infected
// file is deleted at once and its item flagged for the owner.
func (s *Server) feedbackScanResult(w http.ResponseWriter, r *http.Request) {
	if !s.queueOn(w) {
		return
	}
	aid, err := idParam(r, "aid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Result    string `json:"result"`
		Signature string `json:"signature"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Result != "clean" && req.Result != "infected" {
		writeError(w, 400, "bad_request", "result must be clean or infected")
		return
	}
	if req.Result == "infected" && !feedbackSignature.MatchString(req.Signature) {
		writeError(w, 400, "bad_request", "an infected result needs the scanner's signature name")
		return
	}
	key, err := s.Store.RecordFeedbackScan(r.Context(), aid, req.Result == "clean", req.Signature, feedbackActor(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if key != "" {
		if err := s.FeedbackQueue.Disk.Remove(key); err != nil {
			s.Log.Error("infected feedback attachment not deleted; the orphan sweep will retry", "attachment", aid, "err", err)
		}
		s.Log.Warn("feedback attachment flagged by the virus scanner and deleted", "attachment", aid, "signature", req.Signature)
	}
	w.WriteHeader(204)
}

func (s *Server) listFeedbackTokens(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.ListFeedbackAgentTokens(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"tokens": list})
}

func (s *Server) createFeedbackToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Days  int    `json:"days"`
		Scope string `json:"scope"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Name = oneLinePrintable(req.Name, 100)
	if req.Name == "" {
		writeError(w, 400, "bad_request", "name the token (for example triage-agent)")
		return
	}
	if req.Days == 0 {
		req.Days = 30
	}
	if req.Scope == "" {
		req.Scope = feedbackScopeTriage
	}
	if req.Scope != feedbackScopeTriage && req.Scope != feedbackScopeScanner {
		writeError(w, 400, "bad_request", "scope must be triage or scanner")
		return
	}
	if req.Days < 1 || req.Days > 90 {
		writeError(w, 400, "bad_request", "days must be 1 to 90")
		return
	}
	secret, prefix, err := auth.NewToken(FeedbackTokenPrefix)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.Store.CreateFeedbackAgentToken(r.Context(), req.Name, req.Scope, prefix, auth.HashToken(secret), principal(r).User.ID,
		time.Now().Add(time.Duration(req.Days)*24*time.Hour))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.Log.Info("feedback triage token created", "token", t.ID, "name", t.Name, "by", principal(r).User.Email)
	writeJSON(w, 201, map[string]any{"token": secret, "info": t})
}

func (s *Server) revokeFeedbackToken(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.RevokeFeedbackAgentToken(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}
