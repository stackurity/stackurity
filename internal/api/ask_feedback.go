package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Ask Stackurity feedback: a person's thumbs up or down and "what was
// wrong" form, implicit signals the server records on its own, and the
// installation operators' review of both (store/ask_feedback.go).

// limitAskFeedback bounds feedback per person.
var limitAskFeedback = rateLimit{30, time.Hour}

// Snapshot bounds: a whole-chat snapshot keeps the last askSnapshotMessages
// messages with visible text, each cut to askSnapshotChars.
const (
	askSnapshotMessages = 40
	askSnapshotChars    = 8000
)

const feedbackReviewPath = "/api/v1/admin/ask/feedback"

// feedbackReviewRequest reports whether r is one a feedback review token
// may make: reading the feedback list or one row, or setting a row's
// status and notes.
func feedbackReviewRequest(r *http.Request) bool {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path != feedbackReviewPath && !strings.HasPrefix(path, feedbackReviewPath+"/") {
		return false
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		return true
	case http.MethodPatch:
		return path != feedbackReviewPath
	}
	return false
}

// askFeedbackReviewRoutes are mounted outside the organisation routes: a
// review token has no user and no organisation.
func (s *Server) askFeedbackReviewRoutes(r chi.Router) {
	r.Route("/admin/ask/feedback", func(r chi.Router) {
		r.Use(requireFeedbackReview)
		r.Get("/", s.adminListAskFeedback)
		r.Get("/{id}", s.adminGetAskFeedback)
		r.Patch("/{id}", s.adminReviewAskFeedback)
	})
	r.Route("/admin/ask/review-tokens", func(r chi.Router) {
		r.Use(requireInstanceAdminOnly)
		r.Get("/", s.adminListReviewTokens)
		r.Post("/", s.adminCreateReviewToken)
		r.Delete("/{id}", s.adminRevokeReviewToken)
	})
}

// requireFeedbackReview allows the installation's operators and feedback
// review tokens.
func requireFeedbackReview(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		if p == nil {
			writeError(w, 401, "unauthorized", "authentication required")
			return
		}
		if p.FeedbackReviewer != nil {
			next.ServeHTTP(w, r)
			return
		}
		requireInstanceAdmin(next).ServeHTTP(w, r)
	})
}

// requireInstanceAdminOnly is requireInstanceAdmin that also answers 401
// to a request without credentials (these routes are outside requireAuth).
func requireInstanceAdminOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if principal(r) == nil {
			writeError(w, 401, "unauthorized", "authentication required")
			return
		}
		requireInstanceAdmin(next).ServeHTTP(w, r)
	})
}

// --- the person's feedback

type askFeedbackIn struct {
	Seq      int    `json:"seq"`
	Rating   string `json:"rating"`
	Category string `json:"category"`
	Scope    string `json:"scope"`
	Text     string `json:"text"`
	Consent  bool   `json:"consent"`
	PagePath string `json:"page_path"`
	Viewport string `json:"viewport"`
}

// askFeedback records feedback on the person's own conversation
// (POST /ask/conversations/{id}/feedback), or on the panel itself with no
// conversation (POST /ask/feedback, scope ui).
func (s *Server) askFeedback(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	var convID int64
	if chi.URLParam(r, "id") != "" {
		id, err := idParam(r, "id")
		if err != nil {
			s.fail(w, r, err)
			return
		}
		convID = id
	}
	var in askFeedbackIn
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.limited(w, r, "too much feedback; try again later", limitHit{"ask-feedback", strconv.FormatInt(p.User.ID, 10), limitAskFeedback}) {
		return
	}
	fi := store.AskFeedbackInput{UserID: p.User.ID, ConversationID: convID, Seq: in.Seq, Rating: in.Rating, Category: in.Category,
		Scope: in.Scope, Text: ask.CleanText(in.Text), Consent: in.Consent, PagePath: cleanPagePath(in.PagePath), Viewport: cleanViewport(in.Viewport)}
	if convID == 0 && fi.Scope != "ui" {
		s.fail(w, r, badRequest("feedback without a conversation is about the panel itself (scope ui)"))
		return
	}
	if fi.Scope == "" {
		fi.Scope = "answer"
	}
	if in.Consent && convID > 0 {
		msgs, err := s.Store.AskMessages(r.Context(), p.User.ID, convID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		fi.Snapshot = askSnapshot(msgs, fi.Scope, in.Seq)
	}
	fb, err := s.Store.AddAskFeedback(r.Context(), fi)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 201, map[string]any{"id": fb.ID, "consent": fb.Consent})
}

// askSnapshot is what a person agreed to share: for an answer, the answer
// and the question before it; for the whole chat or the panel, the last
// askSnapshotMessages messages with visible text. Text only, cleaned of
// credentials and email addresses.
func askSnapshot(msgs []store.AskMessage, scope string, seq int) []store.AskSnapshotMessage {
	var shown []store.AskMessage
	for _, m := range msgs {
		if m.VisibleText != "" {
			shown = append(shown, m)
		}
	}
	if scope == "answer" {
		var pick []store.AskMessage
		for i, m := range shown {
			if m.Seq == seq && m.Role == "assistant" {
				for j := i - 1; j >= 0; j-- {
					if shown[j].Role == "user" {
						pick = append(pick, shown[j])
						break
					}
				}
				pick = append(pick, m)
				break
			}
		}
		shown = pick
	} else if len(shown) > askSnapshotMessages {
		shown = shown[len(shown)-askSnapshotMessages:]
	}
	out := make([]store.AskSnapshotMessage, 0, len(shown))
	for _, m := range shown {
		t := ask.SnapshotText(m.VisibleText)
		if r := []rune(t); len(r) > askSnapshotChars {
			t = string(r[:askSnapshotChars]) + " [cut]"
		}
		out = append(out, store.AskSnapshotMessage{Seq: m.Seq, Role: m.Role, Text: t})
	}
	return out
}

// cleanPagePath keeps a dashboard path without its query or fragment.
func cleanPagePath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return ""
	}
	if len(p) > 300 {
		p = p[:300]
	}
	return p
}

// cleanViewport keeps "WIDTHxHEIGHT".
func cleanViewport(v string) string {
	w, h, ok := strings.Cut(v, "x")
	if !ok {
		return ""
	}
	if a, err := strconv.Atoi(w); err != nil || a <= 0 || a > 20000 {
		return ""
	}
	if b, err := strconv.Atoi(h); err != nil || b <= 0 || b > 20000 {
		return ""
	}
	return v
}

// askSignals records the implicit signals of a question that just ended
// (metadata only) and returns the answer's sequence number (0: no answer
// after the question). ctx must outlive a stopped request.
func (s *Server) askSignals(ctx context.Context, userID int64, conv *store.AskConversation, out ask.Outcome, askErr error) int {
	msgs, err := s.Store.AskMessages(ctx, userID, conv.ID)
	if err != nil {
		s.Log.Warn("ask: reading the conversation for feedback signals", "err", err)
		return 0
	}
	var questions []string
	qSeq, aSeq := 0, 0
	for _, m := range msgs {
		switch {
		case m.Role == "user" && m.VisibleText != "":
			questions = append(questions, m.VisibleText)
			qSeq = m.Seq
		case m.Role == "assistant":
			aSeq = m.Seq
		}
	}
	if aSeq < qSeq {
		aSeq = 0
	}
	model := conv.Model
	if len(out.Usage) > 0 {
		model = out.Usage[len(out.Usage)-1].Model
	}
	signal := func(seq int, category string) {
		if _, err := s.Store.AddAskSignal(ctx, store.AskSignal{UserID: userID, ConversationID: conv.ID, Seq: seq, Category: category,
			PromptVersion: ask.PromptVersion, Model: model}); err != nil {
			s.Log.Warn("ask: recording a feedback signal", "signal", category, "err", err)
		}
	}
	if n := len(questions); n >= 2 && ask.Rephrased(questions[n-1], questions[:n-1]) {
		signal(qSeq, store.AskSignalRephrased)
	}
	if errors.Is(askErr, context.Canceled) {
		signal(qSeq, store.AskSignalStopped)
	}
	if out.ToolErrors > 0 {
		at := aSeq
		if at == 0 {
			at = qSeq
		}
		signal(at, store.AskSignalToolError)
	}
	if askErr == nil && aSeq > 0 && (out.StopReason == "refusal" || ask.SaysNotFound(out.Text)) {
		signal(aSeq, store.AskSignalNotFound)
	}
	return aSeq
}

// --- the operators' review

func (s *Server) adminListAskFeedback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AskFeedbackFilter{Status: q.Get("status"), Kind: q.Get("kind"), Rating: q.Get("rating"), Category: q.Get("category"),
		PromptVersion: q.Get("prompt_version")}
	for name, dst := range map[string]*int64{"workspace_id": &f.WorkspaceID, "before": &f.Before} {
		if v := q.Get(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n <= 0 {
				s.fail(w, r, badRequest("invalid "+name))
				return
			}
			*dst = n
		}
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			s.fail(w, r, badRequest("limit must be 1 to 200"))
			return
		}
		f.Limit = n
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t, err = time.Parse("2006-01-02", v)
		}
		if err != nil {
			s.fail(w, r, badRequest("since must be a date (2006-01-02) or an RFC 3339 time"))
			return
		}
		f.Since = &t
	}
	items, err := s.Store.ListAskFeedback(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res := map[string]any{"items": items}
	limit := f.Limit
	if limit == 0 {
		limit = 50
	}
	if len(items) == limit {
		res["next_before"] = items[len(items)-1].ID
	}
	writeJSON(w, 200, res)
}

func (s *Server) adminGetAskFeedback(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fb, err := s.Store.GetAskFeedback(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, fb)
}

func (s *Server) adminReviewAskFeedback(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Status          *string `json:"status"`
		ResolutionNotes *string `json:"resolution_notes"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Status == nil && in.ResolutionNotes == nil {
		s.fail(w, r, badRequest("set status or resolution_notes"))
		return
	}
	fb, err := s.Store.ReviewAskFeedback(r.Context(), id, in.Status, in.ResolutionNotes)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), "ask.feedback_reviewed", "ask_feedback", itoa(fb.ID),
		map[string]any{"status": fb.Status, "workspace_id": fb.WorkspaceID})
	writeJSON(w, 200, fb)
}

func (s *Server) adminListReviewTokens(w http.ResponseWriter, r *http.Request) {
	toks, err := s.Store.ListAskFeedbackReviewTokens(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": toks})
}

func (s *Server) adminCreateReviewToken(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name      string `json:"name"`
		ExpiresIn int    `json:"expires_in_days"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.ExpiresIn < 0 || in.ExpiresIn > 366 {
		s.fail(w, r, badRequest("expires_in_days must be 0 (never) to 366"))
		return
	}
	p := principal(r)
	tok, secret, err := s.Store.CreateAskFeedbackReviewToken(r.Context(), in.Name, p.User.ID, time.Duration(in.ExpiresIn)*24*time.Hour)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.System(r.Context()), p.Actor(r), "ask.review_token_created", "ask_feedback_review_token", itoa(tok.ID),
		map[string]any{"name": tok.Name, "prefix": tok.Prefix})
	writeJSON(w, 201, map[string]any{"token": tok, "secret": secret})
}

func (s *Server) adminRevokeReviewToken(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.RevokeAskFeedbackReviewToken(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), "ask.review_token_revoked", "ask_feedback_review_token", itoa(id), nil)
	w.WriteHeader(204)
}
