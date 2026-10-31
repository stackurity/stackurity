package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/ask"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/notify"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Ask Stackurity, the in-app assistant (internal/ask). A person signed in
// to the dashboard asks a question; the answer streams back as server-sent
// events. The model reads Stackurity only through the read-only MCP
// tools, which run here in process with the person's own session (askAPI),
// so every rule of the API applies to them: role, projects, row-level
// security. They may only read (projectGate).
//
// It is opt-in: off unless the server has a model provider
// (STACKURITY_ANTHROPIC_API_KEY, Bedrock or Vertex), the organisation's
// admin turned it on, its plan includes questions, and the person accepted
// the data notice.

// AskNoticeVersion is the data notice's version: a new one is accepted
// again.
const AskNoticeVersion = "2026-11"

// Limits on Ask Stackurity, per person and per organisation.
var (
	limitAskUser     = rateLimit{10, time.Minute}
	limitAskUserHour = rateLimit{60, time.Hour}
	limitAskOrgHour  = rateLimit{300, time.Hour}
)

// askDeadline bounds one question, under the server's write timeout.
const askDeadline = 3 * time.Minute

const maxQuestion = 4000

func (s *Server) askRoutes(r chi.Router) {
	r.Get("/ask/status", s.askStatus)
	r.Post("/ask/notice", s.askAcceptNotice)
	r.Get("/ask/conversations", s.askListConversations)
	r.Post("/ask/conversations", s.askCreateConversation)
	r.Delete("/ask/conversations", s.askDeleteMyConversations)
	r.Get("/ask/conversations/{id}", s.askGetConversation)
	r.Delete("/ask/conversations/{id}", s.askDeleteConversation)
	r.Post("/ask/conversations/{id}/messages", s.askQuestion)
	r.Group(func(r chi.Router) {
		r.Use(requireRole(auth.RoleAdmin))
		r.Get("/ask/settings", s.askSettings)
		r.Put("/ask/settings", s.askPutSettings)
		r.Delete("/ask/settings/conversations", s.askDeleteAllConversations)
	})
	r.With(requireInstanceAdmin).Get("/admin/ask", s.adminAsk)
}

// askPerson is the person asking: a browser session in an organisation.
// API tokens, assistants and the assistant's own tool calls cannot ask.
func askPerson(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	p := principal(r)
	if p == nil || p.User == nil || !p.Session || p.Token != nil || p.Assistant != nil || p.Ask {
		writeError(w, 403, "forbidden", "Ask Stackurity is for people signed in to the dashboard")
		return nil, false
	}
	if p.Workspace <= 0 {
		writeError(w, 403, "forbidden", "choose an organisation first")
		return nil, false
	}
	return p, true
}

// askLimits are the organisation's settings with the server's defaults
// filled in.
type askLimits struct {
	store.AskSettings
	Configured bool   `json:"configured"`
	Provider   string `json:"provider"`
}

func (s *Server) askLimits(ctx context.Context) (askLimits, error) {
	a, err := s.Store.AskSettings(ctx)
	if err != nil {
		return askLimits{}, err
	}
	l := askLimits{AskSettings: a}
	if s.Ask == nil {
		return l, nil
	}
	cfg := s.Ask.Config
	l.Configured, l.Provider = true, cfg.Provider
	if l.QuestionLimit == nil {
		l.QuestionLimit = cfg.QuestionLimit
	}
	if l.SpendCapMicros == nil {
		l.SpendCapMicros = cfg.SpendCapMicros
	}
	if l.Model == "" {
		l.Model = cfg.Model
	}
	return l, nil
}

// askUnavailable says why the organisation cannot ask now ("" : it can).
func (s *Server) askUnavailable(ctx context.Context, l askLimits) (status int, code, msg string) {
	switch {
	case !l.Configured:
		return 404, "not_configured", "Ask Stackurity is not set up on this server"
	case !l.Enabled:
		return 403, "ask_disabled", "an administrator of this organisation has turned Ask Stackurity off"
	case l.QuestionLimit != nil && *l.QuestionLimit == 0:
		return 402, "plan_required", "Ask Stackurity is not included in this organisation's plan"
	}
	if err := s.Store.CheckWritable(ctx); err != nil {
		return 402, "read_only", "Ask Stackurity is off while the organisation is read-only"
	}
	return 0, "", ""
}

// GET /ask/status: what the dashboard needs to show the panel.
func (s *Server) askStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	l, err := s.askLimits(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	accepted, err := s.Store.AskNoticeAccepted(ctx, p.User.ID, AskNoticeVersion)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.Store.AskUsageNow(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_, code, msg := s.askUnavailable(ctx, l)
	if code == "" && l.SpendCapMicros != nil && u.CostMicros >= *l.SpendCapMicros {
		code, msg = "spend_cap", "this organisation's Ask Stackurity budget for the month is used up"
	}
	used := u.Questions
	if l.QuestionPeriod == "total" {
		used, err = s.Store.AskQuestionsTotal(ctx)
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	writeJSON(w, 200, map[string]any{
		"available": code == "", "reason": code, "message": msg,
		"provider": l.Provider, "notice_version": AskNoticeVersion, "notice_accepted": accepted,
		"questions_used": used, "questions_limit": l.QuestionLimit, "question_period": l.QuestionPeriod,
		"resets_at": time.Date(u.Month.Year(), u.Month.Month()+1, 1, 0, 0, 0, 0, time.UTC),
	})
}

// POST /ask/notice {"version"}: the person accepted the data notice.
func (s *Server) askAcceptNotice(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	var in struct {
		Version string `json:"version"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Version != AskNoticeVersion {
		writeError(w, 409, "notice_changed", "the notice changed; read it again")
		return
	}
	if err := s.Store.AcceptAskNotice(r.Context(), p.User.ID, in.Version); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "ask.notice_accepted", "user", itoa(p.User.ID), map[string]any{"version": in.Version})
	w.WriteHeader(204)
}

func (s *Server) askListConversations(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	cs, err := s.Store.ListAskConversations(r.Context(), p.User.ID, 100)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": cs})
}

// POST /ask/conversations: a new conversation, with the organisation's
// model.
func (s *Server) askCreateConversation(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	l, err := s.askLimits(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if status, code, msg := s.askUnavailable(ctx, l); code != "" {
		writeError(w, status, code, msg)
		return
	}
	var project *int64
	if p.Project > 0 {
		project = &p.Project
	}
	c, err := s.Store.CreateAskConversation(ctx, p.User.ID, project, l.Model, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 201, c)
}

// GET /ask/conversations/{id}: one of the person's own conversations, as
// they saw it: their questions and the answers (no tool data).
func (s *Server) askGetConversation(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.AskConversation(r.Context(), p.User.ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ms, err := s.Store.AskMessages(r.Context(), p.User.ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	shown := []store.AskMessage{}
	for _, m := range ms {
		if m.VisibleText != "" || m.StopReason == "refusal" {
			shown = append(shown, m)
		}
	}
	writeJSON(w, 200, map[string]any{"conversation": c, "messages": shown})
}

func (s *Server) askDeleteConversation(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteAskConversation(r.Context(), p.User.ID, id); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) askDeleteMyConversations(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	n, err := s.Store.DeleteAskConversations(r.Context(), p.User.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// GET /ask/settings (organisation admins): the switch, the limits, this
// month's use. Never anyone's conversations.
func (s *Server) askSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	l, err := s.askLimits(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	u, err := s.Store.AskUsageNow(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": l.Enabled, "configured": l.Configured, "provider": l.Provider, "model": l.Model,
		"question_limit": l.QuestionLimit, "question_period": l.QuestionPeriod, "spend_cap_micros": l.SpendCapMicros,
		"questions_this_month": u.Questions, "spend_this_month_micros": u.CostMicros, "notice_version": AskNoticeVersion})
}

// PUT /ask/settings {"enabled"} (organisation admins).
func (s *Server) askPutSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Enabled == nil {
		writeError(w, 400, "bad_request", "enabled is required")
		return
	}
	if err := s.Store.SetAskEnabled(r.Context(), *in.Enabled); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "ask.settings", "workspace", "", map[string]any{"enabled": *in.Enabled})
	s.askSettings(w, r)
}

// DELETE /ask/settings/conversations (organisation admins): every
// conversation in the organisation, whoever had it. The admin learns how
// many; nothing about what they said.
func (s *Server) askDeleteAllConversations(w http.ResponseWriter, r *http.Request) {
	n, err := s.Store.DeleteAllAskConversations(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "ask.conversations_deleted", "workspace", "", map[string]any{"count": n})
	writeJSON(w, 200, map[string]any{"deleted": n})
}

// GET /admin/ask (instance admins): the installation's spend this month.
func (s *Server) adminAsk(w http.ResponseWriter, r *http.Request) {
	spent, err := s.Store.AskGlobalSpend(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"configured": s.Ask != nil, "spend_this_month_micros": spent}
	if s.Ask != nil {
		out["provider"], out["default_model"], out["effort"] = s.Ask.Config.Provider, s.Ask.Config.Model, s.Ask.Config.Effort
		out["global_spend_cap_micros"] = s.Ask.Config.GlobalCapMicros
	}
	writeJSON(w, 200, out)
}

// --- asking

var fixGroupID = regexp.MustCompile(`^[A-Za-z0-9:_.-]{1,128}$`)

// askBusy lets a person ask one question at a time on this replica.
var askBusy sync.Map

// POST /ask/conversations/{id}/messages {"text", "page"}: ask a question;
// the answer streams back as server-sent events:
//
//	event: tool   {"tool": "Reading issue #12"}
//	event: text   {"text": "..."}          a piece of the answer
//	event: reset  {}                      drop the text so far (a refusal or a fallback model)
//	event: done   {"stop_reason", "questions_used", "questions_limit"}
//	event: error  {"code", "message"}
func (s *Server) askQuestion(w http.ResponseWriter, r *http.Request) {
	p, ok := askPerson(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		Text string       `json:"text"`
		Page *ask.PageRef `json:"page"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Text = strings.TrimSpace(ask.CleanText(in.Text))
	if in.Text == "" || utf8.RuneCountInString(in.Text) > maxQuestion {
		writeError(w, 400, "bad_request", fmt.Sprintf("a question is 1 to %d characters", maxQuestion))
		return
	}
	l, err := s.askLimits(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if status, code, msg := s.askUnavailable(ctx, l); code != "" {
		writeError(w, status, code, msg)
		return
	}
	accepted, err := s.Store.AskNoticeAccepted(ctx, p.User.ID, AskNoticeVersion)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !accepted {
		writeError(w, 409, "notice_required", "read and accept how Ask Stackurity uses your data first")
		return
	}
	conv, err := s.Store.AskConversation(ctx, p.User.ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	uid := strconv.FormatInt(p.User.ID, 10)
	ws := strconv.FormatInt(p.Workspace, 10)
	if s.limited(w, r, "too many questions; wait a minute",
		limitHit{"ask-user", uid, limitAskUser}, limitHit{"ask-user-hour", uid, limitAskUserHour}, limitHit{"ask-org-hour", ws, limitAskOrgHour}) {
		return
	}
	busyKey := ws + ":" + uid
	if _, busy := askBusy.LoadOrStore(busyKey, true); busy {
		writeError(w, 429, "busy", "wait for the answer to your last question")
		return
	}
	defer askBusy.Delete(busyKey)

	counted, err := s.Store.CountAskQuestion(ctx, l.QuestionLimit, l.QuestionPeriod)
	if errors.Is(err, store.ErrAskQuota) {
		writeError(w, 429, "quota_reached", "this organisation has used all its Ask Stackurity questions for now")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}

	cookie, _ := r.Cookie(sessionCookie)
	api := &askAPI{s: s, session: cookie.Value, remote: r.RemoteAddr, project: r.Header.Get("X-Stackurity-Project")}
	page := s.askPage(ctx, api, in.Page)
	project := ""
	if p.Project > 0 {
		if pr, err := s.Store.GetProject(ctx, p.Project); err == nil {
			project = pr.Name
		}
	}

	// From here on the answer is a stream.
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(askDeadline + 30*time.Second))
	var mu sync.Mutex
	send := func(event string, v any) {
		b, _ := json.Marshal(v)
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		_ = rc.Flush()
	}
	qctx, cancel := context.WithTimeout(ctx, askDeadline)
	defer cancel()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				mu.Lock()
				_, _ = io.WriteString(w, ": keep-alive\n\n")
				_ = rc.Flush()
				mu.Unlock()
			}
		}
	}()

	if conv.Title == "" {
		_ = s.Store.TitleAskConversation(ctx, p.User.ID, conv.ID, in.Text)
	}
	out, err := s.Ask.Ask(qctx, ask.Question{Conversation: conv, UserID: p.User.ID, Text: in.Text, Page: page, Project: project,
		Model: conv.Model, SpendCapMicros: l.SpendCapMicros, API: api}, func(e ask.Event) {
		switch e.Kind {
		case "text":
			send("text", map[string]string{"text": e.Text})
		case "tool":
			send("tool", map[string]string{"tool": e.Tool})
		case "reset":
			send("reset", map[string]any{})
		}
	})
	if err != nil {
		if out.CostMicros == 0 && len(out.Usage) == 0 {
			// The model was never reached: the question does not count.
			_ = s.Store.RefundAskQuestion(context.WithoutCancel(ctx), counted)
		}
		code, msg := s.askError(r, err)
		if code != "" {
			send("error", map[string]string{"code": code, "message": msg})
		}
		return
	}
	done := map[string]any{"stop_reason": out.StopReason, "questions_used": counted.Used, "questions_limit": l.QuestionLimit}
	switch out.StopReason {
	case "refusal":
		done["message"] = "Claude declined to answer this question. Try asking it another way."
	case "rounds":
		done["message"] = "The answer needed more lookups than one question may make. Ask a narrower question."
	case "too_long":
		done["message"] = "This conversation is getting long. Start a new one to continue."
	case "max_tokens":
		done["message"] = "The answer was cut short."
	}
	send("done", done)
}

// askError turns an engine error into what the person is told; "" for a
// question they stopped themselves.
func (s *Server) askError(r *http.Request, err error) (string, string) {
	var capErr *store.AskSpendCapError
	switch {
	case errors.As(err, &capErr) && capErr.Scope == "global":
		return "spend_cap", "Ask Stackurity has reached its budget for the month on this server. It is back on the 1st."
	case errors.As(err, &capErr):
		return "spend_cap", "This organisation's Ask Stackurity budget for the month is used up. It is back on the 1st."
	case errors.Is(err, ask.ErrTooLong):
		return "too_long", "This conversation is too long to continue. Start a new one."
	case errors.Is(err, context.Canceled):
		return "", ""
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout", "The answer took too long. Try a narrower question."
	case errors.Is(err, ask.ErrUnavailable):
		s.Log.Warn("ask: model provider unavailable", "err", err)
		return "unavailable", "The AI service is busy or unreachable. Try again in a minute."
	case errors.Is(err, ask.ErrRejected):
		s.Log.Error("ask: model provider rejected the request", "err", err)
		return "unavailable", "Ask Stackurity is not working right now. An administrator has been told."
	}
	s.Log.Error("ask: question failed", "err", err, "path", r.URL.Path)
	return "internal", "Something went wrong. Try again."
}

// askPage checks the page the person had open: its id has the right form,
// and they can read it. A page they cannot read is left out, silently.
func (s *Server) askPage(ctx context.Context, api *askAPI, pg *ask.PageRef) *ask.PageRef {
	if pg == nil {
		return nil
	}
	var path string
	switch pg.Kind {
	case "finding", "asset", "component":
		n, err := strconv.ParseInt(pg.ID, 10, 64)
		if err != nil || n <= 0 {
			return nil
		}
		path = map[string]string{"finding": "/api/v1/findings/", "asset": "/api/v1/assets/", "component": "/api/v1/components/"}[pg.Kind] + pg.ID
	case "fix_group":
		if !fixGroupID.MatchString(pg.ID) {
			return nil
		}
		return &ask.PageRef{Kind: pg.Kind, ID: pg.ID}
	default:
		return nil
	}
	var out json.RawMessage
	if err := api.Do(ctx, "GET", path, nil, nil, &out); err != nil {
		return nil
	}
	return &ask.PageRef{Kind: pg.Kind, ID: pg.ID}
}

// --- the tools' API

type viaAskKey struct{}

// viaAsk reports whether the request is a tool of Ask Stackurity calling
// the API in process. Only askAPI sets it; nothing from outside can.
func viaAsk(ctx context.Context) bool {
	v, _ := ctx.Value(viaAskKey{}).(bool)
	return v
}

// askPaths are the API paths the read-only tools use.
var askPaths = []string{"/api/v1/search?", "/api/v1/assets?", "/api/v1/assets/", "/api/v1/fix-groups?", "/api/v1/fix-groups/summary?",
	"/api/v1/findings?", "/api/v1/findings/", "/api/v1/components?", "/api/v1/components/", "/api/v1/inventory?", "/api/v1/inventory/updates?"}

// askAPI is the API as Ask Stackurity's tools see it: each call goes
// through the server's own router with the person's session, as if their
// browser had sent it, marked as Ask's. It reads only (GET, the tools'
// paths). The session never leaves this process: it is not in errors,
// logs or anything the model sees.
type askAPI struct {
	s       *Server
	session string
	remote  string
	project string
}

var errAskPath = errors.New("Ask Stackurity cannot read that")

func (a *askAPI) Do(ctx context.Context, method, path string, body io.Reader, _ map[string]string, out any) error {
	if method != http.MethodGet || body != nil || strings.Contains(path, "..") || !askPathAllowed(path) {
		return errAskPath
	}
	ctx = context.WithValue(context.WithValue(ctx, chi.RouteCtxKey, nil), viaAskKey{}, true)
	req, err := http.NewRequestWithContext(ctx, method, path, nil)
	if err != nil {
		return errAskPath
	}
	req.RemoteAddr = a.remote
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: a.session})
	req.Header.Set("User-Agent", "stackurity-ask")
	if a.project != "" {
		req.Header.Set("X-Stackurity-Project", a.project)
	}
	rec := &recorder{header: http.Header{}, status: 200}
	a.s.router.ServeHTTP(rec, req)
	if rec.status >= 300 {
		var e struct {
			Error client.APIError `json:"error"`
		}
		_ = json.Unmarshal(rec.body.Bytes(), &e)
		e.Error.Status = rec.status
		return &e.Error
	}
	if out == nil || rec.body.Len() == 0 {
		return nil
	}
	return json.NewDecoder(bytes.NewReader(rec.body.Bytes())).Decode(out)
}

func askPathAllowed(path string) bool {
	for _, p := range askPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// --- alerts

// askAlert tells people a spend cap is near or reached: the
// organisation's admins for its cap (audit log and email), the
// installation's admins for the global cap (audit log, server log and
// Platform health).
func (s *Server) askAlert(ctx context.Context, scope string, level int, spent, capMicros int64) {
	detail := map[string]any{"level": level, "spent_micros": spent, "cap_micros": capMicros}
	sys := store.Actor{Type: "system", Name: "Ask Stackurity"}
	if scope == "global" {
		s.Log.Warn("Ask Stackurity: the installation's monthly spend cap", "percent", level, "spent_usd", float64(spent)/1e6, "cap_usd", float64(capMicros)/1e6)
		_ = s.Store.Audit(tenant.System(ctx), sys, "ask.global_spend_alert", "installation", "", detail)
		return
	}
	_ = s.Store.Audit(ctx, sys, "ask.spend_alert", "workspace", "", detail)
	if s.AccountMail == nil {
		return
	}
	users, err := s.Store.ListUsers(ctx)
	if err != nil {
		s.Log.Error("ask: listing admins for a spend alert", "err", err)
		return
	}
	var to []string
	for _, u := range users {
		if u.Role == auth.RoleAdmin && !u.Disabled {
			to = append(to, u.Email)
		}
	}
	if len(to) == 0 {
		return
	}
	title := "Ask Stackurity has used 80% of this month's budget"
	line := "Your organisation has used 80% of its Ask Stackurity budget for this month. When it is used up, questions stop until the 1st."
	if level >= 100 {
		title = "Ask Stackurity's budget for this month is used up"
		line = "Your organisation has used its Ask Stackurity budget for this month. Questions are paused until the 1st."
	}
	m := notify.Message{Event: "ask_spend", Title: title, At: time.Now().UTC(), Summary: []string{line,
		"An administrator can turn Ask Stackurity off under Settings → AI assistants."}}
	if err := s.AccountMail.SendMail(ctx, to, m); err != nil {
		s.Log.Error("ask: spend alert email not sent", "err", err)
	}
}
