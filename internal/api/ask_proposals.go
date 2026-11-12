package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/mcp"
	"github.com/stackurity/stackurity/internal/store"
)

// Changes Ask Stackurity proposed (internal/ask/propose.go). The model can
// only propose: a proposal is the write tool's preview and confirm code,
// stored with the conversation. These endpoints are the person's click:
//
//	POST /ask/conversations/{id}/proposals/{pid}/apply
//	POST /ask/conversations/{id}/proposals/{pid}/dismiss
//	POST /ask/conversations/{id}/proposals/{pid}/undo
//
// They take a browser session only (askPerson: no API token, no connected
// assistant, never Ask's own tool calls), with the CSRF header like every
// other Ask endpoint, for a proposal of the caller's own conversation. Apply
// runs the write tool's confirm path (mcp.ApplyChange) through the
// server's own router with the person's session, as the dashboard would:
// the same API, role checks, project scope and two-factor policy. When what
// the change covers changed since the preview, the confirm code no longer
// matches and nothing is applied: the new preview is stored and shown, to
// apply again. A proposal can be applied once, within store.AskProposalTTL
// of being proposed. The audit log records each change as the person's,
// with "(via Ask Stackurity)" after their name and, for issue actions,
// detail.source "ask" (as Slack's actions have "slack").

// The source of a change applied from an Ask proposal, in the audit log.
const askApplySource = "ask"

func (s *Server) askProposalRoutes(r chi.Router) {
	r.Post("/ask/conversations/{id}/proposals/{pid}/apply", s.askApplyProposal)
	r.Post("/ask/conversations/{id}/proposals/{pid}/dismiss", s.askDismissProposal)
	r.Post("/ask/conversations/{id}/proposals/{pid}/undo", s.askUndoProposal)
}

// askProposalTarget checks the person and the switch and parses the ids.
func (s *Server) askProposalTarget(w http.ResponseWriter, r *http.Request) (*Principal, int64, int64, bool) {
	p, ok := askPerson(w, r)
	if !ok {
		return nil, 0, 0, false
	}
	conv, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return nil, 0, 0, false
	}
	pid, err := idParam(r, "pid")
	if err != nil {
		s.fail(w, r, err)
		return nil, 0, 0, false
	}
	return p, conv, pid, true
}

// askProposalsAllowed answers false (and the error) when Ask cannot be
// used now, or the organisation turned proposals off.
func (s *Server) askProposalsAllowed(w http.ResponseWriter, r *http.Request) bool {
	l, err := s.askLimits(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if status, code, msg := s.askUnavailable(r.Context(), l); code != "" {
		writeError(w, status, code, msg)
		return false
	}
	if !l.Propose {
		writeError(w, 403, "proposals_off", "An administrator has turned off changes proposed by Ask Stackurity. Make the change on its page instead.")
		return false
	}
	return true
}

// proposalError answers an error with the proposal as it now is, so the
// panel can show its new state.
func proposalError(w http.ResponseWriter, status int, code, msg string, p *store.AskProposal) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg, "proposal": p}})
}

// proposalStateError answers a proposal that is not open.
func proposalStateError(w http.ResponseWriter, err error) bool {
	var se *store.AskProposalStateError
	if !errors.As(err, &se) {
		return false
	}
	p := se.Proposal
	msg := map[string]string{
		"applied":   "This change was applied already.",
		"applying":  "This change is being applied.",
		"dismissed": "This change was dismissed.",
		"expired":   "This proposal has expired: proposals can be applied for 15 minutes. Ask again to get a new one.",
		"failed":    "This change could not be applied.",
		"undone":    "This change was undone.",
		"undoing":   "This change is being undone.",
		"proposed":  "This change has not been applied, so there is nothing to undo.",
	}[p.Status]
	if msg == "" {
		msg = "This proposal cannot do that now."
	}
	if p.Status == "applied" && p.Undo != nil && !p.CanUndo {
		msg = "This change can no longer be undone from Ask Stackurity. Change it on its page."
	}
	code := "proposal_" + p.Status
	if p.Status == "expired" {
		writeJSON(w, 410, map[string]any{"error": map[string]any{"code": code, "message": msg, "proposal": p}})
		return true
	}
	proposalError(w, 409, code, msg, p)
	return true
}

// POST /ask/conversations/{id}/proposals/{pid}/apply: the person applies a
// proposal. 200 {"proposal"} when applied. 409 changed (with the new
// preview: nothing was applied), 409 proposal_applied / proposal_dismissed,
// 410 proposal_expired; the API's own refusal (403 for a role too low)
// with the proposal marked failed.
func (s *Server) askApplyProposal(w http.ResponseWriter, r *http.Request) {
	p, conv, pid, ok := s.askProposalTarget(w, r)
	if !ok || !s.askProposalsAllowed(w, r) {
		return
	}
	ctx := r.Context()
	pr, err := s.Store.ClaimAskProposal(ctx, p.User.ID, conv, pid)
	if proposalStateError(w, err) {
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// From here the change runs to its end even if the browser goes away,
	// so the proposal never stays half applied.
	actx := context.WithoutCancel(ctx)
	var args map[string]any
	if err := json.Unmarshal(pr.Args, &args); err != nil {
		args = nil
	}
	api := s.askActingAPI(r, p)
	done, fresh, err := mcp.ApplyChange(actx, api, pr.Tool, args, pr.Code)
	switch {
	case err != nil:
		status, code, msg := askApplyError(err)
		failed, ferr := s.Store.FinishAskProposal(actx, pr.ID, false, nil, msg, "", nil)
		if ferr != nil {
			s.fail(w, r, ferr)
			return
		}
		proposalError(w, status, code, msg, failed)
	case fresh != nil:
		again, err := s.Store.ReproposeAskProposal(actx, pr.ID, fresh.Summary, fresh.Details, fresh.Notes, fresh.Code)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		proposalError(w, 409, "changed", "What this change covers has changed since Ask proposed it, so nothing was changed. "+
			"Check the new preview and click Apply again.", again)
	default:
		var undo any
		if done.Undo != nil {
			undo = done.Undo
		}
		applied, err := s.Store.FinishAskProposal(actx, pr.ID, true, done.Result, "", done.Link, undo)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		writeJSON(w, 200, map[string]any{"proposal": applied})
	}
}

// POST /ask/conversations/{id}/proposals/{pid}/dismiss: the person closes
// a proposal without applying it.
func (s *Server) askDismissProposal(w http.ResponseWriter, r *http.Request) {
	p, conv, pid, ok := s.askProposalTarget(w, r)
	if !ok {
		return
	}
	pr, err := s.Store.DismissAskProposal(r.Context(), p.User.ID, conv, pid)
	if proposalStateError(w, err) {
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"proposal": pr})
}

// POST /ask/conversations/{id}/proposals/{pid}/undo: the person reverses an
// applied change that has a clean reverse (a snooze: the issues are
// reopened; a rename: the old name back), once, within 15 minutes of
// applying it, through the same API and checks.
func (s *Server) askUndoProposal(w http.ResponseWriter, r *http.Request) {
	p, conv, pid, ok := s.askProposalTarget(w, r)
	if !ok || !s.askProposalsAllowed(w, r) {
		return
	}
	pr, err := s.Store.ClaimAskProposalUndo(r.Context(), p.User.ID, conv, pid)
	if proposalStateError(w, err) {
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actx := context.WithoutCancel(r.Context())
	var u mcp.Undo
	_ = json.Unmarshal(pr.Undo, &u)
	if _, err := mcp.UndoChange(actx, s.askActingAPI(r, p), u); err != nil {
		status, code, msg := askApplyError(err)
		back, ferr := s.Store.FinishAskProposalUndo(actx, pr.ID, false, "Undo failed: "+msg)
		if ferr != nil {
			s.fail(w, r, ferr)
			return
		}
		proposalError(w, status, code, msg, back)
		return
	}
	undone, err := s.Store.FinishAskProposalUndo(actx, pr.ID, true, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"proposal": undone})
}

// askApplyError turns an error of the change into what the person is told:
// the API's own refusal as it is (status, code, message), or a change the
// tool would not make (400 not_applied).
func askApplyError(err error) (int, string, string) {
	var apiErr *client.APIError
	if errors.As(err, &apiErr) && apiErr.Status >= 400 {
		msg := apiErr.Message
		if len(apiErr.Details) > 0 {
			msg += " (" + strings.Join(apiErr.Details, "; ") + ")"
		}
		if msg == "" {
			msg = "The change was refused."
		}
		return apiErr.Status, apiErr.Code, msg
	}
	if errors.Is(err, errAskPath) {
		return 500, "internal", "Ask Stackurity could not make this change."
	}
	return 400, "not_applied", strings.TrimPrefix(err.Error(), "not done: ")
}

// --- the person's click, through the API

type viaAskApplyKey struct{}

// askApplyWorkspace is the organisation a proposal is being applied in,
// for a request the apply endpoint makes in process (0: not one). Only
// askActingAPI sets it; nothing from outside can.
func askApplyWorkspace(ctx context.Context) int64 {
	v, _ := ctx.Value(viaAskApplyKey{}).(int64)
	return v
}

// askActingAPI is the API as the person's click on Apply or Undo uses it:
// each call goes through the server's own router with the person's
// session and the CSRF header, as their browser would send it, so every
// check of the dashboard applies. Unlike askAPI (the model's tools, read
// only) it may change things, but only the calls the proposable tools make
// (askActRoutes). It is used only by the apply and undo endpoints, never
// while the model answers.
type askActingAPI struct {
	s         *Server
	session   string
	remote    string
	project   string
	workspace int64
}

func (s *Server) askActingAPI(r *http.Request, p *Principal) *askActingAPI {
	cookie, _ := r.Cookie(sessionCookie)
	a := &askActingAPI{s: s, remote: r.RemoteAddr, project: r.Header.Get("X-Stackurity-Project"), workspace: p.Workspace}
	if cookie != nil {
		a.session = cookie.Value
	}
	return a
}

// askActRoutes are the calls the proposable write tools make (internal/mcp
// write.go: assign, snooze, ignore, check_again, add_assets_to_project,
// rename_project) and their undo (propose.go).
var askActRoutes = []struct {
	method string
	path   *regexp.Regexp
}{
	{"GET", regexp.MustCompile(`^/api/v1/auth/me$`)},
	{"GET", regexp.MustCompile(`^/api/v1/users/directory$`)},
	{"GET", regexp.MustCompile(`^/api/v1/findings/[0-9]+$`)},
	{"GET", regexp.MustCompile(`^/api/v1/fix-groups/[A-Za-z0-9:_.%-]+\?limit=[0-9]+$`)},
	{"GET", regexp.MustCompile(`^/api/v1/projects/[0-9]+$`)},
	{"GET", regexp.MustCompile(`^/api/v1/assets/[0-9]+$`)},
	{"POST", regexp.MustCompile(`^/api/v1/findings/actions$`)},
	{"POST", regexp.MustCompile(`^/api/v1/ignore-requests$`)},
	{"POST", regexp.MustCompile(`^/api/v1/fix-groups/[A-Za-z0-9:_.%-]+/check$`)},
	{"POST", regexp.MustCompile(`^/api/v1/assets/[0-9]+/check$`)},
	{"POST", regexp.MustCompile(`^/api/v1/projects/[0-9]+/assets$`)},
	{"PATCH", regexp.MustCompile(`^/api/v1/projects/[0-9]+$`)},
}

func askActAllowed(method, path string) bool {
	if strings.Contains(path, "..") {
		return false
	}
	for _, rt := range askActRoutes {
		if rt.method == method && rt.path.MatchString(path) {
			return true
		}
	}
	return false
}

func (a *askActingAPI) Do(ctx context.Context, method, path string, body io.Reader, _ map[string]string, out any) error {
	if a.workspace <= 0 || a.session == "" || !askActAllowed(method, path) {
		return errAskPath
	}
	var raw []byte
	if body != nil {
		b, err := io.ReadAll(io.LimitReader(body, 1<<20))
		if err != nil {
			return errAskPath
		}
		raw = b
	}
	ctx = context.WithValue(context.WithValue(ctx, chi.RouteCtxKey, nil), viaAskApplyKey{}, a.workspace)
	ctx = context.WithValue(ctx, originKey{}, actionOrigin{Source: askApplySource})
	req, err := http.NewRequestWithContext(ctx, method, path, bytes.NewReader(raw))
	if err != nil {
		return errAskPath
	}
	req.RemoteAddr = a.remote
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: a.session})
	req.Header.Set("User-Agent", "stackurity-ask-apply")
	req.Header.Set("X-Stackurity-CSRF", "1")
	if len(raw) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
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
