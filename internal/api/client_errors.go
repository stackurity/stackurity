package api

// Error reports (docs/install.md#error-reports): the dashboard reports the
// errors people hit (POST /client-errors), the server records its own 5xx
// answers and panics (captureServerErrors), and instance administrators see
// them counted per fingerprint on Platform health (GET /admin/client-errors).
// Everything stays in this installation's database; nothing is sent
// anywhere. STACKURITY_CLIENT_ERRORS=off turns all of it off.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/stackurity/stackurity/internal/clienterrors"
	"github.com/stackurity/stackurity/internal/store"
)

const clientErrorsPath = "/api/v1/client-errors"

var (
	// limitClientErrorsAddress caps reports from pages before sign-in, per
	// client address; limitClientErrorsUser caps a signed-in person's. A
	// page sends at most 20 reports, a few at a time.
	limitClientErrorsAddress = rateLimit{30, time.Minute}
	limitClientErrorsUser    = rateLimit{60, time.Minute}
)

type clientErrorsRequest struct {
	Reports []json.RawMessage `json:"reports"`
}

// clientErrors records what the dashboard reports. It answers 204 whatever
// it kept, so the browser never has anything to show about reporting; a
// report it cannot read is dropped, not refused.
func (s *Server) clientErrors(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	if p != nil && (p.Token != nil || p.Assistant != nil || p.FeedbackAgent != nil || p.FeedbackReviewer != nil) {
		writeError(w, 403, "forbidden", "error reports come from the dashboard only")
		return
	}
	if !s.ClientErrors {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	hit := limitHit{"client-errors-address", clientIP(r), limitClientErrorsAddress}
	if p != nil && p.User != nil {
		hit = limitHit{"client-errors-user", fmt.Sprint(p.User.ID), limitClientErrorsUser}
	}
	if s.limited(w, r, "too many error reports; wait a minute", hit) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, clienterrors.MaxBody))
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		writeError(w, 413, "too_large", fmt.Sprintf("at most %d bytes of reports", clienterrors.MaxBody))
		return
	}
	if err != nil {
		writeError(w, 400, "bad_request", "could not read the reports")
		return
	}
	var req clientErrorsRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, 400, "bad_request", "invalid JSON body")
		return
	}
	var clean []clienterrors.Clean
	for _, raw := range req.Reports {
		if len(clean) == clienterrors.MaxReports {
			break
		}
		var rep clienterrors.Report
		if json.Unmarshal(raw, &rep) != nil {
			continue
		}
		c, ok := clienterrors.Check(rep)
		if !ok {
			continue
		}
		if pat := s.apiPattern(c.Method, rep.APIRoute); pat != "" {
			c.APIRoute = pat
		}
		clean = append(clean, c)
	}
	var ws int64
	if p != nil && p.Session {
		ws = p.Workspace
	}
	if err := s.Store.RecordClientErrors(r.Context(), ws, clean); err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// apiPattern is the router's pattern for an API path the dashboard called
// ("/api/v1/assets/{id}"), or "" when no route matches it (the report then
// keeps its own path, with identifiers already replaced).
func (s *Server) apiPattern(method, path string) string {
	if s.mux == nil || method == "" || !strings.HasPrefix(path, "/api/") {
		return ""
	}
	if i := strings.IndexAny(path, "?#"); i >= 0 {
		path = path[:i]
	}
	return clienterrors.Path(s.mux.Find(chi.NewRouteContext(), method, path), "{id}")
}

// adminClientErrors lists, for instance administrators, the errors new in
// the last 24 hours and the most frequent over 7 days, across workspaces.
// Workspaces are counted, never named.
func (s *Server) adminClientErrors(w http.ResponseWriter, r *http.Request) {
	sum, err := s.Store.ClientErrorsSummary(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"enabled": s.ClientErrors, "new": sum.New, "top": sum.Top,
		"retention_days": int(store.ClientErrorRetention / (24 * time.Hour))})
}

// --- the server's own errors

// serverErrorNote is filled while a request is served: the workspace once
// authenticate knows it, and what failed (Server.fail, recoverer).
type serverErrorNote struct {
	workspace int64
	name      string
	message   string
	frame     string
}

type serverErrorNoteKey struct{}

func errorNote(ctx context.Context) *serverErrorNote {
	n, _ := ctx.Value(serverErrorNoteKey{}).(*serverErrorNote)
	return n
}

// noteError records what failed, for captureServerErrors.
func noteError(r *http.Request, name, message, frame string) {
	if n := errorNote(r.Context()); n != nil {
		n.name, n.message, n.frame = name, message, frame
	}
}

// noteWorkspace runs after authenticate: server errors are counted under
// the caller's workspace.
func noteWorkspace(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n, p := errorNote(r.Context()), principal(r); n != nil && p != nil {
			n.workspace = p.Workspace
		}
		next.ServeHTTP(w, r)
	})
}

type serverErrorEvent struct {
	workspace int64
	report    clienterrors.Clean
}

// serverErrors writes the server's own error reports in the background, so
// a burst of 5xx answers never waits on (or piles onto) the database: what
// does not fit in the queue is dropped.
type serverErrors struct {
	once sync.Once
	ch   chan serverErrorEvent
	// warned limits the "could not record" warning to one a minute.
	mu     sync.Mutex
	warned time.Time
}

// captureServerErrors records each 5xx answer of the API under its route
// pattern, method, status and error code, with what Server.fail or the
// recoverer noted. It wraps the recoverer, so it sees panics as the 500
// they become.
func (s *Server) captureServerErrors(next http.Handler) http.Handler {
	if !s.ClientErrors {
		return next
	}
	s.serverErrs.once.Do(func() {
		s.serverErrs.ch = make(chan serverErrorEvent, 256)
		go s.recordServerErrors()
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == clientErrorsPath {
			next.ServeHTTP(w, r)
			return
		}
		note := &serverErrorNote{}
		r = r.WithContext(context.WithValue(r.Context(), serverErrorNoteKey{}, note))
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		head := &headBuffer{}
		ww.Tee(head)
		next.ServeHTTP(ww, r)
		status := ww.Status()
		if status < 500 {
			return
		}
		pattern := ""
		if rc := chi.RouteContext(r.Context()); rc != nil {
			pattern = rc.RoutePattern()
		}
		if pattern == "" {
			pattern = "(no route)"
		}
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(head.Bytes(), &body)
		c := clienterrors.Server(r.Method, pattern, status, body.Error.Code, note.name, note.message, note.frame, s.Version)
		select {
		case s.serverErrs.ch <- serverErrorEvent{note.workspace, c}:
		default: // the queue is full: drop it
		}
	})
}

func (s *Server) recordServerErrors() {
	for ev := range s.serverErrs.ch {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.Store.RecordClientErrors(ctx, ev.workspace, []clienterrors.Clean{ev.report})
		cancel()
		if err != nil {
			s.serverErrs.mu.Lock()
			if time.Since(s.serverErrs.warned) > time.Minute {
				s.serverErrs.warned = time.Now()
				s.Log.Warn("could not record a server error report", "err", err)
			}
			s.serverErrs.mu.Unlock()
		}
	}
}

// headBuffer keeps the first bytes written to a response: enough for the
// error code of a JSON error.
type headBuffer struct{ bytes.Buffer }

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := 512 - h.Len(); room > 0 {
		if len(p) > room {
			h.Buffer.Write(p[:room])
		} else {
			h.Buffer.Write(p)
		}
	}
	return len(p), nil
}
