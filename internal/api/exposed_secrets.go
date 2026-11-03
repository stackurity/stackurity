package api

import (
	"net/http"
	"strings"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
)

// Exposed secrets (docs/design/exposed-secrets.md): keys, tokens and
// passwords scans found in repositories and in files web servers send.
// Narrowed to the caller's projects; ignoring and reopening need security
// on every asset that holds the secret.

func (s *Server) listExposedSecrets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	switch status {
	case "", "open", "resolved", "ignored", "all":
	default:
		s.fail(w, r, badRequest("status must be open, resolved, ignored or all"))
		return
	}
	sev := q.Get("severity")
	switch sev {
	case "", "critical", "high", "medium", "low":
	default:
		s.fail(w, r, badRequest("severity must be critical, high, medium or low"))
		return
	}
	pg := page(r)
	items, total, err := s.Store.ListExposedSecrets(r.Context(), store.ExposedSecretFilter{
		Status: status, AssetID: qInt(r, "asset_id"), Severity: sev, Limit: pg.Limit, Offset: pg.Offset,
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": nonNil(items), "total": total})
}

func (s *Server) exposedSecretSummary(w http.ResponseWriter, r *http.Request) {
	out, err := s.Store.SummarizeExposedSecrets(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) ignoreExposedSecret(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if in.Reason == "" || len(in.Reason) > 500 {
		s.fail(w, r, badRequest("reason is required (up to 500 characters): why this secret needs no action, such as a test key or one already revoked"))
		return
	}
	s.changeExposedSecret(w, r, "open", "exposed_secret.ignore", func(id int64) (int64, error) {
		return s.Store.IgnoreExposedSecret(r.Context(), id, actorUserID(principal(r)), in.Reason)
	}, in)
}

func (s *Server) reopenExposedSecret(w http.ResponseWriter, r *http.Request) {
	s.changeExposedSecret(w, r, "ignored", "exposed_secret.reopen", func(id int64) (int64, error) {
		return s.Store.ReopenExposedSecret(r.Context(), id)
	}, nil)
}

func (s *Server) changeExposedSecret(w http.ResponseWriter, r *http.Request, from, action string, change func(int64) (int64, error), detail any) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	assets, err := s.Store.ExposedSecretAssets(r.Context(), id, from)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(assets) > 0 && !s.requireOn(w, r, auth.RoleSecurity, assets...) {
		return
	}
	n, err := change(id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), action, "exposed_secret", itoa(id), map[string]any{"rows": n, "detail": detail})
	writeJSON(w, 200, map[string]any{"changed": n})
}
