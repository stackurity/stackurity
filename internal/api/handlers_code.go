package api

// Code findings (store/code_findings.go): what code-review security
// scanners found in a repository's source, imported from their reports
// (deepsec's JSON export, SARIF 2.1.0; internal/codefindings). Importing is
// for whoever may upload observations (collector tokens, a CI job's token
// for its own repository, engineers and above); reading them is for anyone
// who can see the asset; dismissing one, like ignoring a finding, is for
// the security role. They are part of the free edition.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/codefindings"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// FeatureCodeFindings, in GET /meta's features, says that POST
// /code-findings/import exists.
const FeatureCodeFindings = "code_findings"

// importCodeFindings: POST /code-findings/import?format=deepsec|sarif with
// the report as the body, for the repository named by asset_id or git_url
// (an asset that has reported already: an import never creates one).
// complete=false imports a filtered report without resolving what it does
// not hold; model records the AI model that produced the report.
func (s *Server) importCodeFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format != codefindings.FormatDeepsec && format != codefindings.FormatSARIF {
		s.fail(w, r, badRequest("format must be deepsec or sarif"))
		return
	}
	complete := true
	if v := q.Get("complete"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			s.fail(w, r, badRequest("complete must be true or false"))
			return
		}
		complete = b
	}
	model := q.Get("model")
	if len(model) > 128 {
		s.fail(w, r, badRequest("model is limited to 128 characters"))
		return
	}
	model = codefindings.CleanModel(model)
	assetID, ok := s.codeImportAsset(w, r)
	if !ok {
		return
	}
	rd, err := s.body(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	data, err := io.ReadAll(io.LimitReader(rd, codefindings.MaxDocumentSize+1))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, 413, "too_large", "the report is larger than the server accepts")
			return
		}
		s.fail(w, r, badRequest("could not read the report"))
		return
	}
	if len(data) > codefindings.MaxDocumentSize {
		writeError(w, 413, "too_large", "the report is larger than 16 MB")
		return
	}
	rep, err := codefindings.Parse(format, data)
	if err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	if err := s.Store.CheckWritable(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.Store.ImportCodeFindings(r.Context(), assetID, rep, model, complete)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sources := make([]string, 0, len(res.Sources))
	found, gone := 0, int64(0)
	for _, src := range res.Sources {
		sources = append(sources, src.Source)
		found += src.Found
		gone += src.Gone
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "code_findings.import", "asset", itoa(assetID),
		map[string]any{"format": format, "sources": sources, "found": found, "gone": gone, "complete": complete, "model": model})
	writeJSON(w, 201, res)
}

// codeImportAsset resolves the asset an import is for: asset_id, or
// git_url (a repository's URL, as stackurity scan reports it). A CI job's
// token may import only for its own repository, and a token bound to an
// asset only for that asset. Only repositories and applications hold
// source code.
func (s *Server) codeImportAsset(w http.ResponseWriter, r *http.Request) (int64, bool) {
	q := r.URL.Query()
	idParam, gitURL := q.Get("asset_id"), strings.TrimSpace(q.Get("git_url"))
	if (idParam == "") == (gitURL == "") {
		s.fail(w, r, badRequest("give the asset as asset_id or git_url (one of them)"))
		return 0, false
	}
	ci := ciRepository(r)
	if ci != "" && (gitURL == "" || !strings.EqualFold(gitrepo.NormalizeURL(gitURL), ci)) {
		writeError(w, 403, "forbidden", "this token was issued to a CI job of "+ci+" and can import only for that repository: use --git-url "+ci)
		return 0, false
	}
	var id int64
	var err error
	if gitURL != "" {
		id, err = s.Store.AssetByIdentifier(r.Context(), "git-url", gitrepo.NormalizeURL(gitURL))
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, 404, "not_found", "no repository with this URL has reported yet: scan it first (stackurity scan, or a repository integration)")
			return 0, false
		}
	} else {
		id, err = strconv.ParseInt(idParam, 10, 64)
		if err != nil || id <= 0 {
			s.fail(w, r, badRequest("asset_id must be a number"))
			return 0, false
		}
	}
	if err != nil {
		s.fail(w, r, err)
		return 0, false
	}
	if id, err = s.Store.LiveAssetID(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return 0, false
	}
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return 0, false
	}
	if a.Kind != string(model.AssetRepository) && a.Kind != string(model.AssetApplication) {
		s.fail(w, r, badRequest("code findings can be imported for a repository or an application, not a "+a.Kind))
		return 0, false
	}
	bound, err := s.boundAsset(r)
	if err != nil {
		s.fail(w, r, err)
		return 0, false
	}
	if bound != nil && *bound != id {
		writeError(w, 403, "forbidden", "this token is bound to another asset")
		return 0, false
	}
	return id, true
}

// assetRecords serves an asset's list route (/assets/{id}/...): it checks
// the asset can be seen, sets *assetID and returns what load gives for it,
// never nil, so an empty list says "never checked". Elsewhere it returns
// nil.
func assetRecords[T any](s *Server, r *http.Request, assetID *int64, load func(context.Context, int64) ([]T, error)) (*[]T, error) {
	if chi.URLParam(r, "id") == "" {
		return nil, nil
	}
	id, err := idParam(r, "id")
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.GetAsset(r.Context(), id); err != nil {
		return nil, err
	}
	*assetID = id
	got, err := load(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if got == nil {
		got = []T{}
	}
	return &got, nil
}

func codeFilter(r *http.Request) (store.CodeFindingFilter, error) {
	q := r.URL.Query()
	f := store.CodeFindingFilter{Status: q.Get("status"), Severity: q.Get("severity"), Category: q.Get("category"),
		Source: q.Get("source"), Page: page(r)}
	if v := q.Get("asset_id"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil || id <= 0 {
			return f, badRequest("asset_id must be a number")
		}
		f.AssetID = id
	}
	return f, nil
}

// listCodeFindings: GET /code-findings, and GET /assets/{id}/code-findings
// with the asset's last import of each source (none means no report was
// imported).
func (s *Server) listCodeFindings(w http.ResponseWriter, r *http.Request) {
	f, err := codeFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	imports, err := assetRecords(s, r, &f.AssetID, s.Store.CodeImports)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, total, err := s.Store.ListCodeFindings(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, struct {
		list[store.CodeFinding]
		Imports *[]store.CodeImportRecord `json:"imports,omitempty"`
	}{paged(items, total, f.Page), imports})
}

// codeSummary: GET /code-findings/summary, open findings by severity and
// category, and how many assets have an import.
func (s *Server) codeSummary(w http.ResponseWriter, r *http.Request) {
	f, err := codeFilter(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum, err := s.Store.SummariseCodeFindings(r.Context(), f.AssetID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, sum)
}

// dismissCodeFinding and undismissCodeFinding: POST
// /code-findings/{id}/dismiss and /undismiss, for the security role.
func (s *Server) dismissCodeFinding(w http.ResponseWriter, r *http.Request) {
	s.codeAction(w, r, true)
}

func (s *Server) undismissCodeFinding(w http.ResponseWriter, r *http.Request) {
	s.codeAction(w, r, false)
}

func (s *Server) codeAction(w http.ResponseWriter, r *http.Request, dismiss bool) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
			s.fail(w, r, badRequest("body must be JSON: {\"note\": \"...\"}"))
			return
		}
	}
	note := strings.TrimSpace(req.Note)
	if len(note) > 1000 {
		s.fail(w, r, badRequest("note is limited to 1000 characters"))
		return
	}
	if !s.codeAllowed(w, r, id) {
		return
	}
	p := principal(r)
	var c *store.CodeFinding
	action := "code_finding.dismiss"
	if dismiss {
		var by *int64
		if u := userID(p); u > 0 {
			by = &u
		}
		c, err = s.Store.DismissCodeFinding(r.Context(), id, by, note)
	} else {
		action = "code_finding.undismiss"
		c, err = s.Store.UndismissCodeFinding(r.Context(), id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), action, "code_finding", itoa(id), map[string]any{"asset_id": c.AssetID,
		"path": c.Path, "rule": c.Rule, "source": c.Source, "note": note})
	writeJSON(w, 200, c)
}

// codeAllowed checks the caller has the security role, organisation-wide
// or from a project grant on the finding's asset.
func (s *Server) codeAllowed(w http.ResponseWriter, r *http.Request, id int64) bool {
	p := principal(r)
	if !auth.Higher(p.Role, p.ProjectRole).AtLeast(auth.RoleSecurity) {
		writeError(w, 403, "forbidden", "dismissing a code finding requires the "+string(auth.RoleSecurity)+" role")
		return false
	}
	if p.Role.AtLeast(auth.RoleSecurity) {
		return true
	}
	assets, err := s.Store.CodeFindingAssets(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return false
	}
	if len(assets) == 0 {
		s.fail(w, r, store.ErrNotFound)
		return false
	}
	return s.requireOn(w, r, auth.RoleSecurity, assets...)
}
