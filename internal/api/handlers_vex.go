package api

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/vex"
)

// VEX import and export (docs/risk.md, "VEX"; store/vex.go). The trust
// model: an imported not_affected statement waits in the approval inbox
// for an organisation-wide security or admin user, unless the document
// came from a source an admin trusts to apply on its own, and that source
// is pinned to something the document cannot claim by itself (a public key
// its signed attestation verifies with, or the API token that uploaded it).

// readVEXBody reads an upload of at most limit bytes.
func (s *Server) readVEXBody(w http.ResponseWriter, r *http.Request, limit int) ([]byte, error) {
	rd, err := s.body(w, r)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(rd, int64(limit)+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, badRequest(fmt.Sprintf("the document is larger than %d MiB", limit>>20))
		}
		return nil, badRequest("could not read the document")
	}
	if len(data) > limit {
		return nil, badRequest(fmt.Sprintf("the document is larger than %d MiB", limit>>20))
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, badRequest("send the VEX document as the request body")
	}
	return data, nil
}

// vexScope resolves the asset_id or project_id an import is limited to.
func (s *Server) vexScope(r *http.Request) (assets []int64, assetID, projectID *int64, err error) {
	if id := qInt(r, "asset_id"); id > 0 {
		if _, err := s.Store.GetAsset(r.Context(), id); err != nil {
			return nil, nil, nil, err
		}
		return []int64{id}, &id, nil, nil
	}
	if id := qInt(r, "project_id"); id > 0 {
		if _, err := s.Store.GetProject(r.Context(), id); err != nil {
			return nil, nil, nil, err
		}
		ids, err := s.Store.ProjectAssetIDs(r.Context(), id)
		if err != nil {
			return nil, nil, nil, err
		}
		return ids, nil, &id, nil
	}
	return nil, nil, nil, nil
}

// trust works out whether the document is signed as its source requires,
// and whether it may apply on its own: only for a source that is trusted
// to, every one of whose pins held for this upload.
func trust(p *Principal, src *store.VEXSource, doc *vex.Document) (signature, fingerprint string, auto bool, err error) {
	signature = "none"
	if doc.Envelope != nil {
		signature = "unverified"
	}
	if src == nil {
		return signature, "", false, nil
	}
	if src.KeyFingerprint != "" {
		if doc.Envelope == nil {
			return "", "", false, badRequest("source " + src.Name + " has a public key: upload its signed attestation (a DSSE envelope or Sigstore bundle), not the plain document")
		}
		v, fp, err := vex.ParsePublicKey(src.PublicKey)
		if err != nil {
			return "", "", false, fmt.Errorf("source %d key: %w", src.ID, err)
		}
		if err := v.Verify(doc.Envelope); err != nil {
			return "", "", false, badRequest("the signature does not verify with the key of source " + src.Name + ": " + err.Error())
		}
		signature, fingerprint = "verified", fp
	}
	auto = src.AutoApply && src.Pinned()
	if src.TokenID != nil && (p.Token == nil || p.Token.ID != *src.TokenID) {
		// Uploaded by someone other than the source's token: kept for
		// approval like any other document.
		auto = false
	}
	return signature, fingerprint, auto, nil
}

// importVEX: POST /vex/import. The body is the document: OpenVEX,
// CycloneDX VEX or a BOM with VEX embedded, plain or as a signed
// attestation. source_id names a source, asset_id or project_id limits
// matching, filename records the file name.
func (s *Server) importVEX(w http.ResponseWriter, r *http.Request) {
	data, err := s.readVEXBody(w, r, vex.MaxDocumentSize)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	doc, err := vex.Read(data)
	if err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	var src *store.VEXSource
	if id := qInt(r, "source_id"); id > 0 {
		if src, err = s.Store.GetVEXSource(r.Context(), id); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	p := principal(r)
	signature, fingerprint, auto, err := trust(p, src, doc)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scope, assetID, projectID, err := s.vexScope(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	maxDays, err := s.exceptionMaxDays(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum := sha256.Sum256(data)
	filename := strings.TrimSpace(path.Base(strings.ReplaceAll(r.URL.Query().Get("filename"), `\`, "/")))
	if filename == "." || filename == "/" {
		filename = ""
	}
	if len(filename) > 200 {
		filename = filename[:200]
	}
	actor := p.Actor(r)
	res, err := s.Store.ImportVEX(r.Context(), store.VEXImport{Doc: doc, Filename: filename, SHA256: hex.EncodeToString(sum[:]),
		Size: len(data), Source: src, Signature: signature, KeyFingerprint: fingerprint, ScopeAssets: scope, ScopeAssetID: assetID,
		ScopeProjectID: projectID, AutoApply: auto, MaxDays: maxDays}, actor)
	if err != nil {
		s.failAction(w, r, err)
		return
	}
	s.auditVEXImport(r, actor, res)
	writeJSON(w, 201, res)
}

func (s *Server) auditVEXImport(r *http.Request, actor store.Actor, res *store.VEXImportResult) {
	d := res.Document
	_ = s.Store.Audit(r.Context(), actor, "vex.import", "vex_document", itoa(d.ID), map[string]any{
		"filename": d.Filename, "sha256": d.SHA256, "size": d.Size, "format": d.Format, "doc_id": d.DocID, "author": d.Author,
		"source": d.SourceName, "source_id": d.SourceID, "signature": d.Signature, "key_fingerprint": d.KeyFingerprint,
		"scope_asset_id": d.ScopeAssetID, "scope_project_id": d.ScopeProjectID, "via": d.Via, "statements": res.Statements,
		"matched": res.Matched, "unmatched": res.Unmatched, "pending": res.Pending, "auto_approved": res.AutoApproved,
		"ignored": res.Ignored, "ended": res.Ended})
}

// importEmbeddedVEX imports the VEX in an uploaded CycloneDX SBOM for the
// asset the upload created or updated, for approval like any upload.
// Collector tokens only submit inventory: their SBOM's VEX is left out.
func (s *Server) importEmbeddedVEX(r *http.Request, data []byte, res *store.IngestResult) {
	doc, err := vex.ReadBOM(data)
	if err != nil || len(doc.Statements) == 0 {
		return
	}
	p := principal(r)
	if !auth.Higher(p.Role, p.ProjectRole).AtLeast(auth.RoleEngineer) {
		res.VEXNote = "the SBOM has VEX statements; a collector token does not import them: run stackurity vex import with an engineer, security or admin token"
		return
	}
	maxDays, err := s.exceptionMaxDays(r)
	if err != nil {
		return
	}
	sum := sha256.Sum256(data)
	id := res.AssetID
	actor := p.Actor(r)
	out, err := s.Store.ImportVEX(r.Context(), store.VEXImport{Doc: doc, Filename: "sbom upload", SHA256: hex.EncodeToString(sum[:]),
		Size: len(data), SourceName: doc.Author, Signature: "none", ScopeAssets: []int64{id}, ScopeAssetID: &id, Via: "sbom",
		MaxDays: maxDays}, actor)
	if err != nil {
		s.Log.Warn("vex in sbom", "err", err)
		res.VEXNote = "the SBOM's VEX statements could not be imported: " + err.Error()
		return
	}
	s.auditVEXImport(r, actor, out)
	res.VEX = out
}

func (s *Server) listVEXDocuments(w http.ResponseWriter, r *http.Request) {
	pg := page(r)
	items, total, err := s.Store.ListVEXDocuments(r.Context(), pg)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, pg))
}

func (s *Server) getVEXDocument(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.Store.GetVEXDocument(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, d)
}

func (s *Server) listVEXStatements(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.Store.GetVEXDocument(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	f := store.VEXStatementFilter{DocumentID: id, Outcome: r.URL.Query().Get("outcome"), Page: page(r)}
	items, total, err := s.Store.ListVEXStatements(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

// decideVEXDocument approves or declines every pending request of one
// imported document at once.
func (s *Server) decideVEXDocument(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var b struct {
		Decision string `json:"decision"`
		Note     string `json:"note"`
	}
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if b.Decision != "approve" && b.Decision != "decline" {
		s.fail(w, r, badRequest("decision must be approve or decline"))
		return
	}
	if len(b.Note) > 2000 {
		s.fail(w, r, badRequest("note is limited to 2000 characters"))
		return
	}
	if !s.decidesVEX(w, r) {
		return
	}
	d, err := s.Store.GetVEXDocument(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := s.Store.PendingVEXRequests(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	maxDays, err := s.exceptionMaxDays(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	actor := principal(r).Actor(r)
	decided, applied := 0, 0
	for _, rid := range ids {
		req, err := s.Store.DecideIgnoreRequest(r.Context(), rid, b.Decision == "approve", strings.TrimSpace(b.Note), maxDays, actor)
		if errors.Is(err, store.ErrConflict) {
			continue // decided meanwhile
		}
		if err != nil {
			s.failAction(w, r, err)
			return
		}
		decided++
		applied += req.Applied
		s.auditVEXDecision(r, actor, b.Decision, req, b.Note)
	}
	writeJSON(w, 200, map[string]any{"document_id": d.ID, "decided": decided, "applied": applied})
}

// decidesVEX: VEX statements apply across assets and come from outside;
// only organisation-wide security and admin users decide them.
func (s *Server) decidesVEX(w http.ResponseWriter, r *http.Request) bool {
	p := principal(r)
	if p.boundToProject() || !p.Role.AtLeast(auth.RoleSecurity) {
		writeError(w, 403, "forbidden", "deciding imported VEX statements needs an organisation-wide security or admin role")
		return false
	}
	return true
}

func (s *Server) auditVEXDecision(r *http.Request, actor store.Actor, decision string, req *store.IgnoreRequest, note string) {
	d := map[string]any{"note": note, "applied": req.Applied, "requested_by": req.RequestedByName, "vex_statement_id": req.VEXStatementID}
	if v := req.VEX; v != nil {
		d["vex_document_id"], d["source"], d["vulnerability"], d["justification"] = v.DocumentID, v.Source, v.Vulnerability, v.Justification
		d["filename"], d["sha256"], d["signature"] = v.Filename, v.SHA256, v.Signature
	}
	_ = s.Store.Audit(r.Context(), actor, "ignore_request."+decision, "ignore_request", itoa(req.ID), d)
}

// --- sources

type vexSourceBody struct {
	Name      *string `json:"name"`
	AutoApply *bool   `json:"auto_apply"`
	// TokenID pins the source to an API token (0 removes the pin).
	TokenID *int64 `json:"token_id"`
	// PublicKey is a PEM public key ("" removes it).
	PublicKey *string `json:"public_key"`
}

func (b vexSourceBody) input() (store.VEXSourceInput, error) {
	in := store.VEXSourceInput{Name: b.Name, AutoApply: b.AutoApply, TokenID: b.TokenID, PublicKey: b.PublicKey}
	if b.PublicKey != nil && strings.TrimSpace(*b.PublicKey) != "" {
		if len(*b.PublicKey) > 16<<10 {
			return in, badRequest("the public key is too long")
		}
		_, fp, err := vex.ParsePublicKey(*b.PublicKey)
		if err != nil {
			return in, badRequest(err.Error())
		}
		in.KeyFingerprint = fp
	}
	return in, nil
}

func (s *Server) listVEXSources(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListVEXSources(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(items))
}

func (s *Server) saveVEXSource(create bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var id int64
		if !create {
			var err error
			if id, err = idParam(r, "id"); err != nil {
				s.fail(w, r, err)
				return
			}
		}
		var b vexSourceBody
		if err := decode(r, &b); err != nil {
			s.fail(w, r, err)
			return
		}
		in, err := b.input()
		if err != nil {
			s.fail(w, r, err)
			return
		}
		actor := principal(r).Actor(r)
		src, err := s.Store.SaveVEXSource(r.Context(), id, in, actor)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		action, status := "vex_source.update", 200
		if create {
			action, status = "vex_source.create", 201
		}
		_ = s.Store.Audit(r.Context(), actor, action, "vex_source", itoa(src.ID), map[string]any{"name": src.Name,
			"auto_apply": src.AutoApply, "token_id": src.TokenID, "key_fingerprint": src.KeyFingerprint})
		writeJSON(w, status, src)
	}
}

func (s *Server) deleteVEXSource(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteVEXSource(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "vex_source.delete", "vex_source", itoa(id), nil)
	w.WriteHeader(204)
}

// --- export

// exportVEX: GET /vex/export?format=openvex|cyclonedx&asset_id=. Without
// asset_id it covers every asset the caller sees, in the project chosen
// with project_id (or the switcher).
func (s *Server) exportVEX(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = vex.FormatOpenVEX
	}
	if format != vex.FormatOpenVEX && format != vex.FormatCycloneDX {
		s.fail(w, r, badRequest("format must be openvex or cyclonedx"))
		return
	}
	assetID := qInt(r, "asset_id")
	scope, file := "workspace", "stackurity"
	if assetID > 0 {
		if _, err := s.Store.GetAsset(r.Context(), assetID); err != nil {
			s.fail(w, r, err)
			return
		}
		scope, file = fmt.Sprintf("asset %d", assetID), fmt.Sprintf("asset-%d", assetID)
	} else if p := principal(r).Project; p > 0 {
		scope, file = fmt.Sprintf("project %d", p), fmt.Sprintf("project-%d", p)
	}
	rows, err := s.Store.VEXExport(r.Context(), assetID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	author := "Stackurity"
	if ws, err := s.Store.GetWorkspace(r.Context(), principal(r).Workspace); err == nil && ws.Name != "" {
		author = ws.Name + " (via Stackurity)"
	}
	sts := make([]vex.ExportStatement, 0, len(rows))
	for _, row := range rows {
		sts = append(sts, exportStatement(row))
	}
	meta := vex.ExportMeta{Author: author, Tool: "stackurity " + s.Version, Timestamp: time.Now(), Scope: scope}
	if format == vex.FormatCycloneDX {
		w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.vex.cdx.json"`, file))
		err = vex.WriteCycloneDX(w, meta, sts)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.openvex.json"`, file))
		err = vex.WriteOpenVEX(w, meta, sts)
	}
	if err != nil {
		s.Log.Error("export vex", "err", err)
	}
}

// exportStatement turns a stored decision into a statement: the component
// version, inside its image (by digest) or application (by package URL)
// when the asset has one.
func exportStatement(row store.VEXExportRow) vex.ExportStatement {
	comp := row.Purl
	if pu, err := packageurl.FromString(comp); err == nil && pu.Version == "" && row.Version != "" {
		pu.Version = row.Version
		comp = pu.ToString()
	}
	st := vex.ExportStatement{Vulnerability: row.Key, Status: row.Status, Justification: row.Justification,
		ImpactStatement: row.ImpactStatement, ActionStatement: row.ActionStatement, StatusNotes: row.StatusNotes,
		FalsePositive: row.FalsePositive, Component: vex.Product{Purl: comp}, Timestamp: row.At}
	seen := map[string]bool{row.Key: true}
	for _, src := range row.Sources {
		if a := vex.NormalizeVulnID(src); a != "" && !seen[a] {
			seen[a] = true
			st.Aliases = append(st.Aliases, a)
		}
	}
	switch {
	case row.AssetKind == "image" && row.Digest != "":
		st.Product = vex.Product{Purl: vex.ImagePurl(row.AssetName, row.Digest), Digest: row.Digest}
	case row.AssetPurl != "":
		st.Product = vex.Product{Purl: row.AssetPurl}
	}
	return st
}
