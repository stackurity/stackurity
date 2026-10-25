package api

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/sbom"
	"github.com/stackurity/stackurity/internal/store"
)

const (
	maxIngestBody   = 64 << 20  // compressed or raw bytes on the wire
	maxIngestInflow = 256 << 20 // after gzip decompression
)

// body returns the request body, transparently gunzipping and enforcing
// size limits on both the wire and decompressed size.
func body(w http.ResponseWriter, r *http.Request) (io.Reader, error) {
	rd := io.Reader(http.MaxBytesReader(w, r.Body, maxIngestBody))
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return nil, badRequest("invalid gzip body")
		}
		rd = io.LimitReader(gz, maxIngestInflow)
	}
	return rd, nil
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	rd, err := body(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var b model.ObservationBatch
	dec := json.NewDecoder(rd)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		s.fail(w, r, badRequest("invalid batch JSON: "+err.Error()))
		return
	}
	if err := b.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(b.Asset.Identifiers) == 1 && b.Asset.Identifiers[0].Scheme == model.AppPathScheme {
		if code, err := s.bindAppIdentity(r, &b); err != nil {
			writeError(w, code, map[int]string{403: "forbidden", 409: "conflict"}[code], err.Error())
			return
		}
	} else if err := s.checkBoundIngest(r, &b); err != nil {
		writeError(w, 403, "forbidden", err.Error())
		return
	}
	var tokenID int64
	if p := principal(r); p.Token != nil {
		tokenID = p.Token.ID
	}
	res, err := s.Store.Ingest(r.Context(), &b, tokenID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 201, res)
}

func (s *Server) importSBOM(w http.ResponseWriter, r *http.Request) {
	rd, err := body(w, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	var asset *model.AssetRef
	if name := strings.TrimSpace(q.Get("asset_name")); name != "" {
		kind := model.AssetKind(q.Get("asset_kind"))
		if kind == "" {
			kind = model.AssetApplication
		}
		asset = &model.AssetRef{Kind: kind, Name: name, Environment: q.Get("environment"),
			Identifiers: []model.Identifier{{Scheme: "name:" + string(kind), Value: name}}}
	}
	b, err := sbom.Import(rd, asset, s.Version)
	if err != nil {
		s.fail(w, r, badRequest(err.Error()))
		return
	}
	if err := b.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.checkBoundIngest(r, b); err != nil {
		writeError(w, 403, "forbidden", err.Error())
		return
	}
	p := principal(r)
	var tokenID int64
	if p.Token != nil {
		tokenID = p.Token.ID
	}
	res, err := s.Store.Ingest(r.Context(), b, tokenID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "sbom.import", "asset", itoa(res.AssetID),
		map[string]any{"collector": b.Collector.ID, "components": len(b.Observations)})
	writeJSON(w, 201, res)
}

func (s *Server) exportSBOM(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var comps []sbom.ExportComponent
	for off := 0; ; off += 500 {
		rows, _, err := s.Store.ListInventory(r.Context(), store.InventoryFilter{AssetID: id, Page: store.Page{Limit: 500, Offset: off}})
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, row := range rows {
			name := row.Name
			if row.Namespace != "" {
				name = row.Namespace + "/" + row.Name
			}
			comps = append(comps, sbom.ExportComponent{Purl: row.Purl, Name: name, Version: row.Version, Direct: row.Direct})
		}
		if len(rows) < 500 {
			break
		}
	}
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="asset-%d.cdx.json"`, id))
	if err := sbom.ExportCycloneDX(w, a.Name, a.Kind, s.Version, comps); err != nil {
		s.Log.Error("export sbom", "err", err)
	}
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	o, err := s.Store.Overview(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, o)
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.AssetFilter{Kind: q.Get("kind"), Environment: q.Get("environment"), OwnerTeamID: qInt(r, "owner_team_id"),
		Status: q.Get("status"), Search: q.Get("q"), RebootRequired: q.Get("reboot_required") == "true", Page: page(r)}
	items, total, err := s.Store.ListAssets(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) getAsset(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := s.Store.AssetIdentifiers(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"asset": a, "identifiers": ids})
}

func (s *Server) updateAsset(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var u store.AssetUpdate
	if err := decode(r, &u); err != nil {
		s.fail(w, r, err)
		return
	}
	if u.Criticality != nil {
		switch *u.Criticality {
		case "low", "medium", "high", "critical", "unknown":
		default:
			s.fail(w, r, badRequest("criticality must be low, medium, high, critical or unknown"))
			return
		}
	}
	if u.Name != nil && strings.TrimSpace(*u.Name) == "" {
		s.fail(w, r, badRequest("name cannot be empty"))
		return
	}
	if err := s.Store.UpdateAsset(r.Context(), id, u); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "asset.update", "asset", itoa(id), u)
	s.getAsset(w, r)
}

func (s *Server) deleteAsset(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.Store.GetAsset(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteAsset(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "asset.delete", "asset", itoa(id), map[string]string{"name": a.Name, "kind": a.Kind})
	w.WriteHeader(204)
}

func (s *Server) assetInventory(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.inventory(w, r, store.InventoryFilter{AssetID: id})
}

func (s *Server) listInventory(w http.ResponseWriter, r *http.Request) {
	s.inventory(w, r, store.InventoryFilter{AssetID: qInt(r, "asset_id"), ComponentID: qInt(r, "component_id")})
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request, f store.InventoryFilter) {
	q := r.URL.Query()
	f.Type, f.Search, f.Direct, f.Page = q.Get("type"), q.Get("q"), qBool(r, "direct"), page(r)
	f.IncludeRemoved = q.Get("include_removed") == "true"
	items, total, err := s.Store.ListInventory(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) assetCoverage(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, total, err := s.Store.ListCoverage(r.Context(), id, false, page(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, page(r)))
}

func (s *Server) listCoverage(w http.ResponseWriter, r *http.Request) {
	problems := r.URL.Query().Get("problems") == "true"
	items, total, err := s.Store.ListCoverage(r.Context(), qInt(r, "asset_id"), problems, page(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, page(r)))
}

func (s *Server) assetCollections(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.Store.ListCollections(r.Context(), id, 50)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(items))
}

func (s *Server) assetRelations(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.Store.AssetRelations(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, all(items))
}

type relationRequest struct {
	ToAsset int64  `json:"to_asset"`
	Kind    string `json:"kind"`
}

// replica_of marks an asset (a standby, staging or DR copy) as meant to run
// the same versions as the asset it points at; differences are drift.
var relationKinds = map[string]bool{"runs_on": true, "built_from": true, "deployed_as": true, "contains": true, "depends_on": true, "replica_of": true}

func (s *Server) addRelation(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req relationRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !relationKinds[req.Kind] {
		s.fail(w, r, badRequest("kind must be runs_on, built_from, deployed_as, contains, depends_on or replica_of"))
		return
	}
	for _, a := range []int64{id, req.ToAsset} {
		if _, err := s.Store.GetAsset(r.Context(), a); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if err := s.Store.AddRelation(r.Context(), id, req.ToAsset, req.Kind, "manual"); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "asset.relation_add", "asset", itoa(id), req)
	w.WriteHeader(204)
}

func (s *Server) deleteRelation(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req relationRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Store.DeleteRelation(r.Context(), id, req.ToAsset, req.Kind); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "asset.relation_delete", "asset", itoa(id), req)
	w.WriteHeader(204)
}

func (s *Server) listComponents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ComponentFilter{Type: q.Get("type"), Search: q.Get("q"), Page: page(r)}
	items, total, err := s.Store.ListComponents(r.Context(), f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, f.Page))
}

func (s *Server) getComponent(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.GetComponent(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, c)
}

// checkBoundIngest stops a host-bound token from reporting for any other
// asset, so a host cannot pull another host's remediation actions by
// claiming its identity.
func (s *Server) checkBoundIngest(r *http.Request, b *model.ObservationBatch) error {
	bound, err := s.boundAsset(r)
	if err != nil || bound == nil {
		return err
	}
	// Only identifiers already registered to the bound asset are kept: a
	// host-bound token must not claim new identities (which would absorb
	// another host when it first reports).
	matched := false
	var keep []model.Identifier
	for _, id := range b.Asset.Identifiers {
		a, err := s.Store.AssetByIdentifier(r.Context(), id.Scheme, id.Value)
		if err == store.ErrNotFound {
			continue
		}
		if err != nil {
			return err
		}
		if a != *bound {
			return errors.New("this token is bound to another asset")
		}
		matched = true
		keep = append(keep, id)
	}
	b.Asset.Identifiers = keep
	if !matched {
		return errors.New("this token is bound to an asset; the batch does not identify it")
	}
	return nil
}

// bindAppIdentity scopes an application's path to the host it runs on, so
// identical paths on different hosts stay separate and a host-bound token
// can only report applications on its own host. The host must have
// reported before its applications.
func (s *Server) bindAppIdentity(r *http.Request, b *model.ObservationBatch) (int, error) {
	var host int64
	for _, rel := range b.Relations {
		if rel.Kind != "runs_on" {
			continue
		}
		for _, id := range rel.To {
			a, err := s.Store.AssetByIdentifier(r.Context(), id.Scheme, id.Value)
			if err == store.ErrNotFound {
				continue
			}
			if err != nil {
				return 500, err
			}
			host = a
			break
		}
	}
	if host == 0 {
		return 409, errors.New("the host this application runs on has not reported yet")
	}
	bound, err := s.boundAsset(r)
	if err != nil {
		return 500, err
	}
	if bound != nil && *bound != host {
		return 403, errors.New("this token is bound to another asset")
	}
	id := &b.Asset.Identifiers[0]
	id.Value = fmt.Sprintf("host:%d:%s", host, id.Value)
	return 0, nil
}

// collectionResult lets a CI job read back the evaluation of the batch it
// submitted. Collector tokens only see results for their own submissions;
// users already have read access to findings.
func (s *Server) collectionResult(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	submitter, err := s.Store.CollectionSubmitter(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if p := principal(r); !p.Role.AtLeast(auth.RoleViewer) {
		if p.Token == nil || submitter == nil || *submitter != p.Token.ID {
			s.fail(w, r, store.ErrNotFound)
			return
		}
	}
	res, err := s.Store.GetCollectionResult(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, res)
}

// assetDrift compares an asset's current versions with another asset: the
// one named by ?with=, or else the asset it is a replica_of.
func (s *Server) assetDrift(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.Store.GetAsset(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	ref := qInt(r, "with")
	if ref == 0 {
		rels, err := s.Store.AssetRelations(r.Context(), id)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, rel := range rels {
			if rel.Kind == "replica_of" && rel.FromAsset == id {
				if ref != 0 {
					s.fail(w, r, badRequest("this asset is a replica of several assets; choose one with ?with="))
					return
				}
				ref = rel.ToAsset
			}
		}
		if ref == 0 {
			s.fail(w, r, badRequest("no replica_of relation; choose an asset to compare with ?with="))
			return
		}
	}
	refAsset, err := s.Store.GetAsset(r.Context(), ref)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.Store.CompareAssets(r.Context(), id, ref)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"drift": d, "reference": refAsset})
}

// assetStack returns everything an asset relies on and their open findings
// grouped by layer.
func (s *Server) assetStack(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := s.Store.GetStack(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, st)
}

// boundAsset returns the asset a host-bound token is limited to, or nil.
func (s *Server) boundAsset(r *http.Request) (*int64, error) {
	p := principal(r)
	if p.Token == nil {
		return nil, nil
	}
	return s.Store.TokenAsset(r.Context(), p.Token.ID)
}
