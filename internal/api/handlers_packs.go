package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/packs"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// packSummary is an installed pack as everyone may see it.
type packSummary struct {
	ID        string   `json:"id"`
	Version   string   `json:"version"`
	Name      string   `json:"name"`
	Publisher string   `json:"publisher"`
	Trust     string   `json:"trust"`
	SHA256    string   `json:"sha256"`
	Enabled   bool     `json:"enabled"`
	Files     []string `json:"files"`
	PurlTypes []string `json:"purl_types"`
}

// packSuggestion is an official pack that would read files this workspace
// (or, for instance admins, the installation) reports as unsupported.
type packSuggestion struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Files       int64  `json:"files"`
}

func (s *Server) packsEnabled(w http.ResponseWriter) bool {
	if s.Packs == nil {
		writeError(w, 404, "not_found", "stack packs are not enabled on this server")
		return false
	}
	return true
}

func (s *Server) installedPacks(r *http.Request) ([]packSummary, map[string]store.InstalledPack, error) {
	list, err := s.Store.ListPacks(r.Context())
	if err != nil {
		return nil, nil, err
	}
	out := []packSummary{}
	byID := map[string]store.InstalledPack{}
	for _, p := range list {
		var m packs.Manifest
		_ = json.Unmarshal(p.Manifest, &m)
		// Enterprise packs are listed only where the workspace may use them.
		if m.Edition == "enterprise" && !s.has(r, license.EnterprisePacks) {
			continue
		}
		out = append(out, packSummary{ID: p.ID, Version: p.Version, Name: m.Name, Publisher: m.Publisher, Trust: p.Trust,
			SHA256: p.SHA256, Enabled: p.Enabled, Files: m.Files, PurlTypes: m.PurlTypes})
		byID[p.ID] = p
	}
	return out, byID, nil
}

// suggestions matches unsupported files against official packs not yet active.
func suggestions(unsupported map[string]int64, installed map[string]store.InstalledPack) ([]packSuggestion, error) {
	cat, err := packs.Catalog()
	if err != nil {
		return nil, err
	}
	return suggestFrom(cat, unsupported, installed), nil
}

// suggestFrom names the packs in cat, not installed and enabled, whose
// handles cover files reported as unsupported.
func suggestFrom(cat []packs.CatalogEntry, unsupported map[string]int64, installed map[string]store.InstalledPack) []packSuggestion {
	out := []packSuggestion{}
	for _, e := range cat {
		if p, ok := installed[e.Manifest.ID]; ok && p.Enabled {
			continue
		}
		var n int64
		for _, h := range e.Manifest.Handles {
			n += unsupported[h]
		}
		if n > 0 {
			out = append(out, packSuggestion{ID: e.Manifest.ID, Name: e.Manifest.Name, Description: e.Manifest.Description, Files: n})
		}
	}
	return out
}

// listPacks shows the installed packs, and to people working in a workspace,
// which packs would read files their repositories hold.
func (s *Server) listPacks(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	installed, byID, err := s.installedPacks(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := map[string]any{"installed": installed, "suggestions": []packSuggestion{}}
	if _, ok := tenant.Workspace(r.Context()); ok && principal(r).User != nil {
		counts, err := s.Store.UnsupportedFiles(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		sug, err := suggestions(counts, byID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out["suggestions"] = sug
	}
	writeJSON(w, 200, out)
}

// packArchive serves an enabled pack to clients that run it themselves
// (stackurity scan in CI). They verify its signature before running it.
func (s *Server) packArchive(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	p, err := s.Store.GetPack(r.Context(), chi.URLParam(r, "id"))
	if err != nil || !p.Enabled {
		writeError(w, 404, "not_found", "no such enabled pack")
		return
	}
	var m packs.Manifest
	_ = json.Unmarshal(p.Manifest, &m)
	if m.Edition == "enterprise" && !s.has(r, license.EnterprisePacks) {
		planRequired(w, license.EnterprisePacks)
		return
	}
	data, _, err := s.Store.PackArchive(r.Context(), p.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("X-Stackurity-Pack-SHA256", p.SHA256)
	_, _ = w.Write(data)
}

// adminPacks is the instance view: installed packs, the built-in catalogue
// and how many unsupported files each workspace has in total.
func (s *Server) adminPacks(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	installed, byID, err := s.installedPacks(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cat, err := packs.Catalog()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type catalogItem struct {
		Manifest  packs.Manifest `json:"manifest"`
		SHA256    string         `json:"sha256"`
		Installed string         `json:"installed_version"`
	}
	items := []catalogItem{}
	for _, e := range cat {
		items = append(items, catalogItem{Manifest: e.Manifest, SHA256: e.SHA256, Installed: byID[e.Manifest.ID].Version})
	}
	counts, err := s.Store.UnsupportedFiles(tenant.System(r.Context()))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sug, err := suggestions(counts, byID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"installed": installed, "catalog": items, "suggestions": sug})
}

func (s *Server) installPack(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	a, trust, err := s.Packs.InstallOfficial(r.Context(), req.ID, principal(r).User.ID)
	s.packInstalled(w, r, "pack.install", a, trust, err)
}

// uploadPack installs a pack file sent as the request body.
func (s *Server) uploadPack(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, packs.MaxArchiveSize))
	if err != nil {
		s.fail(w, r, badRequest(fmt.Sprintf("pack files are limited to %d MiB", packs.MaxArchiveSize>>20)))
		return
	}
	a, trust, err := s.Packs.Install(r.Context(), data, principal(r).User.ID)
	s.packInstalled(w, r, "pack.upload", a, trust, err)
}

func (s *Server) rollbackPack(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	a, trust, err := s.Packs.Rollback(r.Context(), chi.URLParam(r, "id"), principal(r).User.ID)
	s.packInstalled(w, r, "pack.rollback", a, trust, err)
}

func (s *Server) packInstalled(w http.ResponseWriter, r *http.Request, action string, a *packs.Archive, trust packs.Trust, err error) {
	if err != nil {
		var ie *packs.InvalidError
		switch {
		case errors.As(err, &ie):
			writeError(w, 400, "invalid", "the pack is not valid", ie.Problems...)
		case errors.Is(err, packs.ErrRejected):
			writeError(w, 400, "rejected", strings.TrimPrefix(err.Error(), packs.ErrRejected.Error()+": "))
		default:
			s.fail(w, r, err)
		}
		return
	}
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), action, "pack", a.Manifest.ID,
		map[string]any{"version": a.Manifest.Version, "sha256": a.SHA256(), "trust": trust})
	queued := s.rescanFor(r, a.Manifest.Handles)
	writeJSON(w, 200, map[string]any{"id": a.Manifest.ID, "version": a.Manifest.Version, "trust": trust, "rescans_queued": queued})
}

// rescanFor queues a scan of every repository, in every workspace, that has
// files the pack can now read, so results appear without waiting.
func (s *Server) rescanFor(r *http.Request, kinds []string) int {
	if len(kinds) == 0 {
		return 0
	}
	ids, err := s.Store.ActiveWorkspaceIDs(r.Context())
	if err != nil {
		return 0
	}
	n := 0
	for _, ws := range ids {
		ctx := tenant.WithWorkspace(r.Context(), ws)
		targets, err := s.Store.RescanTargets(ctx, kinds)
		if err != nil {
			continue
		}
		for _, id := range targets {
			if _, err := s.Store.Enqueue(ctx, "integration.run", map[string]int64{"integration_id": id}, fmt.Sprintf("integration:%d", id), time.Time{}); err == nil {
				n++
			}
		}
	}
	return n
}

func (s *Server) updatePack(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.Packs.SetEnabled(r.Context(), id, req.Enabled); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), "pack.update", "pack", id, map[string]bool{"enabled": req.Enabled})
	w.WriteHeader(204)
}

func (s *Server) removePack(w http.ResponseWriter, r *http.Request) {
	if !s.packsEnabled(w) {
		return
	}
	id := chi.URLParam(r, "id")
	if err := s.Packs.Remove(r.Context(), id); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(tenant.System(r.Context()), principal(r).Actor(r), "pack.remove", "pack", id, nil)
	w.WriteHeader(204)
}
