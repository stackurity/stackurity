package packs

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"github.com/stackurity/stackurity/internal/license"
	"log/slog"
	"sort"
	"sync"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The official packs ship inside the server but are not installed: an
// administrator installs the ones their estate needs.
//
//go:embed official/*.stkpack
var officialFS embed.FS

// CatalogEntry is a pack available to install from this build.
type CatalogEntry struct {
	Manifest Manifest `json:"manifest"`
	SHA256   string   `json:"sha256"`
	data     []byte
}

// Catalog lists the official packs built into this server.
func Catalog() ([]CatalogEntry, error) {
	entries, err := officialFS.ReadDir("official")
	if err != nil {
		return nil, err
	}
	var out []CatalogEntry
	for _, e := range entries {
		data, err := officialFS.ReadFile("official/" + e.Name())
		if err != nil {
			return nil, err
		}
		a, err := ReadArchive(data)
		if err != nil {
			return nil, fmt.Errorf("official pack %s: %w", e.Name(), err)
		}
		out = append(out, CatalogEntry{Manifest: a.Manifest, SHA256: a.SHA256(), data: data})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.ID < out[j].Manifest.ID })
	return out, nil
}

// Manager keeps the enabled packs loaded and installs new ones.
type Manager struct {
	Store *store.Store
	Keys  *Keyring
	Log   *slog.Logger
	// Gate decides who may use Enterprise packs; nil allows none.
	Gate *license.Gate

	mu     sync.RWMutex
	loaded map[string]*Loaded
}

// Active returns the loaded packs a scan in ctx's workspace may use:
// Enterprise packs only where the plan includes them.
func (m *Manager) Active(ctx context.Context) []lockfile.Extension {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]lockfile.Extension, 0, len(m.loaded))
	for _, l := range m.loaded {
		if l.Manifest.Edition == "enterprise" && !m.Gate.Has(ctx, license.EnterprisePacks) {
			continue
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}

// Reload loads the enabled packs from the database. Each archive is checked
// against the keyring again, so a pack altered in the database is not run.
func (m *Manager) Reload(ctx context.Context) error {
	ctx = tenant.System(ctx)
	installed, err := m.Store.ListPacks(ctx)
	if err != nil {
		return err
	}
	next := map[string]*Loaded{}
	m.mu.RLock()
	current := m.loaded
	m.mu.RUnlock()
	for _, p := range installed {
		if !p.Enabled {
			continue
		}
		if l, ok := current[p.ID]; ok && l.SHA256 == p.SHA256 {
			next[p.ID] = l
			continue
		}
		data, _, err := m.Store.PackArchive(ctx, p.ID)
		if err != nil {
			return err
		}
		a, err := ReadArchive(data)
		if err == nil {
			var trust Trust
			if trust, err = m.Keys.Verify(a); err == nil {
				var l *Loaded
				if l, err = Load(ctx, a, trust); err == nil {
					next[p.ID] = l
					continue
				}
			}
		}
		m.Log.Error("stack pack not loaded", "pack", p.ID, "err", err)
	}
	m.mu.Lock()
	old := m.loaded
	m.loaded = next
	m.mu.Unlock()
	for id, l := range old {
		if next[id] != l {
			_ = l.Close(context.Background())
		}
	}
	return nil
}

// ErrRejected wraps the reasons a pack is refused: its format, its
// signature, or a module that does not compile.
var ErrRejected = errors.New("pack rejected")

// Install checks a pack file (format, signature, that it compiles) and
// installs it for the whole server.
func (m *Manager) Install(ctx context.Context, data []byte, by int64) (*Archive, Trust, error) {
	a, err := ReadArchive(data)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	trust, err := m.Keys.Verify(a)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	if a.Manifest.Edition == "enterprise" && !m.Gate.Has(tenant.System(ctx), license.EnterprisePacks) {
		return nil, "", fmt.Errorf("%w: %s needs a Stackurity Enterprise licence", ErrRejected, a.Manifest.Name)
	}
	l, err := Load(ctx, a, trust)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %w", ErrRejected, err)
	}
	_ = l.Close(ctx)
	if err := m.Store.InstallPack(tenant.System(ctx), a.Manifest.ID, a.Manifest.Version, a.ManifestRaw, data, a.SHA256(), string(trust), by); err != nil {
		return nil, "", err
	}
	return a, trust, m.Reload(ctx)
}

// InstallOfficial installs a pack from the built-in catalogue.
func (m *Manager) InstallOfficial(ctx context.Context, id string, by int64) (*Archive, Trust, error) {
	cat, err := Catalog()
	if err != nil {
		return nil, "", err
	}
	for _, e := range cat {
		if e.Manifest.ID == id {
			return m.Install(ctx, e.data, by)
		}
	}
	return nil, "", store.ErrNotFound
}

// Rollback reinstalls the version a pack replaced.
func (m *Manager) Rollback(ctx context.Context, id string, by int64) (*Archive, Trust, error) {
	data, _, err := m.Store.PreviousPackArchive(tenant.System(ctx), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, "", fmt.Errorf("no earlier version of %s to go back to: %w", id, store.ErrConflict)
		}
		return nil, "", err
	}
	return m.Install(ctx, data, by)
}

func (m *Manager) SetEnabled(ctx context.Context, id string, on bool) error {
	if err := m.Store.SetPackEnabled(tenant.System(ctx), id, on); err != nil {
		return err
	}
	return m.Reload(ctx)
}

func (m *Manager) Remove(ctx context.Context, id string) error {
	if err := m.Store.DeletePack(tenant.System(ctx), id); err != nil {
		return err
	}
	return m.Reload(ctx)
}
