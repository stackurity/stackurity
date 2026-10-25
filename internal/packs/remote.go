package packs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path"
	"sync"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/pkg/pack"
)

// Remote gives clients that scan on their own machine (agents, stackurity
// scan) the packs installed on their server. A pack is downloaded, checked
// against this build's keyring and compiled only when a file it reads turns
// up, so hosts without such files never load one. Close releases them.
type Remote struct {
	// Get fetches an API path into w (for example via client.Client.Do).
	Get  func(ctx context.Context, path string, w io.Writer) error
	Keys *Keyring
	Log  *slog.Logger

	mu    sync.Mutex
	packs []*remotePack
}

type listedPack struct {
	ID      string   `json:"id"`
	Enabled bool     `json:"enabled"`
	SHA256  string   `json:"sha256"`
	Files   []string `json:"files"`
}

// Extensions lists the server's enabled packs as scanner extensions.
func (r *Remote) Extensions(ctx context.Context) ([]lockfile.Extension, error) {
	var buf bytes.Buffer
	if err := r.Get(ctx, "/api/v1/packs", &buf); err != nil {
		return nil, err
	}
	var list struct {
		Installed []listedPack `json:"installed"`
	}
	if err := json.Unmarshal(buf.Bytes(), &list); err != nil {
		return nil, err
	}
	var out []lockfile.Extension
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range list.Installed {
		if !p.Enabled {
			continue
		}
		rp := &remotePack{remote: r, info: p}
		r.packs = append(r.packs, rp)
		out = append(out, rp)
	}
	return out, nil
}

// Close unloads every pack this Remote loaded.
func (r *Remote) Close(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.packs {
		p.close(ctx)
	}
	r.packs = nil
}

type remotePack struct {
	remote *Remote
	info   listedPack

	mu     sync.Mutex
	loaded *Loaded
	err    error
}

func (p *remotePack) ID() string { return p.info.ID }

func (p *remotePack) Matches(name string) bool {
	for _, f := range p.info.Files {
		if ok, _ := path.Match(f, name); ok {
			return true
		}
	}
	return false
}

func (p *remotePack) Scan(ctx context.Context, files []pack.File) ([]model.Observation, []model.CoverageItem, error) {
	l, err := p.load(ctx)
	if err != nil {
		return nil, nil, err
	}
	return l.Scan(ctx, files)
}

// load downloads, verifies and compiles the pack once.
func (p *remotePack) load(ctx context.Context) (*Loaded, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded != nil || p.err != nil {
		return p.loaded, p.err
	}
	p.loaded, p.err = func() (*Loaded, error) {
		var buf bytes.Buffer
		if err := p.remote.Get(ctx, "/api/v1/packs/"+p.info.ID+"/archive", &buf); err != nil {
			return nil, fmt.Errorf("download: %w", err)
		}
		a, err := ReadArchive(buf.Bytes())
		if err != nil {
			return nil, err
		}
		if a.SHA256() != p.info.SHA256 || a.Manifest.ID != p.info.ID {
			return nil, fmt.Errorf("the download does not match the pack the server lists")
		}
		trust, err := p.remote.Keys.Verify(a)
		if err != nil {
			return nil, err
		}
		return Load(ctx, a, trust)
	}()
	if p.err != nil && p.remote.Log != nil {
		p.remote.Log.Warn("stack pack not used", "pack", p.info.ID, "err", p.err)
	}
	return p.loaded, p.err
}

func (p *remotePack) close(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded != nil {
		_ = p.loaded.Close(ctx)
		p.loaded = nil
	}
}
