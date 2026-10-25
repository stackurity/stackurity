package packs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing/fstest"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/pkg/pack"
)

// Limits on one run.
const (
	maxInput        = 128 << 20 // total bytes of files handed to a pack
	maxOutput       = 64 << 20
	maxStderr       = 64 << 10
	maxObservations = 200_000
)

// Loaded is a pack compiled and ready to run. The module is compiled once;
// every run gets a fresh instance, so nothing carries over between scans.
type Loaded struct {
	Manifest Manifest
	Trust    Trust
	SHA256   string

	mu       sync.Mutex
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
}

// Load compiles a pack's module in a runtime limited to the pack's memory.
// Close it when the pack is removed.
func Load(ctx context.Context, a *Archive, trust Trust) (*Loaded, error) {
	pages := uint32(a.Manifest.memoryMB() * 16) // 64 KiB pages
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithMemoryLimitPages(pages).
		WithCloseOnContextDone(true))
	// WASI preview 1 gives the module stdin, stdout, stderr and exit; it is
	// given no directories, no environment and no sockets.
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		rt.Close(ctx)
		return nil, err
	}
	compiled, err := rt.CompileModule(ctx, a.Wasm)
	if err != nil {
		rt.Close(ctx)
		return nil, fmt.Errorf("compile pack: %w", err)
	}
	for _, f := range compiled.ImportedFunctions() {
		if mod, _, _ := f.Import(); mod != wasi_snapshot_preview1.ModuleName {
			rt.Close(ctx)
			return nil, fmt.Errorf("pack imports %q; packs may use only WASI preview 1", mod)
		}
	}
	return &Loaded{Manifest: a.Manifest, Trust: trust, SHA256: a.SHA256(), runtime: rt, compiled: compiled}, nil
}

func (l *Loaded) Close(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runtime == nil {
		return nil
	}
	err := l.runtime.Close(ctx)
	l.runtime = nil
	return err
}

func (l *Loaded) ID() string { return l.Manifest.ID }

// Matches reports whether the pack reads files with this base name.
func (l *Loaded) Matches(name string) bool { return l.Manifest.Matches(name) }

// Scan runs the pack over files and returns what it found, checked against
// its manifest. Coverage scopes are prefixed "pack:<id>:" so they are told
// apart from the core's.
func (l *Loaded) Scan(ctx context.Context, files []pack.File) ([]model.Observation, []model.CoverageItem, error) {
	total := 0
	for _, f := range files {
		total += len(f.Content)
	}
	if total > maxInput {
		return nil, nil, fmt.Errorf("pack %s: input larger than %d MiB", l.Manifest.ID, maxInput>>20)
	}
	// The request lists the files; their contents are mounted read-only at
	// /input, which holds these files and nothing else.
	input := fstest.MapFS{}
	listed := make([]pack.File, 0, len(files))
	for _, f := range files {
		input[f.Path] = &fstest.MapFile{Data: f.Content, Mode: 0o444}
		listed = append(listed, pack.File{Path: f.Path, Size: int64(len(f.Content))})
	}
	in, err := json.Marshal(pack.Request{ABI: pack.ABI, Files: listed})
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(l.Manifest.timeoutSeconds())*time.Second)
	defer cancel()
	stdout := &capped{max: maxOutput}
	stderr := &capped{max: maxStderr}
	cfg := wazero.NewModuleConfig().
		WithName("").
		WithArgs("pack").
		WithStdin(bytes.NewReader(in)).
		WithFSConfig(wazero.NewFSConfig().WithFSMount(input, pack.InputDir)).
		WithStdout(stdout).
		WithStderr(stderr)

	l.mu.Lock()
	rt := l.runtime
	l.mu.Unlock()
	if rt == nil {
		return nil, nil, errors.New("pack is unloaded")
	}
	mod, err := rt.InstantiateModule(ctx, l.compiled, cfg)
	if mod != nil {
		_ = mod.Close(ctx)
	}
	var exit *sys.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 0 {
		err = nil
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("pack %s ran longer than %ds", l.Manifest.ID, l.Manifest.timeoutSeconds())
		}
		return nil, nil, fmt.Errorf("pack %s failed: %v %s", l.Manifest.ID, err, strings.TrimSpace(stderr.String()))
	}
	if stdout.over {
		return nil, nil, fmt.Errorf("pack %s wrote more than %d MiB", l.Manifest.ID, maxOutput>>20)
	}
	var resp pack.Response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, nil, fmt.Errorf("pack %s returned invalid output: %w", l.Manifest.ID, err)
	}
	if resp.Error != "" {
		return nil, nil, fmt.Errorf("pack %s: %s", l.Manifest.ID, resp.Error)
	}
	return l.check(files, &resp)
}

// check enforces the manifest on a pack's output: only declared package
// types, valid purls and confidence, locations among the files given.
func (l *Loaded) check(files []pack.File, resp *pack.Response) ([]model.Observation, []model.CoverageItem, error) {
	if len(resp.Observations) > maxObservations {
		return nil, nil, fmt.Errorf("pack %s reported more than %d packages", l.Manifest.ID, maxObservations)
	}
	allowed := map[string]bool{}
	for _, t := range l.Manifest.PurlTypes {
		allowed[t] = true
	}
	given := map[string]bool{}
	for _, f := range files {
		given[f.Path] = true
	}
	out := make([]model.Observation, 0, len(resp.Observations))
	for _, o := range resp.Observations {
		p, err := packageurl.FromString(o.Purl)
		if err != nil {
			return nil, nil, fmt.Errorf("pack %s reported an invalid purl %q", l.Manifest.ID, o.Purl)
		}
		if !allowed[p.Type] {
			return nil, nil, fmt.Errorf("pack %s reported a %s package but may only report %v", l.Manifest.ID, p.Type, l.Manifest.PurlTypes)
		}
		if o.Location != "" && !given[o.Location] {
			return nil, nil, fmt.Errorf("pack %s reported a location it was not given: %q", l.Manifest.ID, o.Location)
		}
		switch o.Confidence {
		case model.ConfidenceConfirmed, model.ConfidenceInferred, model.ConfidenceLow:
		default:
			o.Confidence = model.ConfidenceInferred
		}
		if o.Evidence == nil {
			o.Evidence = map[string]string{}
		}
		o.Evidence["pack"] = l.Manifest.ID + "@" + l.Manifest.Version
		out = append(out, o)
	}
	cov := make([]model.CoverageItem, 0, len(resp.Coverage))
	for _, c := range resp.Coverage {
		switch c.Status {
		case "checked", "partial", "failed", "skipped", "unsupported":
		default:
			c.Status = "partial"
		}
		if len(c.Reason) > 500 {
			c.Reason = c.Reason[:500]
		}
		c.Scope = "pack:" + l.Manifest.ID + ":" + c.Scope
		cov = append(cov, c)
	}
	return out, cov, nil
}

// capped is a writer that keeps at most max bytes and records overflow.
type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.max {
		c.over = true
		p = p[:max(0, c.max-c.Len())]
	}
	c.Buffer.Write(p)
	return len(p), nil
}
