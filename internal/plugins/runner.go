// Package plugins runs external collector plugins (FR-12). Plugins are
// separate processes: they get a clean environment, a scratch working
// directory, a deadline and output limits, and their output is validated
// like any other untrusted input. Plugins can only produce observations;
// they can never trigger remediation.
package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/pkg/plugin"
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const (
	maxStdout = 128 << 20
	maxStderr = 256 << 10
)

// Runner executes plugins installed in Dir. Only executables directly in
// Dir can run; names are validated so a config cannot point elsewhere.
type Runner struct {
	Dir     string
	WorkDir string
	Timeout time.Duration
}

type Installed struct {
	Name     string           `json:"name"`
	Path     string           `json:"path"`
	Metadata *plugin.Metadata `json:"metadata,omitempty"`
	Error    string           `json:"error,omitempty"`
}

// List returns installed plugins with their metadata.
func (r *Runner) List(ctx context.Context) ([]Installed, error) {
	if r.Dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(r.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Installed
	for _, e := range entries {
		if e.IsDir() || !nameRE.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Mode()&0o111 == 0 {
			continue
		}
		in := Installed{Name: e.Name(), Path: filepath.Join(r.Dir, e.Name())}
		if m, err := r.Metadata(ctx, e.Name()); err != nil {
			in.Error = err.Error()
		} else {
			in.Metadata = m
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *Runner) path(name string) (string, error) {
	if !nameRE.MatchString(name) {
		return "", fmt.Errorf("invalid plugin name %q", name)
	}
	p := filepath.Join(r.Dir, name)
	info, err := os.Lstat(p)
	if err != nil {
		return "", fmt.Errorf("plugin %q is not installed", name)
	}
	if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("plugin %q is not an executable file", name)
	}
	if info.Mode()&0o022 != 0 {
		return "", fmt.Errorf("plugin %q is group- or world-writable; refusing to run it", name)
	}
	return p, nil
}

// Exec runs one command against an executable and returns the response.
func Exec(ctx context.Context, exe, workDir string, timeout time.Duration, cmdName string, req *plugin.Request) (*plugin.Response, string, error) {
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return nil, "", err
	}
	scratch, err := os.MkdirTemp(workDir, "plugin-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(scratch)

	var stdin []byte
	if req != nil {
		req.ProtocolVersion, req.Command = plugin.ProtocolVersion, cmdName
		if dl, ok := ctx.Deadline(); ok {
			req.Deadline = dl
		}
		stdin, _ = json.Marshal(req)
	}
	cmd := exec.CommandContext(ctx, exe, cmdName)
	cmd.Dir = scratch
	// Clean environment: the server's own variables (database URL, secret
	// env vars) never reach a plugin. Secrets go explicitly via stdin.
	cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + scratch, "TMPDIR=" + scratch, "LC_ALL=C"}
	cmd.Stdin = bytes.NewReader(stdin)
	stdout := &capped{max: maxStdout}
	stderr := &capped{max: maxStderr}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	killGroup(cmd) // a timeout kills the plugin and anything it started
	runErr := cmd.Run()
	logs := stderr.String()
	if stdout.over {
		return nil, logs, fmt.Errorf("plugin output exceeded %d MiB", maxStdout>>20)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return nil, logs, fmt.Errorf("plugin timed out after %s", timeout)
	}
	var resp plugin.Response
	dec := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if err := dec.Decode(&resp); err != nil {
		if runErr != nil {
			return nil, logs, fmt.Errorf("plugin failed: %v", runErr)
		}
		return nil, logs, fmt.Errorf("plugin wrote invalid JSON: %w", err)
	}
	if resp.ProtocolVersion != plugin.ProtocolVersion {
		return nil, logs, fmt.Errorf("plugin speaks protocol %q, expected %q", resp.ProtocolVersion, plugin.ProtocolVersion)
	}
	if resp.Error != "" {
		return &resp, logs, errors.New("plugin error: " + truncate(resp.Error, 500))
	}
	if runErr != nil {
		return &resp, logs, fmt.Errorf("plugin exited with error: %v", runErr)
	}
	return &resp, logs, nil
}

func (r *Runner) Metadata(ctx context.Context, name string) (*plugin.Metadata, error) {
	p, err := r.path(name)
	if err != nil {
		return nil, err
	}
	resp, _, err := Exec(ctx, p, r.WorkDir, 30*time.Second, "metadata", nil)
	if err != nil {
		return nil, err
	}
	if resp.Metadata == nil {
		return nil, errors.New("plugin returned no metadata")
	}
	return resp.Metadata, CheckMetadata(resp.Metadata)
}

// CheckMetadata enforces the fields administrators rely on for review.
func CheckMetadata(m *plugin.Metadata) error {
	var missing []string
	if !nameRE.MatchString(m.ID) {
		missing = append(missing, "id (lowercase letters, digits, dashes)")
	}
	for k, v := range map[string]string{"name": m.Name, "version": m.Version, "maintainer": m.Maintainer, "license": m.License} {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, k)
		}
	}
	if m.SchemaVersion != model.BatchSchemaVersion {
		missing = append(missing, fmt.Sprintf("schema_version %q (core expects %q)", m.SchemaVersion, model.BatchSchemaVersion))
	}
	if m.NetworkAccess == nil || m.Permissions == nil || m.Limitations == nil {
		missing = append(missing, "permissions, network_access and known_limitations (use [] when none)")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return errors.New("plugin metadata incomplete: " + strings.Join(missing, "; "))
	}
	return nil
}

func (r *Runner) Validate(ctx context.Context, name string, config json.RawMessage) (*plugin.ValidationResult, error) {
	p, err := r.path(name)
	if err != nil {
		return nil, err
	}
	resp, _, err := Exec(ctx, p, r.WorkDir, 30*time.Second, "validate", &plugin.Request{Config: config})
	if err != nil {
		return nil, err
	}
	if resp.Valid == nil {
		return nil, errors.New("plugin returned no validation result")
	}
	return resp.Valid, nil
}

// Collect runs the plugin and validates every batch it returns. Batches are
// stamped with the plugin's identity so provenance shows which plugin (and
// version) produced them.
func (r *Runner) Collect(ctx context.Context, name string, config json.RawMessage, secrets map[string]string) ([]*model.ObservationBatch, string, error) {
	p, err := r.path(name)
	if err != nil {
		return nil, "", err
	}
	meta, err := r.Metadata(ctx, name)
	if err != nil {
		return nil, "", err
	}
	resp, logs, err := Exec(ctx, p, r.WorkDir, r.Timeout, "collect", &plugin.Request{Config: config, Secrets: secrets})
	if err != nil {
		return nil, logs, err
	}
	if len(resp.Batches) > 1000 {
		return nil, logs, errors.New("plugin returned more than 1000 batches")
	}
	for i, b := range resp.Batches {
		if b == nil {
			return nil, logs, fmt.Errorf("batch %d is empty", i)
		}
		b.Collector.ID = "plugin:" + meta.ID
		b.Collector.Version = meta.Version
		b.Collector.Method = "plugin"
		if err := b.Validate(); err != nil {
			return nil, logs, fmt.Errorf("batch %d: %w", i, err)
		}
		// Application paths are scoped to a host by the ingest API; a plugin
		// bypasses it, so it may not use them.
		for _, id := range b.Asset.Identifiers {
			if id.Scheme == model.AppPathScheme {
				return nil, logs, fmt.Errorf("batch %d: plugins cannot report %s identities", i, model.AppPathScheme)
			}
		}
	}
	return resp.Batches, logs, nil
}

func (r *Runner) Health(ctx context.Context, name string, config json.RawMessage, secrets map[string]string) (*plugin.HealthStatus, error) {
	p, err := r.path(name)
	if err != nil {
		return nil, err
	}
	resp, _, err := Exec(ctx, p, r.WorkDir, time.Minute, "health", &plugin.Request{Config: config, Secrets: secrets})
	if err != nil {
		return nil, err
	}
	if resp.Health == nil {
		return nil, errors.New("plugin returned no health status")
	}
	return resp.Health, nil
}

type capped struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.Len()+len(p) > c.max {
		c.over = true
		return 0, errors.New("output limit exceeded")
	}
	return c.Buffer.Write(p)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
