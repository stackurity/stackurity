// Package gitrepo shallow-clones a Git repository and scans its lockfiles.
// The clone is data only: no hooks, submodules, LFS smudging, checkout
// filters or non-HTTPS/SSH transports, and nothing in it is executed.
package gitrepo

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/stackurity/stackurity/internal/netguard"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
)

type Config struct {
	URL         string `json:"url"`
	Ref         string `json:"ref,omitempty"` // branch or tag; default branch when empty
	Environment string `json:"environment,omitempty"`
	// Username for HTTPS token auth. GitHub accepts "x-access-token",
	// GitLab "oauth2", Bitbucket "x-token-auth".
	Username string `json:"username,omitempty"`
}

func (c Config) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("invalid repository url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("repository url must use https")
	}
	if u.User != nil {
		return errors.New("do not embed credentials in the url; use a secret reference")
	}
	if u.Host == "" {
		return errors.New("repository url needs a host")
	}
	if strings.HasPrefix(c.Ref, "-") || strings.ContainsAny(c.Ref, " \t\n") {
		return errors.New("invalid ref")
	}
	return nil
}

// Scanner runs git clones under WorkDir.
type Scanner struct {
	WorkDir string
	Version string
	Timeout time.Duration
	Git     string // git binary; "git" when empty
	// Packs returns the installed stack packs to read files the core
	// cannot; nil for none.
	Packs func(ctx context.Context) []lockfile.Extension
}

// Scan clones the repository at depth 1, scans lockfiles and removes the
// clone. token may be empty for public repositories.
func (s *Scanner) Scan(ctx context.Context, cfg Config, token string) (*model.ObservationBatch, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := os.MkdirAll(s.WorkDir, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(s.WorkDir, "clone-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	src := filepath.Join(dir, "src")
	if err := s.clone(ctx, cfg, token, src); err != nil {
		return nil, err
	}
	git := s.gitBin()
	commit := ""
	if out, err := exec.CommandContext(ctx, git, "-C", src, "rev-parse", "HEAD").Output(); err == nil {
		commit = strings.TrimSpace(string(out))
	}
	asset := model.AssetRef{
		Kind:        model.AssetRepository,
		Name:        RepoName(cfg.URL),
		Identifiers: []model.Identifier{{Scheme: "git-url", Value: NormalizeURL(cfg.URL)}},
		Environment: cfg.Environment,
		Attributes:  map[string]string{"git_url": cfg.URL},
	}
	if cfg.Ref != "" {
		asset.Attributes["git_ref"] = cfg.Ref
	}
	if commit != "" {
		asset.Attributes["git_commit"] = commit
	}
	var exts []lockfile.Extension
	if s.Packs != nil {
		exts = s.Packs(ctx)
	}
	b, err := lockfile.ScanDirWith(ctx, src, asset, s.Version, exts)
	if err != nil {
		return nil, err
	}
	b.Collector.Method = "repository"
	return b, nil
}

func (s *Scanner) gitBin() string {
	if s.Git != "" {
		return s.Git
	}
	return "git"
}

// curlAddr formats an address for curl's resolve list (IPv6 in brackets).
func curlAddr(a netip.Addr) string {
	if a.Is6() && !a.Is4In6() {
		return "[" + a.String() + "]"
	}
	return a.Unmap().String()
}

// clone runs a hardened shallow clone of cfg.URL into dest.
func (s *Scanner) clone(ctx context.Context, cfg Config, token, dest string) error {
	// git makes its own connections, so the host is resolved and checked
	// here and git is pinned to the checked address; redirects are refused
	// so the server cannot send git elsewhere.
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return err
	}
	addrs, err := netguard.Resolve(ctx, u.Hostname())
	if err != nil {
		return err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	args := []string{
		"-c", "http.curloptResolve=" + u.Hostname() + ":" + port + ":" + curlAddr(addrs[0]),
		"-c", "http.followRedirects=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
		"-c", "core.symlinks=false",
		"-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
		"clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
	}
	if cfg.Ref != "" {
		args = append(args, "--branch", cfg.Ref)
	}
	args = append(args, "--", cfg.URL, dest)
	cmd := exec.CommandContext(ctx, s.gitBin(), args...)
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + filepath.Dir(dest), // ignore any user-level gitconfig
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
		"GIT_LFS_SKIP_SMUDGE=1",
	}
	if token != "" {
		user := cfg.Username
		if user == "" {
			user = "x-access-token"
		}
		// Pass the credential as a header via env so it never appears in
		// the process list, the URL or error messages.
		basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
		env = append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "+basic)
	}
	cmd.Env = env
	stderr := &capBuffer{max: 64 << 10}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if token != "" {
			msg = strings.ReplaceAll(msg, token, "[redacted]")
		}
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return fmt.Errorf("git clone failed: %v: %s", err, msg)
	}
	return nil
}

// NormalizeURL lowercases the host and strips ".git" and trailing slashes,
// so the same repository maps to one asset however it is written.
func NormalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Host = strings.ToLower(u.Host)
	u.User = nil
	u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

func RepoName(raw string) string {
	u, err := url.Parse(NormalizeURL(raw))
	if err != nil {
		return raw
	}
	return strings.TrimPrefix(u.Path, "/")
}

// capBuffer keeps at most max bytes and silently drops the rest, so a
// hostile server cannot exhaust memory through progress messages.
type capBuffer struct {
	bytes.Buffer
	max int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}
