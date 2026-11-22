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

	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/confcheck"
	"github.com/stackurity/stackurity/internal/collect/gitremote"
	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/collect/limits"
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
		// Not wrapped: url.Parse quotes the whole URL, credentials included.
		return errors.New("invalid repository url")
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
	// A query or fragment has no meaning to git, but would carry tokens
	// (?private_token=...) into error messages and the asset's attributes.
	if u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("repository url must not have a query or fragment; use a secret reference for credentials")
	}
	if err := netguard.CheckHost(u.Hostname()); err != nil {
		return fmt.Errorf("repository url: %w", err)
	}
	if strings.HasPrefix(c.Ref, "-") || strings.ContainsAny(c.Ref, " \t\n") {
		return errors.New("invalid ref")
	}
	return nil
}

// DefaultMaxCloneBytes bounds a shallow clone on disk. git has no size
// limit of its own, so the clone directory is measured while git runs.
const DefaultMaxCloneBytes = 1 << 30

// Scanner runs git clones under WorkDir.
type Scanner struct {
	WorkDir string
	Version string
	Timeout time.Duration
	Git     string // git binary; "git" when empty
	// MaxBytes bounds the clone on disk; DefaultMaxCloneBytes when 0.
	MaxBytes int64
	// Packs returns the installed stack packs to read files the core
	// cannot; nil for none.
	Packs func(ctx context.Context) []lockfile.Extension
	// CAFile, when set, is the only certificate bundle git trusts (tests
	// serve repositories over HTTPS with their own certificate).
	CAFile string
	// NoLeaks turns off the scan for keys and passwords in the clone.
	NoLeaks bool
	// NoConfigChecks turns off the checks of the clone's GitHub Actions
	// workflows and AI agent hooks (internal/collect/confcheck).
	NoConfigChecks bool
}

// Scan clones the repository at depth 1 (without images, media and other
// binaries: sparsePatterns), scans lockfiles, front-end libraries kept
// outside a package manager and keys written
// in its files, and removes the clone. token may be empty for public
// repositories.
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
	max := s.MaxBytes
	if max <= 0 {
		max = DefaultMaxCloneBytes
	}
	var exts []lockfile.Extension
	if s.Packs != nil {
		exts = s.Packs(ctx)
	}
	cctx, stop := limits.WatchDir(ctx, dir, max, time.Second, "the clone")
	err = s.clone(cctx, cfg, token, src, exts)
	err = limits.Cause(cctx, err)
	stop()
	if err != nil {
		return nil, err
	}
	if _, over := limits.DirSize(dir, max); over {
		return nil, fmt.Errorf("%w: the clone used more than %s on disk", limits.ErrTooLarge, limits.Bytes(max))
	}
	git := s.gitBin()
	commit := ""
	rp := exec.CommandContext(ctx, git, "-c", "core.fsmonitor=false", "-C", src, "rev-parse", "HEAD")
	rp.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_NO_LAZY_FETCH=1"}
	if out, err := rp.Output(); err == nil {
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
	b, err := lockfile.ScanDirWith(ctx, src, asset, s.Version, exts)
	if err != nil {
		return nil, err
	}
	b.Collector.Method = "repository"
	// Front-end libraries outside a package manager: copied files, CDN
	// addresses in templates, committed bundles (apps.RepoWebAssets).
	web, webCov, webMore := apps.RepoWebAssets(ctx, src, b.Observations, nil) // a fresh clone ignores nothing
	b.Observations = append(b.Observations, web...)
	b.Coverage = lockfile.MergeCoverage([]model.CoverageItem{webCov}, b.Coverage, webMore)
	if !s.NoLeaks {
		// Keys and passwords committed to the default branch. A fresh
		// clone holds only tracked files; each keeps its severity.
		res := leaks.Dir(ctx, src, leaks.Options{})
		b.Leaks = &model.LeakScan{Found: []model.Leak{}, Complete: res.Complete, Reason: res.Reason}
		for _, l := range res.Leaks {
			leaks.Grade(&l, "", false)
			b.Leaks.Found = append(b.Leaks.Found, l)
		}
	}
	if !s.NoConfigChecks {
		// The default branch's workflows and checked-in agent hooks.
		b.ConfigFindings = confcheck.Repo(ctx, src)
	}
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

// sparsePatterns are the checkout's sparse-checkout patterns (non-cone):
// every tracked file except images, fonts, media, archives and other
// binaries, the types the leak scan skips (leaks.SkippedExts), so their
// blobs are never downloaded. A type the lockfile scan or an installed pack
// reads (stylesheets, Java archives) is still checked out. Patterns match
// the extension in any case, as the leak scan does.
func sparsePatterns(exts []lockfile.Extension) []string {
	patterns := []string{"/*"}
	for _, e := range leaks.SkippedExts() {
		if lockfile.ReadsExt(e) || packReads(exts, e) {
			continue
		}
		var b strings.Builder
		b.WriteString("!*.")
		for _, r := range strings.TrimPrefix(e, ".") {
			if lo, up := strings.ToLower(string(r)), strings.ToUpper(string(r)); lo != up {
				b.WriteString("[" + lo + up + "]")
			} else {
				b.WriteRune(r)
			}
		}
		patterns = append(patterns, b.String())
	}
	return patterns
}

// packReads reports whether an installed pack reads files with extension
// ext, in either case.
func packReads(exts []lockfile.Extension, ext string) bool {
	for _, x := range exts {
		if x.Matches("file"+ext) || x.Matches("FILE"+strings.ToUpper(ext)) {
			return true
		}
	}
	return false
}

// clone runs a hardened shallow, partial clone of cfg.URL into dest: the
// commit and its trees first (no file contents), then the contents of the
// files the scan reads (sparsePatterns). Repositories full of images or
// media then stay far under the size limit.
//
// Every step that can reach the server (the clone, and the checkout, which
// fetches the missing contents from the same remote) runs through run, with
// the same pinned address, transport limits and credential. Afterwards the
// remote is removed, so no later git command in dest (git rev-parse, the
// lockfile scan's git ls-files) can fetch from it.
func (s *Scanner) clone(ctx context.Context, cfg Config, token, dest string, exts []lockfile.Extension) error {
	run, err := s.gitRunner(ctx, cfg, token, dest)
	if err != nil {
		return err
	}
	args := []string{"clone", "--depth", "1", "--single-branch", "--no-tags", "--no-recurse-submodules",
		"--filter=blob:none", "--no-checkout", "--sparse"}
	if cfg.Ref != "" {
		args = append(args, "--branch", cfg.Ref)
	}
	args = append(args, "--", cfg.URL, dest)
	if err := run("clone", "", args...); err != nil {
		return err
	}
	// Patterns on stdin, so none can be read as an option.
	if err := run("sparse-checkout", strings.Join(sparsePatterns(exts), "\n")+"\n",
		"-C", dest, "sparse-checkout", "set", "--no-cone", "--stdin"); err != nil {
		return err
	}
	if err := run("checkout", "", "-C", dest, "checkout", "--quiet"); err != nil {
		return err
	}
	return run("remote remove", "", "-C", dest, "remote", "remove", "origin")
}

// gitRunner returns a function that runs git with the hardening every step
// of a clone needs: the host resolved and checked once, here, and git
// pinned to that address (redirects refused, so the server cannot send git
// elsewhere), https only, no hooks, symlinks or LFS, no user or system
// configuration, and the credential only in the environment. step names
// the command in errors; stdin, when not empty, is git's input.
func (s *Scanner) gitRunner(ctx context.Context, cfg Config, token, dest string) (func(step, stdin string, args ...string) error, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	addrs, err := netguard.Resolve(ctx, u.Hostname())
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	base := []string{
		"-c", "http.curloptResolve=" + u.Hostname() + ":" + port + ":" + curlAddr(addrs[0]),
		"-c", "http.followRedirects=false",
		"-c", "core.hooksPath=/dev/null",
		"-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
		"-c", "core.symlinks=false",
		"-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false",
		"-c", "core.fsmonitor=false",
	}
	if s.CAFile != "" {
		base = append(base, "-c", "http.sslCAInfo="+s.CAFile)
	}
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
	return func(step, stdin string, args ...string) error {
		cmd := exec.CommandContext(ctx, s.gitBin(), append(append([]string{}, base...), args...)...)
		cmd.Env = env
		if stdin != "" {
			cmd.Stdin = strings.NewReader(stdin)
		}
		limits.KillGroup(cmd) // a deadline or the size limit stops git and its helpers
		stderr := &capBuffer{max: 64 << 10}
		cmd.Stderr = stderr
		if err := cmd.Run(); err != nil {
			msg := strings.TrimSpace(stderr.String())
			if token != "" {
				msg = redact(msg, token, cfg.Username)
			}
			if len(msg) > 500 {
				msg = msg[:500]
			}
			return fmt.Errorf("git %s failed: %v: %s", step, err, msg)
		}
		return nil
	}, nil
}

// redact removes the token, and the Basic credential built from it, from
// git's output.
func redact(msg, token, user string) string {
	if user == "" {
		user = "x-access-token"
	}
	basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + token))
	for _, s := range []string{basic, strings.TrimRight(basic, "="), token} {
		msg = strings.ReplaceAll(msg, s, "[redacted]")
	}
	return msg
}

// NormalizeURL lowercases the host and strips ".git" and trailing slashes,
// so the same repository maps to one asset however it is written. SSH
// remotes (git@host:owner/repo) map to their https form, credentials are
// dropped (gitremote.Normalize).
func NormalizeURL(raw string) string {
	if n := gitremote.Normalize(raw); n != "" {
		return n
	}
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
// The buffer is a named field, not embedded: an embedded bytes.Buffer
// brings its ReadFrom, which io.Copy (and so os/exec) prefers to Write,
// and the cap would never apply.
type capBuffer struct {
	buf bytes.Buffer
	max int
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
		} else {
			c.buf.Write(p)
		}
	}
	return len(p), nil
}

func (c *capBuffer) String() string { return c.buf.String() }
