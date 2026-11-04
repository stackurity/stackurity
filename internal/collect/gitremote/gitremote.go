// Package gitremote turns a Git remote, as `git remote get-url origin` or
// .git/config gives it, into the repository identity Stackurity stores
// (the git-url identifier): https://host/owner/repo, with no credentials.
//
// The same repository is cloned as https://github.com/acme/shop.git, as
// git@github.com:acme/shop.git and as ssh://git@github.com/acme/shop, and
// a deployed checkout often carries a token in its URL. All of them
// normalise to https://github.com/acme/shop, so a repository scanned on a
// laptop, in CI and through an integration, and the application deployed
// from it, name one repository.
package gitremote

import (
	"bufio"
	"bytes"
	"context"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Normalize returns the identity of a hosted remote, or "" for one that
// is not hosted anywhere others could reach (a local path, file://) or
// cannot be read. Credentials, a query and a fragment are always dropped;
// the host is lowercased; a trailing slash and ".git" are removed. SSH
// remotes (scp-style user@host:path, ssh://, git+ssh://) and git:// map to
// https on the same host, without the SSH user or port.
func Normalize(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return ""
	}
	var host, p string
	if _, _, ok := strings.Cut(raw, "://"); ok {
		u, err := url.Parse(raw)
		if err != nil {
			// Never echo the input: it may hold a token.
			return ""
		}
		switch strings.ToLower(u.Scheme) {
		case "https", "http":
			// Exactly what integrations have always stored (gitrepo's
			// NormalizeURL), so existing identities do not change.
			u.Host = strings.ToLower(u.Host)
			u.User = nil
			u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
			u.RawQuery, u.Fragment, u.ForceQuery = "", "", false
			u.Scheme = strings.ToLower(u.Scheme)
			if !hostRE.MatchString(u.Host) || strings.Trim(u.Path, "/") == "" {
				return ""
			}
			return u.String()
		case "ssh", "git+ssh", "ssh+git", "git":
			host = u.Hostname() // the SSH port has no meaning over https
		default:
			return "" // file://, ext::, and anything else
		}
		p = u.Path
	} else {
		// scp-like syntax: [user@]host:path, only when no slash comes
		// before the colon (git's rule; "./a:b" is a local path).
		before, after, ok := strings.Cut(raw, ":")
		if !ok || strings.Contains(before, "/") || before == "" || strings.HasPrefix(after, "//") {
			return ""
		}
		if at := strings.LastIndex(before, "@"); at >= 0 {
			before = before[at+1:]
		}
		host, p = before, "/"+strings.TrimPrefix(after, "/")
	}
	host = strings.ToLower(host)
	if !hostRE.MatchString(host) {
		return ""
	}
	p = strings.TrimSuffix(strings.TrimSuffix(p, "/"), ".git")
	if strings.Trim(p, "/") == "" {
		return ""
	}
	u := url.URL{Scheme: "https", Host: host, Path: p}
	return u.String()
}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$|^\[[0-9a-f:.]+\](:[0-9]{1,5})?$`)

// originURL matches a url line inside a [remote "origin"] section.
var originURL = regexp.MustCompile(`^\s*url\s*=\s*"?([^"\s]+)"?\s*$`)

// FromConfig reads the origin remote's URL from the text of a .git/config
// file, as written (not normalised). It returns "" when there is none.
func FromConfig(data []byte) string {
	in := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		t := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(t, "[") {
			in = isOriginSection(t)
			continue
		}
		if m := originURL.FindStringSubmatch(t); in && m != nil {
			return m[1]
		}
	}
	return ""
}

// isOriginSection: `[remote "origin"]`, with any spacing git accepts.
func isOriginSection(t string) bool {
	t = strings.TrimSuffix(strings.TrimPrefix(t, "["), "]")
	sec, sub, ok := strings.Cut(strings.TrimSpace(t), " ")
	return ok && strings.EqualFold(sec, "remote") && strings.TrimSpace(sub) == `"origin"`
}

// Checkout is what Local finds about a directory in a Git checkout.
type Checkout struct {
	Remote string // the origin remote, normalised; "" when there is none
	Commit string // the commit checked out, when known
	// Root: dir is the top of the work tree, not a directory inside it
	// (one project of a monorepo), so the remote names this project alone.
	Root bool
}

// Local returns the normalised origin remote of the Git checkout at dir,
// the commit checked out and whether dir is the top of the work tree; a
// zero Checkout outside one. It asks git (which follows worktrees,
// includes and url.insteadOf), with the repository's own command hooks
// switched off, and falls back to reading .git/config when git is not
// installed.
func Local(ctx context.Context, dir string) Checkout {
	if git, err := exec.LookPath("git"); err == nil {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		run := func(args ...string) string {
			cmd := exec.CommandContext(ctx, git, append([]string{"-C", dir, "-c", "core.fsmonitor=false"}, args...)...)
			cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0")
			out, err := cmd.Output()
			if err != nil {
				return ""
			}
			return strings.TrimSpace(string(out))
		}
		if top := run("rev-parse", "--show-toplevel"); top != "" {
			c := Checkout{Remote: Normalize(run("remote", "get-url", "origin")), Commit: run("rev-parse", "--verify", "--quiet", "HEAD")}
			if !commitRE.MatchString(c.Commit) {
				c.Commit = ""
			}
			c.Root = sameDir(top, dir)
			return c
		}
		return Checkout{}
	}
	data, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil || len(data) > 256<<10 {
		return Checkout{}
	}
	return Checkout{Remote: Normalize(FromConfig(data)), Root: true}
}

// sameDir reports whether two paths name one directory.
func sameDir(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

var commitRE = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
