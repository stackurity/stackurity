// Package updates tells instance administrators when a newer Stackurity
// release exists and what changed in it.
//
// Twice a day one replica fetches the public list of releases from GitHub.
// The request is an anonymous GET with a generic User-Agent: it carries no
// version, installation id, inventory or anything else about the install, and
// the comparison with the running version happens here, locally. Operators
// turn it off with STACKURITY_UPDATE_CHECK=off (no request at all) or point
// it at a mirror with STACKURITY_UPDATE_URL. A failed check (offline,
// air-gapped, rate-limited) is logged and keeps the last good result; it is
// never shown to users as an error.
package updates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/version"
)

// DefaultURL lists the latest releases of the public repository.
const DefaultURL = "https://api.github.com/repos/stackurity/stackurity/releases?per_page=20"

// Every is how often the check runs.
const Every = 12 * time.Hour

const (
	// UserAgent is sent with the request. It names the product only, never
	// its version: GitHub requires a User-Agent, and a version would tell
	// the receiver which installs are out of date.
	UserAgent = "stackurity"
	stateKey  = "update_check"
	// maxBody caps the response; GitHub release notes are at most 125,000
	// characters each, and 20 releases are listed.
	maxBody = 8 << 20
	// maxNotes caps the notes kept per release.
	maxNotes    = 16 << 10
	maxReleases = 20
)

// Config is the operator's choice, normally read with ConfigFromEnv.
type Config struct {
	Enabled bool
	URL     string
}

// ConfigFromEnv reads STACKURITY_UPDATE_CHECK (on by default; off, false, 0
// or no turn it off) and STACKURITY_UPDATE_URL.
func ConfigFromEnv() (Config, error) {
	c := Config{Enabled: true, URL: DefaultURL}
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv("STACKURITY_UPDATE_CHECK"))); v {
	case "", "on", "true", "1", "yes":
	case "off", "false", "0", "no":
		c.Enabled = false
	default:
		return c, fmt.Errorf("STACKURITY_UPDATE_CHECK must be on or off, not %q", v)
	}
	if u := strings.TrimSpace(os.Getenv("STACKURITY_UPDATE_URL")); u != "" {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return c, fmt.Errorf("STACKURITY_UPDATE_URL must be an http(s) URL, not %q", u)
		}
		c.URL = u
	}
	return c, nil
}

// Release is one published, stable release.
type Release struct {
	Version     string    `json:"version"` // without the leading "v", e.g. 0.4.0
	Tag         string    `json:"tag"`
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	PublishedAt time.Time `json:"published_at"`
	// Notes is the release's Markdown notes, cut at about 16 KB.
	Notes          string `json:"notes"`
	NotesTruncated bool   `json:"notes_truncated,omitempty"`
	// Security is set when the notes have a "Security" heading (the
	// CHANGELOG convention for releases that fix vulnerabilities).
	Security bool `json:"security"`
}

// state is what the last successful check stored.
type state struct {
	CheckedAt time.Time `json:"checked_at"`
	Releases  []Release `json:"releases"` // stable releases, newest first
}

// Checker fetches the release list and stores it for every replica.
type Checker struct {
	Store *store.Store
	Log   *slog.Logger
	URL   string
	HTTP  *http.Client
	// Jitter is the longest random wait before a check, so that installs
	// started together do not all call at the same moment.
	Jitter time.Duration
}

// NewChecker returns a checker with the default client and jitter.
func NewChecker(st *store.Store, log *slog.Logger, cfg Config) *Checker {
	u := cfg.URL
	if u == "" {
		u = DefaultURL
	}
	return &Checker{Store: st, Log: log, URL: u, HTTP: &http.Client{Timeout: 30 * time.Second}, Jitter: 30 * time.Second}
}

// Scheduler is the part of the worker that runs periodic platform tasks.
type Scheduler interface {
	Every(name string, every time.Duration, fn func(ctx context.Context) error)
}

// Register adds the periodic check to w, leased in the database so that one
// replica runs it every 12 hours. When the check is off nothing is
// registered, so no request is ever made.
func Register(w Scheduler, st *store.Store, log *slog.Logger, cfg Config) bool {
	if !cfg.Enabled {
		return false
	}
	w.Every("update-check", Every, NewChecker(st, log, cfg).Run)
	return true
}

// Run is the periodic task. A failed fetch is logged and keeps the last good
// result; only a database failure is returned as an error.
func (c *Checker) Run(ctx context.Context) error {
	if c.Jitter > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(rand.N(c.Jitter)):
		}
	}
	rels, err := c.Fetch(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var se *StatusError
		if errors.As(err, &se) && (se.Status == 403 || se.Status == 429) {
			c.Log.Info("update check rate-limited; keeping the last result", "status", se.Status)
		} else {
			c.Log.Info("update check failed; keeping the last result", "err", err)
		}
		return nil
	}
	b, err := json.Marshal(state{CheckedAt: time.Now().UTC(), Releases: rels})
	if err != nil {
		return err
	}
	if err := c.Store.SetInstanceValue(ctx, stateKey, string(b)); err != nil {
		return err
	}
	c.Log.Debug("update check done", "releases", len(rels))
	return nil
}

// StatusError is a non-200 answer.
type StatusError struct{ Status int }

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Status) }

// ghRelease is the part of GitHub's release object that is read.
type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	Body        string    `json:"body"`
}

// Fetch requests the release list once and returns the stable releases,
// newest first. Nothing about this installation is sent.
func (c *Checker) Fetch(ctx context.Context) ([]Release, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "application/vnd.github+json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, &StatusError{resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("release list larger than %d bytes", maxBody)
	}
	return Parse(b)
}

var tagRE = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)

// Parse reads a GitHub release list. Drafts, prereleases and tags that are
// not a plain vX.Y.Z are skipped.
func Parse(b []byte) ([]Release, error) {
	var in []ghRelease
	if err := json.Unmarshal(b, &in); err != nil {
		return nil, fmt.Errorf("release list: %w", err)
	}
	out := []Release{}
	seen := map[string]bool{}
	for _, r := range in {
		tag := strings.TrimSpace(r.TagName)
		if r.Draft || r.Prerelease || !tagRE.MatchString(tag) {
			continue
		}
		v := strings.TrimPrefix(tag, "v")
		if seen[v] {
			continue
		}
		seen[v] = true
		notes, cut := truncate(r.Body, maxNotes)
		rel := Release{Version: v, Tag: tag, Name: clip(strings.TrimSpace(r.Name), 200), PublishedAt: r.PublishedAt,
			Notes: notes, NotesTruncated: cut, Security: IsSecurity(r.Body)}
		if u, err := url.Parse(r.HTMLURL); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
			rel.URL = r.HTMLURL
		}
		out = append(out, rel)
	}
	sort.SliceStable(out, func(i, j int) bool {
		c, _ := version.CompareSemver(out[i].Version, out[j].Version)
		return c > 0
	})
	if len(out) > maxReleases {
		out = out[:maxReleases]
	}
	return out, nil
}

var securityRE = regexp.MustCompile(`(?mi)^#{2,4}[ \t]+security[ \t]*#*[ \t]*\r?$`)

// IsSecurity reports whether release notes have a "Security" heading.
func IsSecurity(notes string) bool { return securityRE.MatchString(notes) }

// truncate cuts s to at most max bytes, at a line break when there is one
// in the last quarter, and never inside a UTF-8 character.
func truncate(s string, max int) (string, bool) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	if nl := strings.LastIndexByte(s[:cut], '\n'); nl > max*3/4 {
		cut = nl
	}
	return s[:cut], true
}

func clip(s string, max int) string {
	t, _ := truncate(s, max)
	return t
}

var (
	runningRE  = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	describeRE = regexp.MustCompile(`-\d+-g[0-9a-f]+$`)
)

// Running turns the build's version into one that can be compared, or ""
// for development builds ("dev", a bare commit hash). It drops the suffixes
// the build adds: "-ee" for the licensed edition, and git describe's
// "-dirty" and "-<commits>-g<hash>" (a build after that tag counts as the
// tag).
func Running(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "-ee")
	v = strings.TrimSuffix(v, "-dirty")
	v = describeRE.ReplaceAllString(v, "")
	if !runningRE.MatchString(v) {
		return ""
	}
	return strings.TrimPrefix(v, "v")
}

// Report is what instance administrators see.
type Report struct {
	// Enabled is false when STACKURITY_UPDATE_CHECK=off.
	Enabled bool   `json:"enabled"`
	Current string `json:"current"`
	// Comparable is false for development builds, which never show an
	// update.
	Comparable bool `json:"comparable"`
	// Latest is the newest stable release seen, empty before the first
	// successful check.
	Latest            string     `json:"latest"`
	LatestURL         string     `json:"latest_url,omitempty"`
	LatestPublishedAt *time.Time `json:"latest_published_at,omitempty"`
	UpdateAvailable   bool       `json:"update_available"`
	// Security is set when any newer release is a security release.
	Security  bool       `json:"security"`
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	// Releases are those newer than the running one, newest first.
	Releases []Release `json:"releases"`
}

// Status compares the stored release list with the running version.
func Status(ctx context.Context, st *store.Store, running string, enabled bool) (*Report, error) {
	r := &Report{Enabled: enabled, Current: running, Releases: []Release{}}
	cur := Running(running)
	r.Comparable = cur != ""
	if !enabled {
		return r, nil
	}
	raw, ok, err := st.InstanceValue(ctx, stateKey)
	if err != nil || !ok {
		return r, err
	}
	var s state
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return r, nil // an unreadable result is replaced by the next check
	}
	r.CheckedAt = &s.CheckedAt
	return compare(r, cur, s.Releases), nil
}

func compare(r *Report, cur string, rels []Release) *Report {
	if len(rels) > 0 {
		l := rels[0]
		r.Latest, r.LatestURL = l.Version, l.URL
		if !l.PublishedAt.IsZero() {
			r.LatestPublishedAt = &l.PublishedAt
		}
	}
	if cur == "" {
		return r
	}
	for _, rel := range rels {
		if c, err := version.CompareSemver(rel.Version, cur); err == nil && c > 0 {
			r.Releases = append(r.Releases, rel)
			r.Security = r.Security || rel.Security
		}
	}
	r.UpdateAvailable = len(r.Releases) > 0
	return r
}
