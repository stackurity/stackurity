// Package threatnotice tells every organisation about new threats
// (docs/threat-notices.md): it keeps the threat catalogue up to date from
// the signed public feed, works out each organisation's verdict (found,
// covered, needs_connection or upgrade) and delivers the notice once, by
// banner, email and the organisation's notification routes.
//
// The feed request is an anonymous GET of a public file, like the release
// check (internal/updates): it carries no version, installation id,
// inventory or anything else about the install, and it is off with
// STACKURITY_UPDATE_CHECK=off. A self-hosted server never sends anything to
// Stackurity: notices are worked out and delivered here.
package threatnotice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/threats"
	"github.com/stackurity/stackurity/internal/updates"
)

// DefaultFeedURL is the public threat feed: the catalogue and its signature
// in one file (threats.Envelope), so a cache can never serve a new
// catalogue with an old signature.
const DefaultFeedURL = "https://stackurity.ai/threats/feed.signed.json"

// FeedEvery is how often the feed is fetched.
const FeedEvery = 6 * time.Hour

const (
	feedKey     = "threat_feed" // the last verified feed (its envelope)
	maxFeed     = 4 << 20
	feedTimeout = 30 * time.Second
)

// FeedConfig is the operator's choice, normally read with FeedConfigFromEnv.
type FeedConfig struct {
	Enabled bool
	URL     string
	// Mirror: the operator set STACKURITY_THREAT_FEED_URL. Only a mirror
	// may be on a private network or redirect to another host.
	Mirror bool
}

// FeedConfigFromEnv reads STACKURITY_UPDATE_CHECK (the feed is fetched only
// while the release check is on) and STACKURITY_THREAT_FEED_URL (a mirror).
func FeedConfigFromEnv() (FeedConfig, error) {
	u, err := updates.ConfigFromEnv()
	if err != nil {
		return FeedConfig{}, err
	}
	c := FeedConfig{Enabled: u.Enabled, URL: DefaultFeedURL}
	if v := strings.TrimSpace(os.Getenv("STACKURITY_THREAT_FEED_URL")); v != "" {
		p, err := url.Parse(v)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
			return c, fmt.Errorf("STACKURITY_THREAT_FEED_URL must be an http(s) URL, not %q", v)
		}
		c.URL, c.Mirror = v, true
	}
	return c, nil
}

// storedFeed is the last feed that verified, kept as its signed envelope
// so that it is verified again whenever it is read.
type storedFeed struct {
	FetchedAt time.Time `json:"fetched_at"`
	Serial    int64     `json:"serial"`
	Envelope  string    `json:"envelope"`
}

// FeedStatus is the outcome of the last fetch (threats.FeedStatus).
type FeedStatus = threats.FeedStatus

// ReadFeedStatus returns the last fetch's outcome; ok is false before the
// first fetch.
func ReadFeedStatus(ctx context.Context, st *store.Store) (s FeedStatus, ok bool, err error) {
	raw, ok, err := st.InstanceValue(tenant.System(ctx), threats.FeedStatusKey)
	if err != nil || !ok {
		return s, false, err
	}
	if json.Unmarshal([]byte(raw), &s) != nil {
		return s, false, nil
	}
	return s, true, nil
}

// Fetcher fetches the feed and stores it for every replica.
type Fetcher struct {
	Store  *store.Store
	Log    *slog.Logger
	URL    string
	HTTP   *http.Client
	Jitter time.Duration
	Base   context.Context
	// open checks a feed's signature (tests replace it).
	open    func(envelope []byte) ([]byte, error)
	now     func() time.Time
	running atomic.Bool
	done    chan error
}

// NewFetcher returns a fetcher. The default feed is fetched through
// netguard with private networks blocked, and may not redirect to another
// host or to plain HTTP; an operator's mirror may be on a private network
// and redirect within HTTPS.
func NewFetcher(st *store.Store, log *slog.Logger, cfg FeedConfig) *Fetcher {
	u := cfg.URL
	if u == "" {
		u = DefaultFeedURL
	}
	origin, _ := url.Parse(u)
	// The operator's proxy (HTTPS_PROXY) may be on a private network: the
	// address it names is dialled as it is. Everything else keeps the rule
	// for the feed.
	var proxies sync.Map
	proxy := func(req *http.Request) (*url.URL, error) {
		p, err := proxyFromEnvironment(req)
		if p != nil {
			proxies.Store(proxyAddr(p), true)
		}
		return p, err
	}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch _, isProxy := proxies.Load(addr); {
		case isProxy:
			return netguard.Policy{AllowPrivate: true}.DialContext(ctx, network, addr)
		case cfg.Mirror:
			return netguard.DialContext(ctx, network, addr) // system scope: private networks too
		}
		// Public addresses only, and the name as fully qualified: a lookup
		// must never try the resolver's search domains.
		return netguard.Policy{}.DialContext(ctx, network, fullyQualified(addr))
	}
	hc := &http.Client{Timeout: feedTimeout,
		Transport: &http.Transport{DialContext: dial, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true, Proxy: proxy},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return checkRedirect(origin, cfg.Mirror, req, via)
		}}
	return &Fetcher{Store: st, Log: log, URL: u, Jitter: 30 * time.Second, open: threats.OpenEnvelope, HTTP: hc}
}

// proxyFromEnvironment is the operator's proxy (tests replace it: the
// standard library reads the environment once per process).
var proxyFromEnvironment = http.ProxyFromEnvironment

// proxyAddr is the host:port a proxy URL is dialled at.
func proxyAddr(p *url.URL) string {
	if p.Port() != "" {
		return p.Host
	}
	port := "80"
	switch p.Scheme {
	case "https":
		port = "443"
	case "socks5", "socks5h":
		port = "1080"
	}
	return net.JoinHostPort(p.Hostname(), port)
}

// fullyQualified ends a host name with a dot ("stackurity.ai."), so the
// resolver looks up that name only, never name + a search domain. An IP
// address is left as it is.
func fullyQualified(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || strings.HasSuffix(host, ".") {
		return addr
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return addr
	}
	return net.JoinHostPort(host+".", port)
}

// checkRedirect refuses a redirect to plain HTTP from HTTPS, more than 3,
// and, for the default feed, any other host.
func checkRedirect(origin *url.URL, mirror bool, req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return errors.New("threat feed: too many redirects")
	}
	if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return errors.New("threat feed: redirect from HTTPS to HTTP refused")
	}
	if !mirror && origin != nil && !strings.EqualFold(req.URL.Host, origin.Host) {
		return fmt.Errorf("threat feed: redirect to another host (%s) refused", req.URL.Hostname())
	}
	return nil
}

// Scheduler is the part of the worker that runs periodic platform tasks.
type Scheduler interface {
	Every(name string, every time.Duration, fn func(ctx context.Context) error)
}

// RegisterFeed adds the periodic fetch, leased so one replica runs it.
// When the feed is off nothing is registered and no request is made.
func RegisterFeed(base context.Context, w Scheduler, st *store.Store, log *slog.Logger, cfg FeedConfig) bool {
	if !cfg.Enabled {
		return false
	}
	f := NewFetcher(st, log, cfg)
	f.Base = base
	w.Every("threat-feed", FeedEvery, f.Start)
	return true
}

// Start is the periodic task: it fetches in the background after a random
// wait, so it does not hold one of the worker's periodic slots.
func (f *Fetcher) Start(ctx context.Context) error {
	if !f.running.CompareAndSwap(false, true) {
		return nil
	}
	base := f.Base
	if base == nil {
		base = context.WithoutCancel(ctx)
	}
	base = tenant.System(base)
	var wait time.Duration
	if f.Jitter > 0 {
		wait = rand.N(f.Jitter)
	}
	go func() {
		defer f.running.Store(false)
		bctx, cancel := context.WithTimeout(base, wait+feedTimeout+10*time.Second)
		defer cancel()
		var err error
		select {
		case <-bctx.Done():
			err = bctx.Err()
		case <-time.After(wait):
			err = f.Run(bctx)
		}
		if err != nil && base.Err() == nil {
			f.Log.Warn("threat feed check could not store its result", "err", err)
		}
		if f.done != nil {
			f.done <- err
		}
	}()
	return nil
}

func (f *Fetcher) clock() time.Time {
	if f.now != nil {
		return f.now()
	}
	return time.Now().UTC()
}

// Run fetches once. A network failure is logged and keeps the last good
// feed (Platform health warns once no feed was read for 7 days); a feed
// that does not verify, parse, is older than one already used (or than
// this release's catalogue) or has expired is refused and recorded as a
// problem for Platform health. Only a database failure is returned.
func (f *Fetcher) Run(ctx context.Context) error {
	ctx = tenant.System(ctx)
	now := f.clock()
	prev, _, err := ReadFeedStatus(ctx, f.Store)
	if err != nil {
		return err
	}
	status := FeedStatus{CheckedAt: now, Since: prev.Since, LastSuccess: prev.LastSuccess, Serial: prev.Serial, ExpiresAt: prev.ExpiresAt}
	if status.Since == nil {
		status.Since = &now
	}
	env, err := f.get(ctx, f.URL)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Not a problem of its own: an earlier refusal is not carried
		// forward with a fresh time, and a long outage shows as a stale
		// feed instead.
		f.Log.Info("threat feed could not be fetched; keeping the last one", "err", err)
		return f.saveStatus(ctx, status)
	}
	feed, err := f.open(env)
	if err != nil {
		f.Log.Warn("threat feed refused: its signature is not valid", "err", err)
		status.Problem, status.Detail = "bad_signature", err.Error()
		return f.saveStatus(ctx, status)
	}
	c, err := threats.Parse(feed)
	switch {
	case errors.Is(err, threats.ErrNewerSchema):
		status.Problem, status.Detail = "newer_schema", err.Error()
		return f.saveStatus(ctx, status)
	case err != nil:
		f.Log.Warn("threat feed refused: it is not a valid catalogue", "err", err)
		status.Problem, status.Detail = "invalid", err.Error()
		return f.saveStatus(ctx, status)
	}
	if floor := max(prev.Serial, threats.Embedded().Serial); c.Serial < floor {
		status.Problem = "replay"
		status.Detail = fmt.Sprintf("the feed has serial %d, older than serial %d already used", c.Serial, floor)
		return f.saveStatus(ctx, status)
	}
	if c.ExpiresAt == nil || !now.Before(*c.ExpiresAt) {
		status.Problem = "expired"
		status.Detail = "the feed has no expiry date or expired"
		if c.ExpiresAt != nil {
			status.Detail = "the feed expired on " + c.ExpiresAt.UTC().Format(time.DateOnly)
		}
		return f.saveStatus(ctx, status)
	}
	b, err := json.Marshal(storedFeed{FetchedAt: now, Serial: c.Serial, Envelope: string(env)})
	if err != nil {
		return err
	}
	if err := f.Store.SetInstanceValue(ctx, feedKey, string(b)); err != nil {
		return err
	}
	status.LastSuccess, status.Serial, status.ExpiresAt = &now, c.Serial, c.ExpiresAt
	if err := f.saveStatus(ctx, status); err != nil {
		return err
	}
	if err := recordSeen(ctx, f.Store, threats.Merge(threats.Embedded(), c)); err != nil {
		return err
	}
	f.Log.Debug("threat feed fetched", "serial", c.Serial, "threats", len(c.Threats))
	return nil
}

func (f *Fetcher) saveStatus(ctx context.Context, s FeedStatus) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return f.Store.SetInstanceValue(ctx, threats.FeedStatusKey, string(b))
}

type statusError struct{ status int }

func (e *statusError) Error() string { return fmt.Sprintf("HTTP %d", e.status) }

// get requests the public feed. Nothing about this installation is sent:
// a generic User-Agent, no cookie, no query.
func (f *Fetcher) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", updates.UserAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := f.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, &statusError{resp.StatusCode}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFeed+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFeed {
		return nil, fmt.Errorf("the threat feed is larger than %d bytes", maxFeed)
	}
	return b, nil
}

// recordSeen keeps threats_seen in step with the catalogue (system scope).
func recordSeen(ctx context.Context, st *store.Store, c *threats.Catalogue) error {
	list := make([]store.ThreatSeen, 0, len(c.Threats))
	for _, t := range c.Threats {
		list = append(list, store.ThreatSeen{ID: t.ID, Name: t.Name, Revision: t.Revision, Source: t.Source})
	}
	return st.RecordThreatsSeen(tenant.System(ctx), list)
}

// Catalogues gives the current catalogue: the embedded one merged with the
// last stored feed, verified again as it is read. It caches the result
// for a minute. A stored feed past its expiry is still used (it is the
// newest authentic list); Platform health warns about it.
type Catalogues struct {
	Store *store.Store
	// open checks the stored feed (tests replace it).
	open func(envelope []byte) ([]byte, error)
	mu   sync.Mutex
	at   time.Time
	cur  *threats.Catalogue
}

// NewCatalogues returns a loader that verifies with the embedded keys.
func NewCatalogues(st *store.Store) *Catalogues {
	return &Catalogues{Store: st, open: threats.OpenEnvelope}
}

// Current returns the merged catalogue. A stored feed that no longer
// verifies (a key was retired) is ignored: the embedded catalogue is used.
func (c *Catalogues) Current(ctx context.Context) (*threats.Catalogue, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil && time.Since(c.at) < time.Minute {
		return c.cur, nil
	}
	var feed *threats.Catalogue
	raw, ok, err := c.Store.InstanceValue(tenant.System(ctx), feedKey)
	if err != nil {
		return nil, err
	}
	if ok {
		var s storedFeed
		if json.Unmarshal([]byte(raw), &s) == nil {
			if b, err := c.open([]byte(s.Envelope)); err == nil {
				if parsed, err := threats.Parse(b); err == nil {
					feed = parsed
				}
			}
		}
	}
	c.cur, c.at = threats.Merge(threats.Embedded(), feed), time.Now()
	return c.cur, nil
}
