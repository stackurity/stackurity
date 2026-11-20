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
	"net/http"
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

// DefaultFeedURL is the public threat feed; its signature is at the same
// address plus ".sig".
const DefaultFeedURL = "https://stackurity.ai/threats/feed.json"

// FeedEvery is how often the feed is fetched.
const FeedEvery = 6 * time.Hour

const (
	feedKey     = "threat_feed" // the last verified feed and its signature
	maxFeed     = 2 << 20
	maxSig      = 4 << 10
	feedTimeout = 30 * time.Second
)

// FeedConfig is the operator's choice, normally read with FeedConfigFromEnv.
type FeedConfig struct {
	Enabled bool
	URL     string
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
		c.URL = v
	}
	return c, nil
}

// storedFeed is the last feed that verified, kept with its signature so
// that it is verified again whenever it is read.
type storedFeed struct {
	FetchedAt time.Time `json:"fetched_at"`
	Serial    int64     `json:"serial"`
	Feed      string    `json:"feed"`
	Signature string    `json:"signature"`
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
	// verify checks a feed's signature (tests replace it).
	verify  func(feed, sig []byte) error
	running atomic.Bool
	done    chan error
}

// NewFetcher returns a fetcher whose requests go through netguard (in
// system scope, so an operator's mirror on a private network works).
func NewFetcher(st *store.Store, log *slog.Logger, cfg FeedConfig) *Fetcher {
	u := cfg.URL
	if u == "" {
		u = DefaultFeedURL
	}
	return &Fetcher{Store: st, Log: log, URL: u, Jitter: 30 * time.Second, verify: threats.Verify,
		HTTP: &http.Client{Timeout: feedTimeout, Transport: &http.Transport{DialContext: netguard.DialContext,
			TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true, Proxy: http.ProxyFromEnvironment}}}
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
		bctx, cancel := context.WithTimeout(base, wait+2*feedTimeout+10*time.Second)
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

// Run fetches once. A network failure is logged and keeps the last good
// feed; a feed that does not verify or parse is refused and recorded as a
// problem for Platform health. Only a database failure is returned.
func (f *Fetcher) Run(ctx context.Context) error {
	ctx = tenant.System(ctx)
	now := time.Now().UTC()
	prev, _, err := ReadFeedStatus(ctx, f.Store)
	if err != nil {
		return err
	}
	status := FeedStatus{CheckedAt: now, LastSuccess: prev.LastSuccess, Serial: prev.Serial}
	feed, err := f.get(ctx, f.URL, maxFeed)
	var sig []byte
	if err == nil {
		sig, err = f.get(ctx, f.URL+".sig", maxSig)
		if se := (*statusError)(nil); errors.As(err, &se) && se.status == 404 {
			sig, err = nil, nil // unsigned: refused below, as a problem
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.Log.Info("threat feed could not be fetched; keeping the last one", "err", err)
		status.Problem, status.Detail = prev.Problem, prev.Detail
		return f.saveStatus(ctx, status)
	}
	if err := f.verify(feed, sig); err != nil {
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
	if c.Serial < prev.Serial {
		status.Problem = "replay"
		status.Detail = fmt.Sprintf("the feed has serial %d, older than serial %d already accepted", c.Serial, prev.Serial)
		return f.saveStatus(ctx, status)
	}
	b, err := json.Marshal(storedFeed{FetchedAt: now, Serial: c.Serial, Feed: string(feed), Signature: string(sig)})
	if err != nil {
		return err
	}
	if err := f.Store.SetInstanceValue(ctx, feedKey, string(b)); err != nil {
		return err
	}
	status.LastSuccess, status.Serial = &now, c.Serial
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

// get requests one public file. Nothing about this installation is sent:
// a generic User-Agent, no cookie, no query.
func (f *Fetcher) get(ctx context.Context, u string, limit int64) ([]byte, error) {
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
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", u, limit)
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
// for a minute.
type Catalogues struct {
	Store *store.Store
	// verify checks the stored feed (tests replace it).
	verify func(feed, sig []byte) error
	mu     sync.Mutex
	at     time.Time
	cur    *threats.Catalogue
}

// NewCatalogues returns a loader that verifies with the embedded keys.
func NewCatalogues(st *store.Store) *Catalogues {
	return &Catalogues{Store: st, verify: threats.Verify}
}

// Current returns the merged catalogue. A stored feed that no longer
// verifies (a key was retired) is ignored: the embedded catalogue is used.
func (c *Catalogues) Current(ctx context.Context) (*threats.Catalogue, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cur != nil && time.Since(c.at) < time.Minute {
		return c.cur, nil
	}
	cur := threats.Embedded()
	raw, ok, err := c.Store.InstanceValue(tenant.System(ctx), feedKey)
	if err != nil {
		return nil, err
	}
	if ok {
		var s storedFeed
		if json.Unmarshal([]byte(raw), &s) == nil && c.verify([]byte(s.Feed), []byte(s.Signature)) == nil {
			if feed, err := threats.Parse([]byte(s.Feed)); err == nil {
				cur = threats.Merge(cur, feed)
			}
		}
	}
	if cur == threats.Embedded() {
		cur = threats.Merge(cur, nil)
	}
	c.cur, c.at = cur, time.Now()
	return cur, nil
}
