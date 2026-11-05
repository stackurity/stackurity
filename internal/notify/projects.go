package notify

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// A route limited to projects (or an asset's route, or a rule turned off
// for some projects or assets) must never name an asset it does not cover.
// The messages are built from per-asset counts filtered by assetInScope;
// as a second lock, every message to such a route is checked before it is
// queued: an asset it links to (an asset page, an asset's issues or fixes,
// a fix of an asset) outside the route's scope stops it.

var linkedAsset = regexp.MustCompile(`/assets/(\d+)|(?:\?|&|\\u0026)asset_id=(\d+)|/fixes/(\d+)(?:%3A|:)`)

// outsideProjects returns the assets a message links to that the route
// does not cover; nil for a route that hears about every asset.
func outsideProjects(r store.Route, m Message) []int64 {
	if !r.Narrowed() {
		return nil
	}
	b, _ := json.Marshal(m)
	var out []int64
	for _, g := range linkedAsset.FindAllStringSubmatch(string(b), -1) {
		for _, v := range g[1:] {
			if v == "" {
				continue
			}
			if id, err := strconv.ParseInt(v, 10, 64); err == nil && !r.Covers(id) {
				out = append(out, id)
			}
		}
	}
	return out
}

// enqueueRouted queues a grouped message for a route, unless it names an
// asset outside the route's projects (logged as an error: a bug).
func (d *Dispatcher) enqueueRouted(ctx context.Context, r store.Route, event, key string, msg Message) error {
	return d.enqueueTo(ctx, r, r.ChannelID, event, key, msg)
}

// enqueueTo is enqueueRouted to one of the route's channels (an event may
// go to another channel than the route's, see Route.EventChannels).
func (d *Dispatcher) enqueueTo(ctx context.Context, r store.Route, channelID int64, event, key string, msg Message) error {
	if bad := outsideProjects(r, msg); len(bad) > 0 {
		if d.Log != nil {
			d.Log.Error("notification withheld: it names assets outside the route's projects", "route", r.ID, "event", event, "assets", bad)
		}
		return nil
	}
	if sentAlready(ctx, channelID, event, msg) {
		return nil
	}
	if _, err := d.Store.EnqueueDelivery(ctx, channelID, &r.ID, nil, event, key, msg); err != nil {
		// One route's message that cannot be queued must not stop every
		// other route's: it is logged, and the route's channel shows the
		// error (Platform health lists failing channels).
		if ctx.Err() != nil {
			return err
		}
		if d.Log != nil {
			d.Log.Error("notification could not be queued; skipped", "route", r.ID, "channel", channelID, "event", event, "err", err)
		}
		_ = d.Store.ChannelResult(context.WithoutCancel(ctx), r.ChannelID, fmt.Errorf("a %s message of route %q could not be queued: %w", event, r.Name, err))
		return nil
	}
	return nil
}

// The same message to the same channel is sent once per planning pass:
// an asset in two projects, or a rule and a project's copy of it, can make
// two routes build the same message for one channel. The rule's name and
// the time are not compared.

type sentKey struct{}

type sentSet map[string]bool

// withSentOnce starts a planning pass that sends each message once per
// channel.
func withSentOnce(ctx context.Context) context.Context {
	if _, ok := ctx.Value(sentKey{}).(sentSet); ok {
		return ctx
	}
	return context.WithValue(ctx, sentKey{}, sentSet{})
}

// sentAlready reports whether this pass already queued the message for
// the channel, and records it otherwise.
func sentAlready(ctx context.Context, channelID int64, event string, msg Message) bool {
	seen, ok := ctx.Value(sentKey{}).(sentSet)
	if !ok {
		return false
	}
	m := msg
	m.Route, m.At = "", time.Time{}
	b, err := json.Marshal(m)
	if err != nil {
		return false
	}
	sum := sha256.Sum256(b)
	k := fmt.Sprintf("%d:%s:%x", channelID, event, sum)
	if seen[k] {
		return true
	}
	seen[k] = true
	return false
}
