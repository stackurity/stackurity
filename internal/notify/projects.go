package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"

	"github.com/stackurity/stackurity/internal/store"
)

// A route limited to projects must never name an asset outside them. The
// messages are built from per-asset counts filtered by assetInScope; as a
// second lock, every message to such a route is checked before it is
// queued: an asset it links to (an asset page, an asset's issues or fixes,
// a fix of an asset) outside the route's projects stops it.

var linkedAsset = regexp.MustCompile(`/assets/(\d+)|(?:\?|&|\\u0026)asset_id=(\d+)|/fixes/(\d+)(?:%3A|:)`)

// outsideProjects returns the assets a message links to that are not in
// the route's projects; nil for a route that is not limited to projects.
func outsideProjects(r store.Route, m Message) []int64 {
	if len(r.ProjectIDs) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	var out []int64
	for _, g := range linkedAsset.FindAllStringSubmatch(string(b), -1) {
		for _, v := range g[1:] {
			if v == "" {
				continue
			}
			if id, err := strconv.ParseInt(v, 10, 64); err == nil && !r.ProjectAssets[id] {
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
