package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/trustbadge"
	"github.com/stackurity/stackurity/internal/worker"
)

// trustBadgeCloud is true only in the Stackurity Cloud build: the licensed
// overlay's Cloud files (stackurity-pro, build tags ee,cloud) set it from an
// init function. The trust badge is a Stackurity Cloud feature (Free and
// paid plans); self-hosted installations never run it, whatever
// STACKURITY_TRUST_BADGE says.
var trustBadgeCloud = false

// trustBadgeConfig is the trust badge's server configuration.
type trustBadgeConfig struct {
	On        bool
	Retention time.Duration // 0: no retention purge runs
	Policy    string
	// PageBase is where trust pages are published
	// (STACKURITY_TRUST_PAGE_BASE); empty is https://stackurity.ai/trust.
	PageBase string
	// Purge drops cached badge images and trust data at Cloudflare when
	// STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE and _TOKEN are set; nil
	// relies on the cache headers.
	Purge func(ctx context.Context, urls []string) error
}

// trustBadgeFromEnv reads STACKURITY_TRUST_BADGE (on or off, default off)
// and the retention purge settings (docs/trust-badge.md). Off by default.
func trustBadgeFromEnv(cloud bool, getenv func(string) string) (trustBadgeConfig, error) {
	var c trustBadgeConfig
	switch v := strings.TrimSpace(getenv("STACKURITY_TRUST_BADGE")); v {
	case "", "off":
	case "on":
		c.On = true
	default:
		return c, fmt.Errorf("STACKURITY_TRUST_BADGE must be on or off, not %q", v)
	}
	if !cloud {
		// Not Stackurity Cloud: the badge does not exist here, and its
		// other settings are not read.
		return trustBadgeConfig{}, nil
	}
	c.PageBase = strings.TrimSpace(getenv("STACKURITY_TRUST_PAGE_BASE"))
	if c.PageBase != "" && !strings.HasPrefix(c.PageBase, "https://") {
		return c, fmt.Errorf("STACKURITY_TRUST_PAGE_BASE must be an https:// address")
	}
	zone, token := strings.TrimSpace(getenv("STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE")), strings.TrimSpace(getenv("STACKURITY_TRUST_BADGE_CLOUDFLARE_TOKEN"))
	switch {
	case zone != "" && token != "":
		c.Purge = cloudflarePurger(cloudflareAPI, zone, token, &http.Client{Timeout: 15 * time.Second})
	case zone != "" || token != "":
		return c, fmt.Errorf("STACKURITY_TRUST_BADGE_CLOUDFLARE_ZONE and STACKURITY_TRUST_BADGE_CLOUDFLARE_TOKEN are set together")
	}
	if v := strings.TrimSpace(getenv("STACKURITY_TRUST_BADGE_RETENTION")); v != "" {
		d, err := parseRetention(v)
		if err != nil {
			return c, fmt.Errorf("STACKURITY_TRUST_BADGE_RETENTION: %w", err)
		}
		if d < store.TrustBadgeMinRetention {
			return c, fmt.Errorf("STACKURITY_TRUST_BADGE_RETENTION must be at least 30 days, not %s", v)
		}
		c.Retention = d
		c.Policy = strings.TrimSpace(getenv("STACKURITY_TRUST_BADGE_RETENTION_POLICY"))
		if c.Policy == "" {
			return c, fmt.Errorf("STACKURITY_TRUST_BADGE_RETENTION_POLICY must name the retention policy version when STACKURITY_TRUST_BADGE_RETENTION is set")
		}
	}
	return c, nil
}

// cloudflareAPI is Cloudflare's API; tests point it at a fake.
var cloudflareAPI = "https://api.cloudflare.com/client/v4"

// cloudflarePurger purges URLs from a Cloudflare zone's cache, 30 at a
// time (Cloudflare's limit for a purge by URL). The token needs only the
// zone's Cache Purge permission.
func cloudflarePurger(api, zone, token string, client *http.Client) func(ctx context.Context, urls []string) error {
	return func(ctx context.Context, urls []string) error {
		for i := 0; i < len(urls); i += 30 {
			body, _ := json.Marshal(map[string][]string{"files": urls[i:min(i+30, len(urls))]})
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/zones/"+url.PathEscape(zone)+"/purge_cache", bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				return fmt.Errorf("cloudflare purge: HTTP %d", resp.StatusCode)
			}
		}
		return nil
	}
}

// parseRetention reads a number of days ("400d") or a Go duration.
func parseRetention(v string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%q is not a number of days", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(v)
}

// periodicTasks is the part of *worker.Worker that registers periodic
// tasks.
type periodicTasks interface {
	Every(name string, every time.Duration, fn func(ctx context.Context) error)
	EveryWorkspace(name string, every time.Duration, fn func(ctx context.Context) error)
}

var _ periodicTasks = (*worker.Worker)(nil)

// registerTrustBadge adds the badge's periodic tasks. Nothing runs, and
// nothing is written, unless the badge is on.
func registerTrustBadge(w periodicTasks, st *store.Store, log *slog.Logger, c trustBadgeConfig) {
	if !c.On {
		return
	}
	w.EveryWorkspace("trust-badge-evaluate", time.Hour, func(ctx context.Context) error {
		return evaluateTrustBadges(ctx, st, time.Now())
	})
	if c.Retention > 0 {
		w.Every("trust-badge-retention", 24*time.Hour, func(ctx context.Context) error {
			n, err := st.PurgeTrustBadgeStatus(ctx, c.Retention, c.Policy)
			if n > 0 {
				log.Info("trust badge history purged", "entries", n, "older_than", c.Retention, "policy", c.Policy)
			}
			return err
		})
	}
}

// evaluateTrustBadges decides every badge of the workspace in ctx and
// appends each decision to its history. An enabled badge gets an entry on
// every run; a badge that is off gets one only when it was not already
// recorded as off.
func evaluateTrustBadges(ctx context.Context, st *store.Store, now time.Time) error {
	badges, err := st.ListTrustBadges(ctx)
	if err != nil {
		return err
	}
	// The database keeps microseconds: decide at the time that is stored,
	// so the decision can be rebuilt from the entry exactly.
	now = now.UTC().Truncate(time.Microsecond)
	for _, b := range badges {
		if !b.Enabled {
			last, err := st.LatestTrustBadgeStatus(ctx, b.ID)
			if err != nil {
				return err
			}
			if last == nil || last.Reason == trustbadge.ReasonDisabled {
				continue
			}
		}
		in, err := st.TrustBadgeInputs(ctx, b)
		if err != nil {
			return fmt.Errorf("badge %d: %w", b.ID, err)
		}
		d := trustbadge.Evaluate(in, now)
		if _, err := st.AppendTrustBadgeStatus(ctx, b.ID, now, trustbadge.Evidence{Inputs: in, Decision: d}); err != nil {
			return fmt.Errorf("badge %d: %w", b.ID, err)
		}
	}
	return nil
}
