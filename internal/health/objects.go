package health

import (
	"context"
	"fmt"
	"strconv"

	"github.com/stackurity/stackurity/internal/store"
)

// objectProblems reports problems with workspaces' own objects: integrations
// that keep failing, notification channels that cannot deliver, collectors
// that stopped reporting and coverage gaps on production assets. Counts span
// every workspace; names and errors come from viewerWS only.
func (c *Checker) objectProblems(ctx context.Context, viewerWS int64) ([]Problem, error) {
	var out []Problem
	add := func(g *store.HealthGroup, link func(store.HealthItem) string, build func(g *store.HealthGroup) Problem) {
		if g.Count == 0 {
			return
		}
		p := build(g)
		p.Severity = Warning
		p.Scope.Count, p.Scope.Workspaces = g.Count, g.Workspaces
		if p.LastSuccess == nil {
			p.LastSuccess = g.LastSuccess
		}
		for _, it := range g.Items {
			p.Scope.Items = append(p.Scope.Items, ScopeItem{Name: it.Name, Detail: it.Detail, LastSuccess: it.LastSuccess,
				LastError: it.LastError, Link: link(it)})
			if p.LastError == "" {
				p.LastError = it.LastError
			}
		}
		p.Scope.Hidden = g.Count - int64(len(g.Items))
		out = append(out, p)
	}
	where := func(g *store.HealthGroup) string {
		if g.Workspaces == 1 {
			return "in 1 workspace"
		}
		return fmt.Sprintf("in %d workspaces", g.Workspaces)
	}

	ints, err := c.Store.FailingIntegrations(ctx, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(ints, func(store.HealthItem) string { return "/integrations" }, func(g *store.HealthGroup) Problem {
		title := fmt.Sprintf("%d integration(s) failing", g.Count)
		if g.Severe > 0 {
			title = fmt.Sprintf("%d integration(s) failing, %d of them for two scheduled runs or more", g.Count, g.Severe)
		}
		return Problem{Kind: "integration", Key: "failing", Title: title,
			Scope: Scope{Summary: fmt.Sprintf("%d integration(s) %s whose latest run failed", g.Count, where(g))},
			NextStep: "Open Integrations, read the error, fix the credentials, URL or access it names, then use Run now. " +
				"Assets an integration collects go stale while it fails.",
			Docs: docsRepos}
	})

	chans, err := c.Store.FailingChannels(ctx, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(chans, func(store.HealthItem) string { return "/settings/notifications" }, func(g *store.HealthGroup) Problem {
		return Problem{Kind: "notification", Key: "delivery", Title: fmt.Sprintf("Notifications are not being delivered on %d channel(s)", g.Count),
			Scope: Scope{Summary: fmt.Sprintf("%d channel(s) %s with deliveries that failed in the last 7 days (%d) or are being retried", g.Count, where(g), g.Severe)},
			NextStep: "Open Settings > Notifications, send a test message on the channel, fix its URL, secret or mail settings, " +
				"then retry the failed deliveries listed there.",
			Docs: docsNotify}
	})

	// Servers whose agent is silent, and scans past their usual cadence.
	// Assets scanned once are not a problem: their results stay as of that
	// scan. Those an integration reports are covered by its own problem.
	servers, err := c.Store.SilentCollectors(ctx, store.SourceAgent, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(servers, assetLink, func(g *store.HealthGroup) Problem {
		return Problem{Kind: "collector", Key: "silent-agent",
			Title: fmt.Sprintf("The Stackurity agent hasn't reported from %d server(s) or application(s), %d of them production", g.Count, g.Severe),
			Scope: Scope{Summary: fmt.Sprintf("%d server(s) or application(s) %s. Your services may be fine; this is about Stackurity's view. "+
				"Their findings are not refreshed and are marked stale (%d production)", g.Count, where(g), g.Severe)},
			NextStep: "On each server run systemctl status stackurity-agent and journalctl -u stackurity-agent -n 50, and restart it with " +
				"systemctl restart stackurity-agent (on Windows, check the scheduled task that runs stackurity.exe agent). " +
				"Likely causes: the server is off or was rebuilt, the agent service stopped, or it can't reach this server. Delete servers that no longer exist.",
			Docs: docsReporting}
	})
	scans, err := c.Store.SilentCollectors(ctx, store.SourceScan, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(scans, assetLink, func(g *store.HealthGroup) Problem {
		return Problem{Kind: "collector", Key: "silent-scan",
			Title: fmt.Sprintf("%d repository, image or SBOM scan(s) are past their usual schedule, %d of them production", g.Count, g.Severe),
			Scope: Scope{Summary: fmt.Sprintf("%d asset(s) %s that used to be scanned regularly. Your services may be fine; their findings are not refreshed "+
				"and are marked stale (%d production)", g.Count, where(g), g.Severe)},
			NextStep: "Likely cause: the CI job or scheduled scan that uploads it stopped or failed. Check its last pipeline run; " +
				"scan commands are in Settings > Integrations > CI pipeline. If it is only scanned now and then, set its reporting to one-off on the asset page.",
			Docs: docsReporting}
	})

	cov, err := c.Store.ProductionCoverageGaps(ctx, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(cov, func(it store.HealthItem) string { return "/assets/" + strconv.FormatInt(it.ID, 10) + "?tab=coverage" }, func(g *store.HealthGroup) Problem {
		return Problem{Kind: "coverage", Key: "production-collection",
			Title: fmt.Sprintf("%d production asset(s) were not fully inventoried", g.Count),
			Scope: Scope{Summary: fmt.Sprintf("%d production asset(s) %s with a collection scope that failed or was only partly checked", g.Count, where(g))},
			NextStep: "Open the asset's Coverage tab for the scope and reason, fix the collector's access (permissions, tools, network), " +
				"and collect again. Findings on these assets may be missing until then.",
			Docs: docsCollect}
	})

	eval, err := c.Store.ProductionEvaluationGaps(ctx, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(eval, func(it store.HealthItem) string { return "/assets/" + strconv.FormatInt(it.ID, 10) + "?tab=coverage" }, func(g *store.HealthGroup) Problem {
		return Problem{Kind: "coverage", Key: "production-evaluation",
			Title: fmt.Sprintf("%d production asset(s) run components no vulnerability source covers", g.Count),
			Scope: Scope{Summary: fmt.Sprintf("%d production asset(s) %s with components that could not be evaluated", g.Count, where(g))},
			NextStep: "See the evaluation gaps on the Intelligence page for the components and the reason. Enable a feed for the ecosystem, or track the " +
				"components by hand: no findings there means not checked, not clean.",
			Docs: docsVerification}
	})
	return out, nil
}

func assetLink(it store.HealthItem) string { return "/assets/" + strconv.FormatInt(it.ID, 10) }
