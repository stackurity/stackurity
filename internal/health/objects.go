package health

import (
	"context"
	"fmt"
	"strconv"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/words"
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
		return "in " + words.Count(int(g.Workspaces), "workspace", "workspaces")
	}
	// count is "1 integration", "3 integrations".
	count := func(n int64, one, many string) string { return words.Count(int(n), one, many) }

	ints, err := c.Store.FailingIntegrations(ctx, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(ints, func(store.HealthItem) string { return "/integrations" }, func(g *store.HealthGroup) Problem {
		title := count(g.Count, "integration", "integrations") + " failing"
		switch {
		case g.Severe > 0 && g.Count == 1:
			title += " for two scheduled runs or more"
		case g.Severe > 0:
			title += fmt.Sprintf(", %d of them for two scheduled runs or more", g.Severe)
		}
		return Problem{Kind: "integration", Key: "failing", Title: title,
			Scope: Scope{Summary: fmt.Sprintf("%s %s whose latest run failed", count(g.Count, "integration", "integrations"), where(g))},
			NextStep: "Open Integrations, read the error, fix the credentials, URL or access it names, then use Run now. " +
				"Assets an integration collects go stale while it fails.",
			Docs: docsRepos}
	})

	chans, err := c.Store.FailingChannels(ctx, viewerWS, ItemLimit)
	if err != nil {
		return nil, err
	}
	add(chans, func(store.HealthItem) string { return "/settings/notifications" }, func(g *store.HealthGroup) Problem {
		return Problem{Kind: "notification", Key: "delivery", Title: "Notifications are not being delivered on " + count(g.Count, "channel", "channels"),
			Scope: Scope{Summary: fmt.Sprintf("%s %s with deliveries that failed in the last 7 days (%d) or are being retried",
				count(g.Count, "channel", "channels"), where(g), g.Severe)},
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
			Title: "The Stackurity agent hasn't reported from " + count(g.Count, "server or application", "servers or applications") + production(g),
			Scope: Scope{Summary: fmt.Sprintf("%s %s. Your services may be fine; this is about Stackurity's view. "+
				"%s findings are not refreshed and are marked stale (%d production)", count(g.Count, "server or application", "servers or applications"), where(g),
				words.Pick(int(g.Count), "Its", "Their"), g.Severe)},
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
			Title: count(g.Count, "repository, image or SBOM scan is", "repository, image or SBOM scans are") + " past " +
				words.Pick(int(g.Count), "its", "their") + " usual schedule" + production(g),
			Scope: Scope{Summary: fmt.Sprintf("%s %s that used to be scanned regularly. Your services may be fine; %s findings are not refreshed "+
				"and are marked stale (%d production)", count(g.Count, "repository, image or SBOM", "repositories, images or SBOMs"), where(g),
				words.Pick(int(g.Count), "its", "their"), g.Severe)},
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
			Title: count(g.Count, "production asset was", "production assets were") + " not fully inventoried",
			Scope: Scope{Summary: fmt.Sprintf("%s %s with a collection scope that failed or was only partly checked",
				count(g.Count, "production asset", "production assets"), where(g))},
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
			Title: count(g.Count, "production asset runs", "production assets run") + " components no vulnerability source covers",
			Scope: Scope{Summary: fmt.Sprintf("%s %s with components that could not be evaluated", count(g.Count, "production asset", "production assets"), where(g))},
			NextStep: "See the evaluation gaps on the Intelligence page for the components and the reason. Enable a feed for the ecosystem, or track the " +
				"components by hand: no findings there means not checked, not clean.",
			Docs: docsVerification}
	})
	return out, nil
}

func assetLink(it store.HealthItem) string { return "/assets/" + strconv.FormatInt(it.ID, 10) }

// production says how many of a silent group are production: ", 2 of them
// production" for several, " (production)" for one, nothing for none.
func production(g *store.HealthGroup) string {
	switch {
	case g.Severe == 0:
		return ""
	case g.Count == 1:
		return " (production)"
	}
	return fmt.Sprintf(", %d of them production", g.Severe)
}
