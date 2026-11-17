package notify

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/stackurity/stackurity/internal/store"
)

// Policy gates in the weekly summary (docs/design/policy-gates.md,
// section 5): the open violations of each policy, counted over the assets
// the route hears about, each linking to the Violations page narrowed to
// that policy. A standing list, like Overdue: it never makes a summary
// "changed" on its own.

const (
	maxGatePolicies = 10 // policies listed under Policy gates
	maxGateAssets   = 3  // assets listed under each policy
)

// gateViolations reads the violations once per run, for every route's
// weekly summary. A failure is logged and leaves the section out rather
// than holding back the summary.
func (d *Dispatcher) gateViolations(data *summaryData) []store.GateAssetViolations {
	if !data.gateRead {
		data.gateRead = true
		var err error
		if data.gate, err = d.Store.GateViolationsByAsset(data.ctx); err != nil && d.Log != nil {
			d.Log.Warn("policy gate violations", "error", err)
		}
	}
	return data.gate
}

func (d *Dispatcher) violationsURL(policy, asset int64) string {
	q := url.Values{}
	if policy > 0 {
		q.Set("policy_id", strconv.FormatInt(policy, 10))
	}
	if asset > 0 {
		q.Set("asset_id", strconv.FormatInt(asset, 10))
	}
	return d.url("/fixes/policy-violations", q)
}

func gateModeWord(mode string) string {
	if mode == store.GateModeEnforce {
		return "enforce"
	}
	return "warn"
}

// gateSection is the "Policy gates" section for a route: one item per
// policy with violations on the route's assets (team and environment
// filters applied), with the assets that have most under it. ok is false
// when the route hears of no violation.
func (d *Dispatcher) gateSection(r store.Route, rows []store.GateAssetViolations) (sec Section, total int, ok bool) {
	type policy struct {
		id         int64
		name, mode string
		count      int
		assets     []store.GateAssetViolations
	}
	var order []*policy
	byID := map[int64]*policy{}
	for _, v := range rows {
		if !assetInScope(r, v.AssetID, v.Environment, v.OwnerTeamID) {
			continue
		}
		p := byID[v.PolicyID]
		if p == nil {
			p = &policy{id: v.PolicyID, name: v.PolicyName, mode: v.Mode}
			byID[v.PolicyID] = p
			order = append(order, p)
		}
		p.count += v.Count
		p.assets = append(p.assets, v)
		total += v.Count
	}
	if total == 0 {
		return Section{}, 0, false
	}
	var items []Item
	for i, p := range order {
		if i == maxGatePolicies {
			items = append(items, Item{Text: "+" + plural(len(order)-maxGatePolicies, "more policy"), Link: d.violationsURL(0, 0)})
			break
		}
		it := Item{
			Text: fmt.Sprintf("%s [%s]: %s on %s", shorten(p.name, maxNameLen), gateModeWord(p.mode), plural(p.count, "violation"), plural(len(p.assets), "asset")),
			Link: d.violationsURL(p.id, 0),
		}
		if len(p.assets) == 1 {
			it.asset = p.assets[0].AssetID
		}
		top := append([]store.GateAssetViolations(nil), p.assets...)
		// Most violations first; the store's order (by name) breaks ties.
		for a := 1; a < len(top); a++ {
			for b := a; b > 0 && top[b].Count > top[b-1].Count; b-- {
				top[b], top[b-1] = top[b-1], top[b]
			}
		}
		for j, a := range top {
			if j == maxGateAssets {
				it.Items = append(it.Items, Item{Text: "+" + plural(len(top)-maxGateAssets, "more asset"), Link: d.violationsURL(p.id, 0)})
				break
			}
			it.Items = append(it.Items, Item{Text: fmt.Sprintf("%s: %s", shorten(a.AssetName, maxNameLen), plural(a.Count, "violation")),
				Link: d.violationsURL(p.id, a.AssetID), asset: a.AssetID})
		}
		items = append(items, it)
	}
	return Section{Title: "Policy gates", Items: items}, total, true
}
