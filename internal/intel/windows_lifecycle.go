package intel

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/winrelease"
)

// windowsLifecycle evaluates the end of life of a Windows host's operating
// system row (pkg:generic/windows@10.0.<build>.<ubr>, evidence product_name,
// edition_id, display_version). The release comes from the build number
// (winrelease.Map), not the version's dotted prefix: endoflife.date names
// Windows releases "2016", "2012-r2" or "11-23h2-e".
//
// It returns the finding when the release has ended, and gap, the coverage
// reason, when the release cannot be told or is not in the lifecycle data:
// such a host is never reported as supported. c is the release, when known
// (windowsUpdates reads its end of life).
func (e *Evaluator) windowsLifecycle(ctx context.Context, r store.EvalRow, cache map[string][]store.LifecycleCycle,
	now time.Time) (f *store.FindingInput, gap string, c *store.LifecycleCycle, err error) {
	rel, why := winrelease.Map(winrelease.Info{Version: r.Version, ProductName: r.Evidence["product_name"],
		EditionID: r.Evidence["edition_id"], DisplayVersion: r.Evidence["display_version"]})
	if why != "" {
		return nil, "end of life not evaluated: " + why, nil, nil
	}
	cycles, ok := cache[rel.Product]
	if !ok {
		if cycles, err = e.Store.LifecycleCycles(ctx, rel.Product); err != nil {
			return nil, "", nil, err
		}
		cache[rel.Product] = cycles
	}
	c = exactCycle(cycles, rel.Cycles)
	if c == nil {
		if len(cycles) == 0 {
			return nil, fmt.Sprintf("end of life not evaluated: no endoflife.date data for %s yet (the endoflife.date feed has not synced)", rel.Product), nil, nil
		}
		return nil, fmt.Sprintf("end of life not evaluated: endoflife.date %s has no release %s", rel.Product, strings.Join(rel.Cycles, " or ")), nil, nil
	}
	f = eolFinding(r, c, now)
	if f == nil {
		return nil, "", c, nil
	}
	subject := winrelease.Subject(c.Product, c.Cycle, c.Label)
	f.Title = subject + " is end-of-life"
	if c.EOLUntil != nil {
		f.Title += " since " + c.EOLUntil.Format("2006-01-02")
	}
	build, _ := winrelease.Build(r.Version)
	f.Evidence["match"] = map[string]any{"rule": "windows_build", "build": build}
	return f, "", c, nil
}

// exactCycle returns the first of names present in cycles.
func exactCycle(cycles []store.LifecycleCycle, names []string) *store.LifecycleCycle {
	for _, n := range names {
		for i := range cycles {
			if cycles[i].Cycle == n {
				return &cycles[i]
			}
		}
	}
	return nil
}
