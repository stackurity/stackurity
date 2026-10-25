package planner

import (
	"context"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/store"
)

// osProducts maps os-release IDs to endoflife.date products (same table the
// matcher uses for OS lifecycle).
var osProducts = map[string]string{
	"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine-linux", "rocky": "rocky-linux",
	"almalinux": "almalinux", "rhel": "rhel", "centos": "centos", "amzn": "amazon-linux",
	"fedora": "fedora", "opensuse-leap": "opensuse", "sles": "sles", "ol": "oracle-linux",
}

// Package planner rebuilds the stored action plan from current findings.

// Rebuild recomputes the whole action plan and stores it.
func Rebuild(ctx context.Context, st *store.Store, now time.Time) (int, error) {
	rows, err := st.FixPlanRows(ctx)
	if err != nil {
		return 0, err
	}
	advice := map[string]fixplan.Advice{}
	seen := map[string]bool{}
	for _, r := range rows {
		key := r.OS + ":" + r.OSVersion
		if r.OS == "" || seen[key] {
			continue
		}
		seen[key] = true
		product := osProducts[r.OS]
		if product == "" {
			continue
		}
		cycles, err := st.LifecycleCycles(ctx, product)
		if err != nil {
			return 0, err
		}
		a := fixplan.Advice{}
		for _, c := range cycles {
			if a.ProductLabel == "" {
				a.ProductLabel = c.ProductLabel
			}
			if (c.Cycle == r.OSVersion || strings.HasPrefix(r.OSVersion, c.Cycle+".")) && c.EOLUntil != nil {
				a.EOLDate = c.EOLUntil.Format("2006-01-02")
			}
		}
		// Newest supported release; prefer LTS where the product has them.
		for _, preferLTS := range []bool{true, false} {
			for _, c := range cycles { // newest first
				supported := !c.IsEOL && (c.EOLUntil == nil || c.EOLUntil.After(now))
				if supported && (c.LTS || !preferLTS) && c.ReleaseDate != nil && !c.ReleaseDate.After(now) {
					a.Target = c.Cycle
					if c.LTS && strings.EqualFold(r.OS, "ubuntu") {
						a.Target += " LTS"
					}
					break
				}
			}
			if a.Target != "" {
				break
			}
		}
		advice[key] = a
	}
	groups, assign := fixplan.Build(rows, advice)
	return len(groups), st.ReplaceFixGroups(ctx, groups, assign)
}
