package planner

import (
	"context"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/fixplan"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
	"github.com/stackurity/stackurity/internal/version"
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
	if err := recommend(ctx, st, rows, groups, assign, now); err != nil {
		return 0, err
	}
	return len(groups), st.ReplaceFixGroups(ctx, groups, assign)
}

// recommend adds the recommended version to each package upgrade, from the
// group's findings and the component's release data.
func recommend(ctx context.Context, st *store.Store, rows []fixplan.Row, groups []*fixplan.Group, assign map[int64]string, now time.Time) error {
	byGroup := map[string][]fixplan.Row{}
	var ids []int64
	seen := map[int64]bool{}
	for _, r := range rows {
		gid := assign[r.FindingID]
		if !strings.Contains(gid, ":"+fixplan.PackageUpgrade+":") {
			continue
		}
		byGroup[gid] = append(byGroup[gid], r)
		if !seen[r.ComponentID] {
			seen[r.ComponentID] = true
			ids = append(ids, r.ComponentID)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	releases, err := st.ReleasesFor(ctx, ids)
	if err != nil {
		return err
	}
	for _, g := range groups {
		rs := byGroup[g.ID]
		if g.Kind != fixplan.PackageUpgrade || len(rs) == 0 {
			continue
		}
		// A dependency installed at several versions is planned from the
		// oldest one.
		cmp := version.For(version.ForPurlType(rs[0].PurlType))
		in := upgrade.Input{PurlType: rs[0].PurlType, Installed: rs[0].Version, Release: releases[rs[0].ComponentID], Now: now}
		for _, r := range rs {
			if c, err := cmp(r.Version, in.Installed); err == nil && c < 0 {
				in.Installed = r.Version
			}
			in.Findings = append(in.Findings, upgrade.Finding{ID: r.FindingID, Kind: r.Kind, Key: r.Key, FixedVersion: r.FixedVersion,
				Subscription: r.Subscription})
		}
		rec := upgrade.Recommend(in)
		g.SetRecommendation(rec.Recommended, rec.ChangeType, rec.RequiresMajor, rec.RecommendedYanked, rec.Rationale)
	}
	return nil
}
