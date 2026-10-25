package upgrade

import (
	"context"
	"sort"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// ForFinding recommends a version for the inventory row behind a finding,
// considering every open finding on that row.
func ForFinding(ctx context.Context, st *store.Store, f *store.Finding, now time.Time) (*Recommendation, error) {
	c, err := st.GetComponent(ctx, f.ComponentID)
	if err != nil {
		return nil, err
	}
	rows, err := st.UpgradeIssues(ctx, 0, f.InventoryID)
	if err != nil {
		return nil, err
	}
	l := loader{st: st, now: now}
	rec, err := l.recommend(ctx, c.ID, c.Type, c.PurlKey, f.Version, rows)
	if err != nil {
		return nil, err
	}
	return &rec, nil
}

// VersionRecommendation is the recommendation for one installed version
// (and, for OS packages, one distribution) of a component.
type VersionRecommendation struct {
	Version string `json:"version"`
	Distro  string `json:"distro,omitempty"`
	Assets  int    `json:"asset_count"` // assets with open findings on this version
	Recommendation
}

// maxVersions bounds a component's recommendations.
const maxVersions = 50

// ForComponent recommends a version for each installed version of a
// component that has open findings, most findings first.
func ForComponent(ctx context.Context, st *store.Store, componentID int64, now time.Time) ([]VersionRecommendation, int, error) {
	c, err := st.GetComponent(ctx, componentID)
	if err != nil {
		return nil, 0, err
	}
	rows, err := st.UpgradeIssues(ctx, componentID, 0)
	if err != nil {
		return nil, 0, err
	}
	assets, err := st.UpgradeAssetCounts(ctx, componentID)
	if err != nil {
		return nil, 0, err
	}
	type key struct{ version, distro string }
	groups := map[key][]store.UpgradeIssue{}
	var order []key
	for _, r := range rows {
		k := key{r.Version, r.Distro}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], r)
	}
	l := loader{st: st, now: now}
	out := []VersionRecommendation{}
	for _, k := range order {
		rec, err := l.recommend(ctx, componentID, c.Type, c.PurlKey, k.version, groups[k])
		if err != nil {
			return nil, 0, err
		}
		out = append(out, VersionRecommendation{Version: k.version, Distro: k.distro, Assets: int(assets[k.version+"\x00"+k.distro]),
			Recommendation: rec})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Findings != out[j].Findings {
			return out[i].Findings > out[j].Findings
		}
		return out[i].Version < out[j].Version
	})
	total := len(out)
	if total > maxVersions {
		out = out[:maxVersions]
	}
	return out, total, nil
}

// loader fetches release and lifecycle data once per component.
type loader struct {
	st      *store.Store
	now     time.Time
	fetched bool
	release *store.Release
	product string
	cycles  []store.LifecycleCycle
}

func (l *loader) recommend(ctx context.Context, componentID int64, purlType, purlKey, installed string, rows []store.UpgradeIssue) (Recommendation, error) {
	if !l.fetched {
		rels, err := l.st.ReleasesFor(ctx, []int64{componentID})
		if err != nil {
			return Recommendation{}, err
		}
		l.release = rels[componentID]
		// An end-of-life finding names the product the matcher used.
		for _, r := range rows {
			if r.Product != "" {
				l.product = r.Product
				break
			}
		}
		if l.product == "" {
			if l.product, err = l.st.LifecycleProductFor(ctx, purlKey); err != nil {
				return Recommendation{}, err
			}
		}
		if l.product != "" {
			if l.cycles, err = l.st.LifecycleCycles(ctx, l.product); err != nil {
				return Recommendation{}, err
			}
		}
		l.fetched = true
	}
	in := Input{PurlType: purlType, Installed: installed, Release: l.release, Product: l.product, Cycles: l.cycles, Now: l.now}
	var findings int64
	for _, r := range rows {
		in.Findings = append(in.Findings, Finding{ID: r.FindingID, Kind: r.Kind, Key: r.Key, FixedVersion: r.FixedVersion, Subscription: r.Subscription})
		findings += r.Findings
	}
	rec := Recommend(in)
	rec.Findings = int(findings)
	return rec, nil
}
