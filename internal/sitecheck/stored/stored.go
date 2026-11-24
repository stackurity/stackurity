// Package stored answers the website check's questions (sitecheck.Intel)
// from the server's stored advisories and end-of-life catalogue.
package stored

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/lifecycle"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/sitecheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/upgrade"
	"github.com/stackurity/stackurity/internal/vendorbuilds"
	"github.com/stackurity/stackurity/internal/version"
)

// Intel answers the website check's questions from the stored
// advisories and end-of-life catalogue (sitecheck.Intel).
type Intel struct {
	Store *store.Store
	lr    lifecycle.Resolver
	now   func() time.Time
}

// New reads the end-of-life catalogue's product names once.
func New(ctx context.Context, st *store.Store) (*Intel, error) {
	sys := tenant.System(ctx)
	byPurl, err := st.LifecycleProductsByPurl(sys)
	if err != nil {
		return nil, err
	}
	names, err := st.LifecycleProductNames(sys)
	if err != nil {
		return nil, err
	}
	return &Intel{Store: st, lr: lifecycle.Resolver{ByPurl: byPurl, Names: names}, now: time.Now}, nil
}

// Vulnerabilities implements sitecheck.Intel.
func (si *Intel) Vulnerabilities(ctx context.Context, sw sitecheck.Software) ([]sitecheck.Issue, string, error) {
	sys := tenant.System(ctx)
	switch sw.Ecosystem {
	case "npm":
		ns, name := "", sw.Package
		if i := strings.LastIndex(name, "/"); strings.HasPrefix(name, "@") && i > 0 {
			ns, name = name[:i], name[i+1:]
		}
		purl := packageurl.NewPackageURL("npm", ns, name, sw.Version, nil, "").ToString()
		t, ok := osv.TargetFor(purl, sw.Version, nil)
		if !ok {
			return nil, "npm packages are not read on this server", nil
		}
		advs, err := si.Store.AdvisoriesFor(sys, osv.BaseEcosystem(t.Ecosystem), t.Name, t.Ecosystem)
		if err != nil {
			return nil, "", err
		}
		return siteIssues(advs, t), "", nil
	case "vendor":
		p := vendorbuilds.Default().Product(sw.Package)
		if p == nil {
			return nil, "no vulnerability data for " + sw.Name, nil
		}
		v := sw.Version
		if up, err := p.UpstreamVersion(v); err == nil && up != "" {
			v = up
		}
		advs, err := si.Store.AdvisoriesFor(sys, vendorbuilds.Ecosystem, p.ID, p.Ecosystem())
		if err != nil {
			return nil, "", err
		}
		if len(advs) == 0 {
			return nil, fmt.Sprintf("no vulnerability records for %s are stored yet (they are read from NVD)", p.Label), nil
		}
		t := osv.Target{Ecosystem: p.Ecosystem(), Name: p.ID, Version: v, Compare: version.Generic}
		return siteIssues(advs, t), "", nil
	}
	return nil, "no vulnerability data for " + sw.Name, nil
}

// siteIssues are the advisories t's version is affected by, one per issue
// (group key), with the highest fix above it.
func siteIssues(advs []store.AdvisoryMatch, t osv.Target) []sitecheck.Issue {
	cmp := version.For(t.Compare)
	byKey := map[string]*sitecheck.Issue{}
	var order []string
	for _, a := range advs {
		// AdvisoriesFor selected the package by name already.
		if a.Withdrawn != nil || !osv.MatchEcosystem(a.Ecosystem, t.Ecosystem) {
			continue
		}
		m, err := osv.Check(a.Affected, t)
		if err != nil || !m.Affected {
			continue
		}
		key := a.GroupKey
		if key == "" {
			key = a.ID
		}
		is, ok := byKey[key]
		if !ok {
			id := issueID(a)
			var aliases []string
			for _, al := range append([]string{a.ID}, a.Aliases...) {
				if al != id && !slices.Contains(aliases, al) {
					aliases = append(aliases, al)
				}
			}
			is = &sitecheck.Issue{ID: id, Aliases: aliases, Summary: a.Summary, Severity: a.SeverityLevel}
			if a.SeverityScore != nil {
				is.Score = float64(*a.SeverityScore)
			}
			byKey[key] = is
			order = append(order, key)
		}
		is.KnownExploited = is.KnownExploited || a.KnownExploited
		if m.FixedVersion != "" {
			if is.FixedIn == "" {
				is.FixedIn = m.FixedVersion
			} else if c, err := cmp(m.FixedVersion, is.FixedIn); err == nil && c > 0 {
				is.FixedIn = m.FixedVersion
			}
		}
		if a.SeverityScore != nil && float64(*a.SeverityScore) > is.Score {
			is.Score, is.Severity = float64(*a.SeverityScore), a.SeverityLevel
		}
	}
	out := make([]sitecheck.Issue, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out
}

// issueID prefers the CVE an advisory is about.
func issueID(a store.AdvisoryMatch) string {
	if strings.HasPrefix(a.GroupKey, "CVE-") {
		return a.GroupKey
	}
	ids := append([]string{a.ID}, a.Aliases...)
	sort.SliceStable(ids, func(i, j int) bool { return strings.HasPrefix(ids[i], "CVE-") && !strings.HasPrefix(ids[j], "CVE-") })
	return ids[0]
}

// EndOfLife implements sitecheck.Intel.
func (si *Intel) EndOfLife(ctx context.Context, sw sitecheck.Software) (*sitecheck.EOL, error) {
	var m lifecycle.Match
	var ok bool
	switch {
	case sw.Ecosystem == "npm":
		m, ok = si.lr.Resolve("npm", "pkg:npm/"+sw.Package, sw.Version, "")
	case sw.Lifecycle != "":
		m, ok = si.lr.Resolve("generic", "pkg:generic/"+sw.Lifecycle, sw.Version, "")
	}
	if !ok {
		return nil, nil
	}
	cycles, err := si.Store.LifecycleCycles(tenant.System(ctx), m.Product)
	if err != nil {
		return nil, err
	}
	c := upgrade.MatchCycle(cycles, m.CycleVersion)
	if c == nil {
		return nil, nil
	}
	e := &sitecheck.EOL{Product: c.ProductLabel, Cycle: c.Cycle, EOLDate: c.EOLUntil, Latest: c.Latest, Link: c.Link,
		Ended: c.IsEOL || c.EOLUntil != nil && !c.EOLUntil.After(si.now())}
	if e.Product == "" {
		e.Product = c.Product
	}
	return e, nil
}
