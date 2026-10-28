package intel

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/upgrade"
)

// Upstream end of life and distribution packages.
//
// endoflife.date dates are the upstream project's: nginx 1.18 ended in 2021,
// PHP 8.1 on 2025-12-31. A distribution that ships one of those versions
// keeps patching its own package while the distribution release is
// supported (Ubuntu 22.04 until 2027, RHEL 9 until 2032), so an upstream
// end-of-life finding on it is a false positive. The rules for a runtime or
// server that matches an endoflife.date product:
//
//   - Installed outside the package manager (pkg:generic runtimes, language
//     packages): the upstream date applies, as before.
//   - A distribution package (deb, rpm, apk with a distro qualifier) whose
//     distribution release is supported: no finding. The inventory row
//     records the upstream status and the distribution's support date.
//   - The distribution release is itself end of life: its packages stop
//     getting free fixes, which the operating system's own end-of-life
//     finding already says. No separate finding per package when that
//     finding exists on the asset; the action plan lists the packages
//     under the release upgrade. Without an operating system row on the
//     asset (some SBOMs) the package finding stays.
//   - The distribution's lifecycle is unknown (no data for it, no distro
//     qualifier): the upstream finding stays.
//   - The version shows a build from another repository (Ondrej Sury's PHP
//     packages, nginx.org, NodeSource, PGDG, Remi, MySQL's APT
//     repository): the distribution does not maintain it, the finding stays.

// distroIDs are the os-release IDs a distro qualifier starts with, longest
// first, so "opensuse-leap-15.5" is not read as another ID.
var distroIDs = func() []string {
	ids := []string{"sles_sap"}
	for id := range osProducts {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return len(ids[i]) > len(ids[j]) || (len(ids[i]) == len(ids[j]) && ids[i] < ids[j])
	})
	return ids
}()

// distroProduct reads a distro qualifier ("ubuntu-22.04", "rhel-9.4",
// "alpine-3.21.2", "opensuse-leap-15.6") as an endoflife.date product and
// release.
func distroProduct(distro string) (product, release string) {
	for _, id := range distroIDs {
		if rel, ok := strings.CutPrefix(distro, id+"-"); ok && rel != "" {
			if id == "sles_sap" {
				id = "sles"
			}
			return osProducts[id], rel
		}
	}
	return "", ""
}

// distroCycle returns the lifecycle cycle of the distribution release an OS
// package was built for, or nil when it is not an OS package or the release
// is not in the lifecycle data.
func (e *Evaluator) distroCycle(ctx context.Context, r store.EvalRow, cache map[string][]store.LifecycleCycle) (*store.LifecycleCycle, error) {
	if !upgrade.IsDistro(r.Type) {
		return nil, nil
	}
	pu, err := packageurl.FromString(r.Purl)
	if err != nil {
		return nil, nil
	}
	product, release := distroProduct(pu.Qualifiers.Map()["distro"])
	if product == "" {
		return nil, nil
	}
	cycles, ok := cache[product]
	if !ok {
		if cycles, err = e.Store.LifecycleCycles(ctx, product); err != nil {
			return nil, err
		}
		cache[product] = cycles
	}
	return matchCycle(cycles, release), nil
}

func cycleEnded(c *store.LifecycleCycle, now time.Time) bool {
	return c.IsEOL || (c.EOLUntil != nil && !c.EOLUntil.After(now))
}

// distroLifecycle decides whether an upstream end-of-life finding on an OS
// package stands (keep) and returns the note recorded on the inventory row.
// osOnAsset is the asset's operating system as "product|version" ("" when
// the asset has none).
//
// vendor names the repository that built the package when it is not the
// distribution's own build (thirdPartyRepo), or is "".
func distroLifecycle(r store.EvalRow, upstream, dist *store.LifecycleCycle, osOnAsset, vendor string, cache map[string][]store.LifecycleCycle,
	now time.Time) (note map[string]any, keep bool) {
	if dist == nil {
		return nil, true
	}
	subject := upstream.ProductLabel + " " + upstream.Cycle
	text := subject + " is end of life upstream"
	note = map[string]any{"product": upstream.Product, "cycle": upstream.Cycle, "subject": subject, "distribution": dist.ProductLabel + " " + dist.Cycle,
		"distribution_product": dist.Product, "distribution_cycle": dist.Cycle}
	if upstream.EOLUntil != nil {
		note["upstream_eol"] = upstream.EOLUntil.Format("2006-01-02")
		text += " since " + upstream.EOLUntil.Format("2006-01-02")
	}
	label := dist.ProductLabel + " " + dist.Cycle
	distDate := ""
	if dist.EOLUntil != nil {
		distDate = dist.EOLUntil.Format("2006-01-02")
		note["distribution_eol"] = distDate
	}
	switch {
	case vendor != "":
		note["status"] = "third_party_build"
		note["repository"] = vendor
		note["text"] = text + "; this is a build from " + vendor + ", not " + label + "'s own package, so the distribution's security support does not apply."
		return note, true
	case !cycleEnded(dist, now):
		note["status"] = "distribution_supported"
		t := text + "; this is " + label + "'s own package, and " + label + " provides security updates"
		if distDate != "" {
			t += " until " + distDate
		} else {
			t += " while it is supported"
		}
		note["text"] = t + "."
		return note, false
	}
	note["status"] = "distribution_ended"
	t := text + "; " + label + " itself is end of life"
	if distDate != "" {
		t += " since " + distDate
	}
	if osMatches(osOnAsset, dist, cache) {
		note["text"] = t + ", so its packages no longer get free fixes: see the operating system's end-of-life finding."
		return note, false
	}
	note["text"] = t + ", so its packages no longer get free fixes."
	return note, true
}

// osMatches reports whether the asset's operating system row ("product|
// version") is the distribution release dist, whose end-of-life finding then
// covers its packages.
func osMatches(osOnAsset string, dist *store.LifecycleCycle, cache map[string][]store.LifecycleCycle) bool {
	product, v, ok := strings.Cut(osOnAsset, "|")
	if !ok || product != dist.Product {
		return false
	}
	c := matchCycle(cache[product], v)
	return c != nil && c.Cycle == dist.Cycle
}

// debCodenameSuffix matches repository builds named after the release
// codename after the package revision: nginx.org "1.24.0-1~jammy", Docker
// "5:27.3.1-1~ubuntu.22.04~jammy". Distribution updates end in digits
// ("~22.04.1", "+deb12u1"), and an upstream pre-release ("2.0~beta") has
// no revision before it.
var debCodenameSuffix = regexp.MustCompile(`-[0-9][^~]*~(?:[a-z]+\.[0-9.]+~)?[a-z]+$`)

// thirdPartyBuild reports versions that show a package was built by another
// repository rather than the distribution. The agent does not record the
// repository a package came from, so only recognisable builds are caught.
func thirdPartyBuild(purlType, v, release string) bool {
	v = strings.ToLower(v)
	switch purlType {
	case "deb":
		for _, m := range []string{"deb.sury.org", "nodesource", "pgdg"} {
			if strings.Contains(v, m) {
				return true
			}
		}
		if debCodenameSuffix.MatchString(v) {
			return true
		}
		// MySQL's APT repository: "8.0.39-1ubuntu22.04", "8.0.39-1debian12".
		if release != "" && (strings.HasSuffix(v, "ubuntu"+release) || strings.HasSuffix(v, "debian"+release)) {
			return true
		}
	case "rpm":
		for _, m := range []string{".remi", ".ngx", "pgdg", "nodesource"} {
			if strings.Contains(v, m) {
				return true
			}
		}
	}
	return false
}
