package intel

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
)

// Behind its branch's latest release. For a product whose point releases on
// a supported branch are its security releases, and whose vulnerabilities
// are not matched, a version below the branch's latest release (endoflife.date
// latest) is reported as a vulnerability finding fixed by that release. A
// site on WordPress 6.5.3 while 6.5.14 is out misses eleven security and
// maintenance releases and would otherwise look clean.
//
// Only products listed here: nginx, PHP or Node.js point releases are not
// all security fixes, so "behind" would be noise for them.
//
// The finding stands in for vulnerability matching and is not made for a
// row a vulnerability source evaluated (see Evaluator): when a source for
// WordPress core CVEs is added, the CVE findings replace it with no change
// here. Remove the product from this list then.
var behindProducts = map[string]bool{"wordpress": true}

// behindRule is the match rule ("match"."rule" in the evidence) that marks a
// behind finding, for the explanation and the second check.
const behindRule = "behind_latest_release"

// behindHigh is how many releases behind raises the severity to high: one
// or two is a site between a release and its next update (WordPress applies
// minor releases automatically by default); three or more means updates
// are not being applied, and several security releases are missing.
const behindHigh = 3

// behindFinding is the finding for a row of product cycle c below the
// cycle's latest release, nil when it is not behind or not a release
// (pre-releases and development builds are never compared).
func behindFinding(r store.EvalRow, c *store.LifecycleCycle) *store.FindingInput {
	if !behindProducts[c.Product] {
		return nil
	}
	n, ok := releasesBehind(r.Version, c.Latest)
	if !ok || n <= 0 {
		return nil
	}
	severity := "medium"
	if n >= behindHigh {
		severity = "high"
	}
	verification := "confirmed"
	if r.AssetStale {
		verification = "stale"
	} else if r.Confidence != "confirmed" {
		verification = "needs_validation"
	}
	label := c.ProductLabel
	if label == "" {
		label = c.Product
	}
	releases := "releases"
	if n == 1 {
		releases = "release"
	}
	ev := map[string]any{"product": c.Product, "cycle": c.Cycle, "latest_in_cycle": c.Latest, "releases_behind": n,
		"feed": FeedEndOfLife, "source": FeedEndOfLife, "link": c.Link, "match": map[string]any{"rule": behindRule}}
	if c.LatestDate != nil {
		ev["latest_date"] = c.LatestDate.Format("2006-01-02")
	}
	return &store.FindingInput{
		Kind: "vulnerability", Key: "behind:" + c.Product + ":" + c.Cycle, InventoryID: r.InventoryID, AssetID: r.AssetID,
		ComponentID: r.ComponentID, Verification: verification, Severity: severity,
		Title:        fmt.Sprintf("%s %s is %d %s behind %s, the latest %s %s release", label, r.Version, n, releases, c.Latest, label, c.Cycle),
		FixedVersion: c.Latest, Sources: []string{FeedEndOfLife}, Evidence: ev,
	}
}

// releasesBehind counts the point releases between installed and latest on
// one branch (6.5.3 to 6.5.14 is 11; "6.5" is 6.5.0). Both must be plain
// releases of the same major.minor: ok is false for a pre-release or
// development build (6.9-RC1, 6.7-alpha-58576-src) or anything else.
func releasesBehind(installed, latest string) (int, bool) {
	a, ok1 := pointRelease(installed)
	b, ok2 := pointRelease(latest)
	if !ok1 || !ok2 || a[0] != b[0] || a[1] != b[1] {
		return 0, false
	}
	return b[2] - a[2], true
}

// pointRelease reads major.minor[.patch], all numbers.
func pointRelease(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p != strconv.Itoa(n) {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
