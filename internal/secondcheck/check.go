// Package secondcheck is the independent second check of high-impact
// findings. It re-derives a finding from the stored advisory record (each
// affected entry's ranges and listed versions, in the order the feed lists
// them) and the raw observed version through its own, deliberately simple code: its
// own package URL parser, ecosystem and release rules, version comparators
// and a plain reading of OSV ranges. It imports nothing from the matcher
// (internal/intel, internal/osv, internal/version), so a defect there is not
// repeated here.
//
// It reads less than the matcher on purpose. Whatever it cannot read (a
// pre-release, a SUSE product channel, a FIPS build, a GIT range) is "could
// not check" with the reason, never a guess. Only a verdict it fully derived
// can disagree. See docs/verification.md, "Second check".
package secondcheck

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/store"
)

// Claim is what the finding says.
type Claim struct {
	Kind         string
	Key          string
	FixedVersion string
	Sources      []string
	Evidence     map[string]any
}

// Observed is the inventory row as the collector reported it.
type Observed struct {
	Purl     string
	Version  string
	Evidence map[string]string
}

// Outcome is the second check's result for one finding.
type Outcome struct {
	Result      string
	Reason      string
	Differences []store.SecondCheckDifference
	Independent map[string]any
	// Records are the raw records it read, for the disagreement log.
	Records []store.RawAdvisoryRecord
}

func couldNot(format string, a ...any) Outcome {
	return Outcome{Result: store.SecondCheckCouldNotCheck, Reason: fmt.Sprintf(format, a...)}
}

// rawAffected is the part of an OSV affected entry the second check reads.
type rawAffected struct {
	Ranges []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
	Versions []string `json:"versions"`
}

// verdict is one record's answer.
type verdict struct {
	id, ecosystem  string
	affected       bool
	fixed          string // lowest fix above the installed version
	fixedAtOrBelow string // a fix at or below the installed version, when not affected
	paid           bool
}

// CheckVulnerability re-derives a vulnerability finding.
func CheckVulnerability(c Claim, o Observed, recs []store.RawAdvisoryRecord) Outcome {
	t, err := deriveTarget(o.Purl, o.Version, o.Evidence)
	if err != nil {
		return couldNot("%v", err)
	}
	if t.fips {
		return couldNot("FIPS builds take their fixes from Ubuntu Pro FIPS channels, which the second check does not re-derive")
	}
	// A kernel's findings are reported once, on one of its packages; the
	// record may name any package of that kernel version.
	if kp, ok := c.Evidence["kernel_packages"].([]any); ok {
		for _, n := range kp {
			if s, ok := n.(string); ok {
				t.names[normaliseName(t.ecosystem, s)] = true
			}
		}
	}
	cmp := comparatorFor(t.family)
	if _, err := cmp(t.version, t.version); err != nil {
		return couldNot("installed version: %v", err)
	}
	if len(recs) == 0 {
		return couldNot("no advisory record for %s is stored", c.Key)
	}
	var free, paid []verdict
	var otherNames []string
	sameRelease := 0
	for _, r := range recs {
		if r.Withdrawn {
			continue
		}
		applies, isPaid := t.recordApplies(r.Ecosystem)
		if !applies {
			continue // another ecosystem or release
		}
		sameRelease++
		if !t.names[normaliseName(t.ecosystem, r.Name)] {
			otherNames = appendOnce(otherNames, r.Name)
			continue
		}
		var a rawAffected
		if err := json.Unmarshal(r.Affected, &a); err != nil {
			return couldNot("record %s could not be read", r.ID)
		}
		v, err := evaluate(a, t.version, cmp)
		if err != nil {
			return couldNot("record %s: %v", r.ID, err)
		}
		v.id, v.ecosystem, v.paid = r.ID, r.Ecosystem, isPaid
		if isPaid {
			paid = append(paid, v)
		} else {
			free = append(free, v)
		}
	}
	ind := map[string]any{"comparator": string(t.family), "version": t.version}
	used := free
	if len(free) == 0 {
		used = paid
	}
	if len(used) == 0 && t.kernel && !t.kernelSource && kernelRecords(otherNames) {
		// The records name kernel sources, and which one built this binary
		// (linux, linux-aws, linux-hwe-5.15, ...) is not in the observation.
		return couldNot("records name the kernel source %s; which kernel source built %s is not reported (no upstream or source package), "+
			"and the binary name alone does not say", strings.Join(otherNames, ", "), strings.Join(sortedNames(t.names), ", "))
	}
	if len(used) == 0 {
		if sameRelease == 0 {
			// The matcher found a record for this package and release; none
			// of the stored records is one.
			return disagree(ind, store.SecondCheckDifference{Field: "package",
				Matcher:     claimPackage(c),
				Independent: fmt.Sprintf("no record of %s applies to %s %s", c.Key, t.ecosystem, t.release),
				Note:        "the advisory has no record for this ecosystem and release"})
		}
		return disagree(ind, store.SecondCheckDifference{Field: "package",
			Matcher:     claimPackage(c),
			Independent: fmt.Sprintf("records for %s name %s, not %s", t.ecosystem+releaseSuffix(t), strings.Join(otherNames, ", "), strings.Join(sortedNames(t.names), " or ")),
			Note:        "package identity mismatch"})
	}
	affected, fixed := false, ""
	var lines []string
	for _, v := range used {
		state := "not affected"
		if v.affected {
			affected = true
			state = "affected"
			if v.fixed != "" {
				state += ", fixed in " + v.fixed
				if fixed == "" {
					fixed = v.fixed
				} else if c, err := cmp(v.fixed, fixed); err == nil && c > 0 {
					fixed = v.fixed
				}
			}
		} else if v.fixedAtOrBelow != "" {
			state += ", fixed in " + v.fixedAtOrBelow
		}
		lines = append(lines, fmt.Sprintf("%s (%s): %s", v.id, v.ecosystem, state))
	}
	ind["affected"], ind["records"] = affected, lines
	if fixed != "" {
		ind["fixed_version"] = fixed
	}
	if len(free) == 0 {
		ind["subscription_only"] = true
	}
	if !affected {
		d := store.SecondCheckDifference{Field: "affected", Matcher: "affected" + claimRange(c),
			Independent: "not affected: " + strings.Join(lines, "; ")}
		for _, v := range used {
			if v.fixedAtOrBelow != "" && backport(t.family, t.version, v.fixedAtOrBelow) {
				d.Note = fmt.Sprintf("%s backported the fix to this upstream release (%s); an upstream range would still call it vulnerable",
					t.ecosystem, v.fixedAtOrBelow)
				break
			}
		}
		return disagree(ind, d)
	}
	var diffs []store.SecondCheckDifference
	_, claimPaid := c.Evidence["requires_subscription"]
	if claimPaid != (len(free) == 0) {
		diffs = append(diffs, store.SecondCheckDifference{Field: "subscription",
			Matcher: yesNo(claimPaid, "fix needs a paid subscription", "fix is free"), Independent: yesNo(len(free) == 0, "only a paid channel lists it", "a free channel lists it")})
	}
	_, kernel := c.Evidence["kernel_packages"]
	if !kernel && fixed != c.FixedVersion {
		diffs = append(diffs, store.SecondCheckDifference{Field: "fixed_version", Matcher: orNone(c.FixedVersion), Independent: orNone(fixed)})
	}
	if len(diffs) > 0 {
		return disagree(ind, diffs...)
	}
	return Outcome{Result: store.SecondCheckAgreed, Independent: ind}
}

// evaluate reads one affected entry the plain way: the listed versions,
// then each SEMVER or ECOSYSTEM range as introduced..fixed (or ..limit, or
// ..last_affected inclusive) spans in the order the record lists them.
func evaluate(a rawAffected, installed string, cmp comparator) (verdict, error) {
	var v verdict
	for _, x := range a.Versions {
		if x == installed {
			v.affected = true
		}
	}
	readable := len(a.Versions) > 0
	for _, r := range a.Ranges {
		if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
			continue
		}
		readable = true
		c := cmp
		if r.Type == "SEMVER" {
			c = dottedCompare
		}
		lo, open := "", false
		for _, e := range r.Events {
			switch {
			case e["introduced"] != "":
				lo, open = e["introduced"], true
			case e["fixed"] != "" || e["limit"] != "" || e["last_affected"] != "":
				hi, inclusive := e["fixed"], false
				if hi == "" {
					hi = e["limit"]
				}
				if hi == "" {
					hi, inclusive = e["last_affected"], true
				}
				if open {
					in, err := between(installed, lo, hi, inclusive, c)
					if err != nil {
						return v, err
					}
					v.affected = v.affected || in
				}
				open = false
				if f := e["fixed"]; f != "" {
					d, err := c(f, installed)
					if err != nil {
						return v, err
					}
					if d > 0 && (v.fixed == "" || less(f, v.fixed, c)) {
						v.fixed = f
					}
					if d <= 0 && (v.fixedAtOrBelow == "" || less(v.fixedAtOrBelow, f, c)) {
						v.fixedAtOrBelow = f
					}
				}
			}
		}
		if open {
			in, err := between(installed, lo, "", false, c)
			if err != nil {
				return v, err
			}
			v.affected = v.affected || in
		}
	}
	if !readable {
		return v, fmt.Errorf("it has no version list and no SEMVER or ECOSYSTEM range (GIT ranges need commit data)")
	}
	if !v.affected {
		v.fixed = ""
	}
	return v, nil
}

func between(v, lo, hi string, inclusive bool, c comparator) (bool, error) {
	if lo != "0" {
		d, err := c(v, lo)
		if err != nil {
			return false, err
		}
		if d < 0 {
			return false, nil
		}
	}
	if hi == "" {
		return true, nil
	}
	d, err := c(v, hi)
	if err != nil {
		return false, err
	}
	return d < 0 || (inclusive && d == 0), nil
}

func less(a, b string, c comparator) bool {
	d, err := c(a, b)
	return err == nil && d < 0
}

// backport reports whether a fix keeps the installed upstream release and
// changes only the distro revision.
func backport(f family, installed, fixed string) bool {
	up := func(v string) string {
		if _, r, ok := strings.Cut(v, ":"); ok {
			v = r
		}
		if f == famAPK {
			v, _, _ = strings.Cut(v, "-r")
			return v
		}
		if i := strings.LastIndexByte(v, '-'); i > 0 {
			v = v[:i]
		}
		return v
	}
	return f != famDotted && up(installed) == up(fixed)
}

func disagree(ind map[string]any, d ...store.SecondCheckDifference) Outcome {
	parts := make([]string, 0, len(d))
	for _, x := range d {
		s := fmt.Sprintf("%s: the matcher says %s, the second check finds %s", strings.ReplaceAll(x.Field, "_", " "), x.Matcher, x.Independent)
		if x.Note != "" {
			s += " (" + x.Note + ")"
		}
		parts = append(parts, s)
	}
	return Outcome{Result: store.SecondCheckDisagreed, Reason: strings.Join(parts, "; "), Differences: d, Independent: ind}
}

func claimPackage(c Claim) string {
	pkg, _ := c.Evidence["osv_package"].(string)
	eco, _ := c.Evidence["target_ecosystem"].(string)
	if pkg == "" {
		return "a record for this package"
	}
	return fmt.Sprintf("a record for %s in %s", pkg, eco)
}

func claimRange(c Claim) string {
	if rs, ok := c.Evidence["matched_ranges"].([]any); ok && len(rs) > 0 {
		return fmt.Sprintf(" (%v)", rs[0])
	}
	return ""
}

func releaseSuffix(t target) string {
	if t.release == "" {
		return ""
	}
	return " " + t.release
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func appendOnce(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func yesNo(b bool, y, n string) string {
	if b {
		return y
	}
	return n
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// --- end of life

// eolPackage reads the release line a versioned distro package names
// ("php8.1-common" is PHP 8.1, "ruby3.0" is Ruby 3.0).
func eolPackage(name string) (product, cycle string) {
	for _, p := range []struct{ prefix, suffix, product string }{{"php", "-common", "php"}, {"ruby", "", "ruby"}} {
		rest, ok := strings.CutPrefix(name, p.prefix)
		if !ok {
			continue
		}
		rest, ok = strings.CutSuffix(rest, p.suffix)
		if ok && dottedRE.MatchString(rest) && strings.Count(rest, ".") == 1 {
			return p.product, rest
		}
	}
	return "", ""
}

// windowsBuild returns the third dotted field of a Windows version
// ("10.0.14393.7428", "6.3.9600"), or "".
func windowsBuild(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// CheckEndOfLife re-derives an end-of-life finding from the stored release
// lines of its product: the line is the version itself or its longest
// dotted prefix (or, for a versioned distro package, the line its name
// carries), and it has ended when marked so or its end date has passed.
func CheckEndOfLife(c Claim, o Observed, cycles []store.LifecycleCycle, now time.Time) Outcome {
	product, _ := c.Evidence["product"].(string)
	claimCycle, _ := c.Evidence["cycle"].(string)
	if product == "" || claimCycle == "" {
		return couldNot("the finding does not name its product and release line")
	}
	if len(cycles) == 0 {
		return couldNot("no release lines of %s are stored", product)
	}
	ind := map[string]any{"product": product}
	line := ""
	if p, err := parsePurl(o.Purl); err == nil && p.typ == "deb" {
		if prod, cyc := eolPackage(p.name); prod == product {
			line = cyc
			ind["matched_by"] = "package name"
		}
	}
	v := o.Version
	if v == "" {
		return couldNot("no installed version was reported")
	}
	if product == "windows-server" || product == "windows" {
		// Windows releases are not dotted prefixes of the version
		// (10.0.14393.7428 is "2016"): the build is checked against the
		// build endoflife.date lists as each release's latest, which the
		// matcher does not use. Several releases share a build (2019 and
		// 1809 SAC; Home and Enterprise editions), so the claim agrees when
		// its release is one of them.
		ind["matched_by"] = "build"
		build := windowsBuild(v)
		var lines []string
		for _, cy := range cycles {
			if build != "" && windowsBuild(cy.Latest) == build {
				lines = append(lines, cy.Cycle)
				if cy.Cycle == claimCycle {
					line = cy.Cycle
				}
			}
		}
		if line == "" {
			indep := fmt.Sprintf("no release line of %s lists build %s", product, orNone(build))
			if len(lines) > 0 {
				indep = fmt.Sprintf("build %s is %s", build, strings.Join(lines, " or "))
			}
			return disagree(ind, store.SecondCheckDifference{Field: "release_line", Matcher: claimCycle, Independent: indep})
		}
	}
	if line == "" {
		ind["matched_by"] = "version"
		for _, cy := range cycles {
			if (v == cy.Cycle || strings.HasPrefix(v, cy.Cycle+".")) && len(cy.Cycle) > len(line) {
				line = cy.Cycle
			}
		}
	}
	if line == "" {
		return disagree(ind, store.SecondCheckDifference{Field: "release_line", Matcher: claimCycle,
			Independent: fmt.Sprintf("no release line of %s matches version %s", product, v)})
	}
	ind["cycle"] = line
	if line != claimCycle {
		return disagree(ind, store.SecondCheckDifference{Field: "release_line", Matcher: claimCycle, Independent: line})
	}
	for _, cy := range cycles {
		if cy.Cycle != line {
			continue
		}
		ended := cy.IsEOL || (cy.EOLUntil != nil && !cy.EOLUntil.After(now))
		ind["ended"] = ended
		if cy.EOLUntil != nil {
			ind["eol_date"] = cy.EOLUntil.Format("2006-01-02")
		}
		if !ended {
			until := "no end date"
			if cy.EOLUntil != nil {
				until = "supported until " + cy.EOLUntil.Format("2006-01-02")
			}
			return disagree(ind, store.SecondCheckDifference{Field: "end_of_life", Matcher: "end of life", Independent: until})
		}
	}
	return Outcome{Result: store.SecondCheckAgreed, Independent: ind}
}

// kernelRecords reports whether every name is a kernel source package.
func kernelRecords(names []string) bool {
	for _, n := range names {
		if _, ok := kernelSourceName("", n); !ok {
			return false
		}
	}
	return len(names) > 0
}
