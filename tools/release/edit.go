package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/tools/internal/fragments"
)

// version is a release version without the "v": 0.15.0.
type version struct{ major, minor, patch int }

var versionRE = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

func parseVersion(s string) (version, error) {
	m := versionRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, fmt.Errorf("%q is not a release version (vX.Y.Z; prereleases are tagged by hand)", s)
	}
	var v version
	v.major, _ = strconv.Atoi(m[1])
	v.minor, _ = strconv.Atoi(m[2])
	v.patch, _ = strconv.Atoi(m[3])
	return v, nil
}

func (v version) String() string { return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch) }

func (v version) less(o version) bool {
	if v.major != o.major {
		return v.major < o.major
	}
	if v.minor != o.minor {
		return v.minor < o.minor
	}
	return v.patch < o.patch
}

// headingRE matches the CHANGELOG headings that matter here, outside code
// blocks: "## Unreleased" and "## X.Y.Z".
var headingRE = regexp.MustCompile(`^## (Unreleased|\d+\.\d+\.\d+)\s*$`)

type heading struct {
	line int    // index into the lines
	name string // "Unreleased" or a version
}

func changelogHeadings(lines []string) []heading {
	var out []heading
	inFence := false
	for i, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		if m := headingRE.FindStringSubmatch(l); m != nil {
			out = append(out, heading{i, m[1]})
		}
	}
	return out
}

// latestReleased returns the newest released version in a changelog (the
// first version heading).
func latestReleased(changelog string) (version, error) {
	for _, h := range changelogHeadings(strings.Split(changelog, "\n")) {
		if h.name != "Unreleased" {
			return parseVersion(h.name)
		}
	}
	return version{}, errors.New("CHANGELOG.md has no released version")
}

// releaseChangelog renames the single, non-empty "## Unreleased" section to
// "## <v>" and puts a fresh, empty "## Unreleased" above it, so the next
// change has its heading and parallel pull requests do not each add one.
// The entries of frags (changelog.d) are merged into the release section,
// in the standard subsection order, after anything written directly under
// Unreleased. It refuses a changelog with no Unreleased section, nothing to
// release (an empty one and no fragments), two of them, or a version that
// is not newer than the newest release.
func releaseChangelog(changelog string, v version, frags []fragments.Fragment) (string, error) {
	lines := strings.Split(changelog, "\n")
	hs := changelogHeadings(lines)
	unreleased := -1
	for i, h := range hs {
		if h.name != "Unreleased" {
			continue
		}
		if unreleased >= 0 {
			return "", errors.New(`CHANGELOG.md has two "## Unreleased" headings (a merge left one behind); merge them first`)
		}
		unreleased = i
	}
	if unreleased < 0 {
		return "", errors.New(`CHANGELOG.md has no "## Unreleased" section: nothing to release`)
	}
	for i, h := range hs {
		if h.name == "Unreleased" {
			continue
		}
		if hv, _ := parseVersion(h.name); hv == v {
			return "", fmt.Errorf("CHANGELOG.md already has a %s section", v)
		}
		if i < unreleased {
			return "", fmt.Errorf(`"## %s" comes before "## Unreleased" in CHANGELOG.md; Unreleased must be the first section`, h.name)
		}
	}
	end := len(lines)
	if unreleased+1 < len(hs) {
		end = hs[unreleased+1].line
		prev, _ := parseVersion(hs[unreleased+1].name)
		if !prev.less(v) {
			return "", fmt.Errorf("%s is not newer than the newest release, %s", v, prev)
		}
	}
	start := hs[unreleased].line
	body := strings.Join(lines[start+1:end], "\n")
	if strings.TrimSpace(body) == "" && len(frags) == 0 {
		return "", errors.New(`the "## Unreleased" section of CHANGELOG.md is empty and changelog.d has no fragments: nothing to release`)
	}
	out := make([]string, 0, len(lines)+2)
	out = append(out, lines[:start]...)
	out = append(out, "## Unreleased", "", "## "+v.String())
	if len(frags) == 0 {
		out = append(out, lines[start+1:]...)
		return strings.Join(out, "\n"), nil
	}
	merged, err := fragments.Merge(body, frags)
	if err != nil {
		return "", err
	}
	out = append(out, "")
	out = append(out, strings.Split(strings.TrimRight(merged, "\n"), "\n")...)
	if end < len(lines) {
		out = append(out, "")
	}
	out = append(out, lines[end:]...)
	return strings.Join(out, "\n"), nil
}

var (
	chartVersionRE    = regexp.MustCompile(`(?m)^version: .*$`)
	chartAppVersionRE = regexp.MustCompile(`(?m)^appVersion: .*$`)
)

// setChartVersion sets a Helm Chart.yaml's version and appVersion.
func setChartVersion(chart string, v version) (string, error) {
	if len(chartVersionRE.FindAllString(chart, -1)) != 1 || len(chartAppVersionRE.FindAllString(chart, -1)) != 1 {
		return "", errors.New("want exactly one top-level version: and appVersion: line")
	}
	chart = chartVersionRE.ReplaceAllString(chart, "version: "+v.String())
	return chartAppVersionRE.ReplaceAllString(chart, `appVersion: "`+v.String()+`"`), nil
}

var serverJSONVersionRE = regexp.MustCompile(`("version":\s*")[^"]*(")`)

// setServerJSONVersion sets the MCP Registry entry's version (the first
// "version" key, the server's own; packages, if ever added, come later).
func setServerJSONVersion(doc string, v version) (string, error) {
	loc := serverJSONVersionRE.FindStringSubmatchIndex(doc)
	if loc == nil {
		return "", errors.New(`no "version" in server.json`)
	}
	return doc[:loc[3]] + v.String() + doc[loc[4]:], nil
}

// docRefRE is the reference releaselint checks in README.md and the install
// and Kubernetes docs: image tags, chart OCI tags and helm --version.
var docRefRE = regexp.MustCompile(`((?:stackurity/stackurity:|charts/stackurity(?:-reporter)?:|charts/stackurity(?:-reporter)? --version )v?)(\d+\.\d+\.\d+)`)

// setDocVersions rewrites every versioned image and chart reference to v and
// reports how many it changed.
func setDocVersions(doc string, v version) (string, int) {
	n := 0
	out := docRefRE.ReplaceAllStringFunc(doc, func(s string) string {
		m := docRefRE.FindStringSubmatch(s)
		if m[2] == v.String() {
			return s
		}
		n++
		return m[1] + v.String()
	})
	return out, n
}

var matrixRE = regexp.MustCompile(`(from: \[)([^\]]*)(\])`)

// addUpgradeSource adds a published version to the release-checks upgrade
// matrix (from: [...]) if it is not there; added says whether it was.
func addUpgradeSource(workflow string, v version) (out string, added bool, err error) {
	loc := matrixRE.FindStringSubmatchIndex(workflow)
	if loc == nil {
		return "", false, errors.New("release-checks.yml: no from: [...] list")
	}
	list := workflow[loc[4]:loc[5]]
	if strings.Contains(list, `"`+v.String()+`"`) {
		return workflow, false, nil
	}
	sep := ", "
	if strings.TrimSpace(list) == "" {
		sep = ""
	}
	return workflow[:loc[5]] + sep + `"` + v.String() + `"` + workflow[loc[5]:], true, nil
}

// releaseNotesSummary lists the entry titles (the bold lead of each bullet)
// under each subsection of a version's notes, for the pull request body.
func releaseNotesSummary(notes string) string {
	var b strings.Builder
	bold := regexp.MustCompile(`^- \*\*(.+?)\*\*`)
	for _, l := range strings.Split(notes, "\n") {
		switch {
		case strings.HasPrefix(l, "### "):
			fmt.Fprintf(&b, "\n**%s**\n\n", strings.TrimPrefix(l, "### "))
		case strings.HasPrefix(l, "- "):
			title := strings.TrimPrefix(l, "- ")
			if m := bold.FindStringSubmatch(l); m != nil {
				title = m[1]
			} else if len(title) > 120 {
				title = title[:120] + "…"
			}
			fmt.Fprintf(&b, "- %s\n", title)
		}
	}
	return strings.TrimSpace(b.String())
}
