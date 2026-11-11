package notify

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
)

// componentFix is one entry of a vulnerability incident's
// detail.component_fixes (store.CorrelateIncidents): the fixed versions of
// one component and how many assets it is on, and on how many it has none.
type componentFix struct {
	Component     string   `json:"component"`
	Type          string   `json:"type"`
	FixedVersions []string `json:"fixed_versions"`
	Assets        int      `json:"assets"`
	Unfixed       int      `json:"unfixed"`
	// SourcePackage: the fixed versions are this source package's, and the
	// component (a Debian or Ubuntu binary package) has versions of its own.
	SourcePackage string `json:"source_package,omitempty"`
}

// to names what to install for a fixed version: the version itself, or for
// a binary package whose fix is named by its source package's version, a
// build from that source ("a build from inetutils 2:2.5-3ubuntu4.1"), since
// the package manager has no such version of the binary.
func (c componentFix) to(v string) string {
	if c.SourcePackage != "" {
		return "a build from " + c.SourcePackage + " " + v
	}
	return v
}

// osPackageTypes are the purl types whose namespace names the distribution.
var osPackageTypes = map[string]bool{"deb": true, "rpm": true, "apk": true}

// distro names the distribution an OS package comes from ("Debian"), or ""
// for an application package or an unknown distribution.
func (c componentFix) distro() string {
	if !osPackageTypes[c.Type] {
		return ""
	}
	ns, _, ok := strings.Cut(c.Component, "/")
	if !ok {
		return ""
	}
	return store.DistroLabel(ns)
}

func assetsText(n int) string { return plural(n, "asset") }

// componentFixAction says what to do per component of a vulnerability
// incident, so a version published for one distribution is never offered
// for another: "ubuntu/curl (2 assets), ubuntu/libcurl4 (1 asset): upgrade
// to 7.81.0-1ubuntu1.29 or later; debian/curl: no fixed version is
// published yet for Debian, watch the advisory and consider mitigations (1
// asset)". ok is false when the detail has no component_fixes (an incident
// not correlated since they were added): the caller then falls back to the
// flat fixed_versions.
func componentFixAction(detail json.RawMessage) (string, bool) {
	var det struct {
		Fixes []componentFix `json:"component_fixes"`
		Count int            `json:"component_count"`
	}
	if json.Unmarshal(detail, &det) != nil || len(det.Fixes) == 0 {
		return "", false
	}
	type line struct {
		comps []componentFix
		text  string
	}
	var lines []*line
	byKey := map[string]*line{}
	add := func(key string, c componentFix, text string) {
		if l, ok := byKey[key]; ok && key != "" {
			l.comps = append(l.comps, c)
			return
		}
		l := &line{comps: []componentFix{c}, text: text}
		lines = append(lines, l)
		if key != "" {
			byKey[key] = l
		}
	}
	for _, c := range det.Fixes {
		fixed := c.Assets - c.Unfixed
		switch {
		case len(c.FixedVersions) == 0 || fixed <= 0:
			d := c.distro()
			text := "no fixed version is published yet"
			if d != "" {
				text += " for " + d
			}
			text += ", watch the advisory and consider mitigations"
			add("none|"+d, c, text)
		case c.Unfixed > 0:
			add("", c, fmt.Sprintf("upgrade to %s where it is published (%s); no fixed version yet on the other %s, watch the advisory",
				versionsText(c, c.FixedVersions), assetsText(fixed), assetsText(c.Unfixed)))
		case len(c.FixedVersions) > 1:
			to := "the version for each asset's release"
			if c.SourcePackage != "" {
				to = "a build from " + c.SourcePackage + " at the version for each asset's release"
			}
			add("", c, "upgrade to "+to+": "+strings.Join(c.FixedVersions, " / ")+
				" or later (each asset's fixed version is in Stackurity)")
		default:
			add("fix|"+c.SourcePackage+"|"+c.FixedVersions[0], c, "upgrade to "+c.to(c.FixedVersions[0])+" or later")
		}
	}
	if len(lines) == 1 && len(lines[0].comps) == 1 && det.Count <= 1 {
		if c := lines[0].comps[0]; c.Unfixed == 0 && len(c.FixedVersions) == 1 {
			return fmt.Sprintf("Upgrade %s to %s or later (%s)", c.Component, c.to(c.FixedVersions[0]), assetsText(c.Assets)), true
		}
	}
	parts := make([]string, 0, len(lines)+1)
	for _, l := range lines {
		if len(l.comps) == 1 {
			c := l.comps[0]
			if c.Unfixed > 0 && len(c.FixedVersions) > 0 && c.Assets-c.Unfixed > 0 {
				parts = append(parts, c.Component+": "+l.text) // counts are in the text
			} else {
				parts = append(parts, fmt.Sprintf("%s: %s (%s)", c.Component, l.text, assetsText(c.Assets)))
			}
			continue
		}
		names := make([]string, len(l.comps))
		for i, c := range l.comps {
			names[i] = fmt.Sprintf("%s (%s)", c.Component, assetsText(c.Assets))
		}
		parts = append(parts, strings.Join(names, ", ")+": "+l.text)
	}
	if more := det.Count - len(det.Fixes); more > 0 {
		parts = append(parts, fmt.Sprintf("%s more: see the incident", plural(more, "component")))
	}
	return strings.Join(parts, "; "), true
}

// versionsText is one version, or the versions for each release line.
func versionsText(c componentFix, vs []string) string {
	if len(vs) == 1 {
		return c.to(vs[0]) + " or later"
	}
	if c.SourcePackage != "" {
		return "a build from " + c.SourcePackage + " at the version for each asset's release (" + strings.Join(vs, " / ") + " or later)"
	}
	return "the version for each asset's release (" + strings.Join(vs, " / ") + " or later)"
}
