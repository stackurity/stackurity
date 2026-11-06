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
				versionsText(c.FixedVersions), assetsText(fixed), assetsText(c.Unfixed)))
		case len(c.FixedVersions) > 1:
			add("", c, "upgrade to the version for each asset's release: "+strings.Join(c.FixedVersions, " / ")+
				" or later (each asset's fixed version is in Stackurity)")
		default:
			add("fix|"+c.FixedVersions[0], c, "upgrade to "+c.FixedVersions[0]+" or later")
		}
	}
	if len(lines) == 1 && len(lines[0].comps) == 1 && det.Count <= 1 {
		if c := lines[0].comps[0]; c.Unfixed == 0 && len(c.FixedVersions) == 1 {
			return fmt.Sprintf("Upgrade %s to %s or later (%s)", c.Component, c.FixedVersions[0], assetsText(c.Assets)), true
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
func versionsText(vs []string) string {
	if len(vs) == 1 {
		return vs[0] + " or later"
	}
	return "the version for each asset's release (" + strings.Join(vs, " / ") + " or later)"
}
