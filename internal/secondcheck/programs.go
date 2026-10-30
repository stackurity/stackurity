package secondcheck

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/stackurity/stackurity/internal/winprograms"
)

// The second check's own reading of the curated Windows program catalogue.
// It reads the same document (data, like the advisories) but none of the
// matcher's code: its own JSON fields, its own regular expressions and its
// own version formatting, so a mistake in internal/winprograms' reading of
// a pattern or version rule shows as a disagreement.

type scProgram struct {
	ID         string   `json:"id"`
	Names      []string `json:"names"`
	Exclude    []string `json:"exclude"`
	Publishers []string `json:"publishers"`
	Match      string   `json:"version_match"`
	Version    struct {
		From    string `json:"from"`
		Pattern string `json:"pattern"`
		Format  string `json:"format"`
	} `json:"version"`
	Source *json.RawMessage `json:"source"`
}

type scCatalogue struct {
	programs []scProgram
	err      error
}

var (
	scOnce sync.Once
	scCat  scCatalogue
	scRef  = regexp.MustCompile(`\$([0-9]+)`)
	scNums = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
)

func programCatalogue() scCatalogue {
	scOnce.Do(func() {
		var doc struct {
			Programs []scProgram `json:"programs"`
		}
		scCat.err = json.Unmarshal(winprograms.Embedded(), &doc)
		scCat.programs = doc.Programs
	})
	return scCat
}

// matchAny matches s against case-insensitive patterns, each anchored by
// the second check itself.
func matchAny(patterns []string, s string) (bool, error) {
	for _, p := range patterns {
		re, err := regexp.Compile("(?i)^(?:" + strings.TrimSuffix(strings.TrimPrefix(p, "^"), "$") + ")$")
		if err != nil {
			return false, err
		}
		if re.MatchString(s) {
			return true, nil
		}
	}
	return false, nil
}

// windowsProgram derives the target of an installed Windows program: the
// catalogued program it is, and its version read by the entry's rule.
func windowsProgram(name, version string, ev map[string]string) (eco, id, v string, err error) {
	cat := programCatalogue()
	if cat.err != nil {
		return "", "", "", fmt.Errorf("the Windows program catalogue could not be read by the second check: %v", cat.err)
	}
	name, version = strings.TrimSpace(name), strings.TrimSpace(version)
	pub := strings.TrimSpace(ev["publisher"])
	var hit *scProgram
	for i := range cat.programs {
		p := &cat.programs[i]
		if ex, err := matchAny(p.Exclude, name); err != nil || ex {
			continue
		}
		if ok, err := matchAny(p.Names, name); err != nil || !ok {
			continue
		}
		if pub != "" {
			if ok, err := matchAny(p.Publishers, pub); err != nil || !ok {
				continue
			}
		}
		if p.Match != "" {
			if ok, err := matchAny([]string{p.Match}, version); err != nil || !ok {
				continue
			}
		}
		if hit != nil {
			return "", "", "", fmt.Errorf("%q matches two catalogue entries", name)
		}
		hit = p
	}
	switch {
	case hit == nil:
		return "", "", "", fmt.Errorf("%q is not a catalogued Windows program", name)
	case hit.Source == nil:
		return "", "", "", fmt.Errorf("%s is recognised but not matched", hit.ID)
	}
	in := version
	if hit.Version.From == "display_name" {
		in = name
	}
	re, err := regexp.Compile("(?i)" + hit.Version.Pattern)
	if err != nil {
		return "", "", "", err
	}
	m := re.FindStringSubmatch(in)
	if m == nil {
		return "", "", "", fmt.Errorf("version %q of %s is not in the catalogue's form", in, hit.ID)
	}
	out := scRef.ReplaceAllStringFunc(hit.Version.Format, func(ref string) string {
		var n int
		fmt.Sscanf(ref, "$%d", &n)
		if n < len(m) {
			return m[n]
		}
		return ""
	})
	var parts []string
	for _, x := range strings.Split(out, ".") {
		if x != "" {
			parts = append(parts, x)
		}
	}
	v = strings.Join(parts, ".")
	if !scNums.MatchString(v) {
		return "", "", "", fmt.Errorf("version %q of %s does not read as numbers", in, hit.ID)
	}
	return "Windows programs:" + hit.ID, hit.ID, v, nil
}
