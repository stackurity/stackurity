package registry

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tag is one tag of a repository: the digest it points to and when it was
// pushed, when known (a tag a generic registry was not asked about has
// neither).
type Tag struct {
	Name   string
	Digest string
	Pushed time.Time
}

// Image is one image (a digest) an integration tracks.
type Image struct {
	Repository string    `json:"repository"`
	Digest     string    `json:"digest"`
	Ref        string    `json:"ref"`     // the reference scanned: <repository>@<digest>
	Display    string    `json:"display"` // <repository>:<tag>, the asset's name
	Tags       []string  `json:"tags"`
	Pushed     time.Time `json:"pushed"`
}

func newer(a, b Tag) bool {
	if !a.Pushed.Equal(b.Pushed) {
		return a.Pushed.After(b.Pushed)
	}
	return versionLess(b.Name, a.Name)
}

// Select picks the images of one repository: the digests of its most
// recently pushed tags (RecentTags distinct images) and of the tags that
// match a pattern (at most MaxPatternTags images, most recent first).
// Several tags on one digest are one image, so a re-tag does not add
// one. Tags whose digest is unknown are skipped.
func (s *Selector) Select(tags []Tag) []Image {
	known := make([]Tag, 0, len(tags))
	byDigest := map[string][]string{}
	pushed := map[string]time.Time{}
	for _, t := range tags {
		if t.Digest == "" {
			continue
		}
		known = append(known, t)
		byDigest[t.Digest] = append(byDigest[t.Digest], t.Name)
		if t.Pushed.After(pushed[t.Digest]) {
			pushed[t.Digest] = t.Pushed
		}
	}
	sort.SliceStable(known, func(i, j int) bool { return newer(known[i], known[j]) })
	chosen := map[string]bool{}
	var order []string
	recent := 0
	for _, t := range known {
		if recent >= s.recent {
			break
		}
		if !chosen[t.Digest] {
			chosen[t.Digest] = true
			order = append(order, t.Digest)
			recent++
		}
	}
	patterned := map[string]bool{}
	for _, t := range known {
		if len(patterned) >= MaxPatternTags {
			break
		}
		if !s.PatternTag(t.Name) || patterned[t.Digest] {
			continue
		}
		patterned[t.Digest] = true
		if !chosen[t.Digest] {
			chosen[t.Digest] = true
			order = append(order, t.Digest)
		}
	}
	out := make([]Image, 0, len(order))
	for _, d := range order {
		names := append([]string(nil), byDigest[d]...)
		sort.Slice(names, func(i, j int) bool {
			if (names[i] == "latest") != (names[j] == "latest") {
				return names[j] == "latest"
			}
			return versionLess(names[j], names[i])
		})
		out = append(out, Image{Digest: d, Tags: names, Pushed: pushed[d]})
	}
	return out
}

// Candidates orders the tags of a registry that gives no push times for
// reading their manifests: tags matching a pattern first (at most half of
// MaxInspected), then the rest, highest version first, "latest" before
// all. At most MaxInspected are returned.
func (s *Selector) Candidates(names []string) []string {
	sorted := append([]string(nil), names...)
	sort.Slice(sorted, func(i, j int) bool {
		if (sorted[i] == "latest") != (sorted[j] == "latest") {
			return sorted[i] == "latest"
		}
		return versionLess(sorted[j], sorted[i])
	})
	seen := map[string]bool{}
	var out []string
	for _, n := range sorted {
		if len(out) >= MaxInspected/2 {
			break
		}
		if s.PatternTag(n) {
			seen[n] = true
			out = append(out, n)
		}
	}
	for _, n := range sorted {
		if len(out) >= MaxInspected {
			break
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// versionLess orders tags by their numeric parts (1.10 after 1.9), then
// as text.
func versionLess(a, b string) bool {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	if len(pa) != len(pb) {
		return len(pa) < len(pb)
	}
	return a < b
}

func versionParts(s string) []int {
	s = strings.TrimPrefix(s, "v")
	var out []int
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
		n, err := strconv.Atoi(f)
		if err != nil || len(out) == 4 {
			break
		}
		out = append(out, n)
	}
	return out
}
