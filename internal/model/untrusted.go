package model

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Scanner and collector output is untrusted: an agent, a plugin, a pack, an
// SBOM or a lockfile in someone's repository can put anything in it. Before a
// batch is stored, Validate cleans its free text and drops values that could
// do harm when rendered or followed.

// MaxShortField bounds labels that are shown in lists and filters
// (environment, provider, region).
const MaxShortField = 256

// cleanText removes NUL and other control characters (keeping tab and line
// breaks) and replaces invalid UTF-8. PostgreSQL rejects NUL in text, so one
// NUL used to fail the whole ingest.
func cleanText(s string) string {
	if utf8.ValidString(s) {
		clean := true
		for _, r := range s {
			if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
				clean = false
				break
			}
		}
		if clean {
			return s
		}
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == utf8.RuneError:
			return '�'
		case r == '\t' || r == '\n' || r == '\r':
			return r
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, strings.ToValidUTF8(s, "�"))
}

// hasControl reports control characters or invalid UTF-8 in an identity
// field (purl, version), which is refused rather than cleaned: cleaning
// would silently change what is matched.
func hasControl(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// linkLike names keys whose values a dashboard may render as a link.
func linkLike(key string) bool {
	k := strings.ToLower(key)
	return strings.Contains(k, "url") || strings.Contains(k, "link") || strings.Contains(k, "homepage") || strings.Contains(k, "href")
}

// UnsafeLink reports a value with a scheme that runs code or reads local
// files when followed (javascript:, data:, vbscript:, file:), however it is
// disguised with case, whitespace or control characters.
func UnsafeLink(v string) bool {
	var b strings.Builder
	for _, r := range v {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(unicode.ToLower(r))
		if b.Len() > 16 {
			break
		}
	}
	s := b.String()
	for _, p := range []string{"javascript:", "data:", "vbscript:", "file:"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// cleanMap cleans keys and values and drops unsafe link values.
func cleanMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		k, v = cleanText(k), cleanText(v)
		if linkLike(k) && UnsafeLink(v) {
			continue
		}
		out[k] = v
	}
	return out
}

// sanitise cleans every free-text field of the batch in place.
func (b *ObservationBatch) sanitise() {
	b.Collector.ID, b.Collector.Version, b.Collector.Method = cleanText(b.Collector.ID), cleanText(b.Collector.Version), cleanText(b.Collector.Method)
	a := &b.Asset
	a.Name, a.Environment, a.Provider, a.Region = cleanText(a.Name), cleanText(a.Environment), cleanText(a.Provider), cleanText(a.Region)
	for i := range a.Identifiers {
		a.Identifiers[i].Scheme, a.Identifiers[i].Value = cleanText(a.Identifiers[i].Scheme), cleanText(a.Identifiers[i].Value)
	}
	a.Attributes = cleanMap(a.Attributes)
	for i := range b.Observations {
		o := &b.Observations[i]
		o.Location, o.Scope = cleanText(o.Location), cleanText(o.Scope)
		o.Evidence = cleanMap(o.Evidence)
	}
	for i := range b.Coverage {
		b.Coverage[i].Scope, b.Coverage[i].Reason = cleanText(b.Coverage[i].Scope), cleanText(b.Coverage[i].Reason)
	}
	for i := range b.Relations {
		for j := range b.Relations[i].To {
			t := &b.Relations[i].To[j]
			t.Scheme, t.Value = cleanText(t.Scheme), cleanText(t.Value)
		}
	}
}

// KeepUsable drops observations the server would refuse (see Usable), so
// one hostile package name or version cannot make the whole batch invalid.
// When any is dropped it says so in coverage and the batch is no longer
// complete, so nothing it left out is marked removed. It returns how many
// were dropped.
func (b *ObservationBatch) KeepUsable() int {
	kept := b.Observations[:0]
	for _, o := range b.Observations {
		if Usable(o) {
			kept = append(kept, o)
		}
	}
	dropped := len(b.Observations) - len(kept)
	b.Observations = kept
	if dropped > 0 {
		b.Cover("invalid-entries", "partial", fmt.Sprintf("%d entries with an invalid, over-long or control-character name or version were left out", dropped))
		b.Complete = false
	}
	return dropped
}
