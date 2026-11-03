package osv

import (
	"strings"
	"testing"
)

func TestWorkaround(t *testing.T) {
	cases := []struct {
		name, details, want string
	}{
		{"ghsa section", "### Impact\nBad things.\n\n### Patches\nNone yet.\n\n### Workarounds\nDo not pass untrusted input to `compile`.\n\nOr disable the plugin.\n\n### References\n- https://example.com",
			"Do not pass untrusted input to `compile`.\n\nOr disable the plugin."},
		{"singular, level 2, last section", "## Details\nx\n## Mitigation\nSet `strict: true`.", "Set `strict: true`."},
		{"bold heading", "Impact...\n\n**Workarounds**\nBlock the endpoint at the proxy.\n\n**References**\nx", "Block the endpoint at the proxy."},
		{"with colon", "### Workarounds:\r\nUpgrade Node.js.\r\n", "Upgrade Node.js."},
		{"says none", "### Workarounds\nThere are no known workarounds.\n### References\nx", ""},
		{"none", "### Workarounds\nNone.\n", ""},
		{"no section", "### Impact\nAll versions.\nWorkarounds are discussed in the issue.", ""},
		{"empty section", "### Workarounds\n\n### References\nx", ""},
	}
	for _, c := range cases {
		if got := Workaround(c.details); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	long := Workaround("### Workarounds\n" + strings.Repeat("é", MaxWorkaround))
	if len(long) > MaxWorkaround+len("…") || !strings.HasSuffix(long, "…") || !strings.HasPrefix(long, "é") {
		t.Errorf("long workaround not clipped at a rune boundary: %d bytes", len(long))
	}
}
