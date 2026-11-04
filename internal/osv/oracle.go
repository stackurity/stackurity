package osv

import (
	"encoding/json"
	"slices"
	"strings"
)

// OracleConditions is what an Oracle Linux affected entry requires besides
// its version range, read from Oracle's OVAL criteria and stored as the
// entry's ecosystem_specific. Each field is omitted when the criteria do not
// limit the entry that way.
type OracleConditions struct {
	// Arch lists the architectures of the "Oracle Linux arch is ..." tests
	// the entry sits under, when the fix differs by architecture or the
	// package is listed for some architectures only ("aarch64").
	Arch []string `json:"arch,omitempty"`
}

// Empty reports conditions that limit nothing.
func (c OracleConditions) Empty() bool {
	return len(c.Arch) == 0
}

// OracleConditionsOf reads an Oracle Linux entry's conditions; an entry
// stored before they were recorded has none. The caller checks that the
// entry is Oracle Linux's (a stored entry has no package: its ecosystem is
// the row's).
func OracleConditionsOf(a Affected) OracleConditions {
	var c OracleConditions
	if len(a.EcosystemSpecific) == 0 {
		return c
	}
	_ = json.Unmarshal(a.EcosystemSpecific, &c)
	return c
}

// OracleArchApplies reports whether an entry limited to the architectures
// arches applies to a package built for arch (the rpm's own architecture,
// the purl's arch qualifier). Oracle's test checks the host's architecture
// (the oraclelinux-release package's), so a 32-bit x86 package, installed
// alongside the 64-bit ones on an x86_64 host, takes the x86_64 entries. A
// package whose architecture says nothing of the host's (noarch) or is not
// reported, and an entry with no architecture, apply as before.
func OracleArchApplies(arches []string, arch string) bool {
	if len(arches) == 0 {
		return true
	}
	var host []string
	switch strings.ToLower(arch) {
	case "x86_64":
		host = []string{"x86_64"}
	case "i386", "i486", "i586", "i686":
		host = []string{"x86_64", "i686", "i386"}
	case "aarch64":
		host = []string{"aarch64"}
	default:
		return true // noarch, unknown or not reported: the host's architecture is not known
	}
	for _, a := range arches {
		if slices.Contains(host, a) {
			return true
		}
	}
	return false
}
