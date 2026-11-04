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
	// SigningKeys are the key ids of the "signed with the Oracle Linux N key"
	// tests next to the entry ("82562ea9ad986da3"): Oracle's advisory
	// describes the builds Oracle signed with them.
	SigningKeys []string `json:"signing_keys,omitempty"`
	// Module is the "Module name:stream is enabled" test the entry sits
	// under ("container-tools:ol8").
	Module string `json:"module,omitempty"`
}

// Empty reports conditions that limit nothing.
func (c OracleConditions) Empty() bool {
	return len(c.Arch) == 0 && len(c.SigningKeys) == 0 && c.Module == ""
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

// SigningKey is the inventory evidence the rpm collector gives for a
// package's signature: the 16-digit id of the key that signed its header
// ("82562ea9ad986da3"), or SigningKeyNone for an unsigned package. It is
// absent when not reported (an older agent, an SBOM).
const (
	SigningKey     = "signing_key"
	SigningKeyNone = "none"
)

// OracleKeyMismatch reports whether a package's signing key (evidence
// SigningKey) is known and is not one of the keys an entry names: the
// package is unsigned or another vendor's build, which Oracle's advisory
// does not describe. An unknown key (no evidence) and an entry naming no
// key never mismatch.
func OracleKeyMismatch(keys []string, installed string) bool {
	if installed == "" || len(keys) == 0 {
		return false
	}
	return !slices.Contains(keys, strings.ToLower(installed))
}

// ModuleStreams reads the enabled module streams a host reports (asset
// attribute dnf_modules, "container-tools:ol8 nodejs:18") as module name to
// stream. nil means not reported (an older agent, a host without dnf
// module state, an SBOM); an empty map means none is enabled.
func ModuleStreams(attr *string) map[string]string {
	if attr == nil {
		return nil
	}
	out := map[string]string{}
	for _, f := range strings.Fields(*attr) {
		if name, stream, ok := strings.Cut(f, ":"); ok && name != "" && stream != "" {
			out[name] = stream
		}
	}
	return out
}

// OtherModuleStream reports an entry for a module stream ("nodejs:20")
// when the host has that module enabled on another stream ("nodejs:18"):
// the entry describes the other stream's packages. With no stream data, or
// the module not enabled at all (a reset module keeps its packages
// installed), the entry applies as before.
func OtherModuleStream(module string, enabled map[string]string) bool {
	if module == "" || enabled == nil {
		return false
	}
	name, stream, ok := strings.Cut(module, ":")
	if !ok {
		return false
	}
	have, on := enabled[name]
	return on && have != stream
}
