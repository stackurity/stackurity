package osv

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SourceFix is a Debian or Ubuntu fix that is named by the source package's
// version while the installed binary package carries a version of its own.
// telnet 0.17+2.5-3ubuntu4 is built from inetutils 2:2.5-3ubuntu4, and the
// advisory says inetutils 2:2.5-3ubuntu4.1 fixes it: apt cannot install
// "telnet 2:2.5-3ubuntu4.1" (that version of telnet does not exist), so
// advice names the binary package to upgrade and the source version that has
// the fix, never the source version as the binary's target.
type SourceFix struct {
	Binary        string `json:"package"`                  // the installed binary package ("telnet")
	Source        string `json:"source_package"`           // the source package the advisory names ("inetutils")
	SourceVersion string `json:"installed_source_version"` // the source version the binary was built from
	Fixed         string `json:"fixed_source_version,omitempty"`
}

// SourceFixOf reads a SourceFix from a vulnerability finding's evidence.
// The matcher records the source version it compared (evidence
// match.source_version) only when it differs from the binary's own version;
// otherwise the fixed version is also the binary's version and ok is false.
// binary is the component's name, with or without its namespace
// ("ubuntu/telnet"); fixed is the finding's fixed version.
func SourceFixOf(binary string, evidence map[string]any, fixed string) (SourceFix, bool) {
	m, _ := evidence["match"].(map[string]any)
	sv, _ := m["source_version"].(string)
	src, _ := evidence["osv_package"].(string)
	if sv == "" || src == "" {
		return SourceFix{}, false
	}
	if i := strings.LastIndexByte(binary, '/'); i >= 0 {
		binary = binary[i+1:]
	}
	return SourceFix{Binary: binary, Source: src, SourceVersion: sv, Fixed: fixed}, true
}

// SourceFixOfJSON is SourceFixOf for evidence as stored (JSON).
func SourceFixOfJSON(binary string, evidence json.RawMessage, fixed string) (SourceFix, bool) {
	if len(evidence) == 0 {
		return SourceFix{}, false
	}
	var ev map[string]any
	if json.Unmarshal(evidence, &ev) != nil {
		return SourceFix{}, false
	}
	return SourceFixOf(binary, ev, fixed)
}

// Target is what to tell someone to install: "telnet built from inetutils
// 2:2.5-3ubuntu4.1 or later".
func (s SourceFix) Target() string {
	if s.Fixed == "" {
		return s.Binary + " built from a fixed " + s.Source
	}
	return fmt.Sprintf("%s built from %s %s or later", s.Binary, s.Source, s.Fixed)
}

// CheckCommand prints the source version an installed binary package was
// built from.
func (s SourceFix) CheckCommand() string {
	return "dpkg-query -W -f='${source:Version}\\n' " + s.Binary
}

// Advice is the full instruction, for explanations and plans.
func (s SourceFix) Advice() string {
	if s.Fixed == "" {
		return fmt.Sprintf("%s is built from the source package %s (installed %s), which the advisory names; no fixed %s version is listed yet.",
			s.Binary, s.Source, s.SourceVersion, s.Source)
	}
	return fmt.Sprintf("Upgrade the %s package (sudo apt-get install --only-upgrade %s) to a build from %s %s or later. "+
		"The advisory lists versions of the source package %s; %s has a version number of its own, so %s is not a %s version. "+
		"Check the source version installed with: %s",
		s.Binary, s.Binary, s.Source, s.Fixed, s.Source, s.Binary, s.Fixed, s.Binary, s.CheckCommand())
}
