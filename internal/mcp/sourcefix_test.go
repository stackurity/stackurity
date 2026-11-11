package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// An assistant reading the telnet finding must not tell anyone to install
// telnet 2:2.5-3ubuntu4.1 (apt has no such version): source_fix says the
// fixed version is inetutils's and what to upgrade. The evidence itself is
// not passed on.
func TestFindingSourceFix(t *testing.T) {
	var fs []finding
	if err := json.Unmarshal([]byte(`[
		{"id":1,"component_name":"ubuntu/telnet","version":"0.17+2.5-3ubuntu4","fixed_version":"2:2.5-3ubuntu4.1",
		 "evidence":{"osv_package":"inetutils","match":{"rule":"range","source_version":"2:2.5-3ubuntu4"}}},
		{"id":2,"component_name":"ubuntu/inetutils-telnetd","version":"2:2.5-3ubuntu4","fixed_version":"2:2.5-3ubuntu4.1",
		 "evidence":{"osv_package":"inetutils","match":{"rule":"range"}}},
		{"id":3,"component_name":"lodash","fixed_version":"4.17.21","evidence":null}]`), &fs); err != nil {
		t.Fatal(err)
	}
	s := fs[0].SourceFix
	if fs[0].ID != 1 || fs[0].FixedVersion != "2:2.5-3ubuntu4.1" || s == nil || s.Package != "telnet" || s.SourcePackage != "inetutils" ||
		s.Installed != "2:2.5-3ubuntu4" || !strings.HasPrefix(s.Action, "upgrade telnet to a build from inetutils 2:2.5-3ubuntu4.1 or later") {
		t.Errorf("telnet %+v %+v", fs[0], s)
	}
	if fs[1].SourceFix != nil || fs[2].SourceFix != nil || fs[2].FixedVersion != "4.17.21" {
		t.Errorf("own versions: %+v %+v", fs[1], fs[2])
	}
	out, _ := json.Marshal(fs[0])
	if strings.Contains(string(out), "evidence") || !strings.Contains(string(out), `"source_fix"`) {
		t.Errorf("encoded %s", out)
	}
}
