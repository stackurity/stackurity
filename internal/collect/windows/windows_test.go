package windows

import (
	"context"
	"errors"
	"testing"
)

type fakeReg struct{ wowErr error }

func (fakeReg) OSInfo() (map[string]string, error) {
	return map[string]string{"ProductName": "Windows Server 2022 Datacenter", "CurrentBuild": "20348", "UBR": "2227",
		"DisplayVersion": "21H2", "EditionID": "ServerDatacenter"}, nil
}
func (f fakeReg) Uninstall(view string) ([]map[string]string, error) {
	if view == "wow64" {
		if f.wowErr != nil {
			return nil, f.wowErr
		}
		return []map[string]string{{"DisplayName": "7-Zip 23.01", "DisplayVersion": "23.01", "Publisher": "Igor Pavlov"}}, nil
	}
	return []map[string]string{
		{"DisplayName": "Mozilla Firefox (x64 en-US)", "DisplayVersion": "121.0", "Publisher": "Mozilla"},
		{"DisplayName": "Microsoft Visual C++ Runtime", "DisplayVersion": "14.36", "SystemComponent": "1"},
		{"DisplayName": "Security Update for X (KB123)", "ParentKeyName": "X"},
		{"DisplayName": "Legacy Tool"},
		{"DisplayVersion": "1.0"},
	}, nil
}
func (fakeReg) MachineGUID() string { return "6F9619FF-8B86-D011-B42D-00C04FC964FF" }

func TestCollect(t *testing.T) {
	c := &Collector{Reg: fakeReg{}, Version: "t"}
	b, err := c.Collect(context.Background(), "WIN-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Asset.Identifiers[0].Value != "6f9619ff-8b86-d011-b42d-00c04fc964ff" || b.Asset.Attributes["os_version"] != "10.0.20348.2227" {
		t.Errorf("asset = %+v", b.Asset)
	}
	got := map[string]string{}
	for _, o := range b.Observations {
		got[o.Purl] = string(o.Confidence)
	}
	for purl, conf := range map[string]string{
		"pkg:generic/windows@10.0.20348.2227":                     "confirmed",
		"pkg:generic/Mozilla%20Firefox%20%28x64%20en-US%29@121.0": "confirmed",
		"pkg:generic/7-Zip%2023.01@23.01":                         "confirmed",
		"pkg:generic/Legacy%20Tool":                               "unknown",
	} {
		if got[purl] != conf {
			t.Errorf("%s = %q (all %v)", purl, got[purl], got)
		}
	}
	if len(b.Observations) != 4 {
		t.Errorf("system components and updates must be skipped: %v", got)
	}
	if !b.Complete {
		t.Error("expected complete")
	}
	scopes := map[string]string{}
	for _, c := range b.Coverage {
		scopes[c.Scope] = c.Status
	}
	if scopes["windows:user-programs"] != "unsupported" || scopes["registry:uninstall:native"] != "checked" {
		t.Errorf("per-user installs must be reported as not inventoried: %v", scopes)
	}
}

func TestPartialRegistry(t *testing.T) {
	b, err := (&Collector{Reg: fakeReg{wowErr: errors.New("access denied")}}).Collect(context.Background(), "WIN-02")
	if err != nil {
		t.Fatal(err)
	}
	if b.Complete {
		t.Error("a failed registry view must make the batch incomplete")
	}
}
