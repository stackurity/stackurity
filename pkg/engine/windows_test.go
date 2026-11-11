package engine

import (
	"context"
	"runtime"
	"testing"
)

type fakeRegistry struct{}

func (fakeRegistry) OSInfo() (map[string]string, error) {
	return map[string]string{"ProductName": "Windows Server 2022 Datacenter", "CurrentBuild": "20348", "UBR": "2227",
		"DisplayVersion": "21H2", "EditionID": "ServerDatacenter"}, nil
}

func (fakeRegistry) Uninstall(view string) ([]map[string]string, error) {
	if view == "wow64" {
		return []map[string]string{{"DisplayName": "7-Zip 23.01", "DisplayVersion": "23.01", "Publisher": "Igor Pavlov"}}, nil
	}
	return []map[string]string{
		{"DisplayName": "Mozilla Firefox (x64 en-US)", "DisplayVersion": "121.0", "Publisher": "Mozilla"},
		{"DisplayName": "Microsoft Visual C++ Runtime", "DisplayVersion": "14.36", "SystemComponent": "1"},
	}, nil
}

func (fakeRegistry) MachineGUID() string { return "6F9619FF-8B86-D011-B42D-00C04FC964FF" }

// WindowsHost gives the batch the agent's Windows collector uploads: the
// same collector, identifiers (machine GUID first, lower case), OS purl
// and evidence the server's Windows release mapping reads.
func TestWindowsHost(t *testing.T) {
	b, err := WindowsHost(context.Background(), fakeRegistry{}, "WIN-01", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	if b.Collector.ID != "windows-agent" || b.Asset.Kind != "host" || b.Asset.Name != "WIN-01" || len(b.Asset.Identifiers) != 2 ||
		b.Asset.Identifiers[0] != (Identifier{Scheme: "windows-machine-guid", Value: "6f9619ff-8b86-d011-b42d-00c04fc964ff"}) ||
		b.Asset.Identifiers[1] != (Identifier{Scheme: "hostname", Value: "WIN-01"}) {
		t.Errorf("asset = %+v collector %+v", b.Asset, b.Collector)
	}
	osObs := b.Observations[0]
	if osObs.Purl != "pkg:generic/windows@10.0.20348.2227" || osObs.Evidence["product_name"] != "Windows Server 2022 Datacenter" ||
		osObs.Evidence["edition_id"] != "ServerDatacenter" || osObs.Evidence["display_version"] != "21H2" {
		t.Errorf("OS observation = %+v", osObs)
	}
	got := map[string]bool{}
	for _, o := range b.Observations {
		got[o.Purl] = true
	}
	if len(b.Observations) != 3 || !got["pkg:generic/Mozilla%20Firefox%20%28x64%20en-US%29@121.0"] || !got["pkg:generic/7-Zip%2023.01@23.01"] {
		t.Errorf("observations = %v", got)
	}
	if !b.Complete || coverageOf(b, "windows:user-programs").Status != "unsupported" {
		t.Errorf("complete=%v coverage=%+v", b.Complete, b.Coverage)
	}
}

func TestLiveWindowsRegistry(t *testing.T) {
	reg, err := LiveWindowsRegistry()
	if runtime.GOOS == "windows" {
		if err != nil || reg == nil {
			t.Fatalf("live registry: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("the live registry must be unavailable off Windows")
	}
}
