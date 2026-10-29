package winrelease

import (
	"strings"
	"testing"
)

func TestUpdateLine(t *testing.T) {
	for _, c := range []struct {
		info    Info
		line    string
		version string
	}{
		{Info{Version: "10.0.14393.7428", ProductName: "Windows Server 2016 Datacenter", EditionID: "ServerDatacenter"}, "Server 2016", "10.0.14393.7428"},
		{Info{Version: "10.0.17763.6532", ProductName: "Windows Server 2019 Standard", EditionID: "ServerStandard"}, "Server 2019", "10.0.17763.6532"},
		{Info{Version: "10.0.20348.887", ProductName: "Windows Server 2022 Datacenter", EditionID: "ServerDatacenterCor", DisplayVersion: "21H2"}, "Server 2022", "10.0.20348.887"},
		{Info{Version: "10.0.25398.1913", ProductName: "Windows Server Datacenter", EditionID: "ServerDatacenterACor", DisplayVersion: "23H2"}, "Server 23H2", "10.0.25398.1913"},
		{Info{Version: "10.0.26100.6899", ProductName: "Windows Server 2025 Standard", EditionID: "ServerStandard", DisplayVersion: "24H2"}, "Server 2025", "10.0.26100.6899"},
		// No product name: the edition still says Server.
		{Info{Version: "10.0.20348.100", EditionID: "ServerStandard"}, "Server 2022", "10.0.20348.100"},
		// Windows 11 calls itself "Windows 10" in ProductName: the build decides.
		{Info{Version: "10.0.26100.6584", ProductName: "Windows 10 Pro", EditionID: "Professional", DisplayVersion: "24H2"}, "11 24H2", "10.0.26100.6584"},
		{Info{Version: "10.0.26200.6899", ProductName: "Windows 10 Enterprise", EditionID: "Enterprise", DisplayVersion: "25H2"}, "11 25H2", "10.0.26200.6899"},
		{Info{Version: "10.0.22631.4317", ProductName: "Windows 10 Enterprise", EditionID: "Enterprise", DisplayVersion: "23H2"}, "11 23H2", "10.0.22631.4317"},
		{Info{Version: "10.0.19045.5011", ProductName: "Windows 10 Pro", EditionID: "Professional", DisplayVersion: "22H2"}, "10 22H2", "10.0.19045.5011"},
		{Info{Version: "10.0.19044.5011", ProductName: "Windows 10 IoT Enterprise LTSC 2021", EditionID: "IoTEnterpriseS", DisplayVersion: "21H2"}, "10 21H2", "10.0.19044.5011"},
		{Info{Version: "10.0.17763.6532", ProductName: "Windows 10 Enterprise LTSC 2019", EditionID: "EnterpriseS"}, "10 1809", "10.0.17763.6532"},
		{Info{Version: "10.0.14393.7428", ProductName: "Windows 10 Enterprise 2016 LTSB", EditionID: "EnterpriseS"}, "10 1607", "10.0.14393.7428"},
		// An edition endoflife.date's tables do not know does not matter:
		// every edition takes the same update.
		{Info{Version: "10.0.19045.5011", ProductName: "Windows 10 Pro", EditionID: "SomethingNew"}, "10 22H2", "10.0.19045.5011"},
	} {
		got, gap := UpdateLine(c.info)
		if gap != nil || got.Line != c.line || got.Version != c.version {
			t.Errorf("%+v = %+v %+v; want %s %s", c.info, got, gap, c.line, c.version)
		}
	}
}

func TestUpdateLineGaps(t *testing.T) {
	for _, c := range []struct {
		info        Info
		unsupported bool
		reason      string
	}{
		{Info{Version: "10.0.9600.21620", ProductName: "Windows Server 2012 R2 Standard"}, true, "Extended Security Updates"},
		{Info{Version: "10.0.9200.24000", ProductName: "Windows Server 2012 Datacenter"}, true, "Extended Security Updates"},
		{Info{Version: "10.0.7601.24000", ProductName: "Windows Server 2008 R2 Enterprise"}, true, "Extended Security Updates"},
		{Info{Version: "10.0.20348.2227", ProductName: "Windows Server 2022 Datacenter: Azure Edition", EditionID: "ServerTurbine"}, true, "hotpatch"},
		{Info{Version: "10.0.20348.2227", EditionID: "ServerTurbineCor"}, true, "hotpatch"},
		{Info{Version: "10.0.7601.24000", ProductName: "Windows 7 Professional"}, true, "updates have ended"},
		{Info{Version: "10.0.9600.20000", ProductName: "Windows 8.1 Pro"}, true, "updates have ended"},
		{Info{Version: "10.0.20348.1", ProductName: "Azure Stack HCI"}, true, "not a Windows Server or Windows client release"},
		// Semi-annual channel Server: ended, no data.
		{Info{Version: "10.0.17763.1577", ProductName: "Windows Server Datacenter", EditionID: "ServerDatacenterACor"}, false, "semi-annual channel"},
		{Info{Version: "10.0.20348", ProductName: "Windows Server 2022 Datacenter"}, false, "no update revision"},
		{Info{Version: "10.0.19045.5011", ProductName: "Windows 10 Pro", DisplayVersion: "21H2"}, false, "disagree"},
		{Info{Version: "10.0.20348.1", ProductName: "Windows Server 2019 Standard"}, false, "disagree"},
		{Info{Version: "10.0.27000.1", ProductName: "Windows 11 Pro"}, false, "not a known release"},
		{Info{Version: "10.0.20348.1"}, false, "cannot be told apart"},
		{Info{Version: "windows"}, false, "no Windows build number"},
	} {
		_, gap := UpdateLine(c.info)
		if gap == nil || gap.Unsupported != c.unsupported || !strings.Contains(gap.Reason, c.reason) {
			t.Errorf("%+v = %+v; want unsupported=%v and %q", c.info, gap, c.unsupported, c.reason)
		}
	}
}

// Product names as Microsoft's Security Update Guide writes them.
func TestCVRFLine(t *testing.T) {
	for name, line := range map[string]string{
		"Windows Server 2016":                                                  "Server 2016",
		"Windows Server 2016 (Server Core installation)":                       "Server 2016",
		"Windows Server 2019":                                                  "Server 2019",
		"Windows Server 2022 (Server Core installation)":                       "Server 2022",
		"Windows Server 2022, 23H2 Edition (Server Core installation)":         "Server 23H2",
		"Windows Server 2025":                                                  "Server 2025",
		"Windows 10 for x64-based Systems":                                     "10 1507",
		"Windows 10 for 32-bit Systems":                                        "10 1507",
		"Windows 10 Version 1607 for x64-based Systems":                        "10 1607",
		"Windows 10 Version 1809 for 32-bit Systems":                           "10 1809",
		"Windows 10 Version 21H2 for ARM64-based Systems":                      "10 21H2",
		"Windows 10 Version 22H2 for x64-based Systems":                        "10 22H2",
		"Windows 11 Version 23H2 for x64-based Systems":                        "11 23H2",
		"Windows 11 Version 24H2 for ARM64-based Systems":                      "11 24H2",
		"Windows 11 version 26H1 for x64-based Systems":                        "11 26H1", // lower-case "version" in the data
		"Windows Server 2012 R2":                                               "",        // 6.3 builds, paid updates
		"Windows Server 2012 (Server Core installation)":                       "",
		"Windows Server 2008 R2 for x64-based Systems Service Pack 1":          "",
		"Microsoft .NET Framework 3.5 AND 4.8.1 on Windows Server 2022":        "",
		"Raw Image Extension on Windows 11 Version 24H2 for x64-based Systems": "",
		"Windows 11 Version 24H2 for x64-based Systems and Hotpatch":           "",
		"Windows Defender":                                                     "",
		"Windows 10 Version 9999 for x64-based Systems":                        "", // no such release
	} {
		if got := CVRFLine(name); got != line {
			t.Errorf("CVRFLine(%q) = %q, want %q", name, got, line)
		}
	}
}

func TestSiblingsAndBuilds(t *testing.T) {
	for _, c := range []struct {
		a, b int
		want bool
	}{
		{19045, 19044, true}, {19044, 19043, true}, {22621, 22631, true}, {26100, 26200, true},
		{26100, 26100, true}, {20348, 17763, false}, {26200, 28000, false}, {14393, 17763, false},
	} {
		if got := Siblings(c.a, c.b); got != c.want {
			t.Errorf("Siblings(%d, %d) = %v", c.a, c.b, got)
		}
	}
	for line, build := range map[string]int{"Server 2016": 14393, "Server 23H2": 25398, "Server 2025": 26100, "10 22H2": 19045,
		"11 24H2": 26100, "10 1507": 10240} {
		if b, ok := LineBuild(line); !ok || b != build {
			t.Errorf("LineBuild(%q) = %d %v", line, b, ok)
		}
	}
	if _, ok := LineBuild("Server 2012 R2"); ok {
		t.Error("Server 2012 R2 is not an update line")
	}
	if b, u, ok := ParseBuild("10.0.20348.4294"); !ok || b != 20348 || u != 4294 {
		t.Errorf("ParseBuild = %d %d %v", b, u, ok)
	}
	for _, bad := range []string{"6.3.9600.22824", "10.0.20348", "10.0.20348.4294.1", "1.000", ""} {
		if _, _, ok := ParseBuild(bad); ok {
			t.Errorf("ParseBuild(%q) accepted", bad)
		}
	}
}
