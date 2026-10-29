package winrelease

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestServerBuilds(t *testing.T) {
	for _, c := range []struct {
		info  Info
		cycle string
	}{
		{Info{Version: "10.0.6003.22000", ProductName: "Windows Server® 2008 Standard"}, "2008-sp2"},
		{Info{Version: "10.0.6002", ProductName: "Windows Server (R) 2008 Enterprise"}, "2008-sp2"},
		{Info{Version: "10.0.7601.24000", ProductName: "Windows Server 2008 R2 Enterprise"}, "2008-r2-sp1"},
		{Info{Version: "10.0.9200", ProductName: "Windows Server 2012 Standard"}, "2012"},
		{Info{Version: "10.0.9600.21000", ProductName: "Windows Server 2012 R2 Datacenter", EditionID: "ServerDatacenter"}, "2012-r2"},
		{Info{Version: "10.0.14393.7428", ProductName: "Windows Server 2016 Datacenter", EditionID: "ServerDatacenter"}, "2016"},
		{Info{Version: "10.0.14393.7428", ProductName: "Windows Server 2016 Standard", EditionID: "ServerStandard"}, "2016"},
		{Info{Version: "10.0.14393.7428", ProductName: "Windows Server 2016 Essentials", EditionID: "ServerSolution"}, "2016"},
		{Info{Version: "10.0.16299.1", ProductName: "Windows Server Datacenter", EditionID: "ServerDatacenterACor"}, "1709-sac"},
		{Info{Version: "10.0.17134.1", ProductName: "Windows Server Standard", EditionID: "ServerStandardACor"}, "1803-sac"},
		{Info{Version: "10.0.17763.6532", ProductName: "Windows Server 2019 Datacenter", EditionID: "ServerDatacenter"}, "2019"},
		{Info{Version: "10.0.17763.6532", ProductName: "Windows Server 2019 Standard Evaluation", EditionID: "ServerStandardEval"}, "2019"},
		{Info{Version: "10.0.17763.1", ProductName: "Windows Server Datacenter", EditionID: "ServerDatacenterACor"}, "1809-sac"},
		{Info{Version: "10.0.18362.1", ProductName: "Windows Server Datacenter"}, "1903-sac"},
		{Info{Version: "10.0.18363.1", ProductName: "Windows Server Standard"}, "1909-sac"},
		{Info{Version: "10.0.19041.1", ProductName: "Windows Server Datacenter"}, "2004-sac"},
		{Info{Version: "10.0.19042.1", ProductName: "Windows Server Datacenter"}, "20h2-sac"},
		{Info{Version: "10.0.20348.2227", ProductName: "Windows Server 2022 Datacenter", EditionID: "ServerDatacenter", DisplayVersion: "21H2"}, "2022"},
		{Info{Version: "10.0.20348.2227", ProductName: "Windows Server 2022 Datacenter: Azure Edition", EditionID: "ServerTurbine"}, "2022"},
		{Info{Version: "10.0.25398.1", ProductName: "Windows Server Datacenter", DisplayVersion: "23H2"}, "23h2-ac"},
		{Info{Version: "10.0.26100.2033", ProductName: "Windows Server 2025 Standard", EditionID: "ServerStandard", DisplayVersion: "24H2"}, "2025"},
		// Agents report no product name only if the registry lacks it: the
		// edition still says Server.
		{Info{Version: "10.0.14393", EditionID: "ServerStandard"}, "2016"},
	} {
		rel, why := Map(c.info)
		if why != "" || rel.Product != ProductServer || !slices.Equal(rel.Cycles, []string{c.cycle}) {
			t.Errorf("%+v = %+v %q, want windows-server %s", c.info, rel, why, c.cycle)
		}
	}
}

func TestClientBuilds(t *testing.T) {
	for _, c := range []struct {
		info   Info
		cycles []string
	}{
		{Info{Version: "10.0.7601", ProductName: "Windows 7 Professional"}, []string{"7-sp1"}},
		{Info{Version: "10.0.9200", ProductName: "Windows 8 Pro"}, []string{"8"}},
		{Info{Version: "10.0.9600", ProductName: "Windows 8.1 Pro"}, []string{"8.1"}},
		{Info{Version: "10.0.10240", ProductName: "Windows 10 Enterprise 2015 LTSB", EditionID: "EnterpriseS"}, []string{"10-1507-e-lts"}},
		{Info{Version: "10.0.14393.1", ProductName: "Windows 10 Enterprise 2016 LTSB", EditionID: "EnterpriseS"}, []string{"10-1607-e-lts"}},
		{Info{Version: "10.0.17763.1", ProductName: "Windows 10 Enterprise LTSC 2019", EditionID: "EnterpriseS"}, []string{"10-1809-e-lts"}},
		{Info{Version: "10.0.19044.5011", ProductName: "Windows 10 IoT Enterprise LTSC 2021", EditionID: "IoTEnterpriseS", DisplayVersion: "21H2"}, []string{"10-21h2-iot-lts"}},
		{Info{Version: "10.0.19045.5011", ProductName: "Windows 10 Pro", EditionID: "Professional", DisplayVersion: "22H2"}, []string{"10-22h2-w", "10-22h2"}},
		{Info{Version: "10.0.19045.5011", ProductName: "Windows 10 Enterprise", EditionID: "Enterprise", DisplayVersion: "22H2"}, []string{"10-22h2-e", "10-22h2"}},
		// Windows 11 still calls itself "Windows 10" in ProductName.
		{Info{Version: "10.0.22631.4317", ProductName: "Windows 10 Pro", EditionID: "Professional", DisplayVersion: "23H2"}, []string{"11-23h2-w", "11-23h2"}},
		{Info{Version: "10.0.22631.4317", ProductName: "Windows 10 Education", EditionID: "Education", DisplayVersion: "23H2"}, []string{"11-23h2-e", "11-23h2"}},
		{Info{Version: "10.0.22631.4317", ProductName: "Windows 10 Enterprise multi-session", EditionID: "ServerRdsh", DisplayVersion: "23H2"}, []string{"11-23h2-e", "11-23h2"}},
		{Info{Version: "10.0.26100.2033", ProductName: "Windows 10 Pro Education", EditionID: "ProfessionalEducation", DisplayVersion: "24H2"}, []string{"11-24h2-w", "11-24h2"}},
		{Info{Version: "10.0.26100.1", ProductName: "Windows 11 Enterprise LTSC 2024", EditionID: "EnterpriseS", DisplayVersion: "24H2"}, []string{"11-24h2-e-lts"}},
		// Older agents send no EditionID: the product name decides.
		{Info{Version: "10.0.22000.1", ProductName: "Windows 10 Home", DisplayVersion: "21H2"}, []string{"11-21h2-w", "11-21h2"}},
		{Info{Version: "10.0.19044.1", ProductName: "Windows 10 Enterprise LTSC 2021", DisplayVersion: "21H2"}, []string{"10-21h2-e-lts"}},
		{Info{Version: "10.0.19044.1", ProductName: "Windows 10 Pro for Workstations", DisplayVersion: "21H2"}, []string{"10-21h2-w", "10-21h2"}},
	} {
		rel, why := Map(c.info)
		if why != "" || rel.Product != ProductClient || !slices.Equal(rel.Cycles, c.cycles) {
			t.Errorf("%+v = %+v %q, want windows %v", c.info, rel, why, c.cycles)
		}
	}
}

// Anything the build and name do not decide is a reason, never a release.
func TestUnknown(t *testing.T) {
	for _, info := range []Info{
		{Version: "10.0.99999", ProductName: "Windows Server 2028 Datacenter"},      // unknown build
		{Version: "10.0.27000", ProductName: "Windows Server Datacenter"},           // unknown build
		{Version: "10.0.3790", ProductName: "Windows Server 2003 Standard Edition"}, // RTM, SP1 or SP2
		{Version: "10.0.7600", ProductName: "Windows Server 2008 R2 Standard"},      // R2 without SP1
		{Version: "10.0.17763", EditionID: "ServerDatacenter"},                      // 2019 or 1809 SAC
		{Version: "10.0.14393", ProductName: "Windows Server 2019 Datacenter"},      // name and build disagree
		{Version: "10.0.18363", ProductName: "Windows Server 2019 Standard"},        // year on a channel build
		{Version: "10.0.20348", ProductName: "Azure Stack HCI", EditionID: "ServerAzureStackHCICor"},
		{Version: "10.0.17763", ProductName: "Hyper-V Server 2019", EditionID: "ServerHyperCore"},
		{Version: "10.0.20348", EditionID: "ServerAzureStackHCICor"}, // no name, HCI edition
		{Version: "10.0.14393"}, // Server 2016 or Windows 10 1607
		{Version: "10.0.19045", ProductName: "Windows 10 Pro", EditionID: "Professional", DisplayVersion: "21H2"}, // version and build disagree
		{Version: "10.0.19045", ProductName: "Windows 10 Something", EditionID: "Starter"},                        // unknown edition
		{Version: "10.0.19045", ProductName: "Windows 10 Something"},                                              // edition not in the name
		{Version: "10.0.29999", ProductName: "Windows 11 Pro", EditionID: "Professional"},                         // client build not in the table
		{Version: "", ProductName: "Windows Server 2016 Standard"},
		{Version: "10.0", ProductName: "Windows Server 2016 Standard"},
	} {
		if rel, why := Map(info); why == "" || rel.Product != "" {
			t.Errorf("%+v = %+v, want a reason", info, rel)
		}
	}
}

type eolProduct struct {
	Name     string `json:"name"`
	Releases []struct {
		Name   string `json:"name"`
		Label  string `json:"label"`
		Latest *struct {
			Name string `json:"name"`
		} `json:"latest"`
	} `json:"releases"`
}

func loadEOL(t *testing.T, product string) map[string]string {
	t.Helper()
	b, err := os.ReadFile("testdata/endoflife-" + product + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var p eolProduct
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	builds := map[string]string{} // cycle -> latest build
	for _, r := range p.Releases {
		b := ""
		if r.Latest != nil {
			if f := strings.Split(r.Latest.Name, "."); len(f) >= 3 {
				b = f[2]
			}
		}
		builds[r.Name] = b
	}
	return builds
}

// The tables agree with endoflife.date (testdata is
// https://endoflife.date/api/v1/products/windows-server and .../windows,
// fetched 2026-10-28): every mapped cycle exists and lists the same build.
func TestTablesMatchEndOfLifeDate(t *testing.T) {
	server := loadEOL(t, ProductServer)
	for build, cycle := range ServerBuilds {
		got, ok := server[cycle]
		if !ok {
			t.Errorf("windows-server has no cycle %s (build %d)", cycle, build)
			continue
		}
		if b := itoa(build); got != b && !(cycle == "2008-sp2" && build == 6002) {
			t.Errorf("windows-server %s lists build %s, table says %s", cycle, got, b)
		}
	}
	client := loadEOL(t, ProductClient)
	for build, ver := range ClientBuilds {
		n := 0
		for cycle, b := range client {
			if cycle == ver || strings.HasPrefix(cycle, ver+"-") {
				n++
				if b != itoa(build) {
					t.Errorf("windows %s lists build %s, table says %d", cycle, b, build)
				}
			}
		}
		if n == 0 {
			t.Errorf("windows has no cycle for %s (build %d)", ver, build)
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestSubject(t *testing.T) {
	for _, c := range []struct{ product, cycle, label, want string }{
		{ProductServer, "2016", "Windows Server 2016 (LTSC)", "Windows Server 2016"},
		{ProductServer, "2012-r2", "Windows Server 2012 R2 (LTSC)", "Windows Server 2012 R2"},
		{ProductServer, "1809-sac", "Windows Server 1809 SAC", "Windows Server 1809 SAC"},
		{ProductServer, "2016", "", "Windows Server 2016"},
		{ProductClient, "11-23h2-e", "11 23H2 (E)", "Windows 11 23H2 (E)"},
		{ProductClient, "7-sp1", "7 SP1", "Windows 7 SP1"},
	} {
		if got := Subject(c.product, c.cycle, c.label); got != c.want {
			t.Errorf("Subject(%s %s %q) = %q, want %q", c.product, c.cycle, c.label, got, c.want)
		}
	}
}
