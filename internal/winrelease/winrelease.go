// Package winrelease maps what the Windows agent reports about a host's
// operating system to an endoflife.date release: product windows-server
// (cycles "2016", "2012-r2", "1809-sac") or windows (cycles "10-22h2",
// "11-23h2-e", "10-1809-e-lts").
//
// The build number (CurrentBuild) decides the release. The product name and
// edition only tell Server from client and pick between releases that share
// a build: Windows Server 2019 and Windows Server 1809 (semi-annual channel)
// are both build 17763, Windows 11 24H2 Home and Enterprise both 26100. Every
// rule that cannot decide returns a reason instead of a guess, so the host is
// reported as a coverage gap rather than as supported.
package winrelease

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Products on endoflife.date.
const (
	ProductServer = "windows-server"
	ProductClient = "windows"
)

// Info is the operating system as the Windows agent reports it.
type Info struct {
	Version        string // "10.0.14393.7428": the agent's "10.0.<CurrentBuild>.<UBR>"
	ProductName    string // "Windows Server 2016 Datacenter"
	EditionID      string // "ServerDatacenter"; empty from older agents
	DisplayVersion string // "22H2"; empty before Windows 10 20H2
}

// Release is the endoflife.date release line for a host. Cycles lists the
// candidate cycle names in order of preference; the first one present in the
// lifecycle data is the release (client releases are split by edition only
// for some versions, e.g. "10-22h2" covers every edition).
type Release struct {
	Product string
	Cycles  []string
}

// ServerBuilds maps Windows Server build numbers to endoflife.date
// windows-server cycles. Build 17763 is Windows Server 2019 (LTSC) or 1809
// (semi-annual channel); see Map. Windows Server 2003 (build 3790 for RTM,
// SP1 and SP2) and 2008 R2 without SP1 (7600) are not listed: the build does
// not name one release.
var ServerBuilds = map[int]string{
	6002:  "2008-sp2",
	6003:  "2008-sp2", // build after the 2019 servicing update
	7601:  "2008-r2-sp1",
	9200:  "2012",
	9600:  "2012-r2",
	14393: "2016",
	16299: "1709-sac",
	17134: "1803-sac",
	17763: "2019",
	18362: "1903-sac",
	18363: "1909-sac",
	19041: "2004-sac",
	19042: "20h2-sac",
	20348: "2022",
	25398: "23h2-ac",
	26100: "2025",
}

// serverYear is the year (and " R2") a long-term servicing release's product
// name carries. Semi-annual and annual channel releases have none
// ("Windows Server Datacenter").
var serverYear = map[string]string{
	"2008-sp2": "2008", "2008-r2-sp1": "2008 R2", "2012": "2012", "2012-r2": "2012 R2",
	"2016": "2016", "2019": "2019", "2022": "2022", "2025": "2025",
}

// ClientBuilds maps Windows client build numbers to the version part of an
// endoflife.date windows cycle ("10-22h2"); the edition suffix comes from the
// edition. Windows 7 SP1, 8 and 8.1 have one cycle for every edition.
var ClientBuilds = map[int]string{
	7601:  "7-sp1",
	9200:  "8",
	9600:  "8.1",
	10240: "10-1507",
	10586: "10-1511",
	14393: "10-1607",
	15063: "10-1703",
	16299: "10-1709",
	17134: "10-1803",
	17763: "10-1809",
	18362: "10-1903",
	18363: "10-1909",
	19041: "10-2004",
	19042: "10-20h2",
	19043: "10-21h1",
	19044: "10-21h2",
	19045: "10-22h2",
	22000: "11-21h2",
	22621: "11-22h2",
	22631: "11-23h2",
	26100: "11-24h2",
	26200: "11-25h2",
	26300: "11-26h2",
	28000: "11-26h1", // new devices only
}

// Edition classes of Windows client: endoflife.date splits Home/Pro ("w"),
// Enterprise/Education ("e"), Enterprise LTSC ("e-lts") and IoT Enterprise
// LTSC ("iot-lts"), which have different end dates.
const (
	classW      = "w"
	classE      = "e"
	classELTS   = "e-lts"
	classIoTLTS = "iot-lts"
)

var editionClass = map[string]string{
	"core": classW, "coren": classW, "coresinglelanguage": classW, "corecountryspecific": classW,
	"professional": classW, "professionaln": classW, "professionaleducation": classW, "professionaleducationn": classW,
	"professionalworkstation": classW, "professionalworkstationn": classW,
	"enterprise": classE, "enterprisen": classE, "education": classE, "educationn": classE,
	"iotenterprise": classE, "serverrdsh": classE, // Enterprise multi-session
	"enterprises": classELTS, "enterprisesn": classELTS,
	"iotenterprises": classIoTLTS, "iotenterprisesk": classIoTLTS,
}

var (
	serverName = regexp.MustCompile(`^Windows Server(?: (\d{4})(?: (R2))?)?\b`)
	clientName = regexp.MustCompile(`^Windows (?:7|8|8\.1|10|11)\b`)
)

// Build returns the build number in an agent version "10.0.14393.7428".
func Build(version string) (int, bool) {
	parts := strings.Split(version, ".")
	if len(parts) < 3 {
		return 0, false
	}
	b, err := strconv.Atoi(parts[2])
	return b, err == nil && b > 0
}

// cleanName drops the trademark signs Windows Server 2008 puts in its name
// ("Windows Server® 2008 Standard").
func cleanName(s string) string {
	s = strings.NewReplacer("®", "", "™", "", "(R)", "", "(TM)", "").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

// Map returns the release for a host, or a reason it cannot tell.
func Map(i Info) (Release, string) {
	build, ok := Build(i.Version)
	if !ok {
		return Release{}, fmt.Sprintf("no Windows build number in version %q", i.Version)
	}
	name := cleanName(i.ProductName)
	edition := strings.ToLower(strings.TrimSpace(i.EditionID))
	switch {
	case serverName.MatchString(name):
		return mapServer(build, name)
	case clientName.MatchString(name):
		return mapClient(build, name, edition, i.DisplayVersion)
	case name == "" && strings.HasPrefix(edition, "server") && edition != "serverrdsh" && !strings.HasPrefix(edition, "serverazurestackhci"):
		return mapServer(build, "")
	case name == "":
		return Release{}, fmt.Sprintf("Windows build %d: no product name, so Windows Server and client editions cannot be told apart", build)
	}
	return Release{}, fmt.Sprintf("%s (build %d) is not a Windows Server or Windows client release that endoflife.date tracks", name, build)
}

func mapServer(build int, name string) (Release, string) {
	cycle, ok := ServerBuilds[build]
	if !ok {
		return Release{}, fmt.Sprintf("Windows Server build %d is not a known release", build)
	}
	year := ""
	if m := serverName.FindStringSubmatch(name); m != nil && m[1] != "" {
		year = strings.TrimSpace(m[1] + " " + m[2])
	}
	if build == 17763 {
		// 2019 and 1809 (semi-annual channel) share the build: the
		// long-term release has the year in its name, the channel release
		// does not ("Windows Server Datacenter").
		switch {
		case year == "2019":
			return Release{ProductServer, []string{"2019"}}, ""
		case year == "" && name != "":
			return Release{ProductServer, []string{"1809-sac"}}, ""
		case year == "":
			return Release{}, "Windows Server build 17763 is 2019 or 1809 (semi-annual channel); without the product name it cannot tell which"
		}
	}
	want, ltsc := serverYear[cycle]
	switch {
	case year != "" && !ltsc:
		return Release{}, fmt.Sprintf("%s reports build %d, a semi-annual channel build; the name and build disagree", name, build)
	case year != "" && year != want:
		return Release{}, fmt.Sprintf("%s reports build %d, which is Windows Server %s; the name and build disagree", name, build, want)
	}
	return Release{ProductServer, []string{cycle}}, ""
}

func mapClient(build int, name, edition, displayVersion string) (Release, string) {
	ver, ok := ClientBuilds[build]
	if !ok {
		return Release{}, fmt.Sprintf("Windows client build %d is not a known release", build)
	}
	// Windows 7 SP1, 8 and 8.1: one cycle for every edition.
	if !strings.HasPrefix(ver, "10-") && !strings.HasPrefix(ver, "11-") {
		return Release{ProductClient, []string{ver}}, ""
	}
	if dv := strings.ToLower(strings.TrimSpace(displayVersion)); dv != "" && !strings.HasSuffix(ver, "-"+dv) {
		return Release{}, fmt.Sprintf("%s reports version %s but build %d, which is %s; they disagree", name, displayVersion, build, ver)
	}
	class := editionClass[edition]
	if class == "" && edition == "" {
		class = classFromName(name)
	}
	switch class {
	case "":
		what := "edition " + edition
		if edition == "" {
			what = "the edition"
		}
		return Release{}, fmt.Sprintf("%s (build %d): %s does not tell which support policy applies (Home/Pro, Enterprise/Education or LTSC)", name, build, what)
	case classW, classE:
		// Some versions have one cycle for every edition ("10-22h2").
		return Release{ProductClient, []string{ver + "-" + class, ver}}, ""
	}
	return Release{ProductClient, []string{ver + "-" + class}}, ""
}

// classFromName reads the edition class from the product name, for agents
// that do not report EditionID.
func classFromName(name string) string {
	words := " " + strings.ToLower(name) + " "
	switch {
	case strings.Contains(words, " ltsc") || strings.Contains(words, " ltsb"):
		if strings.Contains(words, " iot ") {
			return classIoTLTS
		}
		return classELTS
	case strings.Contains(words, " pro ") || strings.Contains(words, " home "):
		return classW // includes Pro Education and Pro for Workstations
	case strings.Contains(words, " enterprise ") || strings.Contains(words, " education "):
		return classE
	}
	return ""
}

// Subject names the release in a finding title: "Windows Server 2012 R2",
// "Windows 11 23H2 (E)". label is the endoflife.date cycle label
// ("Windows Server 2012 R2 (LTSC)", "11 23H2 (E)").
func Subject(product, cycle, label string) string {
	if label == "" {
		label = cycle
	}
	switch product {
	case ProductServer:
		label = strings.TrimSuffix(label, " (LTSC)")
		if !strings.HasPrefix(label, "Windows Server") {
			label = "Windows Server " + label
		}
	case ProductClient:
		if !strings.HasPrefix(label, "Windows") {
			label = "Windows " + label
		}
	}
	return label
}
