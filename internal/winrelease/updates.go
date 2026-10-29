package winrelease

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Windows updates. Microsoft's Security Update Guide (the MSRC CVRF API)
// lists, for each CVE and product, the update that fixes it and the build it
// brings: "Windows Server 2022" fixed in KB5066782, build 10.0.20348.4294.
// Every edition of a release, its Server Core installation and every
// processor architecture take the same cumulative update and build, so a
// release is one update line: "Server 2022", "10 22H2", "11 24H2". A host is
// missing a fix when its build and update revision (UBR) are below the
// fixed build of its line.

// UpdateTarget is the update line of a host and its build.
type UpdateTarget struct {
	Line    string // "Server 2022", "11 24H2"
	Build   int    // 20348
	UBR     int    // 4294
	Version string // "10.0.20348.4294"
}

// UpdateGap is why a host's updates are not compared: Unsupported when
// Stackurity does not evaluate that kind of host at all (hotpatching, paid
// Extended Security Updates, releases whose builds are not 10.0.x), otherwise
// the data cannot tell (no revision reported, a release that cannot be told).
type UpdateGap struct {
	Reason      string
	Unsupported bool
}

// serverLines are the Windows Server releases (ServerBuilds cycles) whose
// cumulative updates are evaluated, by update line.
var serverLines = map[string]string{
	"2016": "Server 2016", "2019": "Server 2019", "2022": "Server 2022", "2025": "Server 2025",
	"23h2-ac": "Server 23H2",
}

// esuServer are Windows Server releases whose updates are now paid Extended
// Security Updates (or ended), and whose builds Microsoft numbers 6.x.
var esuServer = map[string]string{
	"2008-sp2": "Windows Server 2008 SP2", "2008-r2-sp1": "Windows Server 2008 R2 SP1",
	"2012": "Windows Server 2012", "2012-r2": "Windows Server 2012 R2",
}

// LineBuild returns the build number of an update line.
func LineBuild(line string) (int, bool) {
	if l, ok := strings.CutPrefix(line, "Server "); ok {
		for b, c := range ServerBuilds {
			if serverLines[c] == "Server "+l {
				return b, true
			}
		}
		return 0, false
	}
	for b, v := range ClientBuilds {
		if clientLine(v) == line {
			return b, true
		}
	}
	return 0, false
}

// clientLine turns a ClientBuilds version ("10-22h2", "11-24h2", "10-1809")
// into an update line ("10 22H2"); "" for Windows 7 and 8.x.
func clientLine(v string) string {
	major, rel, ok := strings.Cut(v, "-")
	if !ok || (major != "10" && major != "11") {
		return ""
	}
	return major + " " + strings.ToUpper(rel)
}

// SiblingBuilds share one cumulative update and its revision numbers:
// Windows 10 21H2 and 22H2 (an enablement package on 19041), Windows 11 22H2
// and 23H2, Windows 11 24H2 and 25H2. Microsoft's data sometimes gives a
// sibling's build as a line's fixed build (10.0.19044.6456 for Windows 10
// 22H2); the revision is what counts.
var SiblingBuilds = [][]int{
	{19041, 19042, 19043, 19044, 19045},
	{22621, 22631},
	{26100, 26200},
}

// Siblings reports whether two builds share their cumulative updates.
func Siblings(a, b int) bool {
	if a == b {
		return true
	}
	for _, s := range SiblingBuilds {
		ia, ib := false, false
		for _, x := range s {
			ia, ib = ia || x == a, ib || x == b
		}
		if ia && ib {
			return true
		}
	}
	return false
}

// buildVersion is a Windows 10/11 or Server 2016+ version "10.0.<build>.<ubr>".
var buildVersion = regexp.MustCompile(`^10\.0\.(\d{4,6})\.(\d{1,6})$`)

// ParseBuild reads "10.0.20348.4294" into its build and revision.
func ParseBuild(v string) (build, ubr int, ok bool) {
	m := buildVersion.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return 0, 0, false
	}
	build, _ = strconv.Atoi(m[1])
	ubr, _ = strconv.Atoi(m[2])
	return build, ubr, build > 0
}

// azureEdition is Windows Server Datacenter: Azure Edition, whose monthly
// updates are hotpatches between quarterly baselines.
func azureEdition(name, edition string) bool {
	return strings.Contains(name, "Azure Edition") || strings.HasPrefix(edition, "serverturbine")
}

// UpdateLine returns the update line of a host, or why its updates are not
// compared. The build decides the line, as for end of life (Map); the
// product name and edition tell Server from client.
func UpdateLine(i Info) (UpdateTarget, *UpdateGap) {
	build, ok := Build(i.Version)
	if !ok {
		return UpdateTarget{}, &UpdateGap{Reason: fmt.Sprintf("no Windows build number in version %q", i.Version)}
	}
	name := cleanName(i.ProductName)
	edition := strings.ToLower(strings.TrimSpace(i.EditionID))
	var line string
	switch {
	case serverName.MatchString(name) || (name == "" && strings.HasPrefix(edition, "server") && edition != "serverrdsh" &&
		!strings.HasPrefix(edition, "serverazurestackhci")):
		rel, why := mapServer(build, name)
		if why != "" {
			return UpdateTarget{}, &UpdateGap{Reason: why}
		}
		cycle := rel.Cycles[0]
		if n, ok := esuServer[cycle]; ok {
			return UpdateTarget{}, &UpdateGap{Unsupported: true, Reason: n + ": missing updates are not evaluated (its updates are paid " +
				"Extended Security Updates or have ended, and its builds are numbered 6.x); end of life is tracked"}
		}
		if azureEdition(name, edition) {
			return UpdateTarget{}, &UpdateGap{Unsupported: true, Reason: "Windows Server Datacenter: Azure Edition: missing updates are not " +
				"evaluated, because hotpatched builds do not follow the cumulative update numbering"}
		}
		if line = serverLines[cycle]; line == "" {
			return UpdateTarget{}, &UpdateGap{Reason: fmt.Sprintf("Windows Server build %d (%s, semi-annual channel) has no updates in "+
				"Microsoft's data since it left support", build, cycle)}
		}
	case clientName.MatchString(name):
		v, ok := ClientBuilds[build]
		if !ok {
			return UpdateTarget{}, &UpdateGap{Reason: fmt.Sprintf("Windows client build %d is not a known release", build)}
		}
		if line = clientLine(v); line == "" {
			return UpdateTarget{}, &UpdateGap{Unsupported: true, Reason: fmt.Sprintf("Windows %s: missing updates are not evaluated "+
				"(its builds are numbered 6.x and its updates have ended); end of life is tracked", v)}
		}
		if dv := strings.ToLower(strings.TrimSpace(i.DisplayVersion)); dv != "" && !strings.HasSuffix(v, "-"+dv) {
			return UpdateTarget{}, &UpdateGap{Reason: fmt.Sprintf("%s reports version %s but build %d, which is %s; they disagree",
				name, i.DisplayVersion, build, v)}
		}
	case name == "":
		return UpdateTarget{}, &UpdateGap{Reason: fmt.Sprintf("Windows build %d: no product name, so Windows Server and client cannot be told apart", build)}
	default:
		return UpdateTarget{}, &UpdateGap{Unsupported: true, Reason: fmt.Sprintf("%s (build %d) is not a Windows Server or Windows client "+
			"release whose updates are evaluated", name, build)}
	}
	b, ubr, ok := ParseBuild(i.Version)
	if !ok || b != build {
		return UpdateTarget{}, &UpdateGap{Reason: fmt.Sprintf("version %q has no update revision (UBR), so the installed cumulative "+
			"update is unknown", i.Version)}
	}
	return UpdateTarget{Line: line, Build: build, UBR: ubr, Version: fmt.Sprintf("10.0.%d.%d", build, ubr)}, nil
}

// cvrfProduct reads a Security Update Guide product name: "Windows Server
// 2022", "Windows Server 2022 (Server Core installation)", "Windows Server
// 2022, 23H2 Edition (Server Core installation)", "Windows 11 Version 24H2
// for x64-based Systems", "Windows 10 for 32-bit Systems" (1507).
var (
	cvrfServer   = regexp.MustCompile(`^Windows Server (\d{4})(?: \(Server Core installation\))?$`)
	cvrfServerAC = regexp.MustCompile(`^Windows Server 2022, (\d\dH\d) Edition(?: \(Server Core installation\))?$`)
	cvrfClient   = regexp.MustCompile(`^Windows (10|11) [Vv]ersion (\w+) for (?:x64|ARM64|32-bit)(?:-based)? Systems$`)
	cvrfWin10RTM = regexp.MustCompile(`^Windows 10 for (?:x64|32-bit)(?:-based)? Systems$`)
)

// CVRFLine returns the update line of a Security Update Guide product name,
// or "" for any other product (applications, components, Windows releases
// whose updates are not evaluated, and products "on" a Windows release such
// as ".NET Framework 4.8 on Windows Server 2022").
func CVRFLine(product string) string {
	var line string
	switch p := strings.TrimSpace(product); {
	case cvrfServer.MatchString(p):
		line = "Server " + cvrfServer.FindStringSubmatch(p)[1]
	case cvrfServerAC.MatchString(p):
		line = "Server " + strings.ToUpper(cvrfServerAC.FindStringSubmatch(p)[1])
	case cvrfClient.MatchString(p):
		m := cvrfClient.FindStringSubmatch(p)
		line = m[1] + " " + strings.ToUpper(m[2])
	case cvrfWin10RTM.MatchString(p):
		line = "10 1507"
	}
	if _, ok := LineBuild(line); !ok {
		return ""
	}
	return line
}
