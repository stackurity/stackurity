package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/pkg/pack"
)

// vcpkg has no lock file. A manifest (vcpkg.json) names its ports, and
// vcpkg picks their versions from the registry at builtin-baseline, a commit
// of the vcpkg repository; the pack has no network, so only versions the
// manifest pins with "overrides" are exact. What vcpkg installed is exact:
// every installed port has share/<port>/vcpkg.spdx.json with its version.
//
// There is no purl type for vcpkg ports, so they are pkg:generic/vcpkg/<port>.

type vcpkgManifest struct {
	BuiltinBaseline string            `json:"builtin-baseline"`
	Dependencies    []json.RawMessage `json:"dependencies"`
	Overrides       []vcpkgVersion    `json:"overrides"`
	Features        map[string]struct {
		Dependencies []json.RawMessage `json:"dependencies"`
	} `json:"features"`
}

// vcpkgVersion is an override, or a dependency object. A version is given
// under one of four keys depending on its scheme.
type vcpkgVersion struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	VersionSemver string `json:"version-semver"`
	VersionDate   string `json:"version-date"`
	VersionString string `json:"version-string"`
	PortVersion   *int   `json:"port-version"`
	MinVersion    string `json:"version>="`
}

func (v vcpkgVersion) exact() string {
	for _, s := range []string{v.Version, v.VersionSemver, v.VersionDate, v.VersionString} {
		if s != "" {
			return s
		}
	}
	return ""
}

// splitPortVersion separates vcpkg's "#N" port revision from the upstream
// version: "chromium_7258#2" -> "chromium_7258", "2".
func splitPortVersion(v string) (string, string) {
	base, port, ok := strings.Cut(v, "#")
	if !ok {
		return v, ""
	}
	return base, port
}

func vcpkgPurl(name, ver string) string {
	return packageurl.NewPackageURL("generic", "vcpkg", name, ver, nil, "").ToString()
}

func scanVcpkgManifest(f pack.File, out *pack.Response) {
	scope := "vcpkg:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	var m vcpkgManifest
	if err := json.Unmarshal(data, &m); err != nil {
		out.Failed(scope, "not a vcpkg.json manifest: "+err.Error())
		return
	}
	direct := map[string]bool{}  // dependencies of the manifest itself
	feature := map[string]bool{} // dependencies of optional features only
	readDeps := func(list []json.RawMessage, into map[string]bool) {
		for _, raw := range list {
			var name string
			if json.Unmarshal(raw, &name) != nil {
				var d vcpkgVersion
				if json.Unmarshal(raw, &d) != nil {
					continue
				}
				name = d.Name
			}
			if name != "" {
				into[name] = true
			}
		}
	}
	readDeps(m.Dependencies, direct)
	for _, ft := range m.Features {
		readDeps(ft.Dependencies, feature)
	}
	pinned := map[string]bool{}
	var obs []pack.Observation
	for _, o := range m.Overrides {
		ver := o.exact()
		if o.Name == "" || ver == "" {
			continue
		}
		ver, port := splitPortVersion(ver)
		if o.PortVersion != nil {
			port = strconv.Itoa(*o.PortVersion)
		}
		ev := map[string]string{"manifest": "vcpkg.json", "pinned_by": "overrides"}
		if port != "" && port != "0" {
			ev["port_version"] = port
		}
		conf := pack.ConfidenceConfirmed
		if !direct[o.Name] && !feature[o.Name] {
			// A pin for a port the manifest does not name: used only if
			// something it depends on needs that port.
			conf = pack.ConfidenceInferred
		}
		if feature[o.Name] && !direct[o.Name] {
			ev["feature_only"] = "true"
		}
		obs = append(obs, pack.Observation{Purl: vcpkgPurl(o.Name, ver), Version: ver, Location: f.Path,
			Direct: boolp(direct[o.Name]), Confidence: conf, Evidence: ev})
		pinned[o.Name] = true
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Purl < obs[j].Purl })
	out.Observations = append(out.Observations, obs...)
	unresolved := 0
	for name := range direct {
		if !pinned[name] {
			unresolved++
		}
	}
	if unresolved == 0 {
		out.Checked(scope)
		return
	}
	where := "the vcpkg registry"
	if m.BuiltinBaseline != "" {
		where = "the vcpkg registry at builtin-baseline " + shortSHA(m.BuiltinBaseline)
	}
	out.Partial(scope, fmt.Sprintf("%d %s no exact version here: vcpkg picks %s from %s. Pin them under \"overrides\", or scan the vcpkg_installed directory, whose vcpkg.spdx.json files hold the installed versions",
		unresolved, plural(unresolved, "dependency has", "dependencies have"), plural(unresolved, "it", "them"), where))
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// vcpkgSPDX is the SPDX document vcpkg writes for each installed port.
type vcpkgSPDX struct {
	SPDXVersion string `json:"spdxVersion"`
	Packages    []struct {
		SPDXID      string `json:"SPDXID"`
		Name        string `json:"name"`
		VersionInfo string `json:"versionInfo"`
	} `json:"packages"`
}

func scanVcpkgSPDX(f pack.File, out *pack.Response) {
	scope := "vcpkg:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	var doc vcpkgSPDX
	if err := json.Unmarshal(data, &doc); err != nil || !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		out.Failed(scope, "not an SPDX document written by vcpkg")
		return
	}
	for _, p := range doc.Packages {
		if p.SPDXID != "SPDXRef-port" {
			continue
		}
		ver, port := splitPortVersion(p.VersionInfo)
		if p.Name == "" || ver == "" {
			break
		}
		ev := map[string]string{"installed": "vcpkg.spdx.json"}
		if port != "" && port != "0" {
			ev["port_version"] = port
		}
		out.Observations = append(out.Observations, pack.Observation{Purl: vcpkgPurl(p.Name, ver), Version: ver,
			Location: f.Path, Confidence: pack.ConfidenceConfirmed, Evidence: ev})
		out.Checked(scope)
		return
	}
	out.Failed(scope, "no port package (SPDXRef-port) in the document")
}
