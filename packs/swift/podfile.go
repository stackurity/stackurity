package main

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"
	"go.yaml.in/yaml/v3"

	"github.com/stackurity/stackurity/pkg/pack"
)

// podfileLock is the part of Podfile.lock that names what is installed.
type podfileLock struct {
	// PODS entries are "Name (version)" or, with dependencies, a map from
	// that string to them. Subspecs appear as "Name/Subspec (version)".
	Pods         []yaml.Node                  `yaml:"PODS"`
	Dependencies []string                     `yaml:"DEPENDENCIES"`
	SpecRepos    map[string][]string          `yaml:"SPEC REPOS"`
	External     map[string]map[string]string `yaml:"EXTERNAL SOURCES"`
}

var podEntry = regexp.MustCompile(`^(\S+) \(([^)]+)\)$`)

func scanPodfileLock(f pack.File, out *pack.Response) {
	scope := "cocoapods:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	var lock podfileLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		out.Failed(scope, "not a Podfile.lock: "+err.Error())
		return
	}
	if len(lock.Pods) == 0 {
		out.Failed(scope, "no PODS section")
		return
	}
	direct := map[string]bool{}
	for _, d := range lock.Dependencies {
		name, _, _ := strings.Cut(d, " ")
		direct[podRoot(name)] = true
	}
	repo := map[string]string{} // pod -> spec repository
	for r, pods := range lock.SpecRepos {
		for _, p := range pods {
			repo[p] = r
		}
	}
	versions := map[string]string{} // root pod -> version
	bad := 0
	for _, n := range lock.Pods {
		entry := n.Value
		if n.Kind == yaml.MappingNode && len(n.Content) > 0 {
			entry = n.Content[0].Value
		}
		m := podEntry.FindStringSubmatch(strings.TrimSpace(entry))
		if m == nil {
			bad++
			continue
		}
		versions[podRoot(m[1])] = m[2]
	}
	names := make([]string, 0, len(versions))
	for name := range versions {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		ver := versions[name]
		ev := map[string]string{"lockfile": "Podfile.lock"}
		if ext, ok := lock.External[name]; ok {
			switch {
			case ext[":path"] != "":
				continue // a development pod: the project's own code
			case ext[":git"] != "":
				ev["source"] = "git"
				ev["git"] = ext[":git"]
			case ext[":podspec"] != "":
				ev["source"] = "podspec"
			}
		} else if r := repo[name]; r != "" && r != "trunk" {
			ev["spec_repo"] = r
		}
		out.Observations = append(out.Observations, pack.Observation{
			Purl:    packageurl.NewPackageURL("cocoapods", "", name, ver, nil, "").ToString(),
			Version: ver, Location: f.Path, Direct: boolp(direct[name]),
			Confidence: pack.ConfidenceConfirmed, Evidence: ev,
		})
	}
	if bad > 0 {
		out.Partial(scope, fmt.Sprintf("%d PODS %s not \"Name (version)\"", bad, plural(bad, "entry was", "entries were")))
		return
	}
	out.Checked(scope)
}

// podRoot is the pod a subspec belongs to: Firebase/Analytics -> Firebase.
func podRoot(name string) string {
	root, _, _ := strings.Cut(strings.Trim(name, `"`), "/")
	return root
}
