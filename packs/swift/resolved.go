package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/pkg/pack"
)

// resolvedFile is Package.resolved in all three formats. Format 1 (Swift
// 5.5 and earlier) keeps its pins under "object" and names the repository
// "repositoryURL"; formats 2 (Swift 5.6) and 3 (Swift 5.9, which adds
// originHash) list them at the top level with "identity", "kind" and
// "location".
type resolvedFile struct {
	Version int `json:"version"`
	Object  *struct {
		Pins []resolvedPin `json:"pins"`
	} `json:"object"`
	Pins []resolvedPin `json:"pins"`
}

type resolvedPin struct {
	// Format 1.
	Package       string `json:"package"`
	RepositoryURL string `json:"repositoryURL"`
	// Formats 2 and 3.
	Identity string `json:"identity"`
	Kind     string `json:"kind"` // remoteSourceControl, localSourceControl, registry
	Location string `json:"location"`
	// Set by registries that mirror a source repository (Tuist, Swift 6).
	OriginalLocation string `json:"originalLocation"`
	State            struct {
		Branch   *string `json:"branch"`
		Revision string  `json:"revision"`
		Version  *string `json:"version"`
	} `json:"state"`
}

func scanResolved(f pack.File, out *pack.Response) {
	scope := "swift:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	var rf resolvedFile
	if err := json.Unmarshal(data, &rf); err != nil {
		out.Failed(scope, "not a Package.resolved file: "+err.Error())
		return
	}
	pins := rf.Pins
	if rf.Object != nil {
		pins = append(pins, rf.Object.Pins...)
	}
	if len(pins) == 0 && rf.Version > 3 {
		out.Failed(scope, fmt.Sprintf("Package.resolved format %d is not understood", rf.Version))
		return
	}
	unpinned := 0
	seen := map[string]bool{}
	for _, p := range pins {
		if p.Kind == "localSourceControl" || p.Kind == "fileSystem" {
			continue // the project's own code
		}
		ver := ""
		if p.State.Version != nil {
			ver = strings.TrimSpace(*p.State.Version)
		}
		if ver == "" {
			unpinned++ // a branch or a commit: no released version to check
			continue
		}
		purl, ev, ok := swiftPurl(p, ver)
		if !ok {
			unpinned++
			continue
		}
		if seen[purl] {
			continue
		}
		seen[purl] = true
		ev["lockfile"] = "Package.resolved"
		out.Observations = append(out.Observations, pack.Observation{
			Purl: purl, Version: ver, Location: f.Path, Confidence: pack.ConfidenceConfirmed, Evidence: ev,
		})
	}
	if unpinned > 0 {
		out.Partial(scope, fmt.Sprintf("%d %s pinned to a branch or a commit, not a version, and could not be checked",
			unpinned, plural(unpinned, "package is", "packages are")))
		return
	}
	out.Checked(scope)
}

// swiftPurl names a pin the way OSV's SwiftURL ecosystem does: the
// repository URL without its scheme and ".git" (github.com/apple/swift-nio),
// split into namespace and name. A registry pin uses the repository it
// mirrors when the file records it, else its registry identity (scope.name).
func swiftPurl(p resolvedPin, ver string) (string, map[string]string, bool) {
	ev := map[string]string{}
	loc := p.RepositoryURL
	if loc == "" {
		loc = p.Location
	}
	if p.Kind == "registry" {
		ev["registry_identity"] = p.Identity
		loc = p.OriginalLocation
		if loc == "" {
			scope, name, ok := strings.Cut(p.Identity, ".")
			if !ok || scope == "" || name == "" {
				return "", nil, false
			}
			return packageurl.NewPackageURL("swift", scope, name, ver, nil, "").ToString(), ev, true
		}
	}
	ns, name, ok := repoPath(loc)
	if !ok {
		return "", nil, false
	}
	return packageurl.NewPackageURL("swift", ns, name, ver, nil, "").ToString(), ev, true
}

// repoPath reads a git URL (https://, ssh://, git://, or scp-like
// git@host:owner/repo) into "host/owner" and "repo": the host lower-cased,
// without user, port, ".git" or a trailing slash.
func repoPath(u string) (namespace, name string, ok bool) {
	u = strings.TrimSpace(u)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	} else if at := strings.Index(u, "@"); at >= 0 && strings.Contains(u[at:], ":") {
		u = strings.Replace(u[at+1:], ":", "/", 1) // git@github.com:owner/repo
	} else {
		return "", "", false // a local path
	}
	if at := strings.LastIndex(u, "@"); at >= 0 && at < strings.Index(u+"/", "/") {
		u = u[at+1:]
	}
	u = strings.TrimSuffix(strings.TrimRight(u, "/"), ".git")
	parts := strings.Split(u, "/")
	if len(parts) < 2 {
		return "", "", false
	}
	host := strings.ToLower(parts[0])
	if h, _, found := strings.Cut(host, ":"); found {
		host = h
	}
	for _, p := range parts[1:] {
		if p == "" || p == "." || p == ".." {
			return "", "", false
		}
	}
	if host == "" {
		return "", "", false
	}
	return strings.Join(append([]string{host}, parts[1:len(parts)-1]...), "/"), parts[len(parts)-1], true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
