package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/pkg/pack"
)

// conanLock is conan.lock in both formats. Conan 1 (lockfile versions 0.1
// to 0.4) writes the dependency graph under graph_lock.nodes; node "0" with
// a "path" is the consumer (the conanfile), not a dependency. Conan 2
// (version 0.5) writes flat lists of references.
type conanLock struct {
	Version   string `json:"version"`
	GraphLock *struct {
		Nodes map[string]conanNode `json:"nodes"`
	} `json:"graph_lock"`
	Requires       []string `json:"requires"`
	BuildRequires  []string `json:"build_requires"`
	PythonRequires []string `json:"python_requires"`
}

type conanNode struct {
	Ref           string   `json:"ref"`
	Pref          string   `json:"pref"` // lockfile 0.1-0.3: ref:package_id#prev
	Path          string   `json:"path"`
	Context       string   `json:"context"`
	Requires      []string `json:"requires"`
	BuildRequires []string `json:"build_requires"`
}

// conanRef is a recipe reference: name/version[@user[/channel]][#rrev[%time]].
type conanRef struct {
	name, version, user, channel, rrev string
}

func parseConanRef(s string) (conanRef, bool) {
	s, _, _ = strings.Cut(strings.TrimSpace(s), ":") // drop a package id
	s, _, _ = strings.Cut(s, "%")                    // and a revision timestamp
	var r conanRef
	s, r.rrev, _ = strings.Cut(s, "#")
	s, uc, hasUC := strings.Cut(s, "@")
	if hasUC {
		r.user, r.channel, _ = strings.Cut(uc, "/")
		if r.user == "_" {
			r.user = ""
		}
		if r.channel == "_" {
			r.channel = ""
		}
	}
	var ok bool
	r.name, r.version, ok = strings.Cut(s, "/")
	if !ok || r.name == "" || r.version == "" || strings.ContainsAny(r.version, "[]/ ") {
		return conanRef{}, false
	}
	return r, true
}

func (r conanRef) purl() string {
	var q packageurl.Qualifiers
	if r.user != "" {
		q = append(q, packageurl.Qualifier{Key: "user", Value: r.user})
	}
	if r.channel != "" {
		q = append(q, packageurl.Qualifier{Key: "channel", Value: r.channel})
	}
	return packageurl.NewPackageURL("conan", "", r.name, r.version, q, "").ToString()
}

func scanConanLock(f pack.File, out *pack.Response) {
	scope := "conan:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	var lock conanLock
	if err := json.Unmarshal(data, &lock); err != nil {
		out.Failed(scope, "not a conan.lock file: "+err.Error())
		return
	}
	type dep struct {
		ref    conanRef
		build  bool
		direct *bool
	}
	deps := map[string]*dep{} // by purl
	bad := 0
	add := func(s string, build bool, direct *bool) {
		r, ok := parseConanRef(s)
		if !ok {
			bad++
			return
		}
		p := r.purl()
		if d, ok := deps[p]; ok {
			d.build = d.build && build // needed at run time by anything wins
			if direct != nil && *direct {
				d.direct = direct
			}
			return
		}
		deps[p] = &dep{ref: r, build: build, direct: direct}
	}
	switch {
	case lock.GraphLock != nil:
		nodes := lock.GraphLock.Nodes
		host, buildOnly, rootDeps := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, n := range nodes {
			for _, id := range n.Requires {
				host[id] = true
			}
			for _, id := range n.BuildRequires {
				buildOnly[id] = true
			}
			if n.Path != "" {
				for _, id := range append(append([]string{}, n.Requires...), n.BuildRequires...) {
					rootDeps[id] = true
				}
			}
		}
		ids := make([]string, 0, len(nodes))
		for id := range nodes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			n := nodes[id]
			if n.Path != "" {
				continue // the consumer: the project's own conanfile
			}
			ref := n.Ref
			if ref == "" {
				ref = n.Pref
			}
			if ref == "" {
				continue
			}
			build := n.Context == "build" || (buildOnly[id] && !host[id])
			add(ref, build, boolp(rootDeps[id]))
		}
	case lock.Version != "":
		for _, s := range lock.Requires {
			add(s, false, nil)
		}
		for _, s := range lock.BuildRequires {
			add(s, true, nil)
		}
		// python_requires are recipe helpers run by Conan, not code that is
		// built into the project.
	default:
		out.Failed(scope, "not a conan.lock file: no graph_lock and no version")
		return
	}
	keys := make([]string, 0, len(deps))
	for p := range deps {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		d := deps[p]
		ev := map[string]string{"lockfile": "conan.lock"}
		if d.ref.rrev != "" {
			ev["recipe_revision"] = d.ref.rrev
		}
		o := pack.Observation{Purl: p, Version: d.ref.version, Location: f.Path, Direct: d.direct,
			Confidence: pack.ConfidenceConfirmed, Evidence: ev}
		if d.build {
			o.Scope = "build"
		}
		out.Observations = append(out.Observations, o)
	}
	if bad > 0 {
		out.Partial(scope, fmt.Sprintf("%d %s not name/version", bad, plural(bad, "reference was", "references were")))
		return
	}
	out.Checked(scope)
}
