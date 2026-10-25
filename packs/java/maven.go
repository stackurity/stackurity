package main

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/pkg/pack"
)

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
}

type pom struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
	Properties   properties `xml:"properties"`
	Dependencies []pomDep   `xml:"dependencies>dependency"`
	Managed      []pomDep   `xml:"dependencyManagement>dependencies>dependency"`
}

// properties collects <properties> children of any name.
type properties map[string]string

func (p *properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*p = properties{}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var v string
			if err := d.DecodeElement(&v, &t); err != nil {
				return err
			}
			(*p)[t.Name.Local] = strings.TrimSpace(v)
		case xml.EndElement:
			return nil
		}
	}
}

func parsePOM(data []byte) (*pom, error) {
	var p pom
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = false
	// External entities and DTDs are never fetched: encoding/xml does not
	// resolve them, which also rules out XXE.
	if err := d.Decode(&p); err != nil {
		return nil, err
	}
	return &p, nil
}

var propRef = regexp.MustCompile(`\$\{([^}]+)\}`)

// chain is a pom and its parents found in the same repository, nearest first.
type chain []*pom

func (c chain) prop(name string) (string, bool) {
	self := c[0]
	switch name {
	case "project.version", "pom.version", "version":
		if self.Version != "" {
			return self.Version, true
		}
		return self.Parent.Version, self.Parent.Version != ""
	case "project.groupId", "pom.groupId", "groupId":
		if self.GroupID != "" {
			return self.GroupID, true
		}
		return self.Parent.GroupID, self.Parent.GroupID != ""
	case "project.artifactId":
		return self.ArtifactID, true
	case "project.parent.version", "parent.version":
		return self.Parent.Version, self.Parent.Version != ""
	case "project.parent.groupId", "parent.groupId":
		return self.Parent.GroupID, self.Parent.GroupID != ""
	}
	for _, p := range c {
		if v, ok := p.Properties[name]; ok {
			return v, true
		}
	}
	return "", false
}

// resolve expands ${...} references, a few levels deep; ok is false when one
// stays unresolved.
func (c chain) resolve(s string) (string, bool) {
	for i := 0; i < 8 && strings.Contains(s, "${"); i++ {
		s = propRef.ReplaceAllStringFunc(s, func(m string) string {
			if v, ok := c.prop(m[2 : len(m)-1]); ok {
				return v
			}
			return m
		})
	}
	return s, !strings.Contains(s, "${")
}

// managed finds a version from dependencyManagement anywhere in the chain.
func (c chain) managed(group, artifact string) string {
	for _, p := range c {
		for _, m := range p.Managed {
			g, _ := c.resolve(m.GroupID)
			if g == group && m.ArtifactID == artifact && m.Version != "" {
				return m.Version
			}
		}
	}
	return ""
}

// parents follows <parent> to poms in the same repository: relativePath, or
// ../pom.xml by default, when its coordinates match.
func parents(f pack.File, self *pom, poms map[string]*pom) chain {
	c := chain{self}
	dir, cur := f.Dir(), self
	for i := 0; i < 10 && cur.Parent.ArtifactID != ""; i++ {
		rel := "../pom.xml"
		if cur.Parent.RelativePath != nil {
			rel = *cur.Parent.RelativePath
			if rel == "" {
				break
			}
			if !strings.HasSuffix(rel, ".xml") {
				rel = path.Join(rel, "pom.xml")
			}
		}
		p := path.Clean(path.Join(dir, rel))
		parent, ok := poms[p]
		if !ok || parent.ArtifactID != cur.Parent.ArtifactID {
			break
		}
		c = append(c, parent)
		dir, cur = path.Dir(p), parent
		if dir == "." {
			dir = ""
		}
	}
	return c
}

func scanPOM(f pack.File, poms map[string]*pom, out *pack.Response) {
	scope := "maven:" + f.Path
	self, ok := poms[f.Path]
	if !ok {
		out.Failed(scope, "not a readable pom.xml")
		return
	}
	c := parents(f, self, poms)
	unresolved := 0
	for _, d := range self.Dependencies {
		if d.Type == "pom" && d.Scope == "import" {
			continue
		}
		group, gok := c.resolve(d.GroupID)
		artifact, aok := c.resolve(d.ArtifactID)
		v := d.Version
		if v == "" {
			v = c.managed(group, artifact)
		}
		version, vok := c.resolve(v)
		if !gok || !aok || !vok || version == "" || strings.ContainsAny(version, "[](),") {
			unresolved++
			continue
		}
		o := pack.Observation{
			Purl: purl(group, artifact, version), Version: version, Location: f.Path, Direct: boolp(true),
			Confidence: pack.ConfidenceConfirmed,
		}
		if d.Scope == "test" || d.Scope == "provided" || d.Scope == "system" {
			o.Scope = d.Scope
		}
		out.Observations = append(out.Observations, o)
	}
	reason := "direct dependencies only; for transitive ones import a CycloneDX SBOM (cyclonedx-maven-plugin) or lock with Gradle"
	if unresolved > 0 {
		reason = fmt.Sprintf("%d dependencies have versions set outside this repository (a parent or BOM) or as ranges; ", unresolved) + reason
	}
	out.Partial(scope, reason)
}
