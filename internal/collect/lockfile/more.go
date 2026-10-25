package lockfile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/package-url/packageurl-go"
	"go.yaml.in/yaml/v3"
	"golang.org/x/mod/modfile"

	"github.com/stackurity/stackurity/internal/model"
)

// --- Python

var pep503 = regexp.MustCompile(`[-_.]+`)

// pypiName normalises per PEP 503 so names match OSV and PyPI.
func pypiName(n string) string {
	return strings.ToLower(pep503.ReplaceAllString(strings.TrimSpace(n), "-"))
}

func pypiPurl(name, version string) string {
	return packageurl.NewPackageURL("pypi", "", pypiName(name), version, nil, "").ToString()
}

// directPython reads declared dependencies from pyproject.toml (PEP 621 and
// Poetry) beside a lockfile.
func directPython(fsys fs.FS, dir string) map[string]bool {
	raw, err := readLimited(fsys, path.Join(dir, "pyproject.toml"))
	if err != nil {
		return nil
	}
	var pp struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		Tool struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
		} `toml:"tool"`
	}
	if _, err := toml.Decode(string(raw), &pp); err != nil {
		return nil
	}
	out := map[string]bool{}
	reqName := regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)
	addReq := func(r string) {
		if m := reqName.FindStringSubmatch(r); m != nil {
			out[pypiName(m[1])] = true
		}
	}
	for _, r := range pp.Project.Dependencies {
		addReq(r)
	}
	for _, list := range pp.Project.OptionalDependencies {
		for _, r := range list {
			addReq(r)
		}
	}
	for n := range pp.Tool.Poetry.Dependencies {
		out[pypiName(n)] = true
	}
	for n := range pp.Tool.Poetry.DevDependencies {
		out[pypiName(n)] = true
	}
	for _, g := range pp.Tool.Poetry.Group {
		for n := range g.Dependencies {
			out[pypiName(n)] = true
		}
	}
	delete(out, "python")
	return out
}

func parsePoetry(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Package []struct {
			Name     string   `toml:"name"`
			Version  string   `toml:"version"`
			Category string   `toml:"category"`
			Groups   []string `toml:"groups"`
			Source   struct {
				Type string `toml:"type"`
			} `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	direct := directPython(fsys, dir)
	var obs []model.Observation
	for _, p := range lock.Package {
		if p.Name == "" || p.Version == "" || p.Source.Type == "directory" || p.Source.Type == "file" {
			continue
		}
		scope := "runtime"
		if p.Category == "dev" || (len(p.Groups) > 0 && !contains(p.Groups, "main")) {
			scope = "dev"
		}
		obs = append(obs, model.Observation{Purl: pypiPurl(p.Name, p.Version), Version: p.Version, Location: file,
			Direct: directFlag(direct, pypiName(p.Name)), Scope: scope, Confidence: model.ConfidenceConfirmed,
			Evidence: map[string]string{"lockfile": "poetry"}})
	}
	return obs, nil
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func parsePipfileLock(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var lock map[string]map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	var obs []model.Observation
	for section, scope := range map[string]string{"default": "runtime", "develop": "dev"} {
		for name, p := range lock[section] {
			v := strings.TrimPrefix(p.Version, "==")
			if v == "" || strings.ContainsAny(v, "<>~!*,") {
				continue
			}
			obs = append(obs, model.Observation{Purl: pypiPurl(name, v), Version: v, Location: file, Scope: scope,
				Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"lockfile": "pipenv"}})
		}
	}
	return obs, nil
}

var reqLine = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9.+!_-]+)\s*(;.*)?$`)

// parseRequirements reads pinned requirements ("name==1.2.3"). Unpinned
// lines have no exact version and are reported as partial coverage.
func parseRequirements(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var obs []model.Observation
	unpinned := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	var cont strings.Builder
	for sc.Scan() {
		line := sc.Text()
		if strings.HasSuffix(line, "\\") {
			cont.WriteString(strings.TrimSuffix(line, "\\") + " ")
			continue
		}
		line = cont.String() + line
		cont.Reset()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if i := strings.Index(line, "--hash"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := reqLine.FindStringSubmatch(line)
		if m == nil {
			unpinned++
			continue
		}
		obs = append(obs, model.Observation{Purl: pypiPurl(m[1], m[3]), Version: m[3], Location: file, Direct: boolp(true),
			Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"lockfile": "requirements (pinned)"}})
	}
	if unpinned > 0 {
		return obs, &partialError{fmt.Sprintf("%d requirement(s) without an exact == pin were not inventoried", unpinned)}
	}
	return obs, sc.Err()
}

// partialError marks a parse that succeeded for part of the file.
type partialError struct{ msg string }

func (e *partialError) Error() string { return e.msg }

// --- Go

func parseGoMod(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse(file, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	replaced := map[string]string{}
	for _, r := range f.Replace {
		if r.New.Version != "" {
			replaced[r.Old.Path] = r.New.Path + "@" + r.New.Version
		} else {
			replaced[r.Old.Path] = "" // local directory replacement: project code
		}
	}
	var obs []model.Observation
	for _, r := range f.Require {
		modPath, v := r.Mod.Path, r.Mod.Version
		if rep, ok := replaced[modPath]; ok {
			if rep == "" {
				continue
			}
			modPath, v, _ = strings.Cut(rep, "@")
		}
		ns, name := path.Dir(modPath), path.Base(modPath)
		if ns == "." {
			ns = ""
		}
		obs = append(obs, model.Observation{
			Purl: packageurl.NewPackageURL("golang", ns, name, v, nil, "").ToString(), Version: v, Location: file,
			Direct: boolp(!r.Indirect), Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"lockfile": "go.mod"},
		})
	}
	return obs, nil
}

// --- Rust

// ParseCargoLock reads a Cargo.lock. It is no longer built into the core:
// the Cargo stack pack (packs/cargo) calls it.
func ParseCargoLock(fsys fs.FS, file string) ([]model.Observation, error) {
	return parseCargoLock(fsys, path.Dir(file), file)
}

func parseCargoLock(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
			Source  string `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(data), &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	var obs []model.Observation
	for _, p := range lock.Package {
		if !strings.HasPrefix(p.Source, "registry+") && !strings.HasPrefix(p.Source, "sparse+") {
			continue // path and git sources are the project's own or unversioned code
		}
		obs = append(obs, model.Observation{
			Purl: packageurl.NewPackageURL("cargo", "", p.Name, p.Version, nil, "").ToString(), Version: p.Version,
			Location: file, Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"lockfile": "Cargo.lock"},
		})
	}
	return obs, nil
}

// --- Ruby

var gemSpec = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([^)]+)\)$`)
var gemDep = regexp.MustCompile(`^  ([A-Za-z0-9._-]+)`)
var gemPlatform = regexp.MustCompile(`-(x86|x64|arm|aarch64|java|universal|mingw|mswin|darwin|linux|wasm).*$`)

func parseGemfileLock(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	direct := map[string]bool{}
	type gem struct{ name, version string }
	var gems []gem
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line != "" && !strings.HasPrefix(line, " ") {
			section = strings.TrimSpace(line)
			continue
		}
		switch section {
		case "GEM":
			if m := gemSpec.FindStringSubmatch(line); m != nil {
				// Drop platform suffixes such as 1.15.5-x86_64-linux.
				v := gemPlatform.ReplaceAllString(m[2], "")
				gems = append(gems, gem{m[1], v})
			}
		case "DEPENDENCIES":
			if m := gemDep.FindStringSubmatch(line); m != nil {
				direct[strings.TrimSuffix(m[1], "!")] = true
			}
		}
	}
	var obs []model.Observation
	seen := map[string]bool{}
	for _, g := range gems {
		if seen[g.name+g.version] {
			continue
		}
		seen[g.name+g.version] = true
		obs = append(obs, model.Observation{
			Purl: packageurl.NewPackageURL("gem", "", g.name, g.version, nil, "").ToString(), Version: g.version,
			Location: file, Direct: boolp(direct[g.name]), Confidence: model.ConfidenceConfirmed,
			Evidence: map[string]string{"lockfile": "Gemfile.lock"},
		})
	}
	return obs, sc.Err()
}

// --- .NET

func parseNuGetLock(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	var obs []model.Observation
	seen := map[string]bool{}
	for framework, deps := range lock.Dependencies {
		for name, d := range deps {
			if d.Resolved == "" || d.Type == "Project" || seen[name+d.Resolved] {
				continue
			}
			seen[name+d.Resolved] = true
			obs = append(obs, model.Observation{
				Purl: packageurl.NewPackageURL("nuget", "", name, d.Resolved, nil, "").ToString(), Version: d.Resolved,
				Location: file, Direct: boolp(d.Type == "Direct"), Confidence: model.ConfidenceConfirmed,
				Evidence: map[string]string{"lockfile": "packages.lock.json", "framework": framework},
			})
		}
	}
	return obs, nil
}

// --- Dart and Flutter

// pubHosts are the public pub.dev hosts. Packages from other hosted
// repositories are private and must not be matched against public advisories.
var pubHosts = map[string]bool{"https://pub.dev": true, "https://pub.dartlang.org": true}

func parsePubspecLock(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var lock struct {
		Packages map[string]struct {
			Dependency  string    `yaml:"dependency"`
			Description yaml.Node `yaml:"description"`
			Source      string    `yaml:"source"`
			Version     string    `yaml:"version"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	var obs []model.Observation
	for name, p := range lock.Packages {
		if p.Source != "hosted" || p.Version == "" {
			continue // sdk, path and git packages are not published versions
		}
		var desc struct {
			Name string `yaml:"name"`
			URL  string `yaml:"url"`
		}
		_ = p.Description.Decode(&desc)
		if desc.URL != "" && !pubHosts[strings.TrimRight(desc.URL, "/")] {
			continue
		}
		if desc.Name != "" {
			name = desc.Name
		}
		scope := "runtime"
		if p.Dependency == "direct dev" {
			scope = "dev"
		}
		obs = append(obs, model.Observation{
			Purl:       packageurl.NewPackageURL("pub", "", name, p.Version, nil, "").ToString(),
			Version:    p.Version,
			Location:   cleanRel(file),
			Direct:     boolp(strings.HasPrefix(p.Dependency, "direct")),
			Scope:      scope,
			Confidence: model.ConfidenceConfirmed,
			Evidence:   map[string]string{"lockfile": "pubspec.lock"},
		})
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Purl < obs[j].Purl })
	return obs, nil
}
