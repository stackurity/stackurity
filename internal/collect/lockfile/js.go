package lockfile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/stackurity/stackurity/internal/model"
)

// directNpm reads dependency names from package.json beside a lockfile.
// It returns nil when there is no readable package.json.
func directNpm(fsys fs.FS, dir string) map[string]bool {
	raw, err := readLimited(fsys, path.Join(dir, "package.json"))
	if err != nil {
		return nil
	}
	var pj struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if json.Unmarshal(raw, &pj) != nil {
		return nil
	}
	out := map[string]bool{}
	for _, m := range []map[string]string{pj.Dependencies, pj.DevDependencies, pj.OptionalDependencies, pj.PeerDependencies} {
		for n := range m {
			out[n] = true
		}
	}
	return out
}

func directFlag(direct map[string]bool, name string) *bool {
	if direct == nil {
		return nil
	}
	return boolp(direct[name])
}

// nameFromSpec turns "@scope/pkg@^1.0.0" or "pkg@npm:^1" into the package name.
func nameFromSpec(spec string) string {
	spec = strings.Trim(strings.TrimSpace(spec), `"`)
	at := strings.LastIndex(spec, "@")
	if at <= 0 {
		return spec
	}
	return spec[:at]
}

// parseYarn handles both yarn v1 (custom format) and Berry (v2+, YAML).
func parseYarn(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	direct := directNpm(fsys, dir)
	if bytes.Contains(data, []byte("__metadata:")) {
		return parseYarnBerry(data, file, direct)
	}
	var obs []model.Observation
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 1<<20), MaxLockfileSize)
	var name string
	seen := map[string]bool{}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":"):
			first, _, _ := strings.Cut(strings.TrimSuffix(line, ":"), ",")
			name = nameFromSpec(first)
			if i := strings.Index(name, "@npm:"); i > 0 { // alias "x@npm:real"
				name = name[:i]
			}
		case strings.HasPrefix(line, "  version ") && name != "":
			v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, "  version ")), `"`)
			key := name + "@" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			obs = append(obs, model.Observation{
				Purl: npmPurl(name, v), Version: v, Location: file, Direct: directFlag(direct, name),
				Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"lockfile": "yarn v1"},
			})
		}
	}
	return obs, sc.Err()
}

func parseYarnBerry(data []byte, file string, direct map[string]bool) ([]model.Observation, error) {
	var doc map[string]struct {
		Version    string `yaml:"version"`
		Resolution string `yaml:"resolution"`
		LinkType   string `yaml:"linkType"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	var obs []model.Observation
	for key, e := range doc {
		if key == "__metadata" || e.Version == "" || strings.Contains(e.Resolution, "@workspace:") ||
			strings.Contains(e.Resolution, "@link:") || strings.Contains(e.Resolution, "@portal:") {
			continue
		}
		res := e.Resolution
		if i := strings.Index(res, "@npm:"); i > 0 {
			res = res[:i]
		} else if i := strings.Index(res, "@patch:"); i > 0 {
			res = res[:i]
		} else {
			first, _, _ := strings.Cut(key, ",")
			res = nameFromSpec(strings.Replace(first, "@npm:", "@", 1))
		}
		obs = append(obs, model.Observation{
			Purl: npmPurl(res, e.Version), Version: e.Version, Location: file, Direct: directFlag(direct, res),
			Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"lockfile": "yarn berry", "resolution": e.Resolution},
		})
	}
	return obs, nil
}

var pnpmPeerSuffix = regexp.MustCompile(`[(_].*$`)

// parsePnpm handles pnpm-lock.yaml v5 ("/name/1.0.0"), v6 ("/name@1.0.0")
// and v9 ("name@1.0.0").
func parsePnpm(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var doc struct {
		LockfileVersion any `yaml:"lockfileVersion"`
		Importers       map[string]struct {
			Dependencies         map[string]any `yaml:"dependencies"`
			DevDependencies      map[string]any `yaml:"devDependencies"`
			OptionalDependencies map[string]any `yaml:"optionalDependencies"`
		} `yaml:"importers"`
		Dependencies    map[string]any `yaml:"dependencies"` // v5 single project
		DevDependencies map[string]any `yaml:"devDependencies"`
		Packages        map[string]struct {
			Dev bool `yaml:"dev"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	direct := map[string]bool{}
	for _, imp := range doc.Importers {
		for _, m := range []map[string]any{imp.Dependencies, imp.DevDependencies, imp.OptionalDependencies} {
			for n := range m {
				direct[n] = true
			}
		}
	}
	for _, m := range []map[string]any{doc.Dependencies, doc.DevDependencies} {
		for n := range m {
			direct[n] = true
		}
	}
	var obs []model.Observation
	seen := map[string]bool{}
	for key, p := range doc.Packages {
		k := strings.TrimPrefix(key, "/")
		k = pnpmPeerSuffix.ReplaceAllString(k, "")
		var name, ver string
		if at := strings.LastIndex(k, "@"); at > 0 {
			name, ver = k[:at], k[at+1:]
		} else if slash := strings.LastIndex(k, "/"); slash > 0 { // v5
			name, ver = k[:slash], k[slash+1:]
		}
		if name == "" || ver == "" || strings.ContainsAny(ver, ":/") { // tarball, git, file deps
			continue
		}
		if seen[name+"@"+ver] {
			continue
		}
		seen[name+"@"+ver] = true
		scope := "runtime"
		if p.Dev {
			scope = "dev"
		}
		obs = append(obs, model.Observation{
			Purl: npmPurl(name, ver), Version: ver, Location: file, Direct: boolp(direct[name]), Scope: scope,
			Confidence: model.ConfidenceConfirmed, Evidence: map[string]string{"lockfile": fmt.Sprintf("pnpm %v", doc.LockfileVersion)},
		})
	}
	return obs, nil
}
