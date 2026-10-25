package lockfile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

type npmLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]npmPackage      `json:"packages"`     // v2, v3
	Dependencies    map[string]npmV1Dependency `json:"dependencies"` // v1
}

type npmPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Integrity            string            `json:"integrity"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

type npmV1Dependency struct {
	Version      string                     `json:"version"`
	Resolved     string                     `json:"resolved"`
	Integrity    string                     `json:"integrity"`
	Dev          bool                       `json:"dev"`
	Dependencies map[string]npmV1Dependency `json:"dependencies"`
}

// npmPurl builds pkg:npm/[@scope/]name@version.
func npmPurl(name, version string) string {
	ns := ""
	if strings.HasPrefix(name, "@") {
		if scope, rest, ok := strings.Cut(name, "/"); ok {
			ns, name = scope, rest
		}
	}
	return packageurl.NewPackageURL("npm", ns, name, version, nil, "").ToString()
}

func parseNpm(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	if lock.Packages != nil {
		return npmV2(lock, file), nil
	}
	if lock.Dependencies != nil {
		return npmV1(lock, file), nil
	}
	return nil, fmt.Errorf("%s: no packages or dependencies section", file)
}

func npmV2(lock npmLock, file string) []model.Observation {
	root := lock.Packages[""]
	direct := map[string]bool{}
	for _, deps := range []map[string]string{root.Dependencies, root.DevDependencies, root.OptionalDependencies} {
		for n := range deps {
			direct[n] = true
		}
	}
	var obs []model.Observation
	for key, p := range lock.Packages {
		if key == "" || p.Link {
			continue
		}
		idx := strings.LastIndex(key, "node_modules/")
		if idx < 0 {
			continue // workspace source folder: the project's own code
		}
		name := key[idx+len("node_modules/"):]
		if p.Name != "" {
			name = p.Name // aliased installs ("npm:real-name@x")
		}
		if p.Version == "" || strings.HasPrefix(p.Version, "file:") {
			continue
		}
		top := strings.Count(key, "node_modules/") == 1 && strings.HasPrefix(key, "node_modules/")
		ev := map[string]string{"lockfile_version": fmt.Sprint(lock.LockfileVersion), "lock_path": key}
		if p.Resolved != "" {
			ev["resolved"] = p.Resolved
		}
		if p.Integrity != "" {
			ev["integrity"] = p.Integrity
		}
		scope := "runtime"
		if p.Dev {
			scope = "dev"
		}
		obs = append(obs, model.Observation{
			Purl:       npmPurl(name, p.Version),
			Version:    p.Version,
			Location:   file,
			Direct:     boolp(top && direct[name]),
			Scope:      scope,
			Confidence: model.ConfidenceConfirmed,
			Evidence:   ev,
		})
	}
	return obs
}

func npmV1(lock npmLock, file string) []model.Observation {
	var obs []model.Observation
	var walk func(deps map[string]npmV1Dependency, depth int, parent string)
	walk = func(deps map[string]npmV1Dependency, depth int, parent string) {
		for name, d := range deps {
			if d.Version == "" || strings.HasPrefix(d.Version, "file:") {
				continue
			}
			version := d.Version
			// Aliases are recorded as "npm:real@1.2.3".
			if real, ok := strings.CutPrefix(version, "npm:"); ok {
				if at := strings.LastIndex(real, "@"); at > 0 {
					name, version = real[:at], real[at+1:]
				}
			}
			scope := "runtime"
			if d.Dev {
				scope = "dev"
			}
			lockPath := parent + "node_modules/" + name
			ev := map[string]string{"lockfile_version": "1", "lock_path": lockPath}
			if d.Resolved != "" {
				ev["resolved"] = d.Resolved
			}
			obs = append(obs, model.Observation{
				Purl:     npmPurl(name, version),
				Version:  version,
				Location: file,
				// v1 does not record which top-level entries are direct.
				Direct:     nil,
				Scope:      scope,
				Confidence: model.ConfidenceConfirmed,
				Evidence:   ev,
			})
			walk(d.Dependencies, depth+1, lockPath+"/")
		}
	}
	walk(lock.Dependencies, 0, "")
	return obs
}
