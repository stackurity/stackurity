package lockfile

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

type composerPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Source  struct {
		URL       string `json:"url"`
		Reference string `json:"reference"`
	} `json:"source"`
	Dist struct {
		URL    string `json:"url"`
		Shasum string `json:"shasum"`
	} `json:"dist"`
}

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// composerVersion strips the conventional "v" prefix ("v10.2.3") so versions
// line up with Packagist advisories. Branch aliases ("dev-main") are kept.
func composerVersion(v string) string {
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}

func parseComposer(fsys fs.FS, dir, file string) ([]model.Observation, error) {
	data, err := readLimited(fsys, file)
	if err != nil {
		return nil, err
	}
	var lock composerLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse %s: %w", file, err)
	}
	// composer.json beside the lock tells us which packages are direct.
	var direct map[string]bool
	if raw, err := readLimited(fsys, path.Join(dir, "composer.json")); err == nil {
		var cj composerJSON
		if json.Unmarshal(raw, &cj) == nil {
			direct = map[string]bool{}
			for n := range cj.Require {
				direct[strings.ToLower(n)] = true
			}
			for n := range cj.RequireDev {
				direct[strings.ToLower(n)] = true
			}
		}
	}
	var obs []model.Observation
	add := func(pkgs []composerPackage, scope string) {
		for _, p := range pkgs {
			vendor, name, ok := strings.Cut(strings.ToLower(p.Name), "/")
			if !ok || p.Version == "" {
				continue
			}
			v := composerVersion(p.Version)
			ev := map[string]string{"raw_version": p.Version}
			if p.Source.Reference != "" {
				ev["source_reference"] = p.Source.Reference
			}
			if p.Dist.URL != "" {
				ev["dist_url"] = p.Dist.URL
			}
			conf := model.ConfidenceConfirmed
			if strings.HasPrefix(v, "dev-") {
				conf = model.ConfidenceLow // branch install: version is not a release
			}
			var d *bool
			if direct != nil {
				d = boolp(direct[vendor+"/"+name])
			}
			obs = append(obs, model.Observation{
				Purl:       packageurl.NewPackageURL("composer", vendor, name, v, nil, "").ToString(),
				Version:    v,
				Location:   cleanRel(file),
				Direct:     d,
				Scope:      scope,
				Confidence: conf,
				Evidence:   ev,
			})
		}
	}
	add(lock.Packages, "runtime")
	add(lock.PackagesDev, "dev")
	return obs, nil
}
