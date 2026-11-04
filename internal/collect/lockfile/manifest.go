package lockfile

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"
)

// PackageNamesAttr is the asset attribute that holds the names a project
// gives itself in its manifests, as "type:name" separated by commas
// ("npm:commmerce-analytics,pub:commmerce_chat"). A repository and the
// application deployed from it carry the same names, which is how the
// server suggests linking them (store.LinkSuggestions).
const PackageNamesAttr = "package_names"

// maxManifest bounds each manifest read for its name.
const maxManifest = 1 << 20

var (
	goModule  = regexp.MustCompile(`(?m)^\s*module\s+"?([^\s"]+)"?\s*$`)
	safeName  = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9@._~/+-]{0,213}$`)
	pypiSeps  = regexp.MustCompile(`[-_.]+`)
	nameField struct {
		Name string `json:"name" yaml:"name"`
	}
)

// ManifestNames reads the names a project directory's root manifests give
// it: package.json, composer.json, go.mod, pubspec.yaml, pyproject.toml
// and Cargo.toml. read returns a file's contents by its name relative to
// the directory (nil or an error when it is missing). Names are returned
// as "type:name" (the purl type), lowercased, sorted and without
// duplicates; a name that is not a plain package name is left out.
func ManifestNames(read func(name string) ([]byte, error)) []string {
	get := func(name string) []byte {
		data, err := read(name)
		if err != nil || len(data) > maxManifest {
			return nil
		}
		return data
	}
	seen := map[string]bool{}
	add := func(typ, name string) {
		name = strings.TrimSpace(name)
		if !safeName.MatchString(name) {
			return
		}
		name = strings.ToLower(name)
		if typ == "pypi" {
			name = pypiSeps.ReplaceAllString(name, "-")
		}
		seen[typ+":"+name] = true
	}
	for _, f := range []struct{ file, typ string }{{"package.json", "npm"}, {"composer.json", "composer"}} {
		if data := get(f.file); data != nil {
			v := nameField
			if json.Unmarshal(data, &v) == nil {
				add(f.typ, v.Name)
			}
		}
	}
	if data := get("pubspec.yaml"); data != nil {
		v := nameField
		if yaml.Unmarshal(data, &v) == nil {
			add("pub", v.Name)
		}
	}
	if data := get("go.mod"); data != nil {
		if m := goModule.FindSubmatch(data); m != nil {
			add("golang", string(m[1]))
		}
	}
	if data := get("pyproject.toml"); data != nil {
		var v struct {
			Project struct{ Name string } `toml:"project"`
			Tool    struct {
				Poetry struct{ Name string } `toml:"poetry"`
			} `toml:"tool"`
		}
		if _, err := toml.Decode(string(data), &v); err == nil {
			add("pypi", v.Project.Name)
			add("pypi", v.Tool.Poetry.Name)
		}
	}
	if data := get("Cargo.toml"); data != nil {
		var v struct {
			Package struct{ Name string } `toml:"package"`
		}
		if _, err := toml.Decode(string(data), &v); err == nil {
			add("cargo", v.Package.Name)
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// JoinPackageNames is the attribute value for names, clipped to the
// batch's field limit at a name boundary; "" for none.
func JoinPackageNames(names []string) string {
	out := ""
	for _, n := range names {
		if len(out)+len(n)+1 > 1000 {
			break
		}
		if out != "" {
			out += ","
		}
		out += n
	}
	return out
}
