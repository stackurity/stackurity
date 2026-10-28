// Command hex is the Elixir and Erlang stack pack: Mix's mix.lock, the
// packages fetched from Hex.
// Build it with: GOOS=wasip1 GOARCH=wasm go build -o pack.wasm ./packs/hex
package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/pkg/pack"
)

func main() { pack.Serve(Scan) }

// Scan reads every mix.lock the core hands over.
func Scan(req *pack.Request) (*pack.Response, error) {
	out := &pack.Response{}
	for _, f := range req.Files {
		if f.Name() == "mix.lock" {
			scanMixLock(f, out)
		}
	}
	return out, nil
}

// scanMixLock reads the lock map. Each value is a tuple whose first element
// says where the dependency comes from:
//
//	{:hex, :name, "1.0.2"}                                         Mix 1.0-1.1
//	{:hex, :name, "1.0.4", "sha", [:rebar, :make], [deps]}           Mix 1.2-1.5
//	{:hex, :name, "1.0.4", "sha", [:mix], [deps], "hexpm", "sha"}  Mix 1.6+
//	{:git, "https://...", "commit", [opts]}
//
// The key is the application name; the second element is the package on
// Hex, which can differ ("hpack": {:hex, :hpack_erl, ...}). The repository is
// "hexpm" for public packages, "hexpm:org" for a private organisation's.
func scanMixLock(f pack.File, out *pack.Response) {
	scope := "hex:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	lock, err := parseTerm(string(data))
	if err != nil {
		out.Failed(scope, "not a mix.lock file: "+err.Error())
		return
	}
	if lock.kind != tMap {
		out.Failed(scope, "not a mix.lock file: the file is not a map")
		return
	}
	var obs []pack.Observation
	noVersion, unreadable := 0, 0
	for _, e := range lock.pairs {
		v := e.value
		if v.kind != tTuple || len(v.items) == 0 || v.items[0].kind != tAtom {
			unreadable++
			continue
		}
		switch v.items[0].s {
		case "hex":
			o, ok := hexDep(v.items, f.Path)
			if !ok {
				unreadable++
				continue
			}
			obs = append(obs, o)
		case "git", "path":
			noVersion++ // a commit or a directory, not a released version
		default:
			unreadable++
		}
	}
	sort.Slice(obs, func(i, j int) bool { return obs[i].Purl < obs[j].Purl })
	out.Observations = append(out.Observations, obs...)
	var notes []string
	if noVersion > 0 {
		notes = append(notes, fmt.Sprintf("%d git %s no released version and could not be checked",
			noVersion, plural(noVersion, "dependency has", "dependencies have")))
	}
	if unreadable > 0 {
		notes = append(notes, fmt.Sprintf("%d %s not understood", unreadable, plural(unreadable, "entry was", "entries were")))
	}
	if len(notes) > 0 {
		out.Partial(scope, strings.Join(notes, "; "))
		return
	}
	out.Checked(scope)
}

func hexDep(items []term, file string) (pack.Observation, bool) {
	if len(items) < 3 || items[1].kind != tAtom || items[2].kind != tString || items[1].s == "" || items[2].s == "" {
		return pack.Observation{}, false
	}
	name, ver := items[1].s, items[2].s
	ns := ""
	ev := map[string]string{"lockfile": "mix.lock"}
	if len(items) >= 7 && items[6].kind == tString {
		repo := items[6].s
		switch {
		case repo == "" || repo == "hexpm":
		case strings.HasPrefix(repo, "hexpm:"):
			ns = strings.TrimPrefix(repo, "hexpm:") // a private organisation on hex.pm
			ev["repo"] = repo
		default:
			ns = repo // a self-hosted Hex repository
			ev["repo"] = repo
		}
	}
	return pack.Observation{
		Purl:    packageurl.NewPackageURL("hex", ns, name, ver, nil, "").ToString(),
		Version: ver, Location: file, Confidence: pack.ConfidenceConfirmed, Evidence: ev,
	}, true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
