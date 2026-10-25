// Command cargo is the Rust stack pack. It runs the Cargo.lock reader that
// used to be built into the core, so its results are the same.
// Build it with: GOOS=wasip1 GOARCH=wasm go build -o pack.wasm ./packs/cargo
package main

import (
	"testing/fstest"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/pkg/pack"
)

func main() { pack.Serve(Scan) }

func Scan(req *pack.Request) (*pack.Response, error) {
	fsys := fstest.MapFS{}
	out := &pack.Response{}
	for _, f := range req.Files {
		data, err := f.Bytes()
		if err != nil {
			out.Failed("cargo:"+f.Path, "could not read the file")
			continue
		}
		fsys[f.Path] = &fstest.MapFile{Data: data}
	}
	for _, f := range req.Files {
		if _, ok := fsys[f.Path]; !ok {
			continue
		}
		obs, err := lockfile.ParseCargoLock(fsys, f.Path)
		if err != nil {
			out.Failed("cargo:"+f.Path, err.Error())
			continue
		}
		out.Observations = append(out.Observations, obs...)
		out.Checked("cargo:" + f.Path)
	}
	return out, nil
}
