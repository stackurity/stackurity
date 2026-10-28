// Command cpp is the C and C++ stack pack: Conan lock files and vcpkg
// manifests and installed-port records.
// Build it with: GOOS=wasip1 GOARCH=wasm go build -o pack.wasm ./packs/cpp
package main

import (
	"github.com/stackurity/stackurity/pkg/pack"
)

func main() { pack.Serve(Scan) }

// Scan reads every file the core hands over.
func Scan(req *pack.Request) (*pack.Response, error) {
	out := &pack.Response{}
	for _, f := range req.Files {
		switch f.Name() {
		case "conan.lock":
			scanConanLock(f, out)
		case "vcpkg.json":
			scanVcpkgManifest(f, out)
		case "vcpkg.spdx.json":
			scanVcpkgSPDX(f, out)
		}
	}
	return out, nil
}

func boolp(b bool) *bool { return &b }

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
