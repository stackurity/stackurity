package store

import "testing"

// Libraries read by the stack packs on deployed applications and hosts are
// in the libraries layer (in a repository everything is "declared"), including
// vcpkg ports, which are pkg:generic/vcpkg/<port>: a generic component on a
// host is otherwise the operating system.
func TestFindingLayerPackLibraries(t *testing.T) {
	for _, f := range []Finding{
		{ComponentType: "swift", ComponentName: "github.com/apple/swift-nio"},
		{ComponentType: "hex", ComponentName: "plug"},
		{ComponentType: "cocoapods", ComponentName: "Alamofire"},
		{ComponentType: "conan", ComponentName: "zlib"},
		{ComponentType: "generic", ComponentName: "vcpkg/curl"},
	} {
		for _, kind := range []string{"application", "host"} {
			if got := findingLayer(f, kind); got != "libraries" {
				t.Errorf("%s %s on a %s: layer %q", f.ComponentType, f.ComponentName, kind, got)
			}
		}
	}
}
