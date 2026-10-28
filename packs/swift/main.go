// Command swift is the Swift stack pack: Swift Package Manager's
// Package.resolved and CocoaPods' Podfile.lock.
// Build it with: GOOS=wasip1 GOARCH=wasm go build -o pack.wasm ./packs/swift
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
		case "Package.resolved":
			scanResolved(f, out)
		case "Podfile.lock":
			scanPodfileLock(f, out)
		}
	}
	return out, nil
}

func boolp(b bool) *bool { return &b }
