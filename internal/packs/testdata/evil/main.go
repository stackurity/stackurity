// Command evil is a misbehaving pack for the sandbox tests. What it does
// depends on the name of the first file it is given.
package main

import (
	"net"
	"os"

	"github.com/stackurity/stackurity/pkg/pack"
)

var sink [][]byte

func main() {
	pack.Serve(func(req *pack.Request) (*pack.Response, error) {
		out := &pack.Response{}
		f := req.Files[0]
		switch f.Name() {
		case "loop.txt":
			for {
			}
		case "memory.txt":
			for {
				sink = append(sink, make([]byte, 16<<20))
			}
		case "npm.txt":
			out.Observations = append(out.Observations, pack.Observation{Purl: "pkg:npm/left-pad@1.0.0", Version: "1.0.0", Confidence: pack.ConfidenceConfirmed})
		case "where.txt":
			out.Observations = append(out.Observations, pack.Observation{Purl: "pkg:maven/a/b@1", Version: "1", Location: "/etc/passwd", Confidence: pack.ConfidenceConfirmed})
		case "escape.txt":
			// Try to reach the host: both must fail inside the sandbox.
			_, ferr := os.ReadFile("/etc/passwd")
			if _, err := os.ReadFile("/input/../../etc/passwd"); err == nil {
				ferr = nil
			}
			if entries, err := os.ReadDir("/input"); err != nil || len(entries) != 1 {
				ferr = nil // the mount must hold exactly the one file given
			}
			_, nerr := net.Dial("tcp", "1.1.1.1:80")
			reason := "file read failed; dial failed"
			if ferr == nil {
				reason = "FILE READ SUCCEEDED"
			}
			if nerr == nil {
				reason += "; DIAL SUCCEEDED"
			}
			out.Checked("escape")
			out.Coverage[0].Reason = reason
			out.Observations = append(out.Observations, pack.Observation{Purl: "pkg:maven/a/b@1", Version: "1", Location: f.Path, Confidence: pack.ConfidenceConfirmed})
		case "crash.txt":
			os.Exit(3)
		}
		return out, nil
	})
}
