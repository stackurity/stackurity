// Command java is the Java stack pack: Maven and Gradle dependency files.
// Build it with: GOOS=wasip1 GOARCH=wasm go build -o pack.wasm ./packs/java
package main

import (
	"github.com/stackurity/stackurity/pkg/pack"
)

func main() { pack.Serve(Scan) }

// Scan reads every file the core hands over. Gradle lockfiles win over
// build.gradle in the same directory, because they hold exact versions.
func Scan(req *pack.Request) (*pack.Response, error) {
	out := &pack.Response{}
	locked := map[string]bool{} // directories with a Gradle lockfile
	poms := map[string]*pom{}   // by path, for parent lookups
	for _, f := range req.Files {
		switch {
		case isGradleLockfile(f.Name()):
			locked[gradleProjectDir(f)] = true
		case f.Name() == "pom.xml":
			if data, err := f.Bytes(); err == nil {
				if p, err := parsePOM(data); err == nil {
					poms[f.Path] = p
				}
			}
		}
	}
	for _, f := range req.Files {
		switch {
		case isGradleLockfile(f.Name()):
			scanGradleLockfile(f, out)
		case f.Name() == "pom.xml":
			scanPOM(f, poms, out)
		case isArchive(f.Name()):
			scanArchive(f, out)
		case f.Name() == "build.gradle" || f.Name() == "build.gradle.kts":
			if locked[f.Dir()] {
				out.Coverage = append(out.Coverage, pack.CoverageItem{Scope: "maven:" + f.Path, Status: "checked",
					Reason: "versions taken from the Gradle lockfile next to it"})
				continue
			}
			scanBuildGradle(f, out)
		}
	}
	return out, nil
}

func purl(group, artifact, version string) string {
	return "pkg:maven/" + group + "/" + artifact + "@" + version
}

func boolp(b bool) *bool { return &b }
