package main

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/pkg/pack"
)

// isGradleLockfile matches gradle.lockfile, buildscript-gradle.lockfile and
// the per-configuration files of older Gradle (gradle/dependency-locks/*.lockfile).
func isGradleLockfile(name string) bool { return strings.HasSuffix(name, ".lockfile") }

// gradleProjectDir is the project a lockfile belongs to: its own directory,
// or two levels up for gradle/dependency-locks/x.lockfile.
func gradleProjectDir(f pack.File) string {
	d := f.Dir()
	if strings.HasSuffix(d, "gradle/dependency-locks") {
		d = path.Dir(path.Dir(d))
		if d == "." {
			d = ""
		}
	}
	return d
}

// scanGradleLockfile reads lines of group:name:version[=configuration,...].
func scanGradleLockfile(f pack.File, out *pack.Response) {
	scope := "maven:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	n, bad := 0, 0
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coord, configs, _ := strings.Cut(line, "=")
		parts := strings.Split(coord, ":")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			bad++
			continue
		}
		o := pack.Observation{
			Purl: purl(parts[0], parts[1], parts[2]), Version: parts[2], Location: f.Path,
			Confidence: pack.ConfidenceConfirmed,
		}
		if testOnly(configs) {
			o.Scope = "test"
		} else if strings.HasPrefix(f.Name(), "buildscript") {
			o.Scope = "build"
		}
		out.Observations = append(out.Observations, o)
		n++
	}
	switch {
	case bad > 0:
		out.Partial(scope, fmt.Sprintf("%d lines were not group:name:version", bad))
	default:
		out.Checked(scope)
	}
}

// testOnly reports whether every configuration a dependency is locked in is a
// test one (testCompileClasspath, testRuntimeClasspath, ...).
func testOnly(configs string) bool {
	if configs == "" {
		return false
	}
	for _, c := range strings.Split(configs, ",") {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(c)), "test") {
			return false
		}
	}
	return true
}

// Dependency declarations with a literal "group:name:version" string, in
// Groovy or Kotlin DSL: implementation 'g:a:1.0', api("g:a:1.0") and the like.
var gradleDep = regexp.MustCompile(`(?m)^\s*(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|testCompileOnly|annotationProcessor|kapt|ksp|compile|runtime|testCompile|classpath)\s*\(?\s*(?:platform\s*\()?\s*["']([^"':$\s]+):([^"':$\s]+):([^"'$\s]+)["']`)

func scanBuildGradle(f pack.File, out *pack.Response) {
	scope := "maven:" + f.Path
	data, err := f.Bytes()
	if err != nil {
		out.Failed(scope, "could not read the file")
		return
	}
	matches := gradleDep.FindAllStringSubmatch(string(data), -1)
	for _, m := range matches {
		o := pack.Observation{
			Purl: purl(m[2], m[3], m[4]), Version: m[4], Location: f.Path, Direct: boolp(true),
			Confidence: pack.ConfidenceInferred,
		}
		if strings.HasPrefix(m[1], "test") {
			o.Scope = "test"
		}
		out.Observations = append(out.Observations, o)
	}
	out.Partial(scope, "declared dependencies with literal versions only; enable Gradle dependency locking (gradle.lockfile) "+
		"for exact versions, including transitive dependencies")
}
