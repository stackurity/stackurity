// Package engine is Stackurity's scan engine for use outside this module,
// such as the standalone scanner (github.com/stackurity/scan). It needs no
// server and no database: it reads what is installed (lockfiles, the host's
// packages, running containers), finds keys and passwords written in files,
// and matches components against advisories (OSV) and release lifecycles
// (endoflife.date) that the caller supplies.
//
// It is a thin, stable surface over the same internal packages the server
// and agent use, so a parser or matching fix lands in both.
//
// Stability: the API may change before 1.0; breaking changes are listed in
// CHANGELOG.md under "pkg/engine".
package engine

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/collect/apps"
	"github.com/stackurity/stackurity/internal/collect/darwin"
	"github.com/stackurity/stackurity/internal/collect/docker"
	"github.com/stackurity/stackurity/internal/collect/leaks"
	"github.com/stackurity/stackurity/internal/collect/linux"
	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/intel/eoloverlay"
	"github.com/stackurity/stackurity/internal/lifecycle"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/sbom"
)

// Inventory types: what the agent and `stackurity scan` upload.
type (
	Batch       = model.ObservationBatch
	Observation = model.Observation
	Coverage    = model.CoverageItem
	AssetRef    = model.AssetRef
	Identifier  = model.Identifier
	Leak        = model.Leak
	LeakScan    = model.LeakScan
)

// Advisory types (OSV schema) and match results.
type (
	Vulnerability = osv.Vulnerability
	Affected      = osv.Affected
	Range         = osv.Range
	Event         = osv.Event
	Target        = osv.Target
	AffectedMatch = osv.Match
	Rating        = osv.Rating
)

// Lifecycle types.
type (
	LifecycleResolver = lifecycle.Resolver
	LifecycleMatch    = lifecycle.Match
)

// SBOM export types.
type (
	SBOMComponent = sbom.ExportComponent
	SBOMProperty  = sbom.Property
)

// Asset kinds.
const (
	AssetRepository = model.AssetRepository
)

// ScanDir parses the lockfiles under dir as data (no package manager,
// script or build is run) into a repository batch named name.
func ScanDir(ctx context.Context, dir, name, toolVersion string) (*Batch, error) {
	asset := model.AssetRef{Kind: model.AssetRepository, Name: name,
		Identifiers: []model.Identifier{{Scheme: "name:repository", Value: name}}}
	return lockfile.ScanDirWith(ctx, dir, asset, toolVersion, nil)
}

// HostSoftware reads this machine's operating system, its packages
// (Homebrew and /Applications on macOS; dpkg, rpm or apk on Linux), installed
// runtimes and host-wide libraries. Other systems return nil.
func HostSoftware(ctx context.Context, toolVersion string) ([]*Batch, error) {
	host, _ := os.Hostname()
	scanner := &apps.Scanner{Root: "/"}
	switch runtime.GOOS {
	case "darwin":
		col := darwin.New(toolVersion)
		col.Global = scanner.ScanGlobalDirs
		sys, err := col.Collect(ctx, host)
		if err != nil {
			return nil, err
		}
		return []*Batch{sys, col.CollectSoftware(ctx, sys)}, nil
	case "linux":
		col := linux.New(toolVersion)
		sys, err := col.Collect(ctx, host, col.MachineID())
		if err != nil {
			return nil, err
		}
		return []*Batch{sys}, nil
	}
	return nil, nil
}

// RunningContainers inventories the images of the containers a Docker
// engine runs, read layer by layer from the engine's socket (empty: the
// default socket). The first batch is the host's; one batch per image
// follows. Nothing is pulled or run.
func RunningContainers(ctx context.Context, socket, toolVersion string) []*Batch {
	if socket == "" {
		socket = DefaultDockerSocket()
	}
	work, err := os.MkdirTemp("", "stackurity-image-")
	if err != nil {
		return nil
	}
	defer os.RemoveAll(work)
	host, _ := os.Hostname()
	s := &docker.Scanner{Engine: docker.NewEngine(socket), Version: toolVersion, WorkDir: work}
	return s.Collect(ctx, model.AssetRef{Kind: model.AssetHost, Name: host,
		Identifiers: []model.Identifier{{Scheme: "hostname", Value: host}}})
}

// DefaultDockerSocket is $DOCKER_HOST's unix socket, Docker Desktop's
// per-user socket on macOS, or /var/run/docker.sock.
func DefaultDockerSocket() string {
	if h := os.Getenv("DOCKER_HOST"); len(h) > 7 && h[:7] == "unix://" {
		return h[7:]
	}
	if home, err := os.UserHomeDir(); err == nil && runtime.GOOS == "darwin" {
		if p := filepath.Join(home, ".docker", "run", "docker.sock"); exists(p) {
			return p
		}
	}
	return "/var/run/docker.sock"
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// LeakResult is a leaked-key scan: what was found (graded, values never
// kept) and whether every file was read.
type LeakResult struct {
	Leaks    []Leak
	Complete bool
	Reason   string
	Files    int
}

// RepoLeaks looks for keys and passwords in dir: in a Git checkout only the
// files Git tracks, otherwise every file. Paths are relative to dir.
func RepoLeaks(ctx context.Context, dir string) LeakResult {
	return graded(leaks.Repo(ctx, dir))
}

// DirLeaks looks for keys and passwords in every file under dir (files,
// when not nil, limits the scan to those relative paths).
func DirLeaks(ctx context.Context, dir string, files []string) LeakResult {
	return graded(leaks.Dir(ctx, dir, leaks.Options{Files: files}))
}

// LeaksIn looks for keys and passwords in one file's contents (a Git blob,
// an image layer's file). name decides which rules apply (.env, config).
func LeaksIn(name string, data []byte) []Leak {
	out := leaks.Scan(name, data)
	for i := range out {
		leaks.Grade(&out[i], "", false)
	}
	return out
}

// LeaksWithValues is LeaksIn that also hands each leak's value to onValue,
// for checking whether a key is live. The engine keeps no value; the caller
// must not store or print it either.
func LeaksWithValues(name string, data []byte, onValue func(l Leak, value string)) []Leak {
	out := leaks.ScanValues(name, data, onValue)
	for i := range out {
		leaks.Grade(&out[i], "", false)
	}
	return out
}

func graded(r leaks.Result) LeakResult {
	for i := range r.Leaks {
		leaks.Grade(&r.Leaks[i], "", false)
	}
	return LeakResult{Leaks: r.Leaks, Complete: r.Complete, Reason: r.Reason, Files: r.Files}
}

// LeakAtLeast reports whether severity is min or worse.
func LeakAtLeast(severity, min string) bool { return leaks.AtLeast(severity, min) }

// ValidLeakSeverity reports whether s is low, medium, high or critical.
func ValidLeakSeverity(s string) bool { return leaks.ValidSeverity(s) }

// OSVTarget maps a component (purl with qualifiers, version, evidence) to
// its OSV ecosystem and package name. ok is false for an ecosystem OSV does
// not cover yet: report that as coverage, not as clean.
func OSVTarget(purl, version string, evidence map[string]string) (Target, bool) {
	return osv.TargetFor(purl, version, evidence)
}

// MatchEcosystem reports whether an advisory's ecosystem applies to the
// target's ("Debian:12" to "Debian:12", "npm" to "npm").
func MatchEcosystem(advisory, target string) bool { return osv.MatchEcosystem(advisory, target) }

// CheckAffected evaluates whether t's version is in a's ranges or versions,
// and the lowest fixed version above it.
func CheckAffected(a Affected, t Target) (AffectedMatch, error) { return osv.Check(a, t) }

// Rate derives an advisory's severity from its CVSS vectors and labels.
func Rate(v *Vulnerability) Rating { return osv.Rate(v) }

// SeverityRank orders severities: unknown 0, none 1, low 2 ... critical 5.
func SeverityRank(level string) int { return osv.LevelRank(level) }

// NewLifecycleResolver maps components to endoflife.date products, given
// endoflife.date's purl identifiers (versionless, lower case) and product
// names, with Stackurity's lifecycle overlay applied on top.
func NewLifecycleResolver(byPurl map[string]string, names map[string]bool) *LifecycleResolver {
	return &lifecycle.Resolver{ByPurl: byPurl, Names: names, Overlay: eoloverlay.Default()}
}

// CycleIndex finds the release line a version belongs to among cycle names
// (exact, then the longest dotted prefix); -1 when none.
func CycleIndex(cycles []string, version string) int { return lifecycle.CycleIndex(cycles, version) }

// ExportCycloneDX writes a CycloneDX 1.6 JSON document for one asset.
func ExportCycloneDX(w io.Writer, assetName, assetKind, toolVersion string, comps []SBOMComponent, props ...SBOMProperty) error {
	return sbom.ExportCycloneDX(w, assetName, assetKind, toolVersion, comps, props...)
}

// IngestResult is what the server answers an upload with.
type IngestResult = client.IngestResult

// Upload sends a batch to a Stackurity server or Stackurity Cloud through
// the ingest API (POST /api/v1/ingest), as `stackurity scan` does. token is
// an API or collector token.
func Upload(ctx context.Context, server, token, toolVersion string, b *Batch) (*IngestResult, error) {
	cl, err := client.New(server, token, toolVersion)
	if err != nil {
		return nil, err
	}
	return cl.Ingest(ctx, b)
}
