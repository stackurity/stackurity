// Package model defines the wire types shared by collectors, the CLI and the
// server. ObservationBatch is the single ingest contract: agents, lockfile
// scans, SBOM imports, scanner adapters and plugins all produce one.
package model

import "time"

// BatchSchemaVersion is bumped on any breaking change to ObservationBatch.
const BatchSchemaVersion = "1"

type AssetKind string

const (
	AssetHost           AssetKind = "host"
	AssetRepository     AssetKind = "repository"
	AssetImage          AssetKind = "image"
	AssetApplication    AssetKind = "application"
	AssetManagedService AssetKind = "managed_service"
	AssetSBOM           AssetKind = "sbom"
	// A Kubernetes cluster, and a workload in it (a Deployment, StatefulSet,
	// DaemonSet, CronJob, Job or bare Pod).
	AssetCluster  AssetKind = "cluster"
	AssetWorkload AssetKind = "workload"
)

func (k AssetKind) Valid() bool {
	switch k {
	case AssetHost, AssetRepository, AssetImage, AssetApplication, AssetManagedService, AssetSBOM, AssetCluster, AssetWorkload:
		return true
	}
	return false
}

// Confidence describes how sure a collector is about a version value.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "confirmed" // read from an authoritative local source (package DB, lockfile)
	ConfidenceInferred  Confidence = "inferred"  // derived (manifest range, filename, binary banner)
	ConfidenceLow       Confidence = "low"
	ConfidenceUnknown   Confidence = "unknown" // version missing
)

func (c Confidence) Valid() bool {
	switch c {
	case ConfidenceConfirmed, ConfidenceInferred, ConfidenceLow, ConfidenceUnknown:
		return true
	}
	return false
}

// Collector identifies what produced a batch.
type Collector struct {
	ID      string `json:"id"`      // e.g. "linux-agent", "npm-lockfile", "cyclonedx-import"
	Version string `json:"version"` // collector/tool version
	Method  string `json:"method"`  // agent, lockfile, sbom, scanner, registry, cloud-api, plugin
}

// Identifier is one external identity for an asset, e.g. machine-id or git URL.
type Identifier struct {
	Scheme string `json:"scheme"`
	Value  string `json:"value"`
}

// AssetRef describes the asset a batch is about.
type AssetRef struct {
	Kind        AssetKind         `json:"kind"`
	Name        string            `json:"name"`
	Identifiers []Identifier      `json:"identifiers"`
	Environment string            `json:"environment,omitempty"`
	Provider    string            `json:"provider,omitempty"`
	Region      string            `json:"region,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty"` // os, os_version, arch, git_ref, digest...
}

// Observation is one component seen on the asset.
type Observation struct {
	Purl       string            `json:"purl"` // full purl including version where known
	Version    string            `json:"version"`
	Location   string            `json:"location,omitempty"` // file path, layer, package DB
	Direct     *bool             `json:"direct,omitempty"`   // nil when unknown
	Scope      string            `json:"scope,omitempty"`    // runtime, dev, os
	Confidence Confidence        `json:"confidence"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

// CoverageItem records what a collector did and did not check (FR-16).
type CoverageItem struct {
	Scope  string `json:"scope"`  // e.g. "dpkg", "rpm", "npm:package-lock.json"
	Status string `json:"status"` // checked, skipped, failed, unsupported, partial
	Reason string `json:"reason,omitempty"`
}

// AppPathScheme identifies an application by its directory on a host. The
// server scopes the value to the host named by the batch's runs_on
// relation, so the same path on two hosts is two applications.
const AppPathScheme = "app-path"

// HostImageScheme identifies a container image on a host by the tag its
// containers run (postgres:16), or by its image ID when it has no tag.
// Like AppPathScheme, the server scopes the value to the host named by the
// batch's runs_on relation: the same tag on two hosts can be two different
// builds. A rebuilt image under the same tag is the same asset.
const HostImageScheme = "host-image"

// RelationRef links the batch's asset to another asset, named by any of its
// identifiers (e.g. a host by machine-id, a repository by git-url). The
// server ignores a relation whose target it does not know yet.
type RelationRef struct {
	Kind string       `json:"kind"` // runs_on, built_from, deployed_as
	To   []Identifier `json:"to"`
}

type ObservationBatch struct {
	SchemaVersion string         `json:"schema_version"`
	Collector     Collector      `json:"collector"`
	Asset         AssetRef       `json:"asset"`
	ObservedAt    time.Time      `json:"observed_at"`
	Observations  []Observation  `json:"observations"`
	Coverage      []CoverageItem `json:"coverage"`
	// Complete means the observations are the full set for the collector's
	// scope, so components absent from the batch can be marked gone.
	Complete bool `json:"complete"`
	// Relations are optional; when present they replace the relations this
	// collector reported for the asset before.
	Relations []RelationRef `json:"relations,omitempty"`
	// Apps, on a host's batch, lists every application directory the agent
	// reports for the host in this run (each in its own batch after this
	// one). An application on the host it reported before that is not in
	// the list is gone: its directory was removed, it is no longer the
	// current release, or it is no longer configured. Nil when the agent
	// does not know the full list (an older agent, or discovery that
	// stopped at its limits). Sent only to servers that list the
	// "app_list" feature in GET /meta.
	Apps *AppList `json:"apps,omitempty"`
	// Images, on a host's batch from the agent's Docker check, lists the
	// identities (HostImageScheme values) of every image its running
	// containers use. An image on the host reported before that is not in
	// the list is no longer running and is marked removed. Nil when the
	// agent could not list them all. Sent only to servers that list the
	// "host_images" feature in GET /meta.
	Images *ImageList `json:"images,omitempty"`
	// Secrets: what a secret scan of the asset's files found (API keys,
	// tokens, passwords; never their values). Nil when no scan ran. When
	// Complete, a secret the asset had from the same collector that is not
	// listed is gone. Sent only to servers that list the "exposed_secrets"
	// feature in GET /meta.
	Secrets *SecretList `json:"secrets,omitempty"`
}

// SecretList is the result of one secret scan.
type SecretList struct {
	Findings []SecretFinding `json:"findings"`
	// Complete: every file the scan should read was read.
	Complete bool `json:"complete"`
}

// SecretFinding is one secret in one file. It never holds the value.
type SecretFinding struct {
	Rule     string `json:"rule"`  // github-token, private-key, generic-secret...
	Title    string `json:"title"` // "GitHub token"
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	// Fingerprint: 64 hex characters, the same for the same secret
	// wherever it is (for a weak value, the same only in the same place).
	Fingerprint string `json:"fingerprint"`
	Preview     string `json:"preview"`  // masked: "ghp_…4f2a", "14 characters"
	Severity    string `json:"severity"` // critical, high, medium, low
	Exposure    string `json:"exposure"` // public, repository
	Note        string `json:"note,omitempty"`
}

// MaxSecrets bounds SecretList.Findings.
const MaxSecrets = 1000

// ImageList is the set of container images a host's agent reports.
type ImageList struct {
	Refs []string `json:"refs"`
}

// AppList is the set of application directories a host's agent reports.
type AppList struct {
	Dirs []string `json:"dirs"`
}

// MaxAppDirs bounds AppList.Dirs.
const MaxAppDirs = 1000

// MaxHostImages bounds ImageList.Refs.
const MaxHostImages = 1000

func NewBatch(c Collector, a AssetRef) *ObservationBatch {
	return &ObservationBatch{
		SchemaVersion: BatchSchemaVersion,
		Collector:     c,
		Asset:         a,
		ObservedAt:    time.Now().UTC(),
		Observations:  []Observation{},
		Coverage:      []CoverageItem{},
	}
}

func (b *ObservationBatch) Cover(scope, status, reason string) {
	b.Coverage = append(b.Coverage, CoverageItem{Scope: scope, Status: status, Reason: reason})
}
