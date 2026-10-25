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
	ConfidenceInferred  Confidence = "inferred"  // derived (manifest range, filename, banner)
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
}

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
