// Package plugin is the public contract for Stackurity collector plugins
// (PRD FR-12) and a small SDK for writing them in Go.
//
// A plugin is an executable. Stackurity runs it as
//
//	<plugin> metadata|validate|collect|health
//
// with a JSON Request on stdin, and reads one JSON Response from stdout.
// Anything written to stderr is kept as log output. The protocol is plain
// JSON so plugins can be written in any language; see docs/plugins.md.
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/netguard"
)

// ProtocolVersion is bumped on breaking changes to Request or Response.
const ProtocolVersion = "1"

// Wire types shared with the core (aliases keep them identical).
type (
	ObservationBatch = model.ObservationBatch
	Observation      = model.Observation
	AssetRef         = model.AssetRef
	Identifier       = model.Identifier
	Collector        = model.Collector
	CoverageItem     = model.CoverageItem
	Confidence       = model.Confidence
	AssetKind        = model.AssetKind
	RelationRef      = model.RelationRef
	// NetworkPolicy is the operator's rule for which addresses the plugin
	// may connect to on behalf of the workspace that runs it.
	NetworkPolicy = netguard.Policy
)

const (
	ConfidenceConfirmed = model.ConfidenceConfirmed
	ConfidenceInferred  = model.ConfidenceInferred
	ConfidenceLow       = model.ConfidenceLow
	ConfidenceUnknown   = model.ConfidenceUnknown

	AssetHost           = model.AssetHost
	AssetRepository     = model.AssetRepository
	AssetImage          = model.AssetImage
	AssetApplication    = model.AssetApplication
	AssetManagedService = model.AssetManagedService
	AssetCluster        = model.AssetCluster
	AssetWorkload       = model.AssetWorkload
)

// NewBatch starts a batch with the current schema version and time.
func NewBatch(c Collector, a AssetRef) *ObservationBatch { return model.NewBatch(c, a) }

// Metadata describes a plugin. Every field is shown to administrators
// before they enable it.
type Metadata struct {
	ID              string   `json:"id"`      // lowercase, e.g. "aws-rds"
	Name            string   `json:"name"`    // human readable
	Version         string   `json:"version"` // plugin version
	Maintainer      string   `json:"maintainer"`
	License         string   `json:"license"` // SPDX id
	Homepage        string   `json:"homepage,omitempty"`
	Description     string   `json:"description"`
	ProtocolVersion string   `json:"protocol_version"`
	SchemaVersion   string   `json:"schema_version"` // ObservationBatch schema it emits
	Capabilities    []string `json:"capabilities"`   // e.g. "inventory:managed_service"
	// What it needs, for review before enabling.
	Permissions   []string      `json:"permissions"`    // e.g. "rds:DescribeDBInstances (read-only)"
	Credentials   []string      `json:"credentials"`    // secret names it expects, e.g. "aws_access_key_id"
	NetworkAccess []string      `json:"network_access"` // hosts it contacts, e.g. "*.amazonaws.com"
	ConfigSchema  []ConfigField `json:"config_schema"`
	Frequency     string        `json:"default_frequency,omitempty"` // e.g. "6h"
	RateLimits    string        `json:"rate_limits,omitempty"`
	Limitations   []string      `json:"known_limitations"`
}

type ConfigField struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // string, number, boolean, string_list
	Required    bool   `json:"required"`
	Description string `json:"description"`
}

// Request is sent on stdin.
type Request struct {
	ProtocolVersion string            `json:"protocol_version"`
	Command         string            `json:"command"`
	Config          json.RawMessage   `json:"config,omitempty"`
	Secrets         map[string]string `json:"secrets,omitempty"`
	Deadline        time.Time         `json:"deadline,omitempty"`
	// Network is the address policy for targets taken from config, such as
	// a Kubernetes API server. The server always sends it for collect and
	// health; plugins that dial configured targets should use Dialer.
	Network *NetworkPolicy `json:"network,omitempty"`
}

// Response is written to stdout. Exactly one of the payload fields is set.
type Response struct {
	ProtocolVersion string              `json:"protocol_version"`
	Metadata        *Metadata           `json:"metadata,omitempty"`
	Valid           *ValidationResult   `json:"validation,omitempty"`
	Batches         []*ObservationBatch `json:"batches,omitempty"`
	Health          *HealthStatus       `json:"health,omitempty"`
	Error           string              `json:"error,omitempty"`
}

type ValidationResult struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems,omitempty"`
}

type HealthStatus struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// Plugin is what a Go plugin implements; Serve handles the protocol.
type Plugin interface {
	Metadata() Metadata
	Validate(config json.RawMessage) ValidationResult
	Collect(ctx context.Context, config json.RawMessage, secrets map[string]string) ([]*ObservationBatch, error)
	Health(ctx context.Context, config json.RawMessage, secrets map[string]string) HealthStatus
}

// Serve runs one protocol exchange using os.Args, stdin and stdout, then
// exits. Call it from main.
func Serve(p Plugin) {
	code := serve(p, os.Args[1:], os.Stdin, os.Stdout)
	os.Exit(code)
}

func serve(p Plugin, args []string, in io.Reader, out io.Writer) int {
	resp := Response{ProtocolVersion: ProtocolVersion}
	write := func(code int) int {
		_ = json.NewEncoder(out).Encode(resp)
		return code
	}
	if len(args) != 1 {
		resp.Error = "usage: <plugin> metadata|validate|collect|health"
		return write(2)
	}
	var req Request
	if args[0] != "metadata" {
		if err := json.NewDecoder(io.LimitReader(in, 16<<20)).Decode(&req); err != nil {
			resp.Error = "invalid request: " + err.Error()
			return write(2)
		}
		if req.ProtocolVersion != "" && req.ProtocolVersion != ProtocolVersion {
			resp.Error = fmt.Sprintf("unsupported protocol version %q", req.ProtocolVersion)
			return write(2)
		}
	}
	ctx := context.Background()
	if req.Network != nil {
		ctx = WithNetwork(ctx, *req.Network)
	}
	if !req.Deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, req.Deadline)
		defer cancel()
	}
	switch args[0] {
	case "metadata":
		m := p.Metadata()
		m.ProtocolVersion, m.SchemaVersion = ProtocolVersion, model.BatchSchemaVersion
		resp.Metadata = &m
	case "validate":
		v := p.Validate(req.Config)
		resp.Valid = &v
	case "collect":
		if v := p.Validate(req.Config); !v.OK {
			resp.Error = "invalid config"
			resp.Valid = &v
			return write(1)
		}
		batches, err := p.Collect(ctx, req.Config, req.Secrets)
		if err != nil {
			resp.Error = err.Error()
			return write(1)
		}
		resp.Batches = batches
	case "health":
		h := p.Health(ctx, req.Config, req.Secrets)
		resp.Health = &h
	default:
		resp.Error = "unknown command " + args[0]
		return write(2)
	}
	return write(0)
}

type networkKey struct{}

// WithNetwork returns a context carrying a network policy, as Serve does
// with the one in the request. Use it to test a plugin's Collect.
func WithNetwork(ctx context.Context, p NetworkPolicy) context.Context {
	return context.WithValue(ctx, networkKey{}, p)
}

// Dialer returns a DialContext function, for an http.Transport, that refuses
// addresses the server's network policy blocks for this run (internal
// networks, cloud metadata). Without a policy in the request, as when a
// plugin is run by hand, every address is allowed.
func Dialer(ctx context.Context) func(ctx context.Context, network, addr string) (net.Conn, error) {
	p, ok := ctx.Value(networkKey{}).(NetworkPolicy)
	if !ok {
		p = NetworkPolicy{AllowPrivate: true}
	}
	return p.DialContext
}

// AllowsPrivate reports whether this run may reach internal networks.
func AllowsPrivate(ctx context.Context) bool {
	p, ok := ctx.Value(networkKey{}).(NetworkPolicy)
	return !ok || p.AllowPrivate
}
