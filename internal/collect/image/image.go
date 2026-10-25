// Package image inventories container images by running Syft against a
// registry reference. Syft reads image layers from the registry directly; no
// container runtime is used and nothing from the image is executed.
package image

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/stackurity/stackurity/internal/netguard"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/sbom"
)

type Config struct {
	Image       string `json:"image"` // e.g. ghcr.io/acme/shop:1.4 or ...@sha256:...
	Environment string `json:"environment,omitempty"`
	Platform    string `json:"platform,omitempty"` // e.g. linux/amd64
	Username    string `json:"username,omitempty"` // registry user when the secret is a password/token
}

// Image references: registry/path[:tag][@sha256:digest]. Deliberately strict
// so the value can never be read as a Syft source scheme or option.
var refRE = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$|^[a-z0-9]+([._-][a-z0-9]+)*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

var platformRE = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9]+(/[a-z0-9]+)?$`)

func (c Config) Validate() error {
	if !refRE.MatchString(c.Image) {
		return errors.New("image must be a registry reference such as ghcr.io/acme/app:1.2 or nginx@sha256:...")
	}
	if c.Platform != "" && !platformRE.MatchString(c.Platform) {
		return errors.New("platform must look like linux/amd64")
	}
	return nil
}

type Scanner struct {
	Syft    string // path to the syft binary; "syft" when empty
	Version string
	Timeout time.Duration
	WorkDir string
}

// RegistryHost is the registry an image reference points at; references
// without one (nginx, library/nginx) come from Docker Hub.
func RegistryHost(ref string) string {
	first, _, found := strings.Cut(ref, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host, _, _ := strings.Cut(first, ":")
		if strings.HasPrefix(first, "[") {
			host = strings.Trim(strings.SplitN(first, "]", 2)[0], "[")
		}
		return host
	}
	return "registry-1.docker.io"
}

// Scan generates a CycloneDX SBOM with Syft and converts it to a batch.
func (s *Scanner) Scan(ctx context.Context, cfg Config, secret string) (*model.ObservationBatch, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	bin := s.Syft
	if bin == "" {
		bin = "syft"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("syft is not installed on the server: %w", err)
	}
	// Syft makes its own connections; the registry host is at least checked
	// against the workspace's network policy before it runs.
	if _, err := netguard.Resolve(ctx, RegistryHost(cfg.Image)); err != nil {
		return nil, err
	}
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := os.MkdirAll(s.WorkDir, 0o700); err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp(s.WorkDir, "syft-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	// Not -q: that also silences errors, and the reason a registry refused
	// (DENIED, UNAUTHORIZED) is what the coverage ledger needs. Without a
	// terminal Syft writes nothing else to stderr.
	args := []string{"scan", "registry:" + cfg.Image, "-o", "cyclonedx-json"}
	if cfg.Platform != "" {
		args = append(args, "--platform", cfg.Platform)
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + tmp,
		"TMPDIR=" + tmp,
		"SYFT_CHECK_FOR_APP_UPDATE=false",
	}
	if secret != "" {
		host := registryHost(cfg.Image)
		env = append(env, "SYFT_REGISTRY_AUTH_AUTHORITY="+host)
		if cfg.Username != "" {
			env = append(env, "SYFT_REGISTRY_AUTH_USERNAME="+cfg.Username, "SYFT_REGISTRY_AUTH_PASSWORD="+secret)
		} else {
			env = append(env, "SYFT_REGISTRY_AUTH_TOKEN="+secret)
		}
	}
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limited{w: &stdout, n: sbom.MaxDocumentSize}, &limited{w: &stderr, n: 64 << 10, truncate: true}
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if secret != "" {
			msg = strings.ReplaceAll(msg, secret, "[redacted]")
		}
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return nil, fmt.Errorf("syft failed: %v: %s", err, msg)
	}

	digest := sbomDigest(stdout.Bytes())
	asset := &model.AssetRef{
		Kind:        model.AssetImage,
		Name:        cfg.Image,
		Environment: cfg.Environment,
		Identifiers: []model.Identifier{{Scheme: "image-ref", Value: cfg.Image}},
		Attributes:  map[string]string{"image": cfg.Image},
	}
	if digest != "" {
		asset.Attributes["digest"] = digest
	}
	b, err := sbom.Import(bytes.NewReader(stdout.Bytes()), asset, s.Version)
	if err != nil {
		return nil, err
	}
	b.Collector = model.Collector{ID: "image-scanner", Version: s.Version, Method: "scanner"}
	b.Coverage = []model.CoverageItem{{Scope: "image:" + cfg.Image, Status: "checked"}}
	b.Complete = true
	return b, nil
}

func registryHost(ref string) string {
	first, _, found := strings.Cut(ref, "/")
	if found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		return first
	}
	return "index.docker.io"
}

// sbomDigest pulls the image digest Syft records on the root component.
func sbomDigest(doc []byte) string {
	var bom struct {
		Metadata struct {
			Component struct {
				Version string `json:"version"`
			} `json:"component"`
		} `json:"metadata"`
	}
	if json.Unmarshal(doc, &bom) == nil && strings.HasPrefix(bom.Metadata.Component.Version, "sha256:") {
		return bom.Metadata.Component.Version
	}
	return ""
}

// limited caps how much a subprocess can make us buffer. With truncate,
// output past the cap is dropped instead of failing the write.
type limited struct {
	w        *bytes.Buffer
	n        int64
	truncate bool
}

func (l *limited) Write(p []byte) (int, error) {
	if int64(l.w.Len()+len(p)) > l.n {
		if l.truncate {
			l.w.Write(p[:max(0, int(l.n)-l.w.Len())])
			return len(p), nil
		}
		return 0, errors.New("output too large")
	}
	return l.w.Write(p)
}

// ReferenceOnly reports whether a batch only names an image for the scanner
// to read: an image asset with an image-ref identifier and no packages, as
// the Kubernetes plugin reports the images pods run. It returns the scan
// config, with the platform the image runs on when that is known.
func ReferenceOnly(b *model.ObservationBatch) (Config, bool) {
	if b.Asset.Kind != model.AssetImage || len(b.Observations) > 0 {
		return Config{}, false
	}
	for _, id := range b.Asset.Identifiers {
		if id.Scheme != "image-ref" {
			continue
		}
		cfg := Config{Image: id.Value, Platform: b.Asset.Attributes["platform"]}
		if cfg.Platform != "" && !platformRE.MatchString(cfg.Platform) {
			cfg.Platform = ""
		}
		if cfg.Validate() != nil {
			return Config{}, false
		}
		return cfg, true
	}
	return Config{}, false
}
