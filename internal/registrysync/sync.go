// Package registrysync runs a connected container registry (integration
// kind container_registry): it asks the registry which images to track
// (internal/collect/registry), records them (registry_images), stores each
// new image as an asset, queues the image scanner for them through the
// existing image.scan job, and marks the images the registry no longer
// has as removed.
package registrysync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/collect/image"
	"github.com/stackurity/stackurity/internal/collect/registry"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/secrets"
	"github.com/stackurity/stackurity/internal/store"
)

// Summary says what one run did.
type Summary struct {
	Repositories int `json:"repositories"`
	Tracked      int `json:"tracked"`
	NewImages    int `json:"new_images"`
	Untracked    int `json:"untracked"`
	Removed      int `json:"removed"`
	Refused      int `json:"refused"` // new images left out at the monitored-asset limit
	Scans        store.ImageScanStats
	Problems     []string `json:"problems,omitempty"`
}

// Note is the integration's status line after a run: nil when every
// repository was read and every image stored, else what went wrong
// (wrapping store.ErrAssetLimit when the limit refused images).
func (s Summary) Note() error {
	var parts []string
	if len(s.Problems) > 0 {
		p := s.Problems
		if len(p) > 3 {
			p = append(append([]string(nil), p[:3]...), fmt.Sprintf("and %d more", len(s.Problems)-3))
		}
		parts = append(parts, "not read, nothing in them marked removed: "+strings.Join(p, "; "))
	}
	if s.Refused > 0 {
		return fmt.Errorf("%s%d new images were not added because this organisation is at its monitored-asset limit; "+
			"the images already monitored were updated. See Settings, Usage: %w", prefix(parts), s.Refused, store.ErrAssetLimit)
	}
	if len(parts) > 0 {
		return errors.New(strings.Join(parts, ". "))
	}
	return nil
}

func prefix(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ". ") + ". "
}

// Options are the parts of a run that come from the server.
type Options struct {
	Version string
	// Fresh is how long a successful scan of a digest is reused.
	Fresh time.Duration
}

// Run discovers the registry's images and applies the result.
func Run(ctx context.Context, st *store.Store, in *store.Integration, cfg registry.Config, cr registry.Credentials, o Options) (Summary, error) {
	prev, err := st.RegistryImages(ctx, in.ID)
	if err != nil {
		return Summary{}, err
	}
	known := map[string]time.Time{}
	for _, p := range prev {
		if p.PushedAt != nil {
			known[p.Digest] = *p.PushedAt
		}
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	res, err := registry.Discover(dctx, cfg, cr, known)
	if err != nil {
		return Summary{}, err
	}
	return Apply(ctx, st, in, cfg, res, prev, o)
}

type key struct{ repo, digest string }

// Apply records a discovery result: tracks the images it chose, stores
// new ones as assets, queues their scans (most recently pushed first, at
// most the integration's image_scans), and untracks or removes the images
// it no longer chose. An image is removed only when the registry proves
// it gone: its repository is missing from a complete listing or does not
// exist, or a complete tag list has no tag on its digest (a tag it had
// that now points elsewhere does not keep it). A repository that could
// not be read changes nothing.
func Apply(ctx context.Context, st *store.Store, in *store.Integration, cfg registry.Config, res *registry.Result, prev []store.RegistryImage, o Options) (Summary, error) {
	var sum Summary
	chosen := map[key]bool{}
	var tracked []store.RegistryImage
	var batches []*model.ObservationBatch
	var batchRows []int
	byRepo := map[string]*registry.RepoResult{}
	for i := range res.Repositories {
		rr := &res.Repositories[i]
		byRepo[rr.Name] = rr
		sum.Repositories++
		if rr.Err != nil {
			sum.Problems = append(sum.Problems, rr.Name+": "+rr.Err.Error())
			continue
		}
		for _, im := range rr.Images {
			chosen[key{rr.Name, im.Digest}] = true
			var pushed *time.Time
			if !im.Pushed.IsZero() {
				p := im.Pushed
				pushed = &p
			}
			row, err := st.TrackRegistryImage(ctx, store.RegistryImage{IntegrationID: in.ID, Repository: rr.Name, Digest: im.Digest,
				ImageRef: im.Ref, Tags: im.Tags, PushedAt: pushed})
			if err != nil {
				return sum, err
			}
			tracked = append(tracked, row)
			if row.AssetID == nil {
				batches = append(batches, referenceBatch(cfg, res.Host, im, o.Version))
				batchRows = append(batchRows, len(tracked)-1)
			}
		}
	}
	if res.Skipped > 0 {
		sum.Problems = append(sum.Problems, fmt.Sprintf("%d repositories over the limit of %d", res.Skipped, registry.MaxRepositories))
	}
	// New images become image assets named by repository and tag, found
	// again by their digest reference; at the monitored-asset limit new
	// ones are left out (and tracked, so they are added once there is room).
	if len(batches) > 0 {
		results, refused, err := st.IngestAll(ctx, batches, 0)
		if err != nil {
			return sum, err
		}
		sum.Refused = len(refused)
		for i, r := range results {
			if r == nil {
				continue
			}
			row := &tracked[batchRows[i]]
			if err := st.SetRegistryImageAsset(ctx, row.ID, r.AssetID); err != nil {
				return sum, err
			}
			id := r.AssetID
			row.AssetID = &id
			sum.NewImages++
		}
	}
	sum.Tracked = len(tracked)

	var untrack, remove []int64
	for _, p := range prev {
		if p.RemovedAt != nil || chosen[key{p.Repository, p.Digest}] {
			continue
		}
		switch rr := byRepo[p.Repository]; {
		case rr != nil && rr.Err != nil:
			// Not read this time: nothing is known about it.
		case rr != nil && rr.Gone:
			remove = append(remove, p.ID)
		case rr != nil && !rr.StillTagged(p.Digest, p.Tags):
			remove = append(remove, p.ID)
		case rr == nil && res.ListComplete && !res.Listed[p.Repository]:
			remove = append(remove, p.ID)
		case p.Tracked:
			untrack = append(untrack, p.ID)
		}
	}
	if err := st.UntrackRegistryImages(ctx, untrack); err != nil {
		return sum, err
	}
	sum.Untracked = len(untrack)
	if _, err := st.RemoveRegistryImages(ctx, remove, o.Version); err != nil {
		return sum, err
	}
	sum.Removed = len(remove)

	// Scans: the existing image.scan job, by digest, so an image
	// re-tagged or tracked by several tags is read once.
	sort.SliceStable(tracked, func(i, j int) bool { return pushedAt(tracked[i]).After(pushedAt(tracked[j])) })
	var scans []store.ImageScan
	for _, t := range tracked {
		if t.AssetID == nil {
			continue
		}
		scans = append(scans, store.ImageScan{AssetID: *t.AssetID, Image: t.ImageRef, Platform: cfg.Platform, IntegrationID: in.ID})
	}
	if limit := cfg.ImageScanLimit(); len(scans) > 0 && limit > 0 {
		stats, err := st.QueueImageScans(ctx, scans, limit, o.Fresh)
		if err != nil {
			return sum, err
		}
		sum.Scans = stats
	}
	return sum, nil
}

func pushedAt(r store.RegistryImage) time.Time {
	if r.PushedAt == nil {
		return time.Time{}
	}
	return *r.PushedAt
}

// referenceBatch names an image for the scanner without reading it: the
// asset is created (or found by its digest reference) before its scan.
func referenceBatch(cfg registry.Config, host string, im registry.Image, version string) *model.ObservationBatch {
	attrs := map[string]string{
		"image":      im.Ref,
		"digest":     im.Digest,
		"repository": im.Repository,
		"tags":       strings.Join(im.Tags, ", "),
		"registry":   host,
	}
	if cfg.Platform != "" {
		attrs["platform"] = cfg.Platform
	}
	if !im.Pushed.IsZero() {
		attrs["pushed_at"] = im.Pushed.UTC().Format(time.RFC3339)
	}
	b := model.NewBatch(model.Collector{ID: store.RegistryCollector, Version: version, Method: "registry"}, model.AssetRef{
		Kind:        model.AssetImage,
		Name:        im.Display,
		Environment: cfg.Environment,
		Identifiers: []model.Identifier{{Scheme: "image-ref", Value: im.Ref}},
		Attributes:  attrs,
	})
	return b
}

// ErrAWSIntegration is a configuration whose aws_integration_id does not
// name an aws-managed plugin integration in the workspace.
var ErrAWSIntegration = errors.New("aws_integration_id must name an aws-managed plugin integration")

// AWSIntegration is the aws-managed plugin integration a registry borrows
// access keys (its secret) and role from, in the caller's workspace, with
// that role and external id.
func AWSIntegration(ctx context.Context, st *store.Store, id int64) (*store.Integration, string, string, error) {
	in, err := st.GetIntegration(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, "", "", ErrAWSIntegration
	}
	if err != nil {
		return nil, "", "", err
	}
	var pc struct {
		Plugin string `json:"plugin"`
		Config struct {
			RoleARN    string `json:"role_arn"`
			ExternalID string `json:"external_id"`
		} `json:"config"`
	}
	if in.Kind != "plugin" || json.Unmarshal(in.Config, &pc) != nil || pc.Plugin != "aws-managed" {
		return nil, "", "", ErrAWSIntegration
	}
	return in, pc.Config.RoleARN, pc.Config.ExternalID, nil
}

// Credentials resolves what a registry integration authenticates with:
// its own secret, or for Amazon ECR the access keys in it or in the
// aws-managed plugin integration aws_integration_id names (whose role and
// external id apply when the registry sets none). cfg is returned with
// that role filled in.
func Credentials(ctx context.Context, st *store.Store, res secrets.Resolver, cfg registry.Config, secretRef string) (registry.Config, registry.Credentials, error) {
	secret, err := res.Resolve(ctx, secretRef)
	if err != nil {
		return cfg, registry.Credentials{}, err
	}
	if cfg.Provider != registry.ECR {
		return cfg, registry.Credentials{Secret: secret}, nil
	}
	keys := secret
	if cfg.AWSIntegrationID != 0 {
		aws, role, ext, err := AWSIntegration(ctx, st, cfg.AWSIntegrationID)
		if err != nil {
			return cfg, registry.Credentials{}, err
		}
		if keys == "" {
			if keys, err = res.Resolve(ctx, aws.SecretRef); err != nil {
				return cfg, registry.Credentials{}, err
			}
		}
		if cfg.RoleARN == "" {
			cfg.RoleARN, cfg.ExternalID = role, ext
		}
	}
	k, err := registry.ParseAWSKeys(keys)
	if err != nil {
		return cfg, registry.Credentials{}, err
	}
	return cfg, registry.Credentials{AWS: &k}, nil
}

// ScanSecret is the secret an image scan reads the image with: none,
// unless a connected registry queued it, and then that registry's only
// when the image is on that registry's host (image.RegistryHost), so the
// credentials cannot be sent to another registry. It sets the user name
// on cfg.
func ScanSecret(ctx context.Context, st *store.Store, res secrets.Resolver, p store.ImageScan, cfg *image.Config) (string, error) {
	if p.IntegrationID == 0 {
		return "", nil
	}
	in, err := st.GetIntegration(ctx, p.IntegrationID)
	if errors.Is(err, store.ErrNotFound) {
		return "", nil
	}
	if err != nil || in.Kind != Kind {
		return "", err
	}
	var rc registry.Config
	if err := json.Unmarshal(in.Config, &rc); err != nil {
		return "", err
	}
	rc, cr, err := Credentials(ctx, st, res, rc, in.SecretRef)
	if err != nil {
		return "", err
	}
	host, user, secret, err := registry.ScanAuth(ctx, rc, cr)
	if err != nil || secret == "" {
		return "", err
	}
	if got := image.RegistryHost(cfg.Image); !strings.EqualFold(got, host) {
		return "", fmt.Errorf("refused to read %s with the credentials of %s: the image is on another registry", got, host)
	}
	cfg.Username = user
	return secret, nil
}

// Kind is the integration kind of a connected registry.
const Kind = "container_registry"
