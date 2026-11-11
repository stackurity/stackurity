package docker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"time"

	"github.com/stackurity/stackurity/internal/collect/limits"
	"github.com/stackurity/stackurity/internal/model"
)

// ArchiveOptions say how ReadArchive reads and names an image archive.
type ArchiveOptions struct {
	Version string
	// WorkDir holds the temporary directory the image is unpacked into
	// (removed before ReadArchive returns); os.TempDir() when "".
	WorkDir string
	// MaxImageBytes bounds the image's unpacked files; DefaultMaxImageBytes
	// when <= 0.
	MaxImageBytes int64
	// Timeout bounds the reading; DefaultImageTimeout when <= 0.
	Timeout time.Duration
	// Arch picks the image from a multi-platform OCI index (amd64,
	// arm64); this machine's architecture when "".
	Arch string
	// Ref is the tag to name the image by when the archive carries it, as
	// a container's reference does for a running image.
	Ref string
	// Host, when set, names and identifies the image as on that host, as
	// Scanner.Collect does (HostImageScheme, runs_on). Otherwise the image
	// is identified by its tag (image-ref), or by its image ID (image-id)
	// when it has none.
	Host *model.AssetRef
	// SizeHint is the archive's size when known, for the free disk check.
	SizeHint int64
}

// ErrNotArchive means the input is not a docker save or OCI image archive.
var ErrNotArchive = errors.New("not a docker save or OCI image archive")

// ReadArchive inventories one image from a docker save or OCI image-layout
// archive (a tar, optionally gzip-compressed): the same extraction and
// collectors as a running container's image, with its name, tags, platform
// and working directory taken from the archive. An image over the size
// limit gives a batch whose coverage says it was skipped, not an error;
// input that is not an image archive is an error (ErrNotArchive).
func ReadArchive(ctx context.Context, r io.Reader, o ArchiveOptions) (*model.ObservationBatch, error) {
	max := o.MaxImageBytes
	if max <= 0 {
		max = DefaultMaxImageBytes
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultImageTimeout
	}
	arch := o.Arch
	if arch == "" {
		arch = runtime.GOARCH
	}
	if o.Host != nil && len(o.Host.Identifiers) == 0 {
		return nil, errors.New("the host needs at least one identifier")
	}
	work := o.WorkDir
	if work == "" {
		work = os.TempDir()
	}
	if free, ok := freeBytes(work); ok && o.SizeHint > 0 && free < o.SizeHint+diskMargin {
		return nil, fmt.Errorf("not enough free disk in %s to unpack the image (%s needed, %s free)",
			work, limits.Bytes(o.SizeHint+diskMargin), limits.Bytes(free))
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tmp, err := os.MkdirTemp(work, "stackurity-image-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	br := bufio.NewReaderSize(r, 64<<10)
	var in io.Reader = br
	if head, _ := br.Peek(2); bytes.Equal(head, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNotArchive, err)
		}
		defer gz.Close()
		in = gz
	}
	x := newExtractor(tmp, max)
	x.drain = true
	if err := x.read(ctx, in); err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("stopped after %s: %w", timeout, ctx.Err())
		}
		if x.small["manifest.json"] != nil || x.small["index.json"] != nil {
			return nil, err // an image archive, unreadable further on
		}
		return nil, fmt.Errorf("%w: %v", ErrNotArchive, err)
	}
	info, err := x.image(arch)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotArchive, err)
	}
	b, scope := archiveBatch(o, info)
	if x.tooLarge != nil {
		fill(b, scope, Reading{Coverage: []model.CoverageItem{{Scope: scope, Status: "skipped", Reason: x.tooLarge.Error()}}}, false)
		return b, nil
	}
	root, err := x.build(ctx, arch)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("stopped after %s: %w", timeout, ctx.Err())
		}
		return nil, fmt.Errorf("read image: %w", err)
	}
	fill(b, scope, ReadRoot(ctx, root, info, o.Version), true)
	return b, nil
}

// archiveBatch is the image's batch, named as Scanner.Collect names a
// running image, and the scope of its coverage.
func archiveBatch(o ArchiveOptions, info *Image) (*model.ObservationBatch, string) {
	im := &image{id: info.ID, info: info}
	if o.Ref != "" {
		im.refs = []string{o.Ref}
	}
	ref, ident := naming(im, map[string]bool{})
	attrs := map[string]string{"image": ref, "image_id": info.ID, "source": "archive"}
	infoAttributes(attrs, info)
	col := model.Collector{ID: CollectorID, Version: o.Version, Method: "agent"}
	asset := model.AssetRef{Kind: model.AssetImage, Name: ref, Attributes: attrs}
	var rel []model.RelationRef
	switch {
	case o.Host != nil:
		attrs["host"] = o.Host.Name
		asset.Name = ref + " on " + o.Host.Name
		asset.Environment = o.Host.Environment
		asset.Identifiers = []model.Identifier{{Scheme: model.HostImageScheme, Value: ident}}
		rel = []model.RelationRef{{Kind: "runs_on", To: o.Host.Identifiers}}
	case ident == info.ID:
		asset.Identifiers = []model.Identifier{{Scheme: "image-id", Value: ident}}
	default:
		asset.Identifiers = []model.Identifier{{Scheme: "image-ref", Value: ident}}
	}
	b := model.NewBatch(col, asset)
	b.Relations = rel
	return b, "image:" + ref
}

// image is what the archive says about the image, as Docker's image
// inspect would: its ID (the config's digest), tags, platform and working
// directory.
func (x *extractor) image(arch string) (*Image, error) {
	m, err := x.manifest(arch)
	if err != nil {
		return nil, err
	}
	cfg, ok := x.small[path.Clean(m.config)]
	if m.config == "" || !ok {
		return nil, fmt.Errorf("image config %q is missing", m.config)
	}
	var c struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
		Config       struct {
			WorkingDir string `json:"WorkingDir"`
		} `json:"config"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return nil, fmt.Errorf("image config: %w", err)
	}
	sum := sha256.Sum256(cfg)
	im := &Image{ID: "sha256:" + hex.EncodeToString(sum[:]), Os: c.OS, Architecture: c.Architecture, Variant: c.Variant}
	for _, t := range m.tags {
		if t != "" && t != "<none>:<none>" {
			im.RepoTags = append(im.RepoTags, t)
		}
	}
	if c.Config.WorkingDir != "" {
		im.Config = &struct {
			WorkingDir string `json:"WorkingDir"`
		}{c.Config.WorkingDir}
	}
	return im, nil
}
