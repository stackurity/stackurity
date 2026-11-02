// Package docker inventories the images of the containers running on a
// Linux host, for the agent's --docker option.
//
// It asks the Docker daemon over its Unix socket for the running
// containers, and exports each distinct image (GET /images/{id}/get, what
// docker save does) into a temporary directory, streamed and bounded. The
// image's filesystem is then read by the same collectors that read the host
// (OS package databases, runtimes, applications and their lockfiles). No
// container is entered and nothing in an image is run; no registry is
// contacted, so images built on the host and never pushed are covered too.
//
// Each image is its own asset, linked to the host by runs_on and identified
// on the server by its tag scoped to the host (model.HostImageScheme), or
// by its image ID when it has no tag. An image ID's contents never change,
// so an image is read again only when its ID is new to the agent or its
// last reading is older than Rescan.
package docker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/collect/limits"
	"github.com/stackurity/stackurity/internal/model"
)

// CollectorID reports a host's Docker images (and, on the host, whether
// Docker could be read).
const CollectorID = "linux-docker"

const (
	// DefaultMaxImageBytes bounds an image's unpacked size (as Docker
	// reports it, and as written while extracting). Larger images are
	// skipped with a coverage item.
	DefaultMaxImageBytes = 2 << 30
	// DefaultRescan is how long a reading of an image ID is reused.
	DefaultRescan = 7 * 24 * time.Hour
	// DefaultImageTimeout bounds the export and reading of one image.
	DefaultImageTimeout = 20 * time.Minute
	// MaxImages bounds the distinct images read in one collection.
	MaxImages = 100
	// diskMargin is left free on the work directory's filesystem.
	diskMargin = 256 << 20
)

// Scanner reads the images of a host's running containers. It keeps the
// readings of image IDs between collections, so one Scanner should live as
// long as the agent.
type Scanner struct {
	Engine  *Engine
	Version string
	// WorkDir holds the temporary directory of the image being read.
	WorkDir       string
	MaxImageBytes int64
	Rescan        time.Duration
	Timeout       time.Duration
	// Inventory reads an unpacked image; ReadRoot when nil (tests replace
	// it to count readings).
	Inventory func(ctx context.Context, root string, im *Image, version string) Reading
	Now       func() time.Time

	cache map[string]cached
}

// Reading is what was found in one image.
type Reading struct {
	Observations []model.Observation
	Coverage     []model.CoverageItem
	Attributes   map[string]string // os, os_version, os_name
}

type cached struct {
	at      time.Time
	reading Reading
}

func (s *Scanner) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// image is one distinct image and the containers running it.
type image struct {
	id         string
	info       *Image
	containers []string
	refs       []string // the references the containers were created from
}

// Collect returns a batch for the host (collector linux-docker, with the
// coverage of the Docker check and, when every running image is known, the
// list of images on the host) followed by one batch per image.
func (s *Scanner) Collect(ctx context.Context, host model.AssetRef) []*model.ObservationBatch {
	col := model.Collector{ID: CollectorID, Version: s.Version, Method: "agent"}
	hb := model.NewBatch(col, model.AssetRef{Kind: host.Kind, Name: host.Name, Environment: host.Environment, Identifiers: host.Identifiers})
	out := []*model.ObservationBatch{hb}

	cs, err := s.Engine.Containers(ctx)
	if err != nil {
		switch {
		case errors.Is(err, ErrNoDocker):
			hb.Cover("docker", "skipped", err.Error()+": no containers to check")
		case errors.Is(err, ErrDenied):
			hb.Cover("docker", "failed", err.Error()+": the agent's user needs access to the Docker socket (see the Docker containers section of docs/install.md)")
		default:
			hb.Cover("docker", "failed", "list containers: "+err.Error())
		}
		return out
	}
	images := map[string]*image{}
	running := 0
	for _, c := range cs {
		if c.State != "" && c.State != "running" {
			continue
		}
		running++
		im := images[c.ImageID]
		if im == nil {
			im = &image{id: c.ImageID}
			images[c.ImageID] = im
		}
		name := c.ID
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		im.containers = append(im.containers, name)
		im.refs = append(im.refs, c.Image)
	}
	ids := make([]string, 0, len(images))
	for id := range images {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	full := true // the list names every image running on the host
	if len(ids) > MaxImages {
		hb.Cover("docker:images", "partial", fmt.Sprintf("%d images are running; only the first %d were checked", len(ids), MaxImages))
		ids, full = ids[:MaxImages], false
	}
	var listed []string
	taken := map[string]bool{}
	read := 0
	for _, id := range ids {
		im := images[id]
		info, err := s.Engine.Image(ctx, id)
		if err != nil {
			hb.Cover("image:"+shortID(id), "failed", "inspect image: "+err.Error())
			full = false
			continue
		}
		im.info = info
		ref, ident := naming(im, taken)
		b := s.imageBatch(ctx, col, host, im, ref, ident, &read)
		out = append(out, b)
		listed = append(listed, ident)
	}
	hb.Cover("docker", "checked", fmt.Sprintf("%d running container(s), %d image(s); %d read this time, the rest unchanged since they were last read",
		running, len(listed), read))
	if full {
		hb.Images = &model.ImageList{Refs: listed}
		if hb.Images.Refs == nil {
			hb.Images.Refs = []string{}
		}
	}
	hb.Complete = true
	for _, c := range hb.Coverage {
		if c.Status != "checked" {
			hb.Complete = false
		}
	}
	s.prune(images)
	return out
}

// naming picks the image's name and its identity on the host: the tag a
// container was started from when the image still carries it, else its
// first tag, else (untagged) the image ID.
func naming(im *image, taken map[string]bool) (ref, ident string) {
	tags := map[string]bool{}
	for _, t := range im.info.RepoTags {
		if t != "" && t != "<none>:<none>" {
			tags[t] = true
		}
	}
	for _, r := range im.refs {
		if tags[r] && !taken[r] {
			ref = r
			break
		}
	}
	if ref == "" {
		sorted := make([]string, 0, len(tags))
		for t := range tags {
			sorted = append(sorted, t)
		}
		sort.Strings(sorted)
		for _, t := range sorted {
			if !taken[t] {
				ref = t
				break
			}
		}
	}
	if ref == "" {
		return shortID(im.id), im.id
	}
	taken[ref] = true
	return ref, ref
}

func shortID(id string) string {
	h := strings.TrimPrefix(id, "sha256:")
	if len(h) > 12 {
		h = h[:12]
	}
	return h
}

func (s *Scanner) imageBatch(ctx context.Context, col model.Collector, host model.AssetRef, im *image, ref, ident string, read *int) *model.ObservationBatch {
	sort.Strings(im.containers)
	attrs := map[string]string{
		"image":      ref,
		"image_id":   im.id,
		"host":       host.Name,
		"containers": clip(strings.Join(im.containers, ", ")),
		"source":     "docker",
	}
	if len(im.info.RepoTags) > 0 {
		attrs["tags"] = clip(strings.Join(im.info.RepoTags, ", "))
	}
	for _, d := range im.info.RepoDigests {
		if _, dg, ok := strings.Cut(d, "@"); ok {
			attrs["digest"] = dg
			break
		}
	}
	if im.info.Os != "" && im.info.Architecture != "" {
		attrs["platform"] = im.info.Os + "/" + im.info.Architecture
		if im.info.Variant != "" {
			attrs["platform"] += "/" + im.info.Variant
		}
	}
	b := model.NewBatch(col, model.AssetRef{
		Kind:        model.AssetImage,
		Name:        ref + " on " + host.Name,
		Environment: host.Environment,
		Identifiers: []model.Identifier{{Scheme: model.HostImageScheme, Value: ident}},
		Attributes:  attrs,
	})
	b.Relations = []model.RelationRef{{Kind: "runs_on", To: host.Identifiers}}
	scope := "image:" + ref

	r, ok := s.reading(ctx, im, scope, read)
	if !ok {
		b.Coverage = r.Coverage
		return b // incomplete: nothing it reported before is taken as gone
	}
	for k, v := range r.Attributes {
		attrs[k] = v
	}
	b.Observations = append(b.Observations, r.Observations...)
	b.Coverage = append([]model.CoverageItem{{Scope: scope, Status: "checked"}}, r.Coverage...)
	b.KeepUsable()
	b.Complete = true
	for _, c := range b.Coverage {
		if c.Status != "checked" {
			b.Complete = false
		}
	}
	return b
}

// reading returns the image's contents, from the cache when the image ID
// was read recently enough. ok is false when it could not be read; the
// coverage then says why.
func (s *Scanner) reading(ctx context.Context, im *image, scope string, read *int) (Reading, bool) {
	rescan := s.Rescan
	if rescan <= 0 {
		rescan = DefaultRescan
	}
	if c, ok := s.cache[im.id]; ok && s.now().Sub(c.at) < rescan {
		return c.reading, true
	}
	max := s.MaxImageBytes
	if max <= 0 {
		max = DefaultMaxImageBytes
	}
	fail := func(status, reason string) (Reading, bool) {
		return Reading{Coverage: []model.CoverageItem{{Scope: scope, Status: status, Reason: reason}}}, false
	}
	if im.info.Size > max {
		return fail("skipped", fmt.Sprintf("the image is %s unpacked, above the %s limit (--docker-max-image-mb)",
			limits.Bytes(im.info.Size), limits.Bytes(max)))
	}
	work := s.WorkDir
	if work == "" {
		work = os.TempDir()
	}
	if free, ok := freeBytes(work); ok && free < im.info.Size+diskMargin {
		return fail("skipped", fmt.Sprintf("not enough free disk in %s to unpack the image (%s needed, %s free)",
			work, limits.Bytes(im.info.Size+diskMargin), limits.Bytes(free)))
	}
	r, err := s.read(ctx, im, work, max)
	if err != nil {
		if errors.Is(err, limits.ErrTooLarge) {
			return fail("skipped", err.Error())
		}
		return fail("failed", "read image: "+err.Error())
	}
	*read++
	if s.cache == nil {
		s.cache = map[string]cached{}
	}
	s.cache[im.id] = cached{at: s.now(), reading: r}
	return r, true
}

func (s *Scanner) read(ctx context.Context, im *image, work string, max int64) (Reading, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultImageTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	tmp, err := os.MkdirTemp(work, "stackurity-image-")
	if err != nil {
		return Reading{}, err
	}
	defer os.RemoveAll(tmp)
	body, err := s.Engine.Export(ctx, im.id)
	if err != nil {
		return Reading{}, err
	}
	root, err := extractImage(ctx, body, tmp, max, im.info.Architecture)
	body.Close()
	if err != nil {
		if ctx.Err() != nil {
			return Reading{}, fmt.Errorf("stopped after %s: %w", timeout, ctx.Err())
		}
		return Reading{}, err
	}
	inv := s.Inventory
	if inv == nil {
		inv = ReadRoot
	}
	return inv(ctx, root, im.info, s.Version), nil
}

// prune forgets readings of images no longer running.
func (s *Scanner) prune(running map[string]*image) {
	for id := range s.cache {
		if running[id] == nil {
			delete(s.cache, id)
		}
	}
}

func clip(v string) string {
	if len(v) > 1000 {
		return v[:1000]
	}
	return v
}
