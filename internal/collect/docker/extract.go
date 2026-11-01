package docker

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/stackurity/stackurity/internal/collect/limits"
)

// Image archives are untrusted input: a container image can be built by
// anyone who can run docker build on the host. Extraction therefore
//
//   - never writes outside the work directory: names are cleaned, ".." and
//     absolute names are refused, and no path is written through a link;
//   - stops once the files it has written pass maxBytes (limits.ErrTooLarge);
//   - drops device nodes, FIFOs and set-id bits, and keeps only owner and
//     read/execute permissions;
//   - rewrites every symbolic link in the result to a relative link that
//     resolves inside the root the way it would inside the container, and
//     removes links that loop. The collectors then read the tree with
//     ordinary file calls without being led onto the agent's own host.

const (
	maxSmallFile  = 4 << 20  // a manifest, index or image config kept in memory
	maxSmallTotal = 32 << 20 // all of them together
	maxEntries    = 1_000_000
	maxLinkDepth  = 40
)

// extractImage reads a docker save archive from r and builds the image's
// filesystem under work/rootfs, which it returns.
func extractImage(ctx context.Context, r io.Reader, work string, maxBytes int64, arch string) (string, error) {
	x := &extractor{work: work, maxBytes: maxBytes, layers: map[string]*layer{}, small: map[string][]byte{}}
	if err := os.MkdirAll(filepath.Join(work, "layers"), 0o700); err != nil {
		return "", err
	}
	if err := x.read(ctx, r); err != nil {
		return "", err
	}
	order, err := x.layerOrder(arch)
	if err != nil {
		return "", err
	}
	root := filepath.Join(work, "rootfs")
	if err := os.Mkdir(root, 0o700); err != nil {
		return "", err
	}
	for _, name := range order {
		l, ok := x.layers[path.Clean(name)]
		if !ok {
			return "", fmt.Errorf("image archive lists layer %q but does not contain it", name)
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := l.applyTo(root); err != nil {
			return "", fmt.Errorf("apply layer: %w", err)
		}
	}
	if err := confineLinks(root); err != nil {
		return "", err
	}
	return root, nil
}

type extractor struct {
	work     string
	maxBytes int64
	written  int64
	entries  int
	layers   map[string]*layer // by the name in the outer archive
	small    map[string][]byte
	smallSum int
}

type layer struct {
	dir       string
	whiteouts []string // paths removed from the layers below
	opaque    []string // directories whose lower contents are hidden
}

func (x *extractor) read(ctx context.Context, r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read image archive: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		br := bufio.NewReaderSize(tr, 64<<10)
		head, _ := br.Peek(512)
		var body io.Reader = br
		var gz *gzip.Reader
		switch {
		case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
			if gz, err = gzip.NewReader(br); err != nil {
				return fmt.Errorf("layer %s: %w", name, err)
			}
			body = gz
		case bytes.HasPrefix(head, []byte{0x28, 0xb5, 0x2f, 0xfd}):
			return fmt.Errorf("layer %s is zstd-compressed, which the agent does not read", name)
		case !isTar(head):
			if h.Size > maxSmallFile || x.smallSum+int(h.Size) > maxSmallTotal {
				continue // not a layer and too big to be metadata
			}
			b, err := io.ReadAll(io.LimitReader(br, maxSmallFile))
			if err != nil {
				return err
			}
			x.small[name] = b
			x.smallSum += len(b)
			continue
		}
		l := &layer{dir: filepath.Join(x.work, "layers", strconv.Itoa(len(x.layers)))}
		if err := os.Mkdir(l.dir, 0o700); err != nil {
			return err
		}
		err = x.extractLayer(ctx, body, l)
		if gz != nil {
			gz.Close()
		}
		if err != nil {
			return fmt.Errorf("layer %s: %w", name, err)
		}
		x.layers[name] = l
	}
}

// isTar reports whether a block starts a tar archive: the ustar magic, or
// the zero block of an empty one.
func isTar(head []byte) bool {
	if len(head) >= 263 && string(head[257:262]) == "ustar" {
		return true
	}
	return len(head) == 512 && bytes.Count(head, []byte{0}) == 512
}

func (x *extractor) extractLayer(ctx context.Context, r io.Reader, l *layer) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if x.entries++; x.entries > maxEntries {
			return fmt.Errorf("%w: more than %d files", limits.ErrTooLarge, maxEntries)
		}
		if x.entries%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		rel, ok := cleanRel(h.Name)
		if !ok || !filepath.IsLocal(rel) {
			continue
		}
		dir, base := path.Split(rel)
		if base == ".wh..wh..opq" {
			l.opaque = append(l.opaque, path.Clean("/"+dir))
			continue
		}
		if strings.HasPrefix(base, ".wh.") {
			l.whiteouts = append(l.whiteouts, path.Join("/", dir, strings.TrimPrefix(base, ".wh.")))
			continue
		}
		if !ensureDir(l.dir, path.Dir(rel)) {
			continue // a parent is a file or a link: nothing is written through it
		}
		target := filepath.Join(l.dir, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			ensureDir(l.dir, rel)
		case tar.TypeReg:
			if x.written += h.Size; x.written > x.maxBytes {
				return fmt.Errorf("%w: the image's files are larger than %s", limits.ErrTooLarge, limits.Bytes(x.maxBytes))
			}
			if err := writeFile(target, tr, h.Size, os.FileMode(h.Mode)); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if len(h.Linkname) > 4096 {
				continue
			}
			_ = os.RemoveAll(target)
			_ = os.Symlink(h.Linkname, target) // confined after all layers are applied
		case tar.TypeLink:
			// A hard link names another file of the same layer.
			src, ok := cleanRel(h.Linkname)
			if !ok || !filepath.IsLocal(src) || !ensureDir(l.dir, path.Dir(src)) {
				continue
			}
			from := filepath.Join(l.dir, filepath.FromSlash(src))
			if fi, err := os.Lstat(from); err != nil || !fi.Mode().IsRegular() {
				continue
			}
			_ = os.RemoveAll(target)
			_ = os.Link(from, target)
		}
	}
}

// cleanRel turns an archive name into a clean relative path, refusing any
// that would leave the root.
func cleanRel(name string) (string, bool) {
	name = strings.TrimPrefix(name, "./")
	if name == "" || strings.HasPrefix(name, "/") || strings.ContainsRune(name, 0) {
		return "", false
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", false
		}
	}
	c := path.Clean(name)
	if c == "." || c == "" {
		return "", false
	}
	return c, true
}

// ensureDir makes rel a directory under base, one component at a time,
// and reports false when a component exists as something else (a file or
// a link), so that nothing is ever created through a link.
func ensureDir(base, rel string) bool {
	if rel == "." || rel == "/" || rel == "" {
		return true
	}
	cur := base
	for _, part := range strings.Split(rel, "/") {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(cur, 0o700); err != nil {
				return false
			}
			continue
		}
		if err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}

func writeFile(target string, r io.Reader, size int64, mode os.FileMode) error {
	_ = os.RemoveAll(target)
	// Owner read/write always, execute bits kept (runtime detection looks
	// for executables), nothing set-id and nothing writable by others.
	perm := mode.Perm()&0o555 | 0o600
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY|noFollow, perm)
	if err != nil {
		return err
	}
	_, err = io.CopyN(f, r, size)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// applyTo moves the layer's files into root: whiteouts and opaque
// directories first remove what the layers below put there, then each
// entry replaces what root has at its path.
func (l *layer) applyTo(root string) error {
	for _, d := range l.opaque {
		if !realDir(root, d) {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(d))
		ents, err := os.ReadDir(full)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := os.RemoveAll(filepath.Join(full, e.Name())); err != nil {
				return err
			}
		}
	}
	for _, w := range l.whiteouts {
		if !realDir(root, path.Dir(w)) {
			continue
		}
		if err := os.RemoveAll(filepath.Join(root, filepath.FromSlash(w))); err != nil {
			return err
		}
	}
	return filepath.WalkDir(l.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == l.dir {
			return nil
		}
		rel, err := filepath.Rel(l.dir, p)
		if err != nil {
			return err
		}
		target := filepath.Join(root, rel)
		// Every parent of target is a real directory: the walk only goes
		// into a directory that root already has as a real directory.
		fi, err := os.Lstat(target)
		exists := err == nil
		if d.IsDir() && exists && fi.IsDir() {
			return nil // merge: walk into it
		}
		if exists {
			if err := os.RemoveAll(target); err != nil {
				return err
			}
		}
		if err := os.Rename(p, target); err != nil {
			return err
		}
		if d.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})
}

// realDir reports whether the in-root path d is a directory reached
// through directories only (no link on the way).
func realDir(root, d string) bool {
	cur := root
	for _, part := range strings.Split(strings.Trim(d, "/"), "/") {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}

// confineLinks rewrites every symbolic link under root as a relative link
// to where it resolves inside root (absolute targets against root, ".."
// stopping at root, as in the container), and removes links that loop.
// After it, any path under root resolves to a place under root.
func confineLinks(root string) error {
	links := map[string]string{} // in-root path -> target as stored
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink == 0 {
			return nil
		}
		t, err := os.Readlink(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		links["/"+filepath.ToSlash(rel)] = t
		return nil
	})
	if err != nil {
		return err
	}
	for p, t := range links {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.Remove(full); err != nil {
			return err
		}
		dest, ok := resolveIn(links, path.Dir(p), t)
		if !ok || dest == p {
			continue // a loop: dropped
		}
		rel, err := filepath.Rel(path.Dir(p), dest)
		if err != nil {
			continue
		}
		if err := os.Symlink(rel, full); err != nil {
			return err
		}
	}
	return nil
}

// resolveIn resolves target, read in directory dir, to a clean in-root path
// with no link in it, following the image's links (by their stored
// targets) as the kernel would inside the container.
func resolveIn(links map[string]string, dir, target string) (string, bool) {
	cur := dir
	if strings.HasPrefix(target, "/") {
		cur = "/"
	}
	queue := strings.Split(target, "/")
	depth := 0
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, c)
		t, ok := links[next]
		if !ok {
			cur = next
			continue
		}
		if depth++; depth > maxLinkDepth {
			return "", false
		}
		if strings.HasPrefix(t, "/") {
			cur = "/"
		}
		queue = append(strings.Split(t, "/"), queue...)
	}
	return cur, true
}

// layerOrder returns the archive names of the image's layers, bottom
// first, from manifest.json (docker save), or from an OCI index.
func (x *extractor) layerOrder(arch string) ([]string, error) {
	if b, ok := x.small["manifest.json"]; ok {
		var m []struct {
			Layers []string `json:"Layers"`
		}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("manifest.json: %w", err)
		}
		if len(m) == 0 {
			return nil, errors.New("manifest.json lists no image")
		}
		return m[0].Layers, nil
	}
	b, ok := x.small["index.json"]
	if !ok {
		return nil, errors.New("image archive has no manifest.json or index.json")
	}
	for range 4 { // an index may point to another index
		var idx struct {
			MediaType string `json:"mediaType"`
			Manifests []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Platform  *struct {
					Architecture string `json:"architecture"`
				} `json:"platform"`
			} `json:"manifests"`
			Layers []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}
		if err := json.Unmarshal(b, &idx); err != nil {
			return nil, fmt.Errorf("OCI index: %w", err)
		}
		if len(idx.Layers) > 0 || len(idx.Manifests) == 0 {
			var out []string
			for _, l := range idx.Layers {
				out = append(out, blobPath(l.Digest))
			}
			return out, nil
		}
		pick := idx.Manifests[0].Digest
		for _, m := range idx.Manifests {
			if m.Platform != nil && m.Platform.Architecture == arch {
				pick = m.Digest
				break
			}
		}
		if b, ok = x.small[blobPath(pick)]; !ok {
			return nil, fmt.Errorf("image archive does not contain manifest %s", pick)
		}
	}
	return nil, errors.New("OCI index nested too deeply")
}

func blobPath(digest string) string {
	alg, hex, _ := strings.Cut(digest, ":")
	return "blobs/" + alg + "/" + hex
}
