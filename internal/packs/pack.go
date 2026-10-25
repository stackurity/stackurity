// Package packs installs and runs stack packs: signed WebAssembly modules that
// read one technology's dependency files (docs/packs.md). A pack runs in a
// sandbox with no network, no file system, no clock and capped memory and
// time; it sees only the file contents it is given and may only report the
// package types its manifest declares.
package packs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/pkg/pack"
)

// Limits on what a pack archive may contain.
const (
	MaxArchiveSize = 32 << 20
	MaxWasmSize    = 64 << 20
	maxManifest    = 64 << 10
)

// Manifest is pack.json: what the pack is, who published it and what it may
// read and report. Administrators see all of it before installing.
type Manifest struct {
	ABI         string `json:"abi"`
	ID          string `json:"id"`
	Version     string `json:"version"`
	Name        string `json:"name"`
	Publisher   string `json:"publisher"`
	License     string `json:"license"`
	Description string `json:"description"`
	Homepage    string `json:"homepage,omitempty"`
	// Files are base-name patterns (path.Match syntax) of files the pack reads.
	Files []string `json:"files"`
	// PurlTypes are the only package types the pack may report.
	PurlTypes []string `json:"purl_types"`
	// Handles are coverage scope prefixes the core reports as unsupported
	// without this pack (e.g. "maven"); they drive install suggestions.
	Handles []string `json:"handles,omitempty"`
	// Edition is "enterprise" for packs that need an Enterprise plan; empty
	// for packs everyone may install.
	Edition        string   `json:"edition,omitempty"`
	MaxMemoryMB    int      `json:"max_memory_mb,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
	KnownLimits    []string `json:"known_limitations,omitempty"`
}

var (
	idRE      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	versionRE = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	purlRE    = regexp.MustCompile(`^[a-z][a-z0-9.+-]{0,31}$`)
)

// Validate checks the manifest; problems are listed together.
func (m *Manifest) Validate() error {
	var p []string
	if m.ABI != pack.ABI {
		p = append(p, fmt.Sprintf("abi must be %q", pack.ABI))
	}
	if !idRE.MatchString(m.ID) {
		p = append(p, "id must be lowercase letters, digits and dashes (max 40)")
	}
	if !versionRE.MatchString(m.Version) {
		p = append(p, "version must be semantic, e.g. 1.0.0")
	}
	if strings.TrimSpace(m.Name) == "" || strings.TrimSpace(m.Publisher) == "" || strings.TrimSpace(m.License) == "" {
		p = append(p, "name, publisher and license are required")
	}
	if len(m.Files) == 0 || len(m.Files) > 32 {
		p = append(p, "files must list 1 to 32 file name patterns")
	}
	for _, f := range m.Files {
		if _, err := path.Match(f, "x"); err != nil || strings.Contains(f, "/") || f == "" || f == "*" {
			p = append(p, fmt.Sprintf("file pattern %q must match base names and be specific", f))
		}
	}
	if len(m.PurlTypes) == 0 {
		p = append(p, "purl_types must list the package types the pack reports")
	}
	for _, t := range m.PurlTypes {
		if !purlRE.MatchString(t) {
			p = append(p, fmt.Sprintf("invalid purl type %q", t))
		}
	}
	if m.Edition != "" && m.Edition != "enterprise" {
		p = append(p, `edition must be empty or "enterprise"`)
	}
	if m.MaxMemoryMB < 0 || m.MaxMemoryMB > 512 || m.TimeoutSeconds < 0 || m.TimeoutSeconds > 600 {
		p = append(p, "max_memory_mb must be at most 512 and timeout_seconds at most 600")
	}
	if len(p) > 0 {
		return &InvalidError{Problems: p}
	}
	return nil
}

// Matches reports whether the pack reads files with this base name.
func (m *Manifest) Matches(name string) bool {
	for _, f := range m.Files {
		if ok, _ := path.Match(f, name); ok {
			return true
		}
	}
	return false
}

func (m *Manifest) memoryMB() int {
	if m.MaxMemoryMB == 0 {
		return 128
	}
	return m.MaxMemoryMB
}

func (m *Manifest) timeoutSeconds() int {
	if m.TimeoutSeconds == 0 {
		return 60
	}
	return m.TimeoutSeconds
}

// InvalidError lists everything wrong with a pack.
type InvalidError struct{ Problems []string }

func (e *InvalidError) Error() string { return "invalid pack: " + strings.Join(e.Problems, "; ") }

// Archive is a pack file (.stkpack): a gzipped tar of pack.json, pack.wasm
// and, when signed, signature.json.
type Archive struct {
	Manifest  Manifest
	Wasm      []byte
	Signature *Signature
	// ManifestRaw is pack.json exactly as signed.
	ManifestRaw []byte
}

// Digest is what a signature covers: the pack's identity and the hashes of
// its manifest and module.
func (a *Archive) Digest() []byte {
	m := sha256.Sum256(a.ManifestRaw)
	w := sha256.Sum256(a.Wasm)
	return []byte(fmt.Sprintf("stackurity-pack-signature/1\nid:%s\nversion:%s\nmanifest-sha256:%x\nwasm-sha256:%x\n",
		a.Manifest.ID, a.Manifest.Version, m, w))
}

// SHA256 identifies the module, shown to administrators.
func (a *Archive) SHA256() string { return fmt.Sprintf("%x", sha256.Sum256(a.Wasm)) }

// ReadArchive parses and validates a pack file. It does not check the
// signature; see Keyring.Verify.
func ReadArchive(data []byte) (*Archive, error) {
	if len(data) > MaxArchiveSize {
		return nil, fmt.Errorf("pack is larger than %d MiB", MaxArchiveSize>>20)
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errors.New("not a pack file (expected a gzipped tar)")
	}
	tr := tar.NewReader(zr)
	a := &Archive{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read pack: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("pack entry %q is not a regular file", h.Name)
		}
		var limit int64
		switch h.Name {
		case "pack.json", "signature.json":
			limit = maxManifest
		case "pack.wasm":
			limit = MaxWasmSize
		default:
			continue // README and the like are ignored
		}
		b, err := io.ReadAll(io.LimitReader(tr, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("%s is too large", h.Name)
		}
		switch h.Name {
		case "pack.json":
			a.ManifestRaw = b
		case "pack.wasm":
			a.Wasm = b
		case "signature.json":
			var s Signature
			if err := json.Unmarshal(b, &s); err != nil {
				return nil, fmt.Errorf("signature.json: %w", err)
			}
			a.Signature = &s
		}
	}
	if a.ManifestRaw == nil || a.Wasm == nil {
		return nil, errors.New("a pack needs pack.json and pack.wasm")
	}
	dec := json.NewDecoder(bytes.NewReader(a.ManifestRaw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a.Manifest); err != nil {
		return nil, fmt.Errorf("pack.json: %w", err)
	}
	if err := a.Manifest.Validate(); err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(a.Wasm, []byte("\x00asm")) {
		return nil, errors.New("pack.wasm is not a WebAssembly module")
	}
	return a, nil
}

// Bytes writes the archive as a pack file.
func (a *Archive) Bytes() ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	files := []struct {
		name string
		data []byte
	}{{"pack.json", a.ManifestRaw}, {"pack.wasm", a.Wasm}}
	if a.Signature != nil {
		s, _ := json.MarshalIndent(a.Signature, "", "  ")
		files = append(files, struct {
			name string
			data []byte
		}{"signature.json", s})
	}
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
