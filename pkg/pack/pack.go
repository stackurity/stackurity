// Package pack is the SDK for stack packs: small WebAssembly programs that
// teach Stackurity to read one technology's dependency files. A pack is
// built with GOOS=wasip1 GOARCH=wasm (or any language targeting WASI
// preview 1) and runs in a sandbox with no network, no file system, no clock
// and a memory cap: it sees only the files its manifest asks for.
//
// The core writes one JSON Request to the pack's stdin and reads one JSON
// Response from its stdout. The files themselves are mounted read-only under
// /input, so large ones (a deployed JAR) are read in place rather than
// copied through the request. See docs/packs.md.
//
//	func main() {
//		pack.Serve(func(req *pack.Request) (*pack.Response, error) {
//			var out pack.Response
//			for _, f := range req.Files { ... }
//			return &out, nil
//		})
//	}
package pack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/stackurity/stackurity/internal/model"
)

// ABI is the request/response format version. A breaking change gets a new
// value, and the core keeps running packs built for the previous one.
const ABI = "stackurity-pack/2"

// InputDir is where the core mounts the request's files inside the sandbox.
const InputDir = "/input"

// Wire types shared with the core.
type (
	Observation  = model.Observation
	CoverageItem = model.CoverageItem
	Confidence   = model.Confidence
)

const (
	ConfidenceConfirmed = model.ConfidenceConfirmed
	ConfidenceInferred  = model.ConfidenceInferred
	ConfidenceLow       = model.ConfidenceLow
)

// File is one file the pack's manifest matched, with its path relative to the
// scanned directory (slash-separated). Inside a pack, read it with Bytes or
// Open; Content is set only when a File is built in memory (tests, the core).
type File struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Content []byte `json:"-"`
}

// Bytes returns the whole file.
func (f File) Bytes() ([]byte, error) {
	if f.Content != nil {
		return f.Content, nil
	}
	return os.ReadFile(path.Join(InputDir, f.Path))
}

// ReaderAt opens the file for random access (archives) without reading all of
// it into memory. Call close when done.
func (f File) ReaderAt() (r io.ReaderAt, size int64, close func(), err error) {
	if f.Content != nil {
		return bytes.NewReader(f.Content), int64(len(f.Content)), func() {}, nil
	}
	fh, err := os.Open(path.Join(InputDir, f.Path))
	if err != nil {
		return nil, 0, nil, err
	}
	st, err := fh.Stat()
	if err != nil {
		fh.Close()
		return nil, 0, nil, err
	}
	return fh, st.Size(), func() { fh.Close() }, nil
}

// Dir is the directory part of the file's path ("" at the root).
func (f File) Dir() string {
	d := path.Dir(f.Path)
	if d == "." {
		return ""
	}
	return d
}

// Name is the file's base name.
func (f File) Name() string { return path.Base(f.Path) }

type Request struct {
	ABI   string `json:"abi"`
	Files []File `json:"files"`
}

// Response lists what the pack found and, as coverage, what it read, could
// read only partly, or could not read. Every file the pack was given should
// appear in Coverage.
type Response struct {
	ABI          string         `json:"abi"`
	Observations []Observation  `json:"observations"`
	Coverage     []CoverageItem `json:"coverage"`
	Error        string         `json:"error,omitempty"`
}

// Checked records that a file was read completely.
func (r *Response) Checked(scope string) {
	r.Coverage = append(r.Coverage, CoverageItem{Scope: scope, Status: "checked"})
}

// Partial records that a file was read but some dependencies could not be
// resolved, with the reason.
func (r *Response) Partial(scope, reason string) {
	r.Coverage = append(r.Coverage, CoverageItem{Scope: scope, Status: "partial", Reason: reason})
}

// Failed records that a file could not be read.
func (r *Response) Failed(scope, reason string) {
	r.Coverage = append(r.Coverage, CoverageItem{Scope: scope, Status: "failed", Reason: reason})
}

// Serve reads the request, calls scan and writes its response. It is the
// whole main function of a pack.
func Serve(scan func(*Request) (*Response, error)) {
	if err := serve(os.Stdin, os.Stdout, scan); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(in io.Reader, out io.Writer, scan func(*Request) (*Response, error)) error {
	var req Request
	if err := json.NewDecoder(in).Decode(&req); err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if req.ABI != ABI {
		return json.NewEncoder(out).Encode(Response{ABI: ABI, Error: "unsupported ABI " + req.ABI})
	}
	resp, err := scan(&req)
	if err != nil {
		resp = &Response{Error: err.Error()}
	}
	resp.ABI = ABI
	if resp.Observations == nil {
		resp.Observations = []Observation{}
	}
	if resp.Coverage == nil {
		resp.Coverage = []CoverageItem{}
	}
	return json.NewEncoder(out).Encode(resp)
}
