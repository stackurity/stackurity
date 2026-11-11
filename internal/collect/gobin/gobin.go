// Package gobin reads the Go modules compiled into executables found under a
// directory tree, such as an unpacked container image.
//
// The Go toolchain records the main module, every dependency module (after
// replace directives) and its own version in each binary it builds. That
// record is read with debug/buildinfo as data: nothing found is ever run.
// The modules are reported as pkg:golang components, the toolchain as
// pkg:golang/stdlib, so Go advisories (including standard library ones)
// match the binary as they match a go.mod.
package gobin

import (
	"bytes"
	"context"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/collect/limits"
	"github.com/stackurity/stackurity/internal/model"
)

// Scope is the coverage scope of a scan.
const Scope = "go-binaries"

// Limits bound one scan. A scan that reaches one reports partial coverage.
type Limits struct {
	MaxDirs     int   // directories walked
	MaxEntries  int   // files and directories looked at
	MaxBinaries int   // executables opened
	MaxFileSize int64 // a larger executable is not opened
	MaxBytes    int64 // bytes read from executables, in total
}

// DefaultLimits are generous for an image (the Stackurity image itself has
// a few thousand files) and keep a hostile one to a bounded amount of work.
var DefaultLimits = Limits{
	MaxDirs:     50_000,
	MaxEntries:  1_000_000,
	MaxBinaries: 10_000,
	MaxFileSize: 1 << 30,
	MaxBytes:    256 << 20,
}

// skipDirs are never walked: they hold no installed software, and on a live
// root they are kernel views rather than files.
var skipDirs = map[string]bool{"/proc": true, "/sys": true, "/dev": true}

// Scanner reads the Go binaries under Root.
type Scanner struct {
	Root string
	// Owned reports whether an OS package installed a path (absolute
	// inside Root). Those binaries are left to the package's own entry:
	// distributions patch Go packages without changing the module or
	// toolchain versions a binary records, so matching them as Go modules
	// would report fixed issues as open. Nil reads every binary.
	Owned  func(string) bool
	Limits Limits // DefaultLimits when zero
}

// Scan walks Root and returns one observation per module, per binary. The
// same module@version in two binaries is two observations, each with its
// binary's path as location: rebuilding one binary does not fix the other.
func (s *Scanner) Scan(ctx context.Context) ([]model.Observation, []model.CoverageItem) {
	lim := s.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits
	}
	w := &walk{ctx: ctx, s: s, lim: lim, budget: lim.MaxBytes}
	err := filepath.WalkDir(s.Root, w.visit)
	if err != nil && !errors.Is(err, errStop) {
		return w.obs, []model.CoverageItem{{Scope: Scope, Status: "failed", Reason: "walk: " + err.Error()}}
	}
	if w.stopped != "" {
		w.partial = append([]string{w.stopped}, w.partial...)
	}
	if w.tooBig > 0 {
		w.partial = append(w.partial, fmt.Sprintf("%d executable(s) larger than %s were not read", w.tooBig, limits.Bytes(lim.MaxFileSize)))
	}
	if w.unreadable > 0 {
		w.partial = append(w.partial, fmt.Sprintf("%d file(s) or director(ies) could not be read", w.unreadable))
	}
	if len(w.partial) > 0 {
		return w.obs, []model.CoverageItem{{Scope: Scope, Status: "partial",
			Reason: strings.Join(w.partial, "; ") + "; Go binaries there may not have been read"}}
	}
	return w.obs, []model.CoverageItem{{Scope: Scope, Status: "checked"}}
}

var errStop = errors.New("stop")

type walk struct {
	ctx        context.Context
	s          *Scanner
	lim        Limits
	dirs       int
	entries    int
	binaries   int
	budget     int64
	tooBig     int
	unreadable int
	stopped    string
	partial    []string
	obs        []model.Observation
}

func (w *walk) stop(reason string) error {
	w.stopped = reason
	return errStop
}

func (w *walk) visit(p string, d fs.DirEntry, err error) error {
	if p == w.s.Root {
		return err
	}
	if err != nil {
		w.unreadable++
		if d != nil && d.IsDir() {
			return fs.SkipDir
		}
		return nil
	}
	if w.entries++; w.entries > w.lim.MaxEntries {
		return w.stop(fmt.Sprintf("stopped after %d files", w.lim.MaxEntries))
	}
	if w.entries%1024 == 0 {
		if err := w.ctx.Err(); err != nil {
			return w.stop("stopped: " + err.Error())
		}
	}
	rel, err := filepath.Rel(w.s.Root, p)
	if err != nil {
		return err
	}
	inRoot := "/" + filepath.ToSlash(rel)
	if d.IsDir() {
		if skipDirs[inRoot] {
			return fs.SkipDir
		}
		if w.dirs++; w.dirs > w.lim.MaxDirs {
			return w.stop(fmt.Sprintf("stopped after %d directories", w.lim.MaxDirs))
		}
		return nil
	}
	if !d.Type().IsRegular() {
		return nil // links are read at their target, devices never
	}
	info, err := d.Info()
	if err != nil {
		w.unreadable++
		return nil
	}
	if info.Mode().Perm()&0o111 == 0 || info.Size() < 4 {
		return nil
	}
	if w.s.Owned != nil && w.s.Owned(inRoot) {
		return nil
	}
	if info.Size() > w.lim.MaxFileSize {
		w.tooBig++
		return nil
	}
	if w.binaries >= w.lim.MaxBinaries {
		return w.stop(fmt.Sprintf("stopped after %d executables", w.lim.MaxBinaries))
	}
	if w.budget <= 0 {
		return w.stop(fmt.Sprintf("stopped after reading %s from executables", limits.Bytes(w.lim.MaxBytes)))
	}
	w.binaries++
	obs, err := w.read(p, inRoot)
	if errors.Is(err, errBudget) {
		return w.stop(fmt.Sprintf("stopped after reading %s from executables", limits.Bytes(w.lim.MaxBytes)))
	}
	w.obs = append(w.obs, obs...)
	return nil
}

var errBudget = errors.New("read budget used up")

// budgetReader is the file as buildinfo sees it: reads count against the
// scan's byte budget and fail once it is used up.
type budgetReader struct {
	f      io.ReaderAt
	budget *int64
}

func (b budgetReader) ReadAt(p []byte, off int64) (int, error) {
	if *b.budget <= 0 {
		return 0, errBudget
	}
	if int64(len(p)) > *b.budget {
		p = p[:*b.budget]
	}
	n, err := b.f.ReadAt(p, off)
	*b.budget -= int64(n)
	if err == nil && *b.budget <= 0 {
		err = errBudget
	}
	return n, err
}

// Executable magic numbers: ELF, Mach-O (32/64-bit, both byte orders,
// universal) and PE ("MZ"). Anything else (scripts, data) is not opened
// for build information.
var magics = [][]byte{
	[]byte("\x7fELF"),
	{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
	{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
	{0xca, 0xfe, 0xba, 0xbe},
	[]byte("MZ"),
}

func isExecutable(head []byte) bool {
	for _, m := range magics {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

// read returns the observations for one file, none when it is not a Go
// binary (or has no build information: before Go 1.13, or built without
// module support).
func (w *walk) read(full, inRoot string) ([]model.Observation, error) {
	f, err := os.Open(full)
	if err != nil {
		w.unreadable++
		return nil, nil
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, nil
	}
	r := budgetReader{f: f, budget: &w.budget}
	head := make([]byte, 4)
	if _, err := r.ReadAt(head, 0); err != nil {
		if errors.Is(err, errBudget) {
			return nil, err
		}
		return nil, nil
	}
	if !isExecutable(head) {
		return nil, nil
	}
	bi, err := buildinfo.Read(r)
	if err != nil {
		if errors.Is(err, errBudget) {
			return nil, err
		}
		return nil, nil // not a Go binary, or one without build information
	}
	return Observations(bi, inRoot), nil
}

// Observations turns one binary's build information into observations
// located at the binary's path.
func Observations(bi *buildinfo.BuildInfo, binary string) []model.Observation {
	var out []model.Observation
	seen := map[string]bool{}
	add := func(modPath, v string, extra map[string]string) {
		if modPath == "" || v == "" || v == "(devel)" {
			return
		}
		ns, name := path.Dir(modPath), path.Base(modPath)
		if ns == "." {
			ns = ""
		}
		p := packageurl.NewPackageURL("golang", ns, name, v, nil, "").ToString()
		if seen[p] {
			return
		}
		seen[p] = true
		ev := map[string]string{"kind": "go-binary", "detected_by": "go-buildinfo", "binary": binary}
		if bi.GoVersion != "" {
			ev["go_version"] = bi.GoVersion
		}
		for k, x := range extra {
			ev[k] = x
		}
		out = append(out, model.Observation{Purl: p, Version: v, Location: binary,
			Confidence: model.ConfidenceConfirmed, Evidence: ev})
	}
	if v := StdlibVersion(bi.GoVersion); v != "" {
		add("stdlib", v, nil)
	}
	// A main module built from a checkout without a version tag reports
	// "(devel)": the project's own code, with no version to match (add
	// drops it).
	add(bi.Main.Path, bi.Main.Version, map[string]string{"main_module": "true"})
	for _, d := range bi.Deps {
		m, extra := d, map[string]string(nil)
		if d.Replace != nil {
			m = d.Replace
			if localPath(m.Path) || m.Version == "" || m.Version == "(devel)" {
				continue // replaced by a local directory: project code, as in go.mod
			}
			extra = map[string]string{"replaces": d.Path + "@" + d.Version}
		}
		add(m.Path, m.Version, extra)
	}
	return out
}

// localPath reports whether a replacement names a directory (go.mod's
// "=> ./local" or "=> /abs/path") rather than a module.
func localPath(p string) bool {
	return strings.HasPrefix(p, "./") || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") ||
		p == "." || p == ".." || filepath.IsAbs(p)
}

var toolchain = regexp.MustCompile(`^go(\d+)\.(\d+)(?:\.(\d+))?(?:(rc|beta)(\d+))?(?:$|[ +-])`)

// StdlibVersion turns the toolchain a binary records ("go1.22.1",
// "go1.24.0 X:boringcrypto", "go1.21rc2") into the version OSV's stdlib
// ranges use ("1.22.1", "1.24.0", "1.21.0-rc.2"). Development toolchains
// ("devel go1.23-abc") give "": they have no release to match.
func StdlibVersion(goVersion string) string {
	m := toolchain.FindStringSubmatch(goVersion)
	if m == nil {
		return ""
	}
	patch := m[3]
	if patch == "" {
		patch = "0"
	}
	v := m[1] + "." + m[2] + "." + patch
	if m[4] != "" {
		v += "-" + m[4] + "." + m[5]
	}
	return v
}
