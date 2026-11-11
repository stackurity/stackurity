package linux

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

// pyRoot builds a filesystem root for the Python tests.
type pyRoot struct {
	t    *testing.T
	root string
}

func newPyRoot(t *testing.T) *pyRoot { return &pyRoot{t: t, root: t.TempDir()} }

func (r *pyRoot) file(p, data string, mode os.FileMode) {
	full := filepath.Join(r.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(data), mode); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Chmod(full, mode); err != nil {
		r.t.Fatal(err)
	}
}

func (r *pyRoot) link(p, target string) {
	full := filepath.Join(r.root, p)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.Symlink(target, full); err != nil {
		r.t.Fatal(err)
	}
}

// patchlevelH is the part of CPython's Include/patchlevel.h that matters,
// as installed by 3.12.7.
func patchlevelH(v string) string {
	return `/* Python version identification scheme. */
#define PY_RELEASE_LEVEL_FINAL  0xF     /* Serial should be 0 here */

/*--start constants--*/
#define PY_MAJOR_VERSION        3
#define PY_MINOR_VERSION        12
#define PY_MICRO_VERSION        7
#define PY_RELEASE_LEVEL        PY_RELEASE_LEVEL_FINAL
#define PY_RELEASE_SERIAL       0

/* Version as a string */
#define PY_VERSION              "` + v + `"
/*--end constants--*/
`
}

// officialPythonRoot is laid out like the official python:3.12-slim image:
// Debian's package database for the base system, and CPython built from
// source into /usr/local, which no package owns.
func officialPythonRoot(t *testing.T, header bool) *pyRoot {
	r := newPyRoot(t)
	r.file("usr/lib/os-release", "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n", 0o644)
	r.link("etc/os-release", "../usr/lib/os-release")
	r.file("var/lib/dpkg/status", "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.36-9+deb12u8\n\n", 0o644)
	r.file("var/lib/dpkg/info/libc6:amd64.list", "/.\n/usr/bin/ldd\n/usr/lib/x86_64-linux-gnu/libc.so.6\n", 0o644)
	r.file("usr/local/bin/python3.12", "\x7fELF", 0o755)
	r.link("usr/local/bin/python3", "python3.12")
	r.link("usr/local/bin/python", "python3")
	r.file("usr/local/lib/python3.12/os.py", "", 0o644)
	r.file("usr/local/lib/libpython3.12.so.1.0", "\x7fELF", 0o755)
	if header {
		r.file("usr/local/include/python3.12/patchlevel.h", patchlevelH("3.12.7"), 0o644)
	}
	return r
}

// imageCollector reads root as ReadRoot reads an image: nothing is run.
func imageCollector(root string, env map[string]string) *Collector {
	c := fixture(root)
	c.RunVersion = nil
	c.ImageEnv = env
	return c
}

func runtimes(t *testing.T, c *Collector) (map[string]model.Observation, *model.ObservationBatch) {
	t.Helper()
	osBatch, err := c.Collect(context.Background(), "image", "")
	if err != nil {
		t.Fatal(err)
	}
	b := c.CollectSoftware(context.Background(), osBatch, nil)
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Observation{}
	for _, o := range b.Observations {
		if o.Evidence["kind"] == "runtime" {
			got[o.Purl] = o
		}
	}
	return got, b
}

func onlyPython(t *testing.T, got map[string]model.Observation) model.Observation {
	t.Helper()
	var py []model.Observation
	for _, o := range got {
		if strings.HasPrefix(o.Purl, "pkg:generic/python") {
			py = append(py, o)
		}
	}
	if len(py) != 1 {
		t.Fatalf("want one python, got %v", keys(got))
	}
	return py[0]
}

// The official image's interpreter is read from its patchlevel.h: the
// exact release, confirmed, without running anything.
func TestImagePythonFromHeader(t *testing.T) {
	r := officialPythonRoot(t, true)
	got, _ := runtimes(t, imageCollector(r.root, map[string]string{"PYTHON_VERSION": "3.12.7"}))
	o := onlyPython(t, got)
	if o.Purl != "pkg:generic/python@3.12.7" || o.Version != "3.12.7" || o.Confidence != model.ConfidenceConfirmed ||
		o.Evidence["detected_by"] != "header" || o.Evidence["version_file"] != "/usr/local/include/python3.12/patchlevel.h" ||
		o.Evidence["binary"] != "/usr/local/bin/python3.12" || o.Location != "/usr/local/bin/python3" {
		t.Errorf("python = %+v", o)
	}
	if o.Evidence["not_run"] == "" {
		t.Errorf("evidence should still say the binary was not run: %v", o.Evidence)
	}
}

// Without the headers, the image's PYTHON_VERSION (which the official
// images set to the release they build) gives the release, when it is the
// interpreter's release line.
func TestImagePythonFromEnv(t *testing.T) {
	r := officialPythonRoot(t, false)
	got, _ := runtimes(t, imageCollector(r.root, map[string]string{"PYTHON_VERSION": "3.12.7", "LANG": "C.UTF-8"}))
	o := onlyPython(t, got)
	if o.Purl != "pkg:generic/python@3.12.7" || o.Confidence != model.ConfidenceInferred ||
		o.Evidence["detected_by"] != "image-env" || o.Evidence["version_env"] != "PYTHON_VERSION=3.12.7" {
		t.Errorf("python = %+v", o)
	}

	// PYTHON_VERSION left from a base image whose Python a later layer
	// replaced: not this interpreter's release line, so not used.
	got, _ = runtimes(t, imageCollector(r.root, map[string]string{"PYTHON_VERSION": "3.11.10"}))
	o = onlyPython(t, got)
	if o.Purl != "pkg:generic/python@3.12" || o.Evidence["detected_by"] != "stdlib-dir" {
		t.Errorf("mismatched PYTHON_VERSION used: %+v", o)
	}
}

// With neither, the standard library's directory gives the release line
// only. No patch release is invented, and the evidence says so.
func TestImagePythonReleaseLineOnly(t *testing.T) {
	r := officialPythonRoot(t, false)
	got, _ := runtimes(t, imageCollector(r.root, nil))
	o := onlyPython(t, got)
	if o.Purl != "pkg:generic/python@3.12" || o.Version != "3.12" || o.Confidence != model.ConfidenceInferred ||
		o.Evidence["detected_by"] != "stdlib-dir" || o.Evidence["version_file"] != "/usr/local/lib/python3.12" ||
		!strings.Contains(o.Evidence["version_precision"], "release line") {
		t.Errorf("python = %+v", o)
	}
}

// A python3 binary with no release in its name and one standard library
// next to it.
func TestPythonUnversionedBinaryName(t *testing.T) {
	r := officialPythonRoot(t, false)
	os.Remove(filepath.Join(r.root, "usr/local/bin/python3"))
	os.Rename(filepath.Join(r.root, "usr/local/bin/python3.12"), filepath.Join(r.root, "usr/local/bin/python3"))
	got, _ := runtimes(t, imageCollector(r.root, nil))
	if o := onlyPython(t, got); o.Purl != "pkg:generic/python@3.12" || o.Evidence["detected_by"] != "stdlib-dir" {
		t.Errorf("python = %+v", o)
	}
	// Two standard libraries and no release in the name: unknown, not a guess.
	r.file("usr/local/lib/python3.11/os.py", "", 0o644)
	got, _ = runtimes(t, imageCollector(r.root, nil))
	if o := onlyPython(t, got); o.Purl != "pkg:generic/python" || o.Version != "" || o.Confidence != model.ConfidenceUnknown {
		t.Errorf("python = %+v", o)
	}
}

// Debian's own Python is in the package database (python3.11 3.11.2-6),
// which carries its version and lifecycle; it is not reported a second
// time as a runtime, headers and standard library notwithstanding.
func TestDistroPythonNotDoubleReported(t *testing.T) {
	r := newPyRoot(t)
	r.file("etc/os-release", "ID=debian\nVERSION_ID=12\n", 0o644)
	r.file("var/lib/dpkg/status", "Package: python3.11-minimal\nStatus: install ok installed\nArchitecture: amd64\nSource: python3.11\nVersion: 3.11.2-6+deb12u4\n\n"+
		"Package: python3-minimal\nStatus: install ok installed\nArchitecture: amd64\nSource: python3-defaults\nVersion: 3.11.2-1+b1\n\n", 0o644)
	r.file("var/lib/dpkg/info/python3.11-minimal.list", "/.\n/usr\n/usr/bin\n/usr/bin/python3.11\n/usr/lib/python3.11/os.py\n", 0o644)
	r.file("var/lib/dpkg/info/python3-minimal.list", "/.\n/usr\n/usr/bin\n/usr/bin/python3\n", 0o644)
	r.file("usr/bin/python3.11", "\x7fELF", 0o755)
	r.link("usr/bin/python3", "python3.11")
	r.file("usr/lib/python3.11/os.py", "", 0o644)
	r.file("usr/include/python3.11/patchlevel.h", patchlevelH("3.11.2"), 0o644)

	c := imageCollector(r.root, nil)
	osBatch, err := c.Collect(context.Background(), "image", "")
	if err != nil {
		t.Fatal(err)
	}
	pkgs := 0
	for _, o := range osBatch.Observations {
		if strings.HasPrefix(o.Purl, "pkg:deb/debian/python3.11-minimal@") {
			pkgs++
		}
	}
	if pkgs != 1 {
		t.Errorf("python3.11-minimal package reported %d times", pkgs)
	}
	got, b := runtimes(t, c)
	if len(got) != 0 {
		t.Errorf("distro python reported again as a runtime: %v", keys(got))
	}
	if !b.Complete {
		t.Errorf("coverage = %+v", b.Coverage)
	}
}

// A distroless Python image: Debian's interpreter, but its packages are
// recorded in /var/lib/dpkg/status.d, which the collector does not read,
// so no package reports Python and it cannot be reported twice. No headers
// and no PYTHON_VERSION: the release line comes from /usr/lib/python3.11.
func TestDistrolessPython(t *testing.T) {
	r := newPyRoot(t)
	r.file("etc/os-release", "ID=debian\nVERSION_ID=12\nPRETTY_NAME=\"Distroless\"\n", 0o644)
	r.file("var/lib/dpkg/status.d/python3.11-minimal", "Package: python3.11-minimal\nVersion: 3.11.2-6+deb12u4\nArchitecture: amd64\n", 0o644)
	r.file("usr/bin/python3.11", "\x7fELF", 0o755)
	r.link("usr/bin/python3", "python3.11")
	r.file("usr/lib/python3.11/os.py", "", 0o644)

	got, b := runtimes(t, imageCollector(r.root, nil))
	o := onlyPython(t, got)
	if o.Purl != "pkg:generic/python@3.11" || o.Evidence["detected_by"] != "stdlib-dir" ||
		o.Evidence["version_file"] != "/usr/lib/python3.11" || o.Evidence["binary"] != "/usr/bin/python3.11" {
		t.Errorf("python = %+v", o)
	}
	for _, cv := range b.Coverage {
		if cv.Scope == "runtimes" && cv.Status != "checked" {
			t.Errorf("runtimes coverage = %+v", cv)
		}
	}
}

// A dpkg status file without the per-package file lists: packages were
// reported but ownership is unknown, so runtimes are still skipped (as
// before) rather than risk reporting Python twice.
func TestPythonOwnershipUnknownStillSkipped(t *testing.T) {
	r := newPyRoot(t)
	r.file("etc/os-release", "ID=debian\nVERSION_ID=12\n", 0o644)
	r.file("var/lib/dpkg/status", "Package: python3.11-minimal\nStatus: install ok installed\nVersion: 3.11.2-6\n\n", 0o644)
	r.file("usr/bin/python3.11", "\x7fELF", 0o755)
	r.link("usr/bin/python3", "python3.11")
	got, b := runtimes(t, imageCollector(r.root, nil))
	if len(got) != 0 {
		t.Errorf("reported %v", keys(got))
	}
	skipped := false
	for _, cv := range b.Coverage {
		skipped = skipped || (cv.Scope == "runtimes" && cv.Status == "skipped")
	}
	if !skipped {
		t.Errorf("coverage = %+v", b.Coverage)
	}
}

// On a host, running python3 --version stays the first source. When it
// fails, the files give the version instead of none.
func TestHostPythonFallsBackToFiles(t *testing.T) {
	r := officialPythonRoot(t, true)
	c := fixture(r.root)
	c.RunVersion = func(context.Context, string, []string) ([]byte, error) {
		return []byte("Python 3.12.7\n"), nil
	}
	got, _ := runtimes(t, c)
	if o := onlyPython(t, got); o.Purl != "pkg:generic/python@3.12.7" || o.Evidence["detected_by"] != "version-output" ||
		o.Confidence != model.ConfidenceConfirmed {
		t.Errorf("ran python: %+v", o)
	}

	c.RunVersion = func(context.Context, string, []string) ([]byte, error) {
		return nil, errors.New("exec format error")
	}
	got, _ = runtimes(t, c)
	o := onlyPython(t, got)
	if o.Purl != "pkg:generic/python@3.12.7" || o.Evidence["detected_by"] != "header" || o.Evidence["error"] != "exec format error" {
		t.Errorf("python after a failed run: %+v", o)
	}
}
