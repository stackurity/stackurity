package docker

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

const pythonPatchlevel = `#define PY_MAJOR_VERSION        3
#define PY_MINOR_VERSION        12
#define PY_MICRO_VERSION        7

/* Version as a string */
#define PY_VERSION              "3.12.7"
`

// pythonSlimLayers is laid out like python:3.12-slim: Debian 12 with its
// package database, then CPython 3.12.7 built into /usr/local.
func pythonSlimLayers(header bool) [][]byte {
	py := []entry{
		exe("usr/local/bin/python3.12", "\x7fELF"),
		link("usr/local/bin/python3", "python3.12"),
		link("usr/local/bin/python", "python3"),
		file("usr/local/lib/python3.12/os.py", ""),
	}
	if header {
		py = append(py, file("usr/local/include/python3.12/patchlevel.h", pythonPatchlevel))
	}
	return [][]byte{
		layerTar(file("usr/lib/os-release", "ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"),
			link("etc/os-release", "../usr/lib/os-release"),
			file("var/lib/dpkg/status", dpkgStatus),
			file("var/lib/dpkg/info/curl.list", "/.\n/usr/bin/curl\n")),
		layerTar(py...),
	}
}

var pythonEnv = []string{"PATH=/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8",
	"GPG_KEY=7169605F62C751356D054A26A821E680E5FA6305", "PYTHON_VERSION=3.12.7", "PYTHON_SHA256=24887b92e2afd4a2ac602419ad4b596372f67ac9b077190f459aba390faf5550"}

func pythonObs(t *testing.T, obs []model.Observation) model.Observation {
	t.Helper()
	var py []model.Observation
	for _, o := range obs {
		if strings.HasPrefix(o.Purl, "pkg:generic/python") {
			py = append(py, o)
		}
	}
	if len(py) != 1 {
		t.Fatalf("python observations = %+v", py)
	}
	return py[0]
}

// An image archive read end to end: the interpreter's version comes from
// patchlevel.h, and without it from the image's PYTHON_VERSION.
func TestImageArchivePythonVersion(t *testing.T) {
	im := &Image{Config: &ImageConfig{Env: pythonEnv}}
	for _, c := range []struct {
		header bool
		how    string
		conf   model.Confidence
	}{{true, "header", model.ConfidenceConfirmed}, {false, "image-env", model.ConfidenceInferred}} {
		root, err := extractImage(context.Background(), bytes.NewReader(saveArchive(idShop, pythonSlimLayers(c.header)...)), t.TempDir(), 1<<20, "amd64")
		if err != nil {
			t.Fatal(err)
		}
		r := ReadRoot(context.Background(), root, im, "test")
		o := pythonObs(t, r.Observations)
		if o.Purl != "pkg:generic/python@3.12.7" || o.Version != "3.12.7" || o.Evidence["detected_by"] != c.how || o.Confidence != c.conf ||
			o.Evidence["binary"] != "/usr/local/bin/python3.12" {
			t.Errorf("header=%v: python = %+v", c.header, o)
		}
	}
}

// A running container's image, read through the Docker socket: the image
// inspection's Config.Env reaches the reading.
func TestRunningContainerPythonVersion(t *testing.T) {
	d := startDocker(t)
	d.add(idShop, []string{"python:3.12-slim"}, "", pythonSlimLayers(false)...)
	d.mu.Lock()
	d.images[idShop].info.Config = &ImageConfig{Env: pythonEnv}
	d.mu.Unlock()
	d.run(Container{ID: "c1", Names: []string{"/worker"}, Image: "python:3.12-slim", ImageID: idShop, State: "running"})
	bs := newScanner(t, d.socket).Collect(context.Background(), hostRef)
	b := byIdentity(bs)["python:3.12-slim"]
	if b == nil {
		t.Fatalf("batches = %+v", bs)
	}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	o := pythonObs(t, b.Observations)
	if o.Purl != "pkg:generic/python@3.12.7" || o.Evidence["detected_by"] != "image-env" || o.Evidence["version_env"] != "PYTHON_VERSION=3.12.7" {
		t.Errorf("python = %+v", o)
	}
}

func TestImageEnv(t *testing.T) {
	im := &Image{Config: &ImageConfig{Env: []string{"A=1", "B=x=y", "NOVALUE", "A=2"}}}
	env := im.Env()
	if len(env) != 2 || env["A"] != "2" || env["B"] != "x=y" {
		t.Errorf("env = %v", env)
	}
	if (&Image{}).Env() != nil {
		t.Error("no config: want nil")
	}
}
