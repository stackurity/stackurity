package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/stackurity/stackurity/pkg/pack"
)

// Limits on reading archives, which come from deployed applications.
const (
	maxNestedBytes = 64 << 20 // one library inside an application
	maxDepth       = 3        // EAR > WAR > JAR
)

func isArchive(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".jar", ".war", ".ear":
		return true
	}
	return false
}

// archiveScan collects what one deployed archive holds.
type archiveScan struct {
	file      pack.File
	seen      map[string]bool
	unlabeled int // bundled libraries with no Maven metadata
	unread    int // bundled libraries too large or unreadable
	out       *pack.Response
}

// scanArchive reads a JAR, WAR or EAR as data: the Maven pom.properties of
// the archive and of every library bundled in it (BOOT-INF/lib, WEB-INF/lib,
// lib/). Nothing in the archive is run.
func scanArchive(f pack.File, out *pack.Response) {
	scope := "maven:" + f.Path
	a := &archiveScan{file: f, seen: map[string]bool{}, out: out}
	// Opened in place: only the entries read are loaded into memory.
	ra, size, done, err := f.ReaderAt()
	if err != nil {
		out.Failed(scope, "could not open the archive")
		return
	}
	defer done()
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		out.Failed(scope, "not a readable JAR, WAR or EAR")
		return
	}
	a.walk(zr, "", 0)
	switch {
	case a.unlabeled > 0 || a.unread > 0:
		var why []string
		if a.unlabeled > 0 {
			why = append(why, fmt.Sprintf("%d bundled libraries carry no Maven metadata", a.unlabeled))
		}
		if a.unread > 0 {
			why = append(why, fmt.Sprintf("%d bundled libraries could not be read", a.unread))
		}
		out.Partial(scope, strings.Join(why, "; "))
	default:
		out.Checked(scope)
	}
}

// walk reads one archive level. inner is the path of this archive inside the
// file ("" for the file itself). It reports whether the level had Maven
// metadata of its own.
func (a *archiveScan) walk(zr *zip.Reader, inner string, depth int) bool {
	var nested []*zip.File
	var props []*zip.File
	for _, e := range zr.File {
		name := e.Name
		switch {
		case strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties"):
			props = append(props, e)
		case isArchive(name) && !e.FileInfo().IsDir():
			nested = append(nested, e)
		}
	}
	// An archive that bundles libraries is an application, and a single
	// pom.properties at its top level is its own module, not a dependency.
	// A plain JAR is a library, reported as itself.
	application := len(nested) > 0
	skipOwn := application && len(props) == 1
	for _, e := range props {
		g, art, v, ok := readPomProperties(e)
		if !ok || skipOwn {
			continue
		}
		a.add(g, art, v, inner)
	}
	if depth == 0 && len(props) == 0 && !application {
		a.unlabeled++
	}
	for _, e := range nested {
		where := path.Join(inner, e.Name)
		if depth+1 > maxDepth || e.UncompressedSize64 > maxNestedBytes {
			a.unread++
			continue
		}
		rc, err := e.Open()
		if err != nil {
			a.unread++
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, maxNestedBytes+1))
		rc.Close()
		if err != nil || len(data) > maxNestedBytes {
			a.unread++
			continue
		}
		sub, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			a.unread++
			continue
		}
		if !a.walk(sub, where, depth+1) {
			a.unlabeled++
		}
	}
	return len(props) > 0
}

func (a *archiveScan) add(g, art, v, inner string) {
	p := purl(g, art, v)
	if a.seen[p] {
		return
	}
	a.seen[p] = true
	o := pack.Observation{Purl: p, Version: v, Location: a.file.Path, Confidence: pack.ConfidenceConfirmed}
	if inner != "" {
		o.Evidence = map[string]string{"archive_path": inner}
	}
	a.out.Observations = append(a.out.Observations, o)
}

// readPomProperties reads groupId, artifactId and version.
func readPomProperties(e *zip.File) (g, art, v string, ok bool) {
	if e.UncompressedSize64 > 64<<10 {
		return "", "", "", false
	}
	rc, err := e.Open()
	if err != nil {
		return "", "", "", false
	}
	defer rc.Close()
	sc := bufio.NewScanner(io.LimitReader(rc, 64<<10))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, val, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(k) {
		case "groupId":
			g = strings.TrimSpace(val)
		case "artifactId":
			art = strings.TrimSpace(val)
		case "version":
			v = strings.TrimSpace(val)
		}
	}
	ok = g != "" && art != "" && v != "" && !strings.Contains(v, "${")
	return g, art, v, ok
}
