package apps

// Java web applications deployed in a servlet container (Tomcat, Jetty):
// an exploded directory with a WEB-INF directory, or a .war file the
// container runs without unpacking it beside itself. Discovery finds them
// in the containers' webapps directories (ServletWebapps, and any webapps
// directory the walk of a discovery base reaches) and, elsewhere, by
// WEB-INF/web.xml (markers).
//
// The libraries bundled in WEB-INF/lib are Maven packages: the Java stack
// pack reads their META-INF/maven/.../pom.properties, as it reads any JAR or
// WAR in an application, so OSV's Maven advisories apply. Without the pack
// they are reported as a coverage gap (JavaLibrariesScope), never as an
// application with no libraries.
//
// The application itself is identified from its own files when it is one
// Stackurity knows: Apache Roller records its release as ro.version in
// roller-version.properties, which it loads from its classpath
// (org.apache.roller.weblogger.business.WebloggerImpl), so the file is in
// WEB-INF/classes (Roller 5.2.4, 6.1.4) or at the root of one of Roller's
// own JARs in WEB-INF/lib (roller-business.jar in 4.0.1,
// roller-weblogger-business-5.0.4.jar in 5.0.4). It is reported as
// pkg:generic/apache-roller, as WordPress core is, and matched against
// NVD's records for apache:roller (internal/javaapps).
//
// Archives are read as data with archive/zip: nothing in them is run, only
// regular files are opened (no link is followed), and every read is
// bounded (entries per archive, bytes per entry and per nested JAR, JARs
// opened, nesting depth WAR > JAR).

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/collect/lockfile"
	"github.com/stackurity/stackurity/internal/model"
)

const (
	// KindJavaWebapp is the evidence kind of a Java web application
	// identified by its own files (javaapps.Kind on the server).
	KindJavaWebapp = "java-webapp"
	// JavaLibrariesScope starts the coverage scope (followed by the
	// WEB-INF/lib directory or the .war file) of the JARs no installed
	// stack pack reads.
	JavaLibrariesScope = "maven:jar:"
	// WarScope starts the coverage scope of a deployed .war file.
	WarScope = "war:"

	rollerProduct     = "apache-roller"
	rollerVersionFile = "roller-version.properties"
	// maxPropertiesSize bounds a properties file read from an archive or
	// from disk; Roller's is about 120 bytes.
	maxPropertiesSize = 64 << 10
	// maxNestedJar bounds a JAR read from inside a WAR into memory, in
	// bytes actually decompressed, whatever its header declares.
	maxNestedJar = 32 << 20
	// maxRollerJars bounds Roller's own JARs (WEB-INF/lib/roller*.jar)
	// opened per application; a Roller WAR has four.
	maxRollerJars = 8
	// maxLibJars bounds the JARs counted in WEB-INF/lib.
	maxLibJars = 10_000
)

// maxArchiveEntries bounds the entries of one WAR or JAR read; Roller
// 6.1.4's WAR has about 1,400. Tests lower it.
var maxArchiveEntries = 100_000

// ServletWebapps are the webapps directories of servlet containers outside
// the discovery bases (Debian's and Red Hat's tomcat packages, the official
// Tomcat image, tarball installs). A link is not followed: Red Hat's
// /usr/share/tomcat/webapps links to /var/lib/tomcat/webapps, read as such.
var ServletWebapps = []string{"/var/lib/tomcat*/webapps", "/usr/local/tomcat*/webapps", "/usr/local/apache-tomcat*/webapps",
	"/opt/tomcat*/webapps", "/opt/apache-tomcat*/webapps", "/var/lib/jetty*/webapps", "/usr/local/jetty*/webapps", "/opt/jetty*/webapps"}

// webappsDir is the name of a servlet container's deployment directory.
const webappsDir = "webapps"

// discoverServletWebapps reads the webapps directories of ServletWebapps.
func (s *Scanner) discoverServletWebapps(w *walk) {
	for _, pattern := range ServletWebapps {
		dirs, _ := filepath.Glob(s.path(pattern))
		sort.Strings(dirs)
		for _, full := range dirs {
			if fi, err := os.Lstat(full); err != nil || !fi.IsDir() {
				continue // a link, read where it points if that is listed
			}
			s.discoverWebapps(w, s.hostPath(full))
		}
	}
}

// discoverWebapps lists one webapps directory: each directory with a
// WEB-INF directory is a web application, and each .war file the container
// has not unpacked beside itself (roller.war without roller/) is one too.
// An unpacked WAR is read as its directory, which is what runs.
func (s *Scanner) discoverWebapps(w *walk, dir string) {
	if w.seen[dir] {
		return
	}
	w.seen[dir] = true
	entries, err := os.ReadDir(s.path(dir))
	if err != nil {
		return
	}
	unpacked := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			unpacked[e.Name()] = true
		}
	}
	for _, e := range entries {
		if w.budget <= 0 || len(w.out) >= w.maxApps {
			w.full = false
			return
		}
		name := e.Name()
		p := path.Join(dir, name)
		if strings.HasPrefix(name, ".") || w.seen[p] {
			continue
		}
		switch {
		case e.IsDir():
			w.budget--
			if s.realDir(path.Join(p, "WEB-INF")) {
				w.seen[p] = true
				w.out = append(w.out, Discovered{Dir: p, By: []string{"WEB-INF"}})
			}
		case e.Type().IsRegular() && isWar(name):
			if unpacked[strings.TrimSuffix(name, path.Ext(name))] {
				continue
			}
			w.seen[p] = true
			w.out = append(w.out, Discovered{Dir: p, By: []string{"war"}})
		}
	}
}

func isWar(name string) bool { return strings.EqualFold(path.Ext(name), ".war") }

// realDir reports whether host path p is a directory and not a link to
// one: WEB-INF/lib linking out of the application is not read.
func (s *Scanner) realDir(p string) bool {
	fi, err := os.Lstat(s.path(p))
	return err == nil && fi.IsDir()
}

// isWarFile reports whether host path p is a regular .war file (a link is
// not one).
func (s *Scanner) isWarFile(p string) bool {
	if !isWar(p) {
		return false
	}
	fi, err := os.Lstat(s.path(p))
	return err == nil && fi.Mode().IsRegular()
}

// readsJars reports whether an installed stack pack reads JAR files.
func (s *Scanner) readsJars() bool {
	for _, e := range s.Packs {
		if e.Matches("library.jar") {
			return true
		}
	}
	return false
}

// rollerObservation reports Apache Roller at a release read from the file
// at host path loc (inner: the path inside it, for an archive).
func rollerObservation(v, loc, inner string) model.Observation {
	ev := map[string]string{"kind": KindJavaWebapp, "product": "Apache Roller", "source": "version-file"}
	if inner != "" {
		ev["archive_path"] = clip(inner)
	}
	return model.Observation{
		Purl: packageurl.NewPackageURL("generic", "", rollerProduct, v, nil, "").ToString(), Version: v,
		Location: clip(loc), Direct: boolp(true), Scope: "runtime", Confidence: model.ConfidenceConfirmed, Evidence: ev,
	}
}

// javaRelease is a release as a Java build records it: 6.1.4, 4.0.1,
// 6.1.6-SNAPSHOT. An unfiltered "${project.version}" is not.
var javaRelease = regexp.MustCompile(`^\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z][0-9A-Za-z.-]{0,40})?$`)

// parseRollerVersion reads ro.version from roller-version.properties, as
// java.util.Properties does for this file: "key=value", "key: value" or
// "key value" lines, # and ! comments, the last assignment winning.
func parseRollerVersion(data []byte) (string, bool) {
	v := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), maxPropertiesSize)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		i := strings.IndexAny(line, "=: \t")
		if i < 0 || line[:i] != "ro.version" {
			continue
		}
		v = strings.TrimLeft(strings.TrimSpace(line[i:]), "=:")
		v = strings.TrimSpace(v)
	}
	if !javaRelease.MatchString(v) {
		return "", false
	}
	return v, true
}

// readZipEntry reads one entry of an archive, refusing one that
// decompresses to more than limit bytes, whatever its header says.
func readZipEntry(e *zip.File, limit int64) ([]byte, error) {
	if e.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("%s is larger than %d bytes", e.Name, limit)
	}
	rc, err := e.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s decompresses to more than %d bytes", e.Name, limit)
	}
	return data, nil
}

// openZip reads an archive's directory, refusing one with more entries
// than maxArchiveEntries.
func openZip(r io.ReaderAt, size int64) (*zip.Reader, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, errors.New("not a readable zip archive")
	}
	if len(zr.File) > maxArchiveEntries {
		return nil, fmt.Errorf("more than %d entries", maxArchiveEntries)
	}
	return zr, nil
}

// rollerInJar reads roller-version.properties at the root of one of
// Roller's own JARs.
func rollerInJar(zr *zip.Reader) (string, bool) {
	for _, e := range zr.File {
		if e.Name != rollerVersionFile || !e.Mode().IsRegular() {
			continue
		}
		data, err := readZipEntry(e, maxPropertiesSize)
		if err != nil {
			return "", false
		}
		return parseRollerVersion(data)
	}
	return "", false
}

// isRollerJar reports whether a WEB-INF/lib entry name is one of Roller's
// own JARs, which may carry roller-version.properties.
func isRollerJar(name string) bool {
	base := strings.ToLower(path.Base(name))
	return strings.HasPrefix(base, "roller") && strings.HasSuffix(base, ".jar")
}

// javaWebapp reads an exploded Java web application at host path dir: the
// release of Apache Roller if it is Roller, and a coverage gap for the
// JARs in WEB-INF/lib when no stack pack reads them. Nothing when dir has
// no WEB-INF directory.
func (s *Scanner) javaWebapp(dir string, den *denied) ([]model.Observation, []model.CoverageItem) {
	webInf := path.Join(dir, "WEB-INF")
	if !s.realDir(webInf) {
		return nil, nil
	}
	var obs []model.Observation
	var cov []model.CoverageItem
	if o, ok := s.rollerExploded(webInf, den); ok {
		obs = append(obs, o)
	}
	lib := path.Join(webInf, "lib")
	var entries []os.DirEntry
	if s.realDir(lib) {
		var err error
		entries, err = os.ReadDir(s.path(lib))
		den.note(lib, err)
	}
	jars := 0
	for _, e := range entries {
		if e.Type().IsRegular() && strings.EqualFold(path.Ext(e.Name()), ".jar") {
			if jars++; jars >= maxLibJars {
				break
			}
		}
	}
	if jars > 0 && !s.readsJars() {
		cov = append(cov, javaLibrariesGap(lib, fmt.Sprintf("%d JAR files", jars)))
	}
	return obs, cov
}

// javaLibrariesGap is the coverage item of JARs no stack pack reads.
func javaLibrariesGap(where, what string) model.CoverageItem {
	return model.CoverageItem{Scope: clipScope(JavaLibrariesScope + where), Status: "unsupported",
		Reason: what + ": the libraries bundled in them are read by the Java stack pack, which is not enabled on this server"}
}

// rollerExploded reads Roller's release in an exploded application's
// WEB-INF (host path): WEB-INF/classes/roller-version.properties, else the
// file at the root of one of Roller's JARs in WEB-INF/lib.
func (s *Scanner) rollerExploded(webInf string, den *denied) (model.Observation, bool) {
	props := path.Join(webInf, "classes", rollerVersionFile)
	if s.realDir(path.Dir(props)) && (s.Owned == nil || !s.Owned(props)) {
		if f, err := openRegular(s.path(props)); err == nil {
			data, _ := io.ReadAll(io.LimitReader(f, maxPropertiesSize))
			f.Close()
			if v, ok := parseRollerVersion(data); ok {
				return rollerObservation(v, props, ""), true
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			den.note(props, err)
		}
	}
	lib := path.Join(webInf, "lib")
	if !s.realDir(lib) {
		return model.Observation{}, false
	}
	entries, _ := os.ReadDir(s.path(lib)) // an unreadable lib is noted by javaWebapp
	opened := 0
	for _, e := range entries {
		if !e.Type().IsRegular() || !isRollerJar(e.Name()) {
			continue
		}
		if opened++; opened > maxRollerJars {
			break
		}
		jar := path.Join(lib, e.Name())
		if s.Owned != nil && s.Owned(jar) {
			continue
		}
		f, err := openRegular(s.path(jar))
		if err != nil {
			den.note(jar, err)
			continue
		}
		v, ok := "", false
		if fi, err := f.Stat(); err == nil {
			if zr, err := openZip(f, fi.Size()); err == nil {
				v, ok = rollerInJar(zr)
			}
		}
		f.Close()
		if ok {
			return rollerObservation(v, jar, rollerVersionFile), true
		}
	}
	return model.Observation{}, false
}

// rollerInWar reads Roller's release in a WAR: WEB-INF/classes/
// roller-version.properties, else the file at the root of one of Roller's
// JARs in WEB-INF/lib, read into memory up to maxNestedJar. Nothing deeper
// is opened.
func rollerInWar(zr *zip.Reader) (version, inner string, ok bool) {
	var jars []*zip.File
	for _, e := range zr.File {
		switch {
		case !e.Mode().IsRegular():
		case e.Name == "WEB-INF/classes/"+rollerVersionFile:
			if data, err := readZipEntry(e, maxPropertiesSize); err == nil {
				if v, ok := parseRollerVersion(data); ok {
					return v, e.Name, true
				}
			}
		case path.Dir(e.Name) == "WEB-INF/lib" && isRollerJar(e.Name) && len(jars) < maxRollerJars:
			jars = append(jars, e)
		}
	}
	for _, e := range jars {
		data, err := readZipEntry(e, maxNestedJar)
		if err != nil {
			continue
		}
		jr, err := openZip(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			continue
		}
		if v, ok := rollerInJar(jr); ok {
			return v, e.Name + "/" + rollerVersionFile, true
		}
	}
	return "", "", false
}

// scanWar inventories a .war file a servlet container runs as it is (host
// path file): Roller's release, and the libraries bundled in it through
// the Java stack pack, or a coverage gap without it.
func (s *Scanner) scanWar(ctx context.Context, file string) App {
	app := App{Dir: file, Name: clip(strings.TrimSuffix(path.Base(file), path.Ext(file)))}
	den := &denied{dir: file}
	scope := clipScope(WarScope + file)
	if s.Owned != nil && s.Owned(file) {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: scope, Status: "skipped",
			Reason: "installed by an OS package, which the package database reports"})
		return app
	}
	f, err := openRegular(s.path(file))
	if den.note(file, err) {
		c, _ := den.coverage()
		app.Coverage, app.Unreadable = append(app.Coverage, c), true
		return app
	}
	if err != nil {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: scope, Status: "failed", Reason: clipScope(err.Error())})
		return app
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: scope, Status: "failed", Reason: clipScope(err.Error())})
		return app
	}
	zr, err := openZip(f, fi.Size())
	if err != nil {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: scope, Status: "failed", Reason: "not read: " + err.Error()})
		return app
	}
	if v, inner, ok := rollerInWar(zr); ok {
		app.Observations = append(app.Observations, rollerObservation(v, file, inner))
	}
	app.Coverage = append(app.Coverage, model.CoverageItem{Scope: scope, Status: "checked"})
	jars := 0
	for _, e := range zr.File {
		if path.Dir(e.Name) == "WEB-INF/lib" && strings.EqualFold(path.Ext(e.Name), ".jar") {
			jars++
		}
	}
	switch {
	case jars == 0:
	case !s.readsJars():
		app.Coverage = append(app.Coverage, javaLibrariesGap(file, fmt.Sprintf("%d JAR files in WEB-INF/lib", jars)))
	default:
		// The pack reads the WAR, and only it: the directory may hold other
		// applications.
		dir := path.Dir(file)
		locks, lcov, err := lockfile.ScanWith(ctx, oneFileFS{dir: s.path(dir), name: path.Base(file)}, s.Packs)
		if err != nil {
			app.Coverage = append(app.Coverage, model.CoverageItem{Scope: clipScope("lockfiles:" + file), Status: "failed", Reason: clipScope(err.Error())})
		}
		for _, o := range locks {
			if len(app.Observations) >= MaxPackagesPerApp {
				app.Truncated = true
				break
			}
			if !model.Usable(o) {
				continue
			}
			o.Location = clip(path.Join(dir, o.Location))
			if o.Evidence == nil {
				o.Evidence = map[string]string{}
			}
			o.Evidence["source"] = "archive"
			app.Observations = append(app.Observations, o)
		}
		for _, c := range lcov {
			// "pack:java:old.war" names /var/lib/tomcat10/webapps/old.war.
			kind, rest, ok := strings.Cut(c.Scope, ":")
			if ok && kind == "pack" {
				id, file, found := strings.Cut(rest, ":")
				kind, rest, ok = kind+":"+id, file, found
			}
			if ok {
				c.Scope = clipScope(kind + ":" + path.Join(dir, rest))
			}
			app.Coverage = append(app.Coverage, c)
		}
	}
	if app.Truncated {
		app.Coverage = append(app.Coverage, model.CoverageItem{Scope: scope, Status: "partial",
			Reason: fmt.Sprintf("stopped after %d packages", MaxPackagesPerApp)})
	}
	for i := range app.Observations {
		app.Observations[i].Evidence["app_dir"] = clip(file)
	}
	return app
}

// oneFileFS is the directory dir (an OS path) showing only the file name:
// a stack pack reads one .war file and not the other applications beside
// it.
type oneFileFS struct{ dir, name string }

func (o oneFileFS) Open(name string) (fs.File, error) {
	if name != "." && name != o.name {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return os.DirFS(o.dir).Open(name)
}

func (o oneFileFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name != "." {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fs.ErrNotExist}
	}
	entries, err := os.ReadDir(o.dir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.Name() == o.name {
			return []fs.DirEntry{e}, nil
		}
	}
	return nil, nil
}

// UnreadJavaLibraries reports whether the application is a Java web
// application whose bundled libraries no stack pack read. It is sent with
// that gap even when nothing else was found, rather than left out as an
// empty directory.
func (a App) UnreadJavaLibraries() bool {
	for _, c := range a.Coverage {
		if c.Status == "unsupported" && strings.HasPrefix(c.Scope, JavaLibrariesScope) {
			return true
		}
	}
	return false
}
