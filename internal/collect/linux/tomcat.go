package linux

import (
	"archive/zip"
	"bufio"
	"bytes"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Apache Tomcat installed outside a package manager: the official tomcat
// container images unpack Apache's release into /usr/local/tomcat, and
// servers often run a tarball from /opt/tomcat or /opt/apache-tomcat-x.y.z.
// No package owns it and it is not a binary the runtime probes find, so it
// was not inventoried at all: its webapps were read (apps.ServletWebapps),
// Tomcat itself was not, and neither its end of life nor its own
// vulnerabilities were checked.
//
// Nothing is run. The release is read from the files Apache ships:
//
//  1. lib/catalina.jar's org/apache/catalina/util/ServerInfo.properties:
//     server.number=10.1.62.0 and server.info=Apache Tomcat/10.1.62, the
//     version Tomcat itself reports.
//  2. RELEASE-NOTES ("Apache Tomcat Version 10.1.62"), when the jar cannot
//     be read or its properties were edited to hide the version (a common
//     hardening step).
//  3. TOMCAT_VERSION in the image's configuration, which the official
//     images set, only for /usr/local/tomcat (it is metadata a later layer
//     can leave stale, as for PYTHON_VERSION).
//
// Tomcat is reported as pkg:generic/tomcat (endoflife.date's name, so
// lifecycle attaches) with the edition "apache" for Apache's own release.
// A vendor's build (Red Hat JBoss Web Server prints
// "Apache Tomcat/9.0.62.redhat-00010") has fixes backported under its own
// numbers and is reported as "vendor-build", which is not matched against
// Apache's records (internal/intel/runtimebuilds.go).

// tomcatHomes are where Tomcat is unpacked outside a package manager. The
// distributions' packages (/usr/share/tomcat*, /var/lib/tomcat*) are
// inventoried as packages and are not read here.
var tomcatHomes = []string{
	"/usr/local/tomcat", "/usr/local/tomcat[0-9]*", "/usr/local/apache-tomcat*",
	"/opt/tomcat", "/opt/tomcat[0-9]*", "/opt/tomcat-*", "/opt/apache-tomcat*",
	"/opt/*/tomcat", "/opt/*/apache-tomcat*",
}

// maxTomcatHomes bounds the work on hosts with many unpacked releases.
const maxTomcatHomes = 32

// maxCatalinaJar bounds the jar read (catalina.jar is about 2 MB).
const maxCatalinaJar = 16 << 20

var (
	tomcatServerNumber = regexp.MustCompile(`^(\d+\.\d+\.\d+)(?:\.\d+)?$`)
	tomcatServerInfo   = regexp.MustCompile(`^Apache Tomcat/(\d+\.\d+\.\d+)(\S*)`)
	tomcatReleaseNotes = regexp.MustCompile(`(?m)^\s*Apache Tomcat Version (\d+\.\d+\.\d+)\s*$`)
	tomcatEnvValue     = regexp.MustCompile(`^(\d+\.\d+\.\d+)$`)
)

// collectTomcat reports each Tomcat found outside a package manager. owned
// is the set of package-owned paths, or nil when ownership is not known
// file by file (an rpm host); tomcatHomes holds no rpm or deb paths.
func (c *Collector) collectTomcat(owned map[string]bool) []model.Observation {
	var homes []string
	seen := map[string]bool{}
	for _, pattern := range tomcatHomes {
		matches, _ := filepath.Glob(c.path(pattern))
		sort.Strings(matches)
		for _, m := range matches {
			home := c.hostPath(m)
			resolved, ok := c.resolve(home)
			if !ok || seen[resolved] {
				continue
			}
			if fi, err := os.Stat(c.path(resolved)); err != nil || !fi.IsDir() {
				continue
			}
			// A Tomcat home has its startup script and its server jar.
			if !c.exists(path.Join(resolved, "bin", "catalina.sh")) || !c.exists(path.Join(resolved, "lib", "catalina.jar")) {
				continue
			}
			script := path.Join(resolved, "bin", "catalina.sh")
			if owned != nil && (owned[script] || owned[path.Join(home, "bin", "catalina.sh")]) {
				continue
			}
			seen[resolved] = true
			homes = append(homes, resolved)
			if len(homes) >= maxTomcatHomes {
				break
			}
		}
	}
	var out []model.Observation
	for _, home := range homes {
		out = append(out, c.tomcatObservation(home))
	}
	return out
}

func (c *Collector) tomcatObservation(home string) model.Observation {
	jar := path.Join(home, "lib", "catalina.jar")
	o := model.Observation{
		Purl:       purl("generic", "", "tomcat", "", nil),
		Location:   home,
		Scope:      "runtime",
		Confidence: model.ConfidenceUnknown,
		Evidence:   map[string]string{"kind": "runtime", "install": "unmanaged", "binary": jar},
	}
	set := func(v string, conf model.Confidence, how string) {
		o.Version, o.Confidence = v, conf
		o.Purl = purl("generic", "", "tomcat", v, nil)
		o.Evidence["detected_by"] = how
	}
	if v, edition, ok := c.tomcatFromJar(jar); ok {
		set(v, model.ConfidenceConfirmed, "server-info")
		o.Evidence["version_file"] = jar
		o.Evidence["edition"] = edition
		return o
	}
	notes := path.Join(home, "RELEASE-NOTES")
	if data, err := c.readSmall(notes); err == nil {
		if m := tomcatReleaseNotes.FindSubmatch(data); m != nil {
			set(string(m[1]), model.ConfidenceConfirmed, "release-notes")
			o.Evidence["version_file"] = notes
			o.Evidence["edition"] = "apache"
			return o
		}
	}
	if raw := c.ImageEnv["TOMCAT_VERSION"]; home == "/usr/local/tomcat" {
		if m := tomcatEnvValue.FindStringSubmatch(raw); m != nil {
			set(m[1], model.ConfidenceInferred, "image-env")
			o.Evidence["version_env"] = "TOMCAT_VERSION=" + raw
			o.Evidence["edition"] = "apache"
			return o
		}
	}
	o.Evidence["error"] = "no file gave Tomcat's version"
	return o
}

// tomcatFromJar reads the release and edition from catalina.jar's
// ServerInfo.properties; ok false when the jar or the properties cannot be
// read or no longer name a version.
func (c *Collector) tomcatFromJar(jar string) (version, edition string, ok bool) {
	f, err := os.Open(c.path(jar))
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxCatalinaJar {
		return "", "", false
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return "", "", false
	}
	var props map[string]string
	for _, zf := range zr.File {
		if zf.Name != "org/apache/catalina/util/ServerInfo.properties" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return "", "", false
		}
		data, err := io.ReadAll(io.LimitReader(rc, 64<<10))
		rc.Close()
		if err != nil {
			return "", "", false
		}
		props = parseProperties(data)
		break
	}
	if props == nil {
		return "", "", false
	}
	info := tomcatServerInfo.FindStringSubmatch(props["server.info"])
	num := tomcatServerNumber.FindStringSubmatch(props["server.number"])
	switch {
	case info != nil && info[2] != "":
		// A suffix after the release: a vendor's build of it.
		return info[1], "vendor-build", true
	case num != nil && (info == nil || info[1] == num[1]):
		return num[1], "apache", true
	case info != nil && num == nil:
		return info[1], "apache", true
	}
	return "", "", false
}

// parseProperties reads the key=value lines of a Java properties file
// (enough for ServerInfo.properties: no continuations or escapes).
func parseProperties(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
