package darwin

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/stackurity/stackurity/internal/model"
)

// Runtimes installed outside Homebrew: official installers, version
// managers in users' home directories, and JDKs. Their versions are read
// from files or from the folder a version manager names after the version;
// unlike the Linux agent, nothing is run, so the agent can stay an
// unprivileged account that never executes code a user installed.

// maxRuntimes bounds the runtimes reported (a developer with every Python
// release in pyenv has a few dozen).
const maxRuntimes = 1000

// versionDirs are version managers' install folders under a home
// directory: the folder name is the version.
var versionDirs = []struct {
	glob, product, manager string
	re                     *regexp.Regexp // the folder name; first group is the version
}{
	{".nvm/versions/node/*", "nodejs", "nvm", regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`)},
	// pyenv also installs PyPy, Miniconda and others under names that
	// are not CPython versions; only CPython's are read.
	{".pyenv/versions/*", "python", "pyenv", regexp.MustCompile(`^(\d+\.\d+\.\d+)$`)},
	{".rbenv/versions/*", "ruby", "rbenv", regexp.MustCompile(`^(\d+\.\d+\.\d+)$`)},
	{".asdf/installs/nodejs/*", "nodejs", "asdf", regexp.MustCompile(`^(\d+\.\d+\.\d+)$`)},
	{".asdf/installs/python/*", "python", "asdf", regexp.MustCompile(`^(\d+\.\d+\.\d+)$`)},
	{".asdf/installs/ruby/*", "ruby", "asdf", regexp.MustCompile(`^(\d+\.\d+\.\d+)$`)},
	{".asdf/installs/golang/*", "go", "asdf", regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?)$`)},
}

func (c *Collector) collectRuntimes(ctx context.Context, b *model.ObservationBatch, homes []string) {
	var obs []model.Observation
	add := func(o model.Observation) { obs = append(obs, o) }

	// The official Go installer.
	if data, err := readSmall(c.path("/usr/local/go/VERSION")); err == nil {
		line, _, _ := strings.Cut(string(data), "\n")
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "go"); ok && runtimeVersion.MatchString(v) {
			add(runtimeObs("go", v, "/usr/local/go", "installer", "/usr/local/go/VERSION", model.ConfidenceConfirmed))
		}
	}
	// The python.org installer.
	frameworks, _ := filepath.Glob(c.path("/Library/Frameworks/Python.framework/Versions/*"))
	sort.Strings(frameworks)
	for _, full := range frameworks {
		if fi, err := os.Lstat(full); err != nil || !fi.IsDir() {
			continue // "Current" is a symlink to one of the others
		}
		host := c.hostPath(full)
		m, err := readPlist(full + "/Resources/Info.plist")
		if err != nil {
			continue
		}
		if v := cleanVersion(str(m, "CFBundleVersion")); runtimeVersion.MatchString(v) {
			add(runtimeObs("python", v, host, "python.org", host+"/Resources/Info.plist", model.ConfidenceConfirmed))
		}
	}
	// The nodejs.org installer puts node in /usr/local; Homebrew on Intel
	// does too, through symlinks into its Cellar (reported as a keg).
	if hdr := c.path("/usr/local/include/node/node_version.h"); !c.intoCellar(hdr) {
		if v := nodeHeaderVersion(hdr); v != "" {
			add(runtimeObs("nodejs", v, "/usr/local/bin/node", "nodejs.org", "/usr/local/include/node/node_version.h", model.ConfidenceConfirmed))
		}
	}
	c.collectJDKs("/Library/Java/JavaVirtualMachines", add)

	for _, h := range homes {
		if ctx.Err() != nil {
			break
		}
		for _, vd := range versionDirs {
			dirs, _ := filepath.Glob(c.path(h + "/" + vd.glob))
			sort.Strings(dirs)
			for _, full := range dirs {
				m := vd.re.FindStringSubmatch(filepath.Base(full))
				if m == nil {
					continue
				}
				if fi, err := os.Stat(full); err != nil || !fi.IsDir() {
					continue
				}
				host := c.hostPath(full)
				add(runtimeObs(vd.product, m[1], host, vd.manager, "install-path", model.ConfidenceInferred))
			}
		}
		c.collectJDKs(h+"/Library/Java/JavaVirtualMachines", add)
	}
	if len(obs) > maxRuntimes {
		obs = obs[:maxRuntimes]
		b.Cover("runtimes", "partial", fmt.Sprintf("stopped after %d runtimes", maxRuntimes))
	} else {
		b.Cover("runtimes", "checked", "")
	}
	b.Observations = append(b.Observations, obs...)
}

func runtimeObs(product, version, location, install, detectedBy string, conf model.Confidence) model.Observation {
	return model.Observation{
		Purl: genericPurl(product, version), Version: version, Location: location, Scope: "runtime", Confidence: conf,
		Evidence: map[string]string{"kind": "runtime", "install": install, "detected_by": detectedBy},
	}
}

// jdkProducts maps a JDK bundle's identifier prefix to its endoflife.date
// product. JDK builds share version numbers but not support dates, so a JDK
// whose vendor is not recognised is reported as "jdk", with no lifecycle.
var jdkProducts = []struct{ prefix, product string }{
	{"net.temurin.", "eclipse-temurin"},
	{"com.amazon.corretto.", "amazon-corretto"},
	{"com.azul.zulu.", "azul-zulu"},
	{"com.microsoft.", "microsoft-build-of-openjdk"},
	{"com.sap.openjdk.", "sapmachine"},
	{"com.bell-sw.", "bellsoft-liberica"},
	{"com.oracle.java.", "oracle-jdk"},
}

// collectJDKs reads <dir>/*.jdk/Contents/Info.plist (the layout
// /usr/libexec/java_home reads).
func (c *Collector) collectJDKs(dir string, add func(model.Observation)) {
	jdks, _ := filepath.Glob(c.path(dir + "/*"))
	sort.Strings(jdks)
	for _, full := range jdks {
		m, err := readPlist(full + "/Contents/Info.plist")
		if err != nil {
			continue
		}
		jvm, _ := m["JavaVM"].(map[string]any)
		v := ""
		if jvm != nil {
			v = cleanVersion(str(jvm, "JVMVersion"))
		}
		v, _, _ = strings.Cut(v, "+") // 21.0.2+13: the build is not part of the release
		if v == "" {
			v = cleanVersion(str(m, "CFBundleShortVersionString"))
		}
		if !runtimeVersion.MatchString(javaVersion(v)) {
			continue
		}
		v = javaVersion(v)
		id := clean(str(m, "CFBundleIdentifier"), 255)
		product := "jdk"
		for _, p := range jdkProducts {
			if strings.HasPrefix(id, p.prefix) {
				product = p.product
				break
			}
		}
		host := c.hostPath(full)
		o := runtimeObs(product, v, host, "jdk", host+"/Contents/Info.plist", model.ConfidenceConfirmed)
		o.Evidence["bundle_id"] = id
		if jvm != nil {
			if vendor := clean(str(jvm, "JVMVendor"), 200); vendor != "" {
				o.Evidence["vendor"] = vendor
			}
		}
		add(o)
	}
}

// javaVersion reads Java 8's "1.8.0_402" as 8.0.402, the way endoflife.date
// names its release line ("8").
func javaVersion(v string) string {
	if rest, ok := strings.CutPrefix(v, "1.8.0"); ok {
		return "8.0." + strings.TrimPrefix(rest, "_")
	}
	return v
}

var nodeDefine = regexp.MustCompile(`^#define NODE_(MAJOR|MINOR|PATCH)_VERSION (\d+)\s*$`)

// nodeHeaderVersion reads the version from node_version.h.
func nodeHeaderVersion(file string) string {
	data, err := readSmall(file)
	if err != nil {
		return ""
	}
	parts := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		if m := nodeDefine.FindStringSubmatch(sc.Text()); m != nil && parts[m[1]] == "" {
			parts[m[1]] = m[2]
		}
	}
	if parts["MAJOR"] == "" || parts["MINOR"] == "" || parts["PATCH"] == "" {
		return ""
	}
	return parts["MAJOR"] + "." + parts["MINOR"] + "." + parts["PATCH"]
}

// intoCellar reports whether file resolves into a Homebrew Cellar.
func (c *Collector) intoCellar(file string) bool {
	real, err := filepath.EvalSymlinks(file)
	return err == nil && strings.Contains(real, "/Cellar/")
}

// readSmall reads at most 64 KiB.
func readSmall(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64<<10))
}

// hostPath turns a path under Root back into the host's absolute path.
func (c *Collector) hostPath(p string) string {
	rel, err := filepath.Rel(c.Root, p)
	if err != nil {
		return p
	}
	return path.Clean("/" + filepath.ToSlash(rel))
}
