// Package linux collects OS release and package inventory from a Linux host.
// It only reads package databases; it never installs or changes anything.
package linux

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

const CollectorID = "linux-agent"

// Collector reads from Root, which is "/" on a real host and a fixture
// directory in tests. RPM inventory needs the rpm binary, so it is looked up
// through LookPath and skipped (with a coverage record) when missing.
type Collector struct {
	Root     string
	Version  string
	LookPath func(string) (string, error)
	RunRPM   func(ctx context.Context, root string) ([]byte, error)

	// Runtimes enables detection of runtimes installed outside the package
	// manager (see runtimes.go). RunVersion is nil when binaries must not be
	// run, such as under a --root that holds someone else's filesystem.
	Runtimes    bool
	RunVersion  func(ctx context.Context, bin string, args []string) ([]byte, error)
	RunRPMOwner func(ctx context.Context, root string, paths []string) (map[string]bool, error)
	UID         uint32 // the agent's effective uid; binaries it owns may be run
}

func New(version string) *Collector {
	return &Collector{Root: "/", Version: version, LookPath: exec.LookPath, RunRPM: runRPM,
		Runtimes: true, RunVersion: runVersion, RunRPMOwner: runRPMOwner, UID: currentUID()}
}

type OSRelease struct {
	ID, VersionID, VersionCodename, PrettyName, IDLike string
}

func (c *Collector) path(p string) string { return filepath.Join(c.Root, p) }

func (c *Collector) Collect(ctx context.Context, hostname, machineID string) (*model.ObservationBatch, error) {
	osr, err := c.readOSRelease()
	if err != nil {
		return nil, fmt.Errorf("read os-release: %w", err)
	}
	attrs := map[string]string{
		"os":         osr.ID,
		"os_version": osr.VersionID,
		"os_name":    osr.PrettyName,
	}
	if osr.VersionCodename != "" {
		attrs["os_codename"] = osr.VersionCodename
	}
	for k, v := range c.rebootState() {
		attrs[k] = v
	}
	ids := []model.Identifier{{Scheme: "hostname", Value: hostname}}
	if machineID != "" {
		ids = append([]model.Identifier{{Scheme: "machine-id", Value: machineID}}, ids...)
	}
	b := model.NewBatch(
		model.Collector{ID: CollectorID, Version: c.Version, Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: hostname, Identifiers: ids, Attributes: attrs},
	)
	b.Complete = true
	distro := osr.ID + "-" + osr.VersionID

	// The OS itself is a component, so lifecycle data can attach to it.
	if osr.ID != "" {
		b.Observations = append(b.Observations, model.Observation{
			Purl:       purl("generic", "", osr.ID, osr.VersionID, nil),
			Version:    osr.VersionID,
			Location:   "/etc/os-release",
			Scope:      "os",
			Confidence: model.ConfidenceConfirmed,
			Evidence:   map[string]string{"pretty_name": osr.PrettyName, "kind": "operating-system"},
		})
	}

	found := false
	if f, err := os.Open(c.path("var/lib/dpkg/status")); err == nil {
		obs, perr := parseDpkgStatus(f, osr.ID, distro)
		f.Close()
		if perr != nil {
			b.Cover("dpkg", "failed", perr.Error())
		} else {
			b.Observations = append(b.Observations, obs...)
			b.Cover("dpkg", "checked", "")
		}
		found = true
	}
	if f, err := os.Open(c.path("lib/apk/db/installed")); err == nil {
		obs, perr := parseApkInstalled(f, distro)
		f.Close()
		if perr != nil {
			b.Cover("apk", "failed", perr.Error())
		} else {
			b.Observations = append(b.Observations, obs...)
			b.Cover("apk", "checked", "")
		}
		found = true
	}
	if hasRPMDB(c) {
		found = true
		if _, err := c.LookPath("rpm"); err != nil {
			b.Cover("rpm", "skipped", "rpm database present but rpm binary not found")
		} else if out, err := c.RunRPM(ctx, c.Root); err != nil {
			b.Cover("rpm", "failed", err.Error())
		} else {
			obs, perr := parseRPMQuery(out, osr.ID, distro)
			if perr != nil {
				b.Cover("rpm", "failed", perr.Error())
			} else {
				b.Observations = append(b.Observations, obs...)
				b.Cover("rpm", "checked", "")
			}
		}
	}
	if !found {
		b.Cover("os-packages", "unsupported", "no dpkg, rpm or apk package database found")
		b.Complete = false
	}
	b.KeepUsable()
	for _, cov := range b.Coverage {
		if cov.Status != "checked" {
			b.Complete = false
		}
	}
	return b, nil
}

// SoftwareCollectorID reports software outside the OS package database:
// runtimes and host-wide (global) libraries. It is a separate collection
// so a problem reading either never makes the package inventory incomplete,
// and the package database never vouches for what this one did not see.
const SoftwareCollectorID = "linux-software"

// CollectSoftware returns a batch for the same host as os with runtimes
// (when enabled) and the libraries global reports.
func (c *Collector) CollectSoftware(ctx context.Context, os *model.ObservationBatch,
	global func() ([]model.Observation, []model.CoverageItem)) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: SoftwareCollectorID, Version: c.Version, Method: "agent"}, os.Asset)
	if c.Runtimes {
		c.collectRuntimes(ctx, b)
	}
	if global != nil {
		obs, cov := global()
		b.Observations = append(b.Observations, obs...)
		b.Coverage = append(b.Coverage, cov...)
	}
	b.Complete = true
	for _, cov := range b.Coverage {
		if cov.Status != "checked" {
			b.Complete = false
		}
	}
	return b
}

// OwnedFunc reports whether an OS package installed a host path. On rpm
// hosts, where listing every file is expensive, system library directories
// under /usr/lib and /usr/lib64 count as owned; pip and npm install
// system-wide packages under /usr/local instead.
func (c *Collector) OwnedFunc() func(string) bool {
	owned, err := c.ownedFiles()
	if err == nil && owned != nil {
		return func(p string) bool { return owned[p] || owned[usrMerge(p)] }
	}
	return func(p string) bool {
		return strings.HasPrefix(p, "/usr/lib/") || strings.HasPrefix(p, "/usr/lib64/")
	}
}

func hasRPMDB(c *Collector) bool {
	for _, p := range []string{"var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite"} {
		if _, err := os.Stat(c.path(p)); err == nil {
			return true
		}
	}
	return false
}

func (c *Collector) readOSRelease() (OSRelease, error) {
	var data []byte
	var err error
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		data, err = os.ReadFile(c.path(p))
		if err == nil {
			break
		}
	}
	if err != nil {
		return OSRelease{}, err
	}
	return ParseOSRelease(data), nil
}

func ParseOSRelease(data []byte) OSRelease {
	kv := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[k] = strings.Trim(v, `"'`)
	}
	return OSRelease{
		ID: kv["ID"], VersionID: kv["VERSION_ID"], VersionCodename: kv["VERSION_CODENAME"],
		PrettyName: kv["PRETTY_NAME"], IDLike: kv["ID_LIKE"],
	}
}

// MachineID returns /etc/machine-id when readable.
func (c *Collector) MachineID() string {
	b, err := os.ReadFile(c.path("etc/machine-id"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func purl(typ, ns, name, version string, q map[string]string) string {
	return packageurl.NewPackageURL(typ, ns, name, version, packageurl.QualifiersFromMap(q), "").ToString()
}

// parseStanzas splits RFC822-style package databases (dpkg status, apk installed).
func parseStanzas(r io.Reader, sep func(line string) (key, val string, ok bool)) ([]map[string]string, error) {
	var out []map[string]string
	cur := map[string]string{}
	var lastKey string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				out = append(out, cur)
				cur = map[string]string{}
			}
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && lastKey != "" {
			continue // continuation line (descriptions, conffiles)
		}
		k, v, ok := sep(line)
		if !ok {
			continue
		}
		cur[k] = v
		lastKey = k
	}
	if len(cur) > 0 {
		out = append(out, cur)
	}
	return out, sc.Err()
}

func parseDpkgStatus(r io.Reader, osID, distro string) ([]model.Observation, error) {
	stanzas, err := parseStanzas(r, func(line string) (string, string, bool) {
		k, v, ok := strings.Cut(line, ":")
		return k, strings.TrimSpace(v), ok
	})
	if err != nil {
		return nil, err
	}
	ns := osID
	if ns == "" {
		ns = "debian"
	}
	var obs []model.Observation
	for _, s := range stanzas {
		if !strings.HasSuffix(s["Status"], " installed") || s["Package"] == "" {
			continue
		}
		q := map[string]string{"distro": distro}
		if s["Architecture"] != "" {
			q["arch"] = s["Architecture"]
		}
		ev := map[string]string{"db": "dpkg"}
		// OSV Debian/Ubuntu advisories are keyed by source package.
		if src := s["Source"]; src != "" {
			name, ver, _ := strings.Cut(src, " ")
			ev["source_package"] = name
			if ver = strings.Trim(ver, "()"); ver != "" {
				ev["source_version"] = ver
			}
			q["upstream"] = name
		}
		obs = append(obs, model.Observation{
			Purl:       purl("deb", ns, s["Package"], s["Version"], q),
			Version:    s["Version"],
			Location:   "/var/lib/dpkg/status",
			Scope:      "os",
			Confidence: model.ConfidenceConfirmed,
			Evidence:   ev,
		})
	}
	return obs, nil
}

func parseApkInstalled(r io.Reader, distro string) ([]model.Observation, error) {
	stanzas, err := parseStanzas(r, func(line string) (string, string, bool) {
		if len(line) < 2 || line[1] != ':' {
			return "", "", false
		}
		return line[:1], line[2:], true
	})
	if err != nil {
		return nil, err
	}
	var obs []model.Observation
	for _, s := range stanzas {
		if s["P"] == "" {
			continue
		}
		q := map[string]string{"distro": distro}
		if s["A"] != "" {
			q["arch"] = s["A"]
		}
		ev := map[string]string{"db": "apk"}
		if s["o"] != "" {
			ev["source_package"] = s["o"]
			q["upstream"] = s["o"]
		}
		obs = append(obs, model.Observation{
			Purl:       purl("apk", "alpine", s["P"], s["V"], q),
			Version:    s["V"],
			Location:   "/lib/apk/db/installed",
			Scope:      "os",
			Confidence: model.ConfidenceConfirmed,
			Evidence:   ev,
		})
	}
	return obs, nil
}

// rpmQueryFormat emits one tab-separated line per package.
const rpmQueryFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`

func runRPM(ctx context.Context, root string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	args := []string{"-qa", "--queryformat", rpmQueryFormat}
	if root != "/" && root != "" {
		args = append([]string{"--root", root}, args...)
	}
	cmd := exec.CommandContext(ctx, "rpm", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	return cmd.Output()
}

func parseRPMQuery(out []byte, osID, distro string) ([]model.Observation, error) {
	var obs []model.Observation
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 6 || f[0] == "gpg-pubkey" {
			continue
		}
		name, epoch, ver, rel, arch, srpm := f[0], f[1], f[2], f[3], f[4], f[5]
		version := ver + "-" + rel
		full := version
		q := map[string]string{"distro": distro, "arch": arch}
		if epoch != "" && epoch != "0" {
			q["epoch"] = epoch
			full = epoch + ":" + version
		}
		ev := map[string]string{"db": "rpm", "evr": full}
		if srpm != "" && srpm != "(none)" {
			ev["source_rpm"] = srpm
		}
		obs = append(obs, model.Observation{
			Purl:       purl("rpm", osID, name, version, q),
			Version:    full,
			Location:   "rpmdb",
			Scope:      "os",
			Confidence: model.ConfidenceConfirmed,
			Evidence:   ev,
		})
	}
	return obs, sc.Err()
}
