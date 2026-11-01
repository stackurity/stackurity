// Package darwin collects the operating system version, installed
// applications, Homebrew packages and language runtimes of a macOS host.
// It reads files only (property lists, Homebrew's install receipts,
// version manager directories); the one command it runs is ioreg, for the
// machine's hardware UUID. It never installs or changes anything, and needs
// no root: what the agent's user cannot read is reported as coverage.
package darwin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

// CollectorID reports the system-wide inventory: the OS, applications in
// /Applications and Homebrew.
const CollectorID = "macos-agent"

// SoftwareCollectorID reports what lives outside those: runtimes from
// version managers and installers, JDKs, host-wide npm and pip libraries,
// and applications in users' ~/Applications. It is a separate collection,
// as on Linux, so a home directory the agent may not read never makes the
// system-wide inventory incomplete.
const SoftwareCollectorID = "macos-software"

// SystemVersionPlist is where macOS records its version (what sw_vers prints).
const SystemVersionPlist = "/System/Library/CoreServices/SystemVersion.plist"

// Collector reads from Root, which is "/" on a real Mac and a fixture
// directory in tests.
type Collector struct {
	Root    string
	Version string
	// PlatformUUID returns the hardware UUID (IOPlatformUUID), "" when
	// unknown. Nil in tests.
	PlatformUUID func(ctx context.Context) string
	// Global inventories host-wide libraries in the given directories
	// (apps.Scanner.ScanGlobalDirs). Nil skips them.
	Global func(patterns []string) ([]model.Observation, []model.CoverageItem)
	// Runtimes enables runtime and JDK detection (--no-runtimes turns it
	// off; nothing is run either way).
	Runtimes bool
	// MaxBundles bounds the applications read under one directory, and the
	// Homebrew kegs and casks under one prefix.
	MaxBundles int
}

// DefaultMaxBundles is far above a real Mac (a developer laptop has a few
// hundred applications and Homebrew kegs) and keeps a pathological
// directory from making the batch unbounded.
const DefaultMaxBundles = 5000

func New(version string) *Collector {
	return &Collector{Root: "/", Version: version, PlatformUUID: ioregUUID, Runtimes: true, MaxBundles: DefaultMaxBundles}
}

func (c *Collector) path(p string) string { return filepath.Join(c.Root, p) }

func (c *Collector) maxBundles() int {
	if c.MaxBundles > 0 {
		return c.MaxBundles
	}
	return DefaultMaxBundles
}

// OSInfo is what SystemVersion.plist says.
type OSInfo struct {
	Name, Version, Build string
}

func (c *Collector) readOS() (OSInfo, error) {
	m, err := readPlist(c.path(SystemVersionPlist))
	if err != nil {
		return OSInfo{}, err
	}
	o := OSInfo{Name: str(m, "ProductName"), Version: str(m, "ProductVersion"), Build: str(m, "ProductBuildVersion")}
	if o.Version == "" {
		return OSInfo{}, fmt.Errorf("%s has no ProductVersion", SystemVersionPlist)
	}
	if o.Name == "" {
		o.Name = "macOS"
	}
	return o, nil
}

// Collect returns the system-wide batch: the OS, /Applications and Homebrew.
func (c *Collector) Collect(ctx context.Context, hostname string) (*model.ObservationBatch, error) {
	osi, err := c.readOS()
	if err != nil {
		return nil, fmt.Errorf("read macOS version: %w", err)
	}
	attrs := map[string]string{"os": "macos", "os_version": osi.Version, "os_name": strings.TrimSpace(osi.Name + " " + osi.Version)}
	if osi.Build != "" {
		attrs["os_build"] = osi.Build
	}
	ids := []model.Identifier{{Scheme: "hostname", Value: hostname}}
	if c.PlatformUUID != nil {
		if u := c.PlatformUUID(ctx); u != "" {
			ids = append([]model.Identifier{{Scheme: "macos-platform-uuid", Value: u}}, ids...)
		}
	}
	b := model.NewBatch(model.Collector{ID: CollectorID, Version: c.Version, Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: hostname, Identifiers: ids, Attributes: attrs})
	b.Observations = append(b.Observations, model.Observation{
		Purl: packageurl.NewPackageURL("generic", "", "macos", osi.Version, nil, "").ToString(), Version: osi.Version,
		Location: SystemVersionPlist, Scope: "os", Confidence: model.ConfidenceConfirmed,
		Evidence: map[string]string{"kind": "operating-system", "product_name": osi.Name, "build": osi.Build},
	})
	c.scanApps(ctx, b, "/Applications", false)
	c.collectHomebrew(ctx, b)
	// Not collected, and said so: never shown as up to date.
	b.Cover("macos:software-updates", "unsupported",
		"pending macOS updates are not read (softwareupdate --list asks Apple's servers and can take minutes); the release's end of life is evaluated")
	b.Cover("macos:system-applications", "unsupported",
		"applications in /System/Applications are part of macOS and updated with it; they are not inventoried separately")
	finish(b)
	return b, nil
}

// finish drops unusable rows, decides completeness and sorts the rows after
// the first (the OS, when there is one) for stable output.
//
// Complete means the batch is everything the collector inventories, so the
// server may mark what is missing as removed. Items reported "unsupported"
// are outside what it inventories (like the Windows collector's hotfixes);
// anything "partial", "skipped" or "failed" names the path it could not
// read, so the server can still prove removals elsewhere.
func finish(b *model.ObservationBatch) {
	b.Complete = true
	b.KeepUsable()
	for _, cov := range b.Coverage {
		if cov.Status != "checked" && cov.Status != "unsupported" {
			b.Complete = false
		}
	}
	start := 0
	if len(b.Observations) > 0 && b.Observations[0].Evidence["kind"] == "operating-system" {
		start = 1
	}
	rest := b.Observations[start:]
	sort.SliceStable(rest, func(i, j int) bool {
		if rest[i].Purl != rest[j].Purl {
			return rest[i].Purl < rest[j].Purl
		}
		return rest[i].Location < rest[j].Location
	})
}

// CollectSoftware returns the batch for the same host as sys with runtimes,
// JDKs, host-wide libraries and per-user applications.
func (c *Collector) CollectSoftware(ctx context.Context, sys *model.ObservationBatch) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: SoftwareCollectorID, Version: c.Version, Method: "agent"}, sys.Asset)
	homes := c.homes(b)
	if c.Runtimes {
		c.collectRuntimes(ctx, b, homes)
	}
	for _, h := range homes {
		c.scanApps(ctx, b, h+"/Applications", true)
	}
	if c.Global != nil {
		obs, cov := c.Global(GlobalDirs)
		b.Observations = append(b.Observations, obs...)
		b.Coverage = append(b.Coverage, cov...)
	}
	finish(b)
	return b
}

// GlobalDirs hold libraries installed for the whole Mac rather than one
// project: Homebrew's and the official installers' global npm packages and
// pip installs, and global packages of nvm's Node versions.
var GlobalDirs = []string{
	"/opt/homebrew/lib/node_modules", "/usr/local/lib/node_modules",
	"/opt/homebrew/lib/python3*/site-packages", "/usr/local/lib/python3*/site-packages",
	"/Library/Frameworks/Python.framework/Versions/[0-9]*/lib/python3*/site-packages", // not Current, a link to one of them
	"/Users/*/.nvm/versions/node/*/lib/node_modules",
}

// homes returns the users' home directories under /Users the agent can
// read, and reports the others: a LaunchDaemon running as its own user
// cannot read home directories, which are private to their owner.
func (c *Collector) homes(b *model.ObservationBatch) []string {
	entries, err := os.ReadDir(c.path("/Users"))
	if err != nil {
		b.Cover("path:/Users", "skipped", "cannot list users' home directories: "+errText(err))
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == "Shared" || name == "Guest" {
			continue
		}
		host := "/Users/" + name
		fi, err := os.Stat(c.path(host))
		if err != nil || !fi.IsDir() {
			continue
		}
		if _, err := os.ReadDir(c.path(host)); err != nil {
			b.Cover("path:"+host, "skipped",
				"home directory not readable by the agent's user ("+errText(err)+"): its ~/Applications, version managers and JDKs are not inventoried")
			continue
		}
		out = append(out, host)
		if len(out) >= 500 {
			b.Cover("path:/Users", "partial", "stopped after 500 home directories")
			break
		}
	}
	return out
}

func errText(err error) string {
	switch {
	case os.IsPermission(err):
		return "permission denied"
	case os.IsNotExist(err):
		return "not found"
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// --- identity

var platformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"`)

// ParseIOReg reads IOPlatformUUID from `ioreg -rd1 -c IOPlatformExpertDevice`.
func ParseIOReg(out []byte) string {
	if m := platformUUID.FindSubmatch(out); m != nil {
		return strings.ToLower(string(m[1]))
	}
	return ""
}

// ioregUUID runs ioreg once, with a clean environment and a short timeout.
// The hardware UUID is the Mac's stable identity, like /etc/machine-id on
// Linux; no file holds it, and reading it needs no privileges.
func ioregUUID(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
	cmd.Dir = "/"
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if u := ParseIOReg(sc.Bytes()); u != "" {
			return u
		}
	}
	return ""
}
