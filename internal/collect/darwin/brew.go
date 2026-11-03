package darwin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

// HomebrewPrefixes are where Homebrew installs: /opt/homebrew on Apple
// silicon, /usr/local on Intel (and under Rosetta on Apple silicon).
var HomebrewPrefixes = []string{"/opt/homebrew", "/usr/local"}

// brewRuntimes maps Homebrew formula names (without the "@<line>" of a
// versioned formula) to endoflife.date products: the runtimes and servers
// the Linux agent detects (internal/collect/linux runtimeProbes). Such a
// formula is reported as that product, so its end of life is evaluated as
// it is for the same runtime on Linux. Formula names verified against
// formulae.brew.sh; mongodb-community comes from MongoDB's own tap
// (mongodb/brew).
var brewRuntimes = map[string]string{
	"node": "nodejs", "python": "python", "go": "go", "ruby": "ruby", "php": "php",
	"redis": "redis", "valkey": "valkey", "mysql": "mysql", "mariadb": "mariadb",
	"postgresql": "postgresql", "mongodb-community": "mongodb", "nginx": "nginx",
	"haproxy": "haproxy", "meilisearch": "meilisearch",
}

// brewRevision is the "_1" Homebrew appends to a version when it rebuilds
// the same upstream release.
var brewRevision = regexp.MustCompile(`_\d+$`)

// formulaName is what Homebrew allows in a formula or cask name.
var formulaName = regexp.MustCompile(`^[a-z0-9][a-z0-9@._+-]{0,127}$`)

// maxReceiptBytes bounds one INSTALL_RECEIPT.json (they are a few KB).
const maxReceiptBytes = 1 << 20

type brewReceipt struct {
	InstalledOnRequest *bool `json:"installed_on_request"`
	Source             struct {
		Tap      string `json:"tap"`
		Version  string `json:"version"` // casks
		Versions struct {
			Stable string `json:"stable"`
		} `json:"versions"`
	} `json:"source"`
}

func readReceipt(file string) (*brewReceipt, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxReceiptBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxReceiptBytes {
		return nil, fmt.Errorf("larger than 1 MiB")
	}
	var r brewReceipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// collectHomebrew reports every installed keg (Cellar/<formula>/<version>)
// and cask (Caskroom/<token>/<version>) under each prefix that has them.
func (c *Collector) collectHomebrew(ctx context.Context, b *model.ObservationBatch) {
	for _, prefix := range HomebrewPrefixes {
		c.collectCellar(ctx, b, prefix)
		c.collectCaskroom(ctx, b, prefix)
	}
}

func (c *Collector) collectCellar(ctx context.Context, b *model.ObservationBatch, prefix string) {
	cellar := prefix + "/Cellar"
	formulae, err := readDirBounded(c.path(cellar))
	if err != nil {
		if !os.IsNotExist(err) {
			b.Cover("path:"+cellar, "skipped", "cannot read Homebrew's Cellar: "+errText(err))
		}
		return
	}
	limit, n := c.maxBundles(), 0
	truncated := len(formulae) > maxDirEntries
	unreadable := 0
outer:
	for _, f := range formulae {
		name := f.Name()
		if !f.IsDir() || !formulaName.MatchString(name) {
			continue
		}
		kegs, err := readDirBounded(c.path(cellar + "/" + name))
		if err != nil {
			unreadable++
			continue
		}
		linked := c.linkedKeg(prefix, name)
		for _, k := range kegs {
			if ctx.Err() != nil {
				b.Cover("path:"+cellar, "partial", "stopped: "+ctx.Err().Error())
				return
			}
			if !k.IsDir() || strings.HasPrefix(k.Name(), ".") {
				continue
			}
			if n >= limit {
				truncated = true
				break outer
			}
			n++
			b.Observations = append(b.Observations, c.kegObservation(prefix, name, k.Name(), linked == k.Name()))
		}
	}
	switch {
	case truncated:
		b.Cover("path:"+cellar, "partial", fmt.Sprintf("stopped after %d kegs or %d entries", limit, maxDirEntries))
	case unreadable > 0:
		b.Cover("path:"+cellar, "partial", fmt.Sprintf("%d formula folder(s) could not be read", unreadable))
	default:
		b.Cover("path:"+cellar, "checked", "")
	}
}

// linkedKeg returns the version <prefix>/opt/<name> points at: the keg in
// use when several are installed.
func (c *Collector) linkedKeg(prefix, name string) string {
	target, err := os.Readlink(c.path(prefix + "/opt/" + name))
	if err != nil {
		return ""
	}
	dir, ver := path.Split(path.Clean(target))
	if path.Base(path.Clean(dir)) != name {
		return ""
	}
	return ver
}

func (c *Collector) kegObservation(prefix, name, kegVersion string, linked bool) model.Observation {
	keg := prefix + "/Cellar/" + name + "/" + kegVersion
	ev := map[string]string{"kind": "homebrew-formula", "formula": name, "homebrew_prefix": prefix, "keg_version": clean(kegVersion, 128)}
	if linked {
		ev["linked"] = "true"
	}
	conf := model.ConfidenceConfirmed
	if r, err := readReceipt(c.path(keg + "/INSTALL_RECEIPT.json")); err != nil {
		// The folder name is the version Homebrew installed; the receipt
		// only adds where it came from.
		conf = model.ConfidenceInferred
		ev["receipt"] = "INSTALL_RECEIPT.json: " + errText(err)
	} else {
		if t := clean(r.Source.Tap, 128); t != "" {
			ev["tap"] = t
		}
		if r.InstalledOnRequest != nil {
			ev["installed_on_request"] = fmt.Sprint(*r.InstalledOnRequest)
		}
	}
	version := clean(brewRevision.ReplaceAllString(kegVersion, ""), 128)
	base, _, _ := strings.Cut(name, "@")
	if product := brewRuntimes[base]; product != "" && runtimeVersion.MatchString(version) {
		// Reported as the runtime, so lifecycle applies as on Linux.
		ev["kind"], ev["install"] = "runtime", "homebrew"
		return model.Observation{Purl: genericPurl(product, version), Version: version, Location: keg, Scope: "runtime",
			Confidence: conf, Evidence: ev}
	}
	return model.Observation{
		Purl: packageurl.NewPackageURL("brew", "", name, version, nil, "").ToString(), Version: version,
		Location: keg, Scope: "os", Confidence: conf, Evidence: ev,
	}
}

// runtimeVersion is a release version a lifecycle line can be read from.
var runtimeVersion = regexp.MustCompile(`^\d+(\.\d+){0,3}$`)

func genericPurl(name, version string) string {
	return packageurl.NewPackageURL("generic", "", name, version, nil, "").ToString()
}

// collectCaskroom reports installed casks. Casks are mostly applications
// (also seen in /Applications) and command-line tools shipped as binaries.
func (c *Collector) collectCaskroom(ctx context.Context, b *model.ObservationBatch, prefix string) {
	room := prefix + "/Caskroom"
	casks, err := readDirBounded(c.path(room))
	if err != nil {
		if !os.IsNotExist(err) {
			b.Cover("path:"+room, "skipped", "cannot read Homebrew's Caskroom: "+errText(err))
		}
		return
	}
	limit, n := c.maxBundles(), 0
	truncated := len(casks) > maxDirEntries
	unreadable := 0
outer:
	for _, cask := range casks {
		token := cask.Name()
		if !cask.IsDir() || !formulaName.MatchString(token) {
			continue
		}
		dir := room + "/" + token
		versions, err := readDirBounded(c.path(dir))
		if err != nil {
			unreadable++
			continue
		}
		receipt, rerr := readReceipt(c.path(dir + "/.metadata/INSTALL_RECEIPT.json"))
		for _, v := range versions {
			if ctx.Err() != nil {
				b.Cover("path:"+room, "partial", "stopped: "+ctx.Err().Error())
				return
			}
			if !v.IsDir() || strings.HasPrefix(v.Name(), ".") {
				continue
			}
			if n >= limit {
				truncated = true
				break outer
			}
			n++
			ev := map[string]string{"kind": "homebrew-cask", "cask": token, "homebrew_prefix": prefix}
			version := clean(v.Name(), 128)
			if rerr == nil {
				if t := clean(receipt.Source.Tap, 128); t != "" {
					ev["tap"] = t
				}
			}
			conf := model.ConfidenceConfirmed
			if version == "latest" {
				// Casks that always download the vendor's newest build
				// record no version.
				ev["cask_version"], version, conf = "latest", "", model.ConfidenceUnknown
			}
			b.Observations = append(b.Observations, model.Observation{
				Purl: packageurl.NewPackageURL("brew", "cask", token, version, nil, "").ToString(), Version: version,
				Location: dir + "/" + v.Name(), Scope: "os", Confidence: conf, Evidence: ev,
			})
		}
	}
	switch {
	case truncated:
		b.Cover("path:"+room, "partial", fmt.Sprintf("stopped after %d casks or %d entries", limit, maxDirEntries))
	case unreadable > 0:
		b.Cover("path:"+room, "partial", fmt.Sprintf("%d cask folder(s) could not be read", unreadable))
	default:
		b.Cover("path:"+room, "checked", "")
	}
}
