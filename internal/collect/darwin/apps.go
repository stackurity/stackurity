package darwin

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

// maxDirEntries bounds one directory listing: a folder with more entries
// than this is not an Applications folder anyone maintains by hand.
const maxDirEntries = 20000

// scanApps reports the application bundles in dir (a host path): every
// <name>.app in it and in its subfolders one level down (Utilities, a
// vendor's folder). Bundles inside bundles are not separate applications.
func (c *Collector) scanApps(ctx context.Context, b *model.ObservationBatch, dir string, perUser bool) {
	entries, err := readDirBounded(c.path(dir))
	if err != nil {
		if os.IsNotExist(err) {
			if !perUser {
				b.Cover("path:"+dir, "checked", "no such directory")
			}
			return
		}
		b.Cover("path:"+dir, "skipped", "cannot read the folder: "+errText(err))
		return
	}
	limit := c.maxBundles()
	found, truncated := 0, len(entries) > maxDirEntries
	add := func(bundle string) bool {
		if found >= limit {
			truncated = true
			return false
		}
		found++
		b.Observations = append(b.Observations, c.appObservation(bundle, perUser))
		return true
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			b.Cover("path:"+dir, "partial", "stopped: "+ctx.Err().Error())
			return
		}
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		host := path.Join(dir, name)
		fi, err := os.Stat(c.path(host)) // follows a symlinked application
		if err != nil || !fi.IsDir() {
			continue
		}
		if strings.HasSuffix(name, ".app") {
			if !add(host) {
				break
			}
			continue
		}
		sub, err := readDirBounded(c.path(host))
		if err != nil {
			if !os.IsNotExist(err) {
				b.Cover("path:"+host, "skipped", "cannot read the folder: "+errText(err))
			}
			continue
		}
		truncated = truncated || len(sub) > maxDirEntries
		for _, s := range sub {
			if !strings.HasSuffix(s.Name(), ".app") || strings.HasPrefix(s.Name(), ".") {
				continue
			}
			if fi, err := os.Stat(c.path(path.Join(host, s.Name()))); err != nil || !fi.IsDir() {
				continue
			}
			if !add(path.Join(host, s.Name())) {
				break
			}
		}
	}
	if truncated {
		b.Cover("path:"+dir, "partial", fmt.Sprintf("stopped after %d applications or %d folder entries", limit, maxDirEntries))
		return
	}
	b.Cover("path:"+dir, "checked", "")
}

// readDirBounded lists at most maxDirEntries+1 entries, so the caller can
// tell a truncated listing.
func readDirBounded(dir string) ([]os.DirEntry, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maxDirEntries + 1)
	if err == io.EOF {
		err = nil
	}
	return entries, err
}

// appObservation describes one bundle from its Contents/Info.plist. A
// bundle whose plist cannot be read is still reported, by its folder name
// and without a version, so it is never missing from the inventory; its
// version is "unknown" and nothing is assessed for it.
func (c *Collector) appObservation(bundle string, perUser bool) model.Observation {
	ev := map[string]string{"kind": "macos-app"}
	if perUser {
		ev["per_user"] = "true"
	}
	name := clean(strings.TrimSuffix(path.Base(bundle), ".app"), 200)
	short, ver := "", ""
	plistPath := bundle + "/Contents/Info.plist"
	if w, ok := c.wrappedBundle(bundle); ok {
		// An iPhone or iPad app installed on Apple silicon: the iOS
		// bundle, with its Info.plist at the top, is wrapped inside.
		plistPath, ev["platform"] = w+"/Info.plist", "ios"
	}
	m, err := readPlist(c.path(plistPath))
	if err != nil {
		ev["error"] = "Info.plist: " + errText(err)
	} else {
		for _, k := range []string{"CFBundleDisplayName", "CFBundleName"} {
			if n := clean(str(m, k), 200); n != "" {
				name = n
				break
			}
		}
		short, ver = cleanVersion(str(m, "CFBundleShortVersionString")), cleanVersion(str(m, "CFBundleVersion"))
		if id := clean(str(m, "CFBundleIdentifier"), 255); id != "" {
			ev["bundle_id"] = id
		}
		if ver != "" {
			ev["bundle_version"] = ver
		}
	}
	if _, err := os.Stat(c.path(bundle + "/Contents/_MASReceipt/receipt")); err == nil {
		ev["installed_from"] = "app-store"
	}
	// The marketing version is what vendors publish advisories and
	// releases against; CFBundleVersion is often a build number.
	version, conf := short, model.ConfidenceConfirmed
	if version == "" && ver != "" {
		version, conf = ver, model.ConfidenceInferred
	}
	if version == "" {
		conf = model.ConfidenceUnknown
	}
	return model.Observation{
		Purl: packageurl.NewPackageURL("generic", "", name, version, nil, "").ToString(), Version: version,
		Location: bundle, Scope: "os", Confidence: conf, Evidence: ev,
	}
}

// wrappedBundle returns the iOS bundle inside a wrapper (WrappedBundle ->
// Wrapper/<name>.app), only when the link stays inside the wrapper.
func (c *Collector) wrappedBundle(bundle string) (string, bool) {
	target, err := os.Readlink(c.path(bundle + "/WrappedBundle"))
	if err != nil || path.IsAbs(target) {
		return "", false
	}
	t := path.Clean(target)
	if t == "." || strings.HasPrefix(t, "..") || !strings.HasSuffix(t, ".app") {
		return "", false
	}
	return bundle + "/" + t, true
}
