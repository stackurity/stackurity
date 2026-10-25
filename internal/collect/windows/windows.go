// Package windows collects OS build and installed programs from a Windows
// host's registry (the same data as "Apps & features"). It only reads.
package windows

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/model"
)

const CollectorID = "windows-agent"

// Registry abstracts the few registry reads the collector needs, so the
// logic is testable on any platform.
type Registry interface {
	// OSInfo returns values under HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion.
	OSInfo() (map[string]string, error)
	// Uninstall returns one map of values per subkey of an Uninstall key.
	// view is "native" or "wow64".
	Uninstall(view string) ([]map[string]string, error)
	MachineGUID() string
}

type Collector struct {
	Reg     Registry
	Version string
}

func (c *Collector) Collect(ctx context.Context, hostname string) (*model.ObservationBatch, error) {
	osi, err := c.Reg.OSInfo()
	if err != nil {
		return nil, fmt.Errorf("read OS version: %w", err)
	}
	build := osi["CurrentBuild"]
	if build == "" {
		build = osi["CurrentBuildNumber"]
	}
	ver := "10.0." + build
	if ubr := osi["UBR"]; ubr != "" {
		ver += "." + ubr
	}
	attrs := map[string]string{"os": "windows", "os_version": ver, "os_name": osi["ProductName"]}
	if dv := osi["DisplayVersion"]; dv != "" {
		attrs["os_release"] = dv // e.g. 23H2
	}
	if ed := osi["EditionID"]; ed != "" {
		attrs["os_edition"] = ed
	}
	ids := []model.Identifier{{Scheme: "hostname", Value: hostname}}
	if g := c.Reg.MachineGUID(); g != "" {
		ids = append([]model.Identifier{{Scheme: "windows-machine-guid", Value: strings.ToLower(g)}}, ids...)
	}
	b := model.NewBatch(model.Collector{ID: CollectorID, Version: c.Version, Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: hostname, Identifiers: ids, Attributes: attrs})
	b.Complete = true
	b.Observations = append(b.Observations, model.Observation{
		Purl: packageurl.NewPackageURL("generic", "", "windows", ver, nil, "").ToString(), Version: ver,
		Location: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, Scope: "os", Confidence: model.ConfidenceConfirmed,
		Evidence: map[string]string{"kind": "operating-system", "product_name": osi["ProductName"], "display_version": osi["DisplayVersion"]},
	})
	seen := map[string]bool{}
	for _, view := range []string{"native", "wow64"} {
		entries, err := c.Reg.Uninstall(view)
		if err != nil {
			b.Cover("registry:uninstall:"+view, "failed", err.Error())
			b.Complete = false
			continue
		}
		for _, e := range entries {
			name, v := strings.TrimSpace(e["DisplayName"]), strings.TrimSpace(e["DisplayVersion"])
			// System components and update entries are not separate programs.
			if name == "" || e["SystemComponent"] == "1" || e["ParentKeyName"] != "" || e["ReleaseType"] == "Update" ||
				e["ReleaseType"] == "Hotfix" || e["ReleaseType"] == "Security Update" {
				continue
			}
			key := strings.ToLower(name) + "@" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			conf := model.ConfidenceConfirmed
			if v == "" {
				conf = model.ConfidenceUnknown
			}
			ev := map[string]string{"registry_view": view}
			if p := strings.TrimSpace(e["Publisher"]); p != "" {
				ev["publisher"] = p
			}
			b.Observations = append(b.Observations, model.Observation{
				Purl: packageurl.NewPackageURL("generic", "", name, v, nil, "").ToString(), Version: v,
				Location: `HKLM\...\Uninstall (` + view + `)`, Scope: "os", Confidence: conf, Evidence: ev,
			})
		}
		b.Cover("registry:uninstall:"+view, "checked", "")
	}
	// Not collected yet: per-user installs (HKCU), Store apps, hotfixes.
	b.Cover("windows:hotfixes", "unsupported", "installed updates (KBs) are not inventoried yet")
	b.Cover("windows:store-apps", "unsupported", "Microsoft Store (AppX) packages are not inventoried yet")
	sort.SliceStable(b.Observations[1:], func(i, j int) bool { return b.Observations[i+1].Purl < b.Observations[j+1].Purl })
	return b, nil
}
