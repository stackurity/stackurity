package intel

import (
	"context"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A kernel left behind by a release upgrade (a 22.04 kernel on a host now
// running 24.04) is not matched against the new release's advisories, which
// list fixes in 6.8 versions that every 5.15 version sorts before: it is
// not evaluated, with the command that removes it. The same kernel on its
// own release, and any kernel that is running, are evaluated.
func TestKernelFromEarlierRelease(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	host := func(name, running string, purls ...string) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "linux-agent", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: name,
			Identifiers: []model.Identifier{{Scheme: "machine-id", Value: name}}, Attributes: map[string]string{"kernel_running": running}})
		for _, p := range purls {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed, Scope: "os"})
		}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := st.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	const (
		old24 = "pkg:deb/ubuntu/linux-image-5.15.0-202-generic@5.15.0-202.212?distro=ubuntu-24.04&upstream=linux"
		mod24 = "pkg:deb/ubuntu/linux-modules-5.15.0-202-generic@5.15.0-202.212?distro=ubuntu-24.04&upstream=linux"
		new24 = "pkg:deb/ubuntu/linux-image-6.8.0-147-generic@6.8.0-147.147?distro=ubuntu-24.04&upstream=linux"
	)
	upgraded := host("outdocartkb", "6.8.0-147-generic", old24, mod24, new24)
	notRebooted := host("not-rebooted", "5.15.0-202-generic", old24, new24)
	// Boots a kernel no package provides; the 5.15 kernel is the newest
	// installed, so it is never marked, whatever the release says.
	newestOnly := host("custom-kernel", "6.10.3-1-custom", old24)
	jammy := host("jammy", "5.15.0-198-generic",
		"pkg:deb/ubuntu/linux-image-5.15.0-198-generic@5.15.0-198.208?distro=ubuntu-22.04&upstream=linux",
		"pkg:deb/ubuntu/linux-image-5.15.0-202-generic@5.15.0-202.212?distro=ubuntu-22.04&upstream=linux")

	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	up.set("/osv/Ubuntu/all.zip", zipOf(t, map[string]string{
		"noble.json": `{"id":"UBUNTU-CVE-2026-24","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2026-24"],
		  "affected":[{"package":{"ecosystem":"Ubuntu:24.04:LTS","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"6.8.0-150.150"}]}]}]}`,
		"jammy.json": `{"id":"UBUNTU-CVE-2026-22","modified":"2026-01-01T00:00:00Z","upstream":["CVE-2026-22"],
		  "affected":[{"package":{"ecosystem":"Ubuntu:22.04:LTS","name":"linux"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"5.15.0-203.213"}]}]}]}`,
	}))
	if _, err := sy.Sync(ctx, "osv:Ubuntu"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	findingsOn := func(asset int64) map[string]bool {
		t.Helper()
		fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: asset})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, f := range fs {
			out[strings.TrimPrefix(f.ComponentName, "ubuntu/")+" "+f.Key] = true
		}
		return out
	}

	// The upgraded host: only its running 24.04 kernel has the 24.04 issue.
	if got := findingsOn(upgraded); len(got) != 1 || !got["linux-image-6.8.0-147-generic CVE-2026-24"] {
		t.Errorf("upgraded host findings = %v, want only the 6.8 kernel's", got)
	}
	// Not rebooted since the upgrade: the 5.15 kernel runs, so it is evaluated.
	if got := findingsOn(notRebooted); !got["linux-image-5.15.0-202-generic CVE-2026-24"] || !got["linux-image-6.8.0-147-generic CVE-2026-24"] {
		t.Errorf("not-rebooted host findings = %v, want the running 5.15 kernel evaluated", got)
	}
	if got := findingsOn(newestOnly); !got["linux-image-5.15.0-202-generic CVE-2026-24"] {
		t.Errorf("newest-installed kernel findings = %v, want it evaluated", got)
	}
	// On 22.04 the same 5.15.0-202 kernel is its own release's: evaluated,
	// although not running.
	if got := findingsOn(jammy); !got["linux-image-5.15.0-202-generic CVE-2026-22"] || !got["linux-image-5.15.0-198-generic CVE-2026-22"] {
		t.Errorf("22.04 host findings = %v, want both kernels evaluated", got)
	}

	// Its rows are not evaluated, with the reason and the command.
	rows, _, err := st.ListInventory(ctx, store.InventoryFilter{AssetID: upgraded})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		old := strings.Contains(r.Name, "5.15.0-202")
		switch {
		case old && (r.Coverage != store.CoverageNotEvaluated || !strings.Contains(r.CoverageReason, "from a release before Ubuntu 24.04") ||
			!strings.HasSuffix(r.CoverageReason, "Remove old kernels: sudo apt autoremove --purge, or this one: "+
				"sudo apt purge linux-image-5.15.0-202-generic linux-modules-5.15.0-202-generic")):
			t.Errorf("%s: coverage %s %q", r.Name, r.Coverage, r.CoverageReason)
		case !old && r.Coverage != store.CoverageEvaluated:
			t.Errorf("%s: coverage %s %q, want evaluated", r.Name, r.Coverage, r.CoverageReason)
		}
	}
}
