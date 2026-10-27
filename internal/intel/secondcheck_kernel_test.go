package intel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/secondcheck"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// A production shape: an Ubuntu host's running kernel is several binary
// packages from different source packages (the image from linux-signed, the
// modules from linux). The matcher reports one finding per issue per kernel
// version, on one of them, from the Ubuntu record for the source package
// linux. The second check must accept that relation and agree; it did not
// in 0.9.0 (package identity mismatch on every Ubuntu kernel finding).
func TestSecondCheckUbuntuKernelSources(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	st, sy, ev, up := setup(t)
	focal := func(name, upstream string) model.Observation {
		return confirmed("pkg:deb/ubuntu/"+name+"@5.4.0-190.210?arch=amd64&distro=ubuntu-20.04&upstream="+upstream,
			map[string]string{"source_package": upstream, "source_version": "5.4.0-190.210"})
	}
	host := ingest(t, st, model.AssetHost, "focal-1", true,
		focal("linux-image-5.4.0-190-generic", "linux-signed"),
		focal("linux-modules-5.4.0-190-generic", "linux"),
		focal("linux-modules-extra-5.4.0-190-generic", "linux"),
		focal("linux-headers-5.4.0-190-generic", "linux"),
	)
	if err := EnsureFeeds(ctx, st); err != nil {
		t.Fatal(err)
	}
	serveCorpus(t, filepath.Join("testdata", "corpus", "ubuntu"), "osv:Ubuntu", sy, up)
	if _, err := sy.Sync(ctx, "osv:Ubuntu"); err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Evaluate(ctx, nil, 0); err != nil {
		t.Fatal(err)
	}
	fs, _, err := st.ListFindings(ctx, store.FindingFilter{AssetID: host, Key: "CVE-2024-36971"})
	if err != nil || len(fs) != 1 {
		t.Fatalf("kernel findings: %d %v", len(fs), err)
	}
	stats, err := (&secondcheck.Runner{Store: st, All: true}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Agreed != 1 || stats.Disagreed != 0 {
		sc, _ := st.FindingSecondCheck(ctx, fs[0].ID)
		t.Fatalf("second check on %s: %+v %+v", fs[0].ComponentName, stats, sc)
	}
}
