package confcheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

func TestShirudo(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{
			"proc/sys/kernel/osrelease":                         kernelRel + "\n",
			"var/lib/shirudo/upatches/java4shell.upatch":        "x",
			"var/lib/shirudo/upatches/cve.2026.1.upatch":        "x",
			"var/lib/shirudo/upatches/cve.2026.1.unload.upatch": "x",
			"var/lib/shirudo/upatches/notes.txt":                "x",
			"run/shirudo/bpffs/lsm_link":                        "",
			"run/shirudo/bpffs/upatches/java4shell/link":        "",
			"run/shirudo/bpffs/upatches/cve~d2026~d1/link":      "",
		}
	}
	cases := []struct {
		name string
		edit func(map[string]string)
		want []string // subjects, in order
	}{
		{name: "all loaded and enforced", edit: func(map[string]string) {}},
		{name: "one not loaded", edit: func(m map[string]string) {
			delete(m, "run/shirudo/bpffs/upatches/java4shell/link")
		}, want: []string{"upatch java4shell not loaded in kernel " + kernelRel}},
		{name: "dotted name not loaded", edit: func(m map[string]string) {
			delete(m, "run/shirudo/bpffs/upatches/cve~d2026~d1/link")
		}, want: []string{"upatch cve.2026.1 not loaded in kernel " + kernelRel}},
		{name: "lsm off", edit: func(m map[string]string) {
			delete(m, "run/shirudo/bpffs/lsm_link")
		}, want: []string{"shirudo lsm_link missing in kernel " + kernelRel}},
		{name: "shirudo did not run this boot", edit: func(m map[string]string) {
			for k := range m {
				if strings.HasPrefix(k, "run/") {
					delete(m, k)
				}
			}
		}, want: []string{"shirudo lsm_link missing in kernel " + kernelRel,
			"upatch cve.2026.1 not loaded in kernel " + kernelRel, "upatch java4shell not loaded in kernel " + kernelRel}},
		{name: "no archives: shirudo not used", edit: func(m map[string]string) {
			for k := range m {
				if strings.HasPrefix(k, "var/") || strings.HasPrefix(k, "run/") {
					delete(m, k)
				}
			}
		}},
		{name: "unknown kernel release (mounted root, image)", edit: func(m map[string]string) {
			delete(m, "proc/sys/kernel/osrelease")
			delete(m, "run/shirudo/bpffs/lsm_link")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			files := base()
			c.edit(files)
			writeTree(t, root, files)
			h := &hostFS{Root: root}
			got := h.shirudo()
			if len(got) != len(c.want) {
				t.Fatalf("want %d findings, got %+v", len(c.want), got)
			}
			for i, f := range got {
				if f.Subject != c.want[i] {
					t.Errorf("finding %d subject %q, want %q", i, f.Subject, c.want[i])
				}
				if f.Category != model.ConfigKernel || f.Severity != "medium" || len(f.Fingerprint) != 32 {
					t.Errorf("category/severity/fingerprint: %+v", f)
				}
				if RuleDoc(f.Rule) != ShirudoDoc {
					t.Errorf("doc for %s", f.Rule)
				}
				if strings.Contains(strings.ToLower(f.Why+f.Fix), "secure") {
					t.Errorf("wording claims security: %q %q", f.Why, f.Fix)
				}
				if len(f.Why) > model.MaxFieldLen || len(f.Fix) > model.MaxFieldLen || len(f.Title) > model.MaxShortField {
					t.Errorf("field limits: %+v", f)
				}
			}
			if len(h.problems) != 0 {
				t.Errorf("problems: %v", h.problems)
			}
		})
	}
}

// A bpffs the agent cannot list (not root) is noted as not read, never
// reported as "not loaded".
func TestShirudoUnreadableBPFFS(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can list a mode 0000 directory")
	}
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"proc/sys/kernel/osrelease":                  kernelRel + "\n",
		"var/lib/shirudo/upatches/java4shell.upatch": "x",
		"run/shirudo/bpffs/lsm_link":                 "",
	})
	dir := filepath.Join(root, "run/shirudo/bpffs")
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	h := &hostFS{Root: root}
	if got := h.shirudo(); len(got) != 0 {
		t.Fatalf("want no finding, got %+v", got)
	}
	if len(h.problems) != 1 || !strings.Contains(h.problems[0], "run as root") {
		t.Errorf("problems: %v", h.problems)
	}
	s := Host(context.Background(), root, nil)
	if s.Complete {
		t.Error("scan marked complete although the bpffs was not read")
	}
}

// Host runs the Shirudo check and the batch accepts its findings.
func TestHostRunsShirudo(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/passwd":                "root:x:0:0:root:/root:/bin/bash\n",
		"proc/sys/kernel/osrelease": kernelRel,
		"var/lib/shirudo/upatches/java4shell.upatch": "x",
	})
	s := Host(context.Background(), root, nil)
	var n int
	for _, f := range s.Found {
		if f.Rule == RuleShirudoNotLoaded || f.Rule == RuleShirudoLSMOff {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("shirudo findings: %d in %+v", n, s.Found)
	}
	b := model.NewBatch(model.Collector{ID: "linux"}, model.AssetRef{Kind: model.AssetHost, Name: "h"})
	b.ConfigFindings = s
	if err := b.Validate(); err != nil && strings.Contains(err.Error(), "config_findings") {
		t.Errorf("batch validation: %v", err)
	}
}
