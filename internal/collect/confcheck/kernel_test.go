package confcheck

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/model"
)

const kernelRel = "6.8.0-49-generic"

const procModulesWithSCTP = `nf_tables 372736 0 - Live 0x0000000000000000
sctp 446464 2 - Live 0x0000000000000000
libcrc32c 12288 2 nf_tables,sctp, Live 0x0000000000000000
`

const procModulesWithout = `nf_tables 372736 0 - Live 0x0000000000000000
libcrc32c 12288 1 nf_tables, Live 0x0000000000000000
`

func TestKernelSCTP(t *testing.T) {
	mod := "lib/modules/" + kernelRel + "/kernel/net/sctp/sctp.ko.zst"
	base := func() map[string]string {
		return map[string]string{
			"proc/sys/kernel/osrelease":        kernelRel + "\n",
			"proc/modules":                     procModulesWithout,
			"proc/cmdline":                     "BOOT_IMAGE=/vmlinuz root=/dev/vda1 ro quiet",
			"proc/sys/kernel/modules_disabled": "0\n",
			mod:                                "x",
			"lib/modules/" + kernelRel + "/modules.builtin": "kernel/net/ipv4/tcp_cubic.ko\n",
		}
	}
	cases := []struct {
		name     string
		edit     func(map[string]string)
		severity string // "" for no finding
		subject  string
		path     string
		why      string
	}{
		{name: "loadable", edit: func(map[string]string) {}, severity: "low", subject: "sctp loadable in kernel " + kernelRel, path: "/" + mod,
			why: "loads it by itself"},
		{name: "blacklist alone does not stop it", edit: func(m map[string]string) {
			m["etc/modprobe.d/blacklist-sctp.conf"] = "# no sctp\nblacklist sctp\n"
		}, severity: "low", why: "\"blacklist sctp\" in /etc/modprobe.d/blacklist-sctp.conf does not stop that"},
		{name: "install false blocks", edit: func(m map[string]string) {
			m["etc/modprobe.d/disable-sctp.conf"] = "install sctp /bin/false\n"
		}},
		{name: "install true in /usr/lib blocks", edit: func(m map[string]string) {
			m["usr/lib/modprobe.d/50-sctp.conf"] = "install  sctp \\\n  /usr/bin/true\n"
		}},
		{name: "/etc file of the same name hides /usr/lib", edit: func(m map[string]string) {
			m["usr/lib/modprobe.d/sctp.conf"] = "install sctp /bin/false\n"
			m["etc/modprobe.d/sctp.conf"] = "# allowed here\n"
		}, severity: "low"},
		{name: "commented install line does not block", edit: func(m map[string]string) {
			m["etc/modprobe.d/disable-sctp.conf"] = "# install sctp /bin/false\n"
		}, severity: "low"},
		{name: "install with a real command does not block", edit: func(m map[string]string) {
			m["etc/modprobe.d/sctp.conf"] = "install sctp /sbin/modprobe --ignore-install sctp\n"
		}, severity: "low"},
		{name: "module_blacklist on the command line blocks", edit: func(m map[string]string) {
			m["proc/cmdline"] = "root=/dev/vda1 module_blacklist=dccp,sctp quiet"
		}},
		{name: "modules_disabled blocks", edit: func(m map[string]string) {
			m["proc/sys/kernel/modules_disabled"] = "1\n"
		}},
		{name: "not installed", edit: func(m map[string]string) { delete(m, mod) }},
		{name: "loaded", edit: func(m map[string]string) { m["proc/modules"] = procModulesWithSCTP }, severity: "medium",
			subject: "sctp loaded in kernel " + kernelRel, path: "/proc/modules", why: "is loaded"},
		{name: "loaded but blocked since", edit: func(m map[string]string) {
			m["proc/modules"] = procModulesWithSCTP
			m["etc/modprobe.d/disable-sctp.conf"] = "install sctp /bin/false\n"
		}, severity: "medium", why: "Loading is already blocked"},
		{name: "loaded, seen only in /sys/module", edit: func(m map[string]string) {
			delete(m, "proc/modules")
			m["sys/module/sctp/refcnt"] = "2\n"
		}, severity: "medium", path: "/sys/module/sctp"},
		{name: "built in", edit: func(m map[string]string) {
			delete(m, mod)
			m["lib/modules/"+kernelRel+"/modules.builtin"] = "kernel/net/sctp/sctp.ko\n"
			m["etc/modprobe.d/disable-sctp.conf"] = "install sctp /bin/false\n"
		}, severity: "medium", subject: "sctp built into kernel " + kernelRel, why: "built into the running kernel"},
		{name: "module under /usr/lib/modules", edit: func(m map[string]string) {
			delete(m, mod)
			m["usr/lib/modules/"+kernelRel+"/kernel/net/sctp/sctp.ko.xz"] = "x"
		}, severity: "low", path: "/usr/lib/modules/" + kernelRel + "/kernel/net/sctp/sctp.ko.xz"},
		{name: "unknown kernel release (older data, image, mounted root)", edit: func(m map[string]string) {
			delete(m, "proc/sys/kernel/osrelease")
			m["proc/modules"] = procModulesWithSCTP
		}},
		{name: "release for another kernel only", edit: func(m map[string]string) {
			m["proc/sys/kernel/osrelease"] = "6.8.0-50-generic\n"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			files := base()
			c.edit(files)
			writeTree(t, root, files)
			h := &hostFS{Root: root}
			got := h.kernelModules()
			if c.severity == "" {
				if len(got) != 0 {
					t.Fatalf("want no finding, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("want one finding, got %+v", got)
			}
			f := got[0]
			if f.Rule != RuleKernelSCTP || f.Category != model.ConfigKernel || f.Severity != c.severity {
				t.Errorf("rule/category/severity: %+v", f)
			}
			if c.subject != "" && f.Subject != c.subject {
				t.Errorf("subject %q, want %q", f.Subject, c.subject)
			}
			if c.path != "" && f.Path != c.path {
				t.Errorf("path %q, want %q", f.Path, c.path)
			}
			if c.why != "" && !strings.Contains(f.Why, c.why) {
				t.Errorf("why %q lacks %q", f.Why, c.why)
			}
			if !strings.Contains(f.Fix, "install sctp /bin/false") && !strings.Contains(f.Fix, "rmmod sctp") {
				t.Errorf("fix: %q", f.Fix)
			}
			if strings.Contains(strings.ToLower(f.Why+f.Fix), "secure") {
				t.Errorf("wording claims security: %q %q", f.Why, f.Fix)
			}
			if len(f.Fingerprint) != 32 {
				t.Errorf("fingerprint %q", f.Fingerprint)
			}
			if f.Path == "" || len(f.Why) > model.MaxFieldLen || len(f.Fix) > model.MaxFieldLen || len(f.Title) > model.MaxShortField {
				t.Errorf("field limits: %+v", f)
			}
		})
	}
}

// The kernel check runs as part of Host, and a finding passes the batch's
// validation.
func TestHostRunsKernelCheck(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"etc/passwd":                "root:x:0:0:root:/root:/bin/bash\n",
		"proc/sys/kernel/osrelease": kernelRel,
		"proc/modules":              procModulesWithSCTP,
	})
	s := Host(context.Background(), root, nil)
	var n int
	for _, f := range s.Found {
		if f.Rule == RuleKernelSCTP {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("kernel findings: %d in %+v", n, s.Found)
	}
	b := model.NewBatch(model.Collector{ID: "linux"}, model.AssetRef{Kind: model.AssetHost, Name: "h"})
	b.ConfigFindings = s
	if err := b.Validate(); err != nil && strings.Contains(err.Error(), "config_findings") {
		t.Errorf("batch validation: %v", err)
	}
	if RuleDoc(RuleKernelSCTP) != KernelModulesDoc {
		t.Error("doc link")
	}
}

// A modprobe.d directory that is a symbolic link out of a mounted root is
// not followed.
func TestKernelModprobeLinkOutOfRoot(t *testing.T) {
	outside := t.TempDir()
	writeTree(t, outside, map[string]string{"disable-sctp.conf": "install sctp /bin/false\n"})
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"proc/sys/kernel/osrelease":                             kernelRel,
		"lib/modules/" + kernelRel + "/kernel/net/sctp/sctp.ko": "x",
	})
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "etc", "modprobe.d")); err != nil {
		t.Fatal(err)
	}
	h := &hostFS{Root: root}
	if got := h.kernelModules(); len(got) != 1 || got[0].Severity != "low" {
		t.Errorf("a link out of the root must not count as a block: %+v", got)
	}
}
