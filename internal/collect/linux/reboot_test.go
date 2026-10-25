package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rootWith(t *testing.T, running string, modules []string, files map[string]string) *Collector {
	t.Helper()
	root := t.TempDir()
	write := func(p, data string) {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if running != "" {
		write("proc/sys/kernel/osrelease", running+"\n")
	}
	for _, m := range modules {
		if err := os.MkdirAll(filepath.Join(root, "lib/modules", m), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for p, d := range files {
		write(p, d)
	}
	return fixture(root)
}

func TestRebootState(t *testing.T) {
	cases := []struct {
		name    string
		c       *Collector
		want    string
		latest  string
		hasText string
	}{
		{"up to date", rootWith(t, "6.8.0-50-generic", []string{"6.8.0-45-generic", "6.8.0-50-generic"}, nil), "false", "6.8.0-50-generic", ""},
		{"newer kernel installed", rootWith(t, "6.8.0-45-generic", []string{"6.8.0-45-generic", "6.8.0-50-generic", "6.8.0-9-generic"}, nil),
			"true", "6.8.0-50-generic", "kernel 6.8.0-50-generic is installed but 6.8.0-45-generic is running"},
		{"other flavour ignored", rootWith(t, "6.8.0-45-generic", []string{"6.8.0-45-generic", "6.8.0-60-lowlatency"}, nil), "false", "6.8.0-45-generic", ""},
		{"running kernel removed (alpine)", rootWith(t, "6.6.14-0-lts", []string{"6.6.22-0-lts"}, nil),
			"true", "6.6.22-0-lts", "kernel 6.6.22-0-lts is installed"},
		{"rhel releases", rootWith(t, "5.14.0-362.18.1.el9_3.x86_64", []string{"5.14.0-362.18.1.el9_3.x86_64", "5.14.0-427.13.1.el9_4.x86_64"}, nil),
			"true", "5.14.0-427.13.1.el9_4.x86_64", ""},
		{"flag file with packages", rootWith(t, "6.1.0-18-amd64", []string{"6.1.0-18-amd64"}, map[string]string{
			"run/reboot-required": "*** System restart required ***\n", "run/reboot-required.pkgs": "libc6\nlibssl3\nlibc6\n"}),
			"true", "", "the package manager requested a reboot (libc6, libssl3)"},
		{"container", rootWith(t, "6.10.4-linuxkit", nil, nil), "unknown", "", ""},
	}
	for _, c := range cases {
		got := c.c.rebootState()
		if got["reboot_required"] != c.want {
			t.Errorf("%s: reboot_required = %q (%q)", c.name, got["reboot_required"], got["reboot_reason"])
		}
		if c.latest != "" && got["kernel_latest_installed"] != c.latest {
			t.Errorf("%s: latest = %q", c.name, got["kernel_latest_installed"])
		}
		if c.hasText != "" && !contains(got["reboot_reason"], c.hasText) {
			t.Errorf("%s: reason = %q", c.name, got["reboot_reason"])
		}
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

func TestNaturalCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"6.8.0-9-generic", "6.8.0-45-generic", -1},
		{"6.10.0", "6.9.0", 1},
		{"6.1.0-18-amd64", "6.1.0-18-amd64", 0},
	} {
		got := naturalCompare(c.a, c.b)
		if (got < 0) != (c.want < 0) || (got > 0) != (c.want > 0) {
			t.Errorf("naturalCompare(%q, %q) = %d", c.a, c.b, got)
		}
	}
}
