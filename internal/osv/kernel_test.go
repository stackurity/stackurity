package osv

import "testing"

func TestKernelNotRunning(t *testing.T) {
	cases := []struct {
		typ, name, ver, running string
		want                    bool
	}{
		{"deb", "linux-image-5.4.0-190-generic", "5.4.0-190.210", "5.4.0-216-generic", true},
		{"deb", "linux-headers-5.4.0-190", "5.4.0-190.210", "5.4.0-216-generic", true},
		{"deb", "linux-modules-extra-5.4.0-216-generic", "5.4.0-216.236", "5.4.0-216-generic", false},
		{"deb", "linux-image-5.4.0-216-generic", "5.4.0-216.236", "5.4.0-216-generic", false},
		{"deb", "linux-image-generic", "5.4.0.216.208", "5.4.0-216-generic", false}, // metapackage
		{"deb", "linux-libc-dev", "5.4.0-216.236", "5.4.0-216-generic", false},
		{"deb", "openssl", "1.1.1f", "5.4.0-216-generic", false},
		{"deb", "linux-image-5.4.0-190-generic", "5.4.0-190.210", "", false}, // unknown running kernel
		{"rpm", "kernel-core", "5.14.0-362.8.1.el9_3", "5.14.0-427.13.1.el9_4.x86_64", true},
		{"rpm", "kernel-core", "5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_4.x86_64", false},
		{"rpm", "kernel-headers", "5.14.0-362.8.1.el9_3", "5.14.0-427.13.1.el9_4.x86_64", false},
	}
	for _, c := range cases {
		if got := KernelNotRunning(c.typ, c.name, c.ver, c.running); got != c.want {
			t.Errorf("%s %s (running %s) = %v", c.typ, c.name, c.running, got)
		}
	}
}
