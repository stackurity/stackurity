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
		{"deb", "linux-tools-common", "5.4.0-216.236", "5.4.0-216-generic", false},
		{"deb", "openssl", "1.1.1f", "5.4.0-216-generic", false},
		{"deb", "linux-image-5.4.0-190-generic", "5.4.0-190.210", "", false}, // unknown running kernel
		{"rpm", "kernel-core", "5.14.0-362.8.1.el9_3", "5.14.0-427.13.1.el9_4.x86_64", true},
		{"rpm", "kernel-core", "5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_4.x86_64", false},
		{"rpm", "kernel-headers", "5.14.0-362.8.1.el9_3", "5.14.0-427.13.1.el9_4.x86_64", false},
		{"rpm", "kernel-tools", "5.14.0-362.8.1.el9_3", "5.14.0-427.13.1.el9_4.x86_64", false}, // userspace, not installonly
		{"rpm", "kernel", "5.10.205-195.807.amzn2", "5.10.205-195.807.amzn2.x86_64", false},
		{"rpm", "kernel", "5.10.199-190.747.amzn2", "5.10.205-195.807.amzn2.x86_64", true},
		{"rpm", "kernel-default", "5.14.21-150500.55.39.1", "5.14.21-150500.55.39-default", false},
		{"rpm", "kernel-default", "5.14.21-150500.55.31.1", "5.14.21-150500.55.39-default", true},
		{"rpm", "kernel-default", "5.14.21-150500.55.3.1", "5.14.21-150500.55.39-default", true}, // not a prefix match
		{"rpm", "kernel-rt-core", "5.14.0-427.13.1.el9_4", "5.14.0-427.13.1.el9_4.x86_64+rt", false},
	}
	for _, c := range cases {
		if got := KernelNotRunning(c.typ, c.name, c.ver, c.running); got != c.want {
			t.Errorf("%s %s (running %s) = %v", c.typ, c.name, c.running, got)
		}
	}
}

func TestKernelPackage(t *testing.T) {
	cases := []struct {
		typ, name, ver string
		role           KernelRole
		release        string
	}{
		{"deb", "linux-image-5.4.0-190-generic", "5.4.0-190.210", KernelCode, "5.4.0-190"},
		{"deb", "linux-image-unsigned-5.4.0-190-generic", "5.4.0-190.210", KernelCode, "5.4.0-190"},
		{"deb", "linux-modules-5.4.0-190-generic", "5.4.0-190.210", KernelCode, "5.4.0-190"},
		{"deb", "linux-modules-extra-5.15.0-91-generic", "5.15.0-91.101", KernelCode, "5.15.0-91"},
		{"deb", "linux-tools-5.4.0-190", "5.4.0-190.210", KernelCode, "5.4.0-190"},
		{"deb", "linux-headers-5.4.0-190", "5.4.0-190.210", KernelNoCode, "5.4.0-190"},
		{"deb", "linux-headers-5.4.0-190-generic", "5.4.0-190.210", KernelNoCode, "5.4.0-190"},
		{"deb", "linux-hwe-5.15-headers-5.15.0-91", "5.15.0-91.101~20.04.1", KernelNoCode, "5.15.0-91"},
		{"deb", "linux-headers-generic", "5.4.0.216.208", KernelNoCode, ""},
		{"deb", "linux-libc-dev", "5.4.0-216.236", KernelNoCode, ""},
		{"deb", "linux-tools-common", "5.4.0-216.236", KernelNoCode, ""},
		{"deb", "linux-source-5.4.0", "5.4.0-216.236", KernelNoCode, ""},
		{"deb", "linux-image-generic", "5.4.0.216.208", NotKernel, ""},
		{"deb", "linux-firmware", "1.187.39", NotKernel, ""},
		{"deb", "openssl", "1.1.1f-1ubuntu2.24", NotKernel, ""},
		{"rpm", "kernel", "5.14.0-427.13.1.el9_4", KernelCode, "5.14.0-427.13.1.el9_4"},
		{"rpm", "kernel-core", "5.14.0-427.13.1.el9_4", KernelCode, "5.14.0-427.13.1.el9_4"},
		{"rpm", "kernel-modules-extra", "5.14.0-427.13.1.el9_4", KernelCode, "5.14.0-427.13.1.el9_4"},
		{"rpm", "kernel-rt-core", "5.14.0-427.13.1.el9_4", KernelCode, "5.14.0-427.13.1.el9_4"},
		{"rpm", "kernel-uek", "5.15.0-200.131.27.el9uek", KernelCode, "5.15.0-200.131.27.el9uek"},
		{"rpm", "kernel-default", "5.14.21-150500.55.39.1", KernelCode, "5.14.21-150500.55.39.1"},
		{"rpm", "kernel-default-extra", "5.14.21-150500.55.39.1", KernelCode, "5.14.21-150500.55.39.1"},
		{"rpm", "kernel-devel", "5.14.0-427.13.1.el9_4", KernelNoCode, "5.14.0-427.13.1.el9_4"},
		{"rpm", "kernel-default-devel", "5.14.21-150500.55.39.1", KernelNoCode, "5.14.21-150500.55.39.1"},
		{"rpm", "kernel-headers", "5.14.0-427.13.1.el9_4", KernelNoCode, ""},
		{"rpm", "kernel-macros", "5.14.21-150500.55.39.1", KernelNoCode, "5.14.21-150500.55.39.1"},
		{"rpm", "kernel-tools", "5.14.0-427.13.1.el9_4", NotKernel, ""},
		{"rpm", "kernel-firmware", "20230814-140.el9", NotKernel, ""},
		{"rpm", "kernel-srpm-macros", "1.0-13.el9", NotKernel, ""},
		{"rpm", "kernelshark", "2.2.1-1.el9", NotKernel, ""},
		{"apk", "linux-lts", "6.6.31-r0", NotKernel, ""},
	}
	for _, c := range cases {
		role, rel := KernelPackage(c.typ, c.name, c.ver)
		if role != c.role || rel != c.release {
			t.Errorf("%s %s = %v %q, want %v %q", c.typ, c.name, role, rel, c.role, c.release)
		}
	}
}
