package linux

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCloudAttributes(t *testing.T) {
	cases := []struct {
		name              string
		dmi               map[string]string
		provider, service string
	}{
		{"aws nitro", map[string]string{"sys_vendor": "Amazon EC2\n", "product_name": "t3.micro\n"}, "aws", "EC2"},
		{"aws bios only", map[string]string{"sys_vendor": "\n", "bios_vendor": "Amazon EC2\n"}, "aws", "EC2"},
		{"digitalocean", map[string]string{"sys_vendor": "DigitalOcean\n", "product_name": "Droplet\n"}, "digitalocean", "Droplet"},
		{"gcp product", map[string]string{"sys_vendor": "Google\n", "product_name": "Google Compute Engine\n"}, "gcp", "Compute Engine"},
		{"gcp vendor only", map[string]string{"sys_vendor": "google"}, "gcp", "Compute Engine"},
		{"azure", map[string]string{"sys_vendor": "Microsoft Corporation\n", "chassis_asset_tag": "7783-7084-3265-9085-8269-3286-77\n"}, "azure", "Virtual Machine"},
		{"hyper-v not azure", map[string]string{"sys_vendor": "Microsoft Corporation\n", "chassis_asset_tag": "None\n"}, "", ""},
		{"oracle", map[string]string{"sys_vendor": "QEMU\n", "chassis_asset_tag": "OracleCloud.com\n"}, "oracle", "Compute"},
		{"hetzner", map[string]string{"sys_vendor": "Hetzner\n", "product_name": "vServer\n"}, "hetzner", "Cloud server"},
		{"linode", map[string]string{"sys_vendor": "Linode\n"}, "linode", "Linode"},
		{"akamai", map[string]string{"sys_vendor": "Akamai Technologies\n"}, "linode", "Linode"},
		{"vultr", map[string]string{"sys_vendor": "  VULTR  \n"}, "vultr", "Instance"},
		{"alibaba", map[string]string{"sys_vendor": "Alibaba Cloud\n", "product_name": "Alibaba Cloud ECS\n"}, "alibaba", "ECS"},
		{"bare metal", map[string]string{"sys_vendor": "Dell Inc.\n", "product_name": "PowerEdge R640\n", "chassis_asset_tag": "\n"}, "", ""},
		{"prefix of another word", map[string]string{"sys_vendor": "Googleplex Labs\n"}, "", ""},
		{"no dmi (container)", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for f, v := range tc.dmi {
				p := filepath.Join(root, "sys/class/dmi/id", f)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(v), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			got := fixture(root).cloudAttributes()
			if got[CloudProviderAttribute] != tc.provider || got[CloudServiceAttribute] != tc.service {
				t.Errorf("got %v, want %s/%s", got, tc.provider, tc.service)
			}
			if tc.provider == "" && got != nil {
				t.Errorf("want nil, got %v", got)
			}
		})
	}
}
