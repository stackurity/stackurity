package linux

import "strings"

// Cloud host attributes. They name the provider and its compute service,
// so the dashboard can show "host · DigitalOcean Droplet".
const (
	CloudProviderAttribute = "cloud_provider"
	CloudServiceAttribute  = "cloud_service"
)

// cloudRule matches one DMI field against a value the provider's
// hypervisor sets. Matching ignores case and surrounding space, and also
// accepts the value followed by more words ("Akamai Technologies").
type cloudRule struct {
	field, value      string
	provider, service string
}

// cloudRules are checked in order; the first match wins.
var cloudRules = []cloudRule{
	{"sys_vendor", "Amazon EC2", "aws", "EC2"},
	{"bios_vendor", "Amazon EC2", "aws", "EC2"},
	{"sys_vendor", "DigitalOcean", "digitalocean", "Droplet"},
	{"product_name", "Google Compute Engine", "gcp", "Compute Engine"},
	{"sys_vendor", "Google", "gcp", "Compute Engine"},
	{"chassis_asset_tag", "7783-7084-3265-9085-8269-3286-77", "azure", "Virtual Machine"},
	{"chassis_asset_tag", "OracleCloud.com", "oracle", "Compute"},
	{"sys_vendor", "Hetzner", "hetzner", "Cloud server"},
	{"sys_vendor", "Linode", "linode", "Linode"},
	{"sys_vendor", "Akamai", "linode", "Linode"},
	{"sys_vendor", "Vultr", "vultr", "Instance"},
	{"sys_vendor", "Alibaba Cloud", "alibaba", "ECS"},
}

// cloudAttributes names the cloud the host runs on, from the DMI strings
// in /sys/class/dmi/id only: no metadata service or other network call,
// so it stays fast and works offline. It returns nil when nothing matches
// or the files are missing or unreadable (containers, bare metal).
func (c *Collector) cloudAttributes() map[string]string {
	dmi := map[string]string{}
	for _, r := range cloudRules {
		v, ok := dmi[r.field]
		if !ok {
			v = strings.ToLower(strings.TrimSpace(readFirst(c.path("sys/class/dmi/id/" + r.field))))
			dmi[r.field] = v
		}
		if want := strings.ToLower(r.value); v != "" && (v == want || strings.HasPrefix(v, want+" ")) {
			return map[string]string{CloudProviderAttribute: r.provider, CloudServiceAttribute: r.service}
		}
	}
	return nil
}
