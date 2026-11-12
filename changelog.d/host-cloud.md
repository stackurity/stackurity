### Added

- **The Linux agent records which cloud a host runs on.** It reads the machine's DMI strings (`/sys/class/dmi/id`), with no network or metadata-service call, and sets the host attributes `cloud_provider` and `cloud_service` for AWS EC2, DigitalOcean Droplets, Google Compute Engine, Azure, Oracle Cloud, Hetzner, Akamai (Linode), Vultr and Alibaba Cloud ECS. The Assets list then shows the cloud under the OS, for example "Ubuntu 24.04" over "host · DigitalOcean Droplet". Containers, bare metal and other clouds set nothing. Hosts show it after their agent is upgraded and reports again.
