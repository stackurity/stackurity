### Added

- **Docker Engine and containerd from Docker's repository are checked.** `docker-ce`, `docker-ce-cli`, `docker-ce-rootless-extras` and `containerd.io` from download.docker.com (deb and rpm) are matched by upstream version against NVD's records for Docker Engine (`docker:engine`, `mobyproject:moby`, `docker:docker` Community Edition) and containerd (`linuxfoundation:containerd`), instead of being listed as not supported yet. Docker Compose and Buildx stay coverage gaps: NVD's records for them name no product or versions. See [Vendor builds](docs/compatibility.md#vendor-builds).

### Fixed

- **Ubuntu's own snapd is no longer reported as a vendor build.** A version such as `2.77.1+ubuntu24.04` was mistaken for MySQL's APT repository (`8.0.39-1ubuntu22.04`), so snapd on Ubuntu 24.04 hosts showed under "not supported yet" instead of being checked against Ubuntu's advisories.
