### Added

- **Docker Engine and containerd from Docker's repository are checked.** `docker-ce`, `docker-ce-cli`, `docker-ce-rootless-extras` and `containerd.io` from download.docker.com (deb and rpm) are matched by upstream version against NVD's records for Docker Engine (`docker:engine`, `mobyproject:moby`, `docker:docker` Community Edition) and containerd (`linuxfoundation:containerd`), instead of being listed as not supported yet. Docker Compose and Buildx stay coverage gaps: NVD's records for them name no product or versions. See [Vendor builds](docs/compatibility.md#vendor-builds).
