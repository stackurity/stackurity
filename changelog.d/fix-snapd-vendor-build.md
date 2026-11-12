### Fixed

- **Ubuntu's own snapd is no longer reported as a vendor build.** A version such as `2.77.1+ubuntu24.04` was mistaken for MySQL's APT repository (`8.0.39-1ubuntu22.04`), so snapd on Ubuntu 24.04 hosts showed under "not supported yet" and was not checked against Ubuntu's advisories.
