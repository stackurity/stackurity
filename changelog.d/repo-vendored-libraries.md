### Added

- **Repository scans find front-end libraries kept outside a package manager.** A copied `js/jquery-3.6.0.min.js` or `bootstrap.bundle.min.js` is named by its version banner, a CDN address in a template by its path, and a library compiled into a committed bundle as on a deployed application. A PHP or static site's repository with no manifest now lists the jQuery, Bootstrap or jQuery Validate it ships, instead of no components. This applies to server-side, GitHub App and GitLab scans and to `stackurity scan` in CI, which skips files git ignores. A copy a lockfile also lists at the same version is reported once. See [Compatibility](docs/compatibility.md).

### Changed

- **A repository scan that did not look for copied front-end libraries no longer removes them.** A CI scan by an older `stackurity scan` (or any batch without a `web-assets:` coverage item) reports the same repository without looking. The libraries the server's scan found stay, rather than their findings closing and reopening at each alternating scan.
