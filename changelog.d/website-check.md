### Added

- **Website check.** Enter a domain and see what the website shows anyone who visits it: server and framework versions from its headers, the JavaScript and CSS libraries its page loads, its TLS and browser protection headers, each version matched to stored vulnerabilities (with CISA known-exploited flags and fixed versions) and end-of-life data. The report also lists WordPress plugins and other problems, each with its fix: leaked keys in the page's code (shown masked), cookie and password-form settings, mixed content, files from public CDNs without an integrity check, directory listings, TLS 1.0/1.1 still accepted, and missing or permissive SPF and DMARC records. One browser-like visit, nothing probed; only public addresses on ports 80 and 443. In the dashboard under Reports > Website check, and through `POST /api/v1/site-checks`. On Stackurity Cloud, each plan includes a number of checks a month. See [Website check](docs/website-check.md).

### Upgrading

- Migration `0126_site_checks` adds the `site_checks` table and lets `plan_allowances` hold `site_checks`.
- While website checks are on (the default; `STACKURITY_SITE_CHECKS=off` turns them off), nginx and PHP are read from NVD even when no asset runs them: two more products in the vendor builds sync.
