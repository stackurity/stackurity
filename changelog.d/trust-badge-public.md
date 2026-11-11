### Added

- **Trust badge, part 2: the badge, trust data and settings (Stackurity Cloud only, off).** The public badge image (`/badge/<slug>.svg`) and trust page data (`/api/v1/public/trust/<slug>`, plus the listed slugs for the sitemap and the customer's logo), with a contract test that no response carries an id, a count, a package, host, repository, image or project name, or an item the customer switched off. **Settings → Trust badge**: choose the projects or assets it covers, the address, name, website and what is shown, preview exactly what the public would see, accept the badge terms (pending counsel's sign-off), turn it on or off, copy the snippets, and read the badge's status timeline. Every change and every history read is audited. **Admin → Trust badges**: Stackurity's operators see the full evidence behind any decision, each view audited. Free plans have one badge with the marketing line always shown; the licensed Cloud build lets paid plans switch the line off, add a logo and have one badge per project. Turning a badge off takes effect at once, and with Cloudflare credentials set its cached copies are purged. Nothing exists on self-hosted servers, and the badge launches only after counsel's sign-off. See [Trust badge](docs/trust-badge.md).

### Upgrading

- Migration `0104_trust_badge_public` adds the trust page name, website and logo to `trust_badges`.
