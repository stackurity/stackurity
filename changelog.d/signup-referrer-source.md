### Added

- **Sign-ups from untagged links record the website they came from.** When the sign-up page has no `?ref=` and no `utm_source`, the referring website counts as `web-<host>` (for example `web-reddit-com`), so the trial report and the admin Customers page say where more sign-ups came from. Only the host is kept, and stackurity.ai and stackurity.dev pages are ignored; tagged links still win. The browser stores nothing for it.
