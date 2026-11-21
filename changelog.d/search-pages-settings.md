### Added

- **Search finds pages, settings and help.** The top search now lists matching pages, settings and help articles first, under **Pages and settings**, by their name or a word people use for them: `sso` opens Single sign-on, `invite` People, `mfa` your account and the two-factor article, `api token` API tokens. Only pages the person's role can open are offered, and Billing and other hosted-only pages only where the server has them. Each result says where it lives in the sidebar ("Administration › Integrations"). The full results page has the same group. Found in the browser: no API change.
- **Ctrl+K (⌘K) opens the search** from anywhere, as well as `/`.

### Changed

- The Settings sections are defined once (`web/src/navModel.ts`, `SETTINGS_GROUPS`) and shared by the Settings page and search.
