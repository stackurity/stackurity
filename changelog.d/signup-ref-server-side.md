### Changed

- **The sign-up source of a Google, Microsoft or GitHub sign-up is kept on the server, and nothing is stored in the browser.** The sign-up page now passes where the person came from (`?ref=`) in the provider's start link, and the server keeps it with the sign-in in progress until the account is created. The sessionStorage entry used for it since v0.20.14 is removed: no cookie, localStorage or sessionStorage holds the sign-up source. A sign-up started with a middle-click (new tab) now keeps its source too.

### Upgrading

- No action needed. Stackurity Cloud builds apply the additive migration `cloud/0014_social_flow_ref` (one column on `cloud_social_flows`).
