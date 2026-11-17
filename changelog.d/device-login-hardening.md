### Security

- **Terminal sign-in approvals are harder to abuse.** Where an organisation requires two-factor sign-in, approving a sign-in on `/device` now needs a second factor confirmed in the last 15 minutes; the page asks for it first. Wrong codes are also capped across the whole server (1,000 in 15 minutes), not only per person and address. An approved token that its tool never collected is revoked within 5 minutes of the code expiring, by a periodic task, rather than when the next sign-in starts. See [Signing in a terminal from the browser](docs/device-login.md).
