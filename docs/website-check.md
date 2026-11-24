# Website check

The website check shows what a public website gives away to anyone who visits it, and what the stored vulnerability, known-exploited and end-of-life data says about it. Enter a domain such as `example.com` and you get:

- **Server software and versions** the site names in its headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) or in its page's generator tag: nginx, Apache HTTP Server, PHP, OpenSSL, Microsoft IIS, Express, Next.js, Tomcat, WordPress, Drupal, Joomla! and others.
- **JavaScript and CSS libraries** the page loads, with exact versions: from their CDN address (jsDelivr, unpkg, cdnjs, code.jquery.com, BootstrapCDN, Google's) or from the version banner at the top of the file (jQuery, jQuery UI, Bootstrap, AngularJS, Vue, React and the other libraries the agent recognises in vendored files).
- For each: its **vulnerabilities** for that version (with whether CISA lists them as known exploited, and the version that fixes them) and whether its release line has reached **end of life**.
- **TLS**: protocol version, certificate issuer and how many days it has left.
- **Browser protection headers** the page does or does not send (Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, clickjacking protection, Referrer-Policy).

## What a check does, and does not do

A check is one browser-like visit. It requests the page you asked for (following up to five redirects), then the first 16 KB of up to 20 of the scripts and stylesheets that page links to. That is all: no port scans, no paths the page does not link, no login attempts, no payloads. Requests say who they are from: `Mozilla/5.0 (compatible; StackurityWebsiteCheck/1.0; +https://stackurity.ai/website-check)`.

Only public websites are checked: http or https on ports 80 and 443, by name. IP addresses, `localhost`, `.local` and `.internal` names, other ports and addresses with a user name are refused, and every connection is checked again on the address actually dialled, so a name that resolves to a private, loopback, link-local or cloud metadata address is refused too (whatever `STACKURITY_PRIVATE_TARGETS` allows for other outbound requests). A check gives up after 30 seconds.

What a site does not show cannot be found: a server that hides its version, a library bundled into one file without its banner, or anything behind a login. The report says so where it applies (a product with no vulnerability data, scripts that did not load). A version a server names is matched as that release: a distribution that patches fixes into an older version (Ubuntu's nginx 1.18.0, for example) can show issues it has fixed.

## Where the data comes from

Libraries are matched against the stored OSV advisories for npm, nginx and PHP against NVD (the [vendor builds](remediation.md) catalogue, read for these two even when no asset runs them while website checks are on), known-exploited flags from CISA KEV and release lines from endoflife.date: the same data, and the same matching, as for the assets Stackurity monitors. Nothing is looked up live during a check.

## In the dashboard and the API

**Reports > Website check** runs a check and lists the organisation's earlier ones, each with its report. Engineers and above can run checks; viewers can open them.

| Endpoint | |
|---|---|
| `POST /api/v1/site-checks` `{"url": "example.com"}` | Runs a check and stores it; `201` with the check and its `report` |
| `GET /api/v1/site-checks` | The organisation's checks, newest first, without reports |
| `GET /api/v1/site-checks/{id}` | One check with its report |

Errors: `400 bad_target` (not a public website address), `422 site_unreachable` (the site did not answer, does not resolve, or its certificate is refused), `402 plan_limit` (see below), `429` (more than 10 checks a minute for one organisation).

## Plans

On Stackurity Cloud each plan has a number of website checks a month (`site_checks_per_month`, see [plan limits](asset-limits.md#plan-limits)); a check that could not run does not count. Plans without API access (`no_site_check_api`) run checks from the dashboard only. A self-hosted server has no limits.

Without an account, the public page at [stackurity.ai/website-check](https://stackurity.ai/website-check) runs one check a day per visitor and shows a summary: what was found, how many issues each has, end of life, and the most serious issue. The full report comes with a free account.

## Settings

| Variable | |
|---|---|
| `STACKURITY_SITE_CHECKS=off` | Turns website checks off: no routes, and nginx and PHP are read from NVD only when an asset runs them |
| `STACKURITY_SITE_CHECK_PUBLIC_KEY` (or `_FILE`) | The key the stackurity.ai website sends to `POST /api/v1/public/site-check` for its public page. Unset, that endpoint answers 404 |
