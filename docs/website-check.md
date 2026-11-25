# Website check

The website check shows what a public website gives away to anyone who visits it, and what the stored vulnerability, known-exploited and end-of-life data says about it. Enter a domain such as `example.com` and you get:

- **Server software and versions** the site names in its headers (`Server`, `X-Powered-By`, `X-AspNet-Version`) or in its page's generator tag: nginx, Apache HTTP Server, PHP, OpenSSL, Microsoft IIS, Express, Next.js, Tomcat, WordPress, Drupal, Joomla! and others.
- **JavaScript and CSS libraries** the page loads, with exact versions: from their CDN address (jsDelivr, unpkg, cdnjs, code.jquery.com, BootstrapCDN, Google's) or from the version banner at the top of the file (jQuery, jQuery UI, Bootstrap, AngularJS, Vue, React and the other libraries the agent recognises in vendored files).
- For each: its **vulnerabilities** for that version (with whether CISA lists them as known exploited, and the version that fixes them) and whether its release line has reached **end of life**.
- **TLS**: protocol version, certificate issuer and how many days it has left.
- **Browser protection headers** the page does or does not send (Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, clickjacking protection, Referrer-Policy).
- **WordPress plugins** the page loads files from, with the version in their `?ver=` parameter. There is no stored vulnerability data for plugins; the report says so.
- **Other problems**, worst first, each with what to do about it:
  - **Leaked keys** in the page's inline scripts and in the first bytes of the site's own scripts (the same rules as [leaked keys](leaked-keys.md)). Only a masked preview is shown, never the key.
  - **Cookies** without Secure (on an https site), and session cookies without HttpOnly or SameSite.
  - **Mixed content** (an https page loading scripts, frames or images over http), and **password forms** on an http page or posting to an http address.
  - **Files from public CDNs without an integrity check** (Subresource Integrity), and a **directory listing**.
  - **TLS 1.0 or 1.1 still accepted** alongside newer versions.
  - **Email records**: no SPF record or one ending in `+all`, and no DMARC record or one with `p=none`. Skipped for a site on a hosting platform's domain (`app.herokuapp.com`), which has no email records of its own.

## The grade

The full report starts with a grade from **A** to **F**, with the deductions behind it, most points first. A score starts at 100 and loses points for each problem a visitor can see:

| Problem | Points |
|---|---|
| Critical (a leaked live key, for example), or a vulnerability CISA lists as exploited in the wild | 30 |
| High (a page served over plain http, a password form posting to http) | 15 |
| Medium (a release past end of life, TLS 1.0/1.1 accepted, a certificate expiring within 14 days) | 6 |
| Low (a cookie without SameSite, for example) | 2 |
| Browser protection headers missing | 2 each, at most 8 |

Each piece of software counts once, at its worst vulnerability, plus once more if its release line has reached end of life. 90 and above is A, 80 B, 65 C, 50 D, below 50 F. A critical problem keeps the grade at D or below, and a high one at C or below, whatever the score. The grade is part of the full report only: the public summary without an account does not show it.

## What a check does, and does not do

A check is one browser-like visit. It requests the page you asked for (following up to five redirects), then the first 16 KB of up to 20 of the scripts and stylesheets that page links to. For an https site it also sends one TLS hello offering nothing newer than TLS 1.1 and reads which version the server picks, then closes the connection: no handshake is completed and nothing is encrypted or sent beyond the hello. It also looks up the domain's SPF and DMARC records in DNS. That is all: no port scans, no paths the page does not link, no login attempts, no payloads. Requests say who they are from: `Mozilla/5.0 (compatible; StackurityWebsiteCheck/1.0; +https://stackurity.ai/website-check)`.

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

AI assistants connected to Stackurity run checks with the `run_website_check` tool, and read them with `list_website_checks` and `website_check_report` ([AI assistants](ai-assistants.md)). An assistant's connection counts as API access for the plan.

Errors: `400 bad_target` (not a public website address), `422 site_unreachable` (the site did not answer, does not resolve, or its certificate is refused), `402 plan_limit` (see below), `429` (more than 10 checks a minute for one organisation).

## Plans

On Stackurity Cloud each plan has a number of website checks a month (`site_checks_per_month`, see [plan limits](asset-limits.md#plan-limits)); a check that could not run does not count. Plans without API access (`no_site_check_api`) run checks from the dashboard only. A self-hosted server has no limits.

Without an account, the public page at [stackurity.ai/website-check](https://stackurity.ai/website-check) runs one check a day per visitor and shows a summary: what was found, how many issues each has, end of life, and the most serious issue. The full report comes with a free account.

## Settings

| Variable | |
|---|---|
| `STACKURITY_SITE_CHECKS=off` | Turns website checks off: no routes, and nginx and PHP are read from NVD only when an asset runs them |
| `STACKURITY_SITE_CHECK_PUBLIC_KEY` (or `_FILE`) | The key the stackurity.ai website sends to `POST /api/v1/public/site-check` for its public page. Unset, that endpoint answers 404 |
