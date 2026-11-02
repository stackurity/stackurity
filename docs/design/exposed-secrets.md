# Exposed secrets

Status: implemented (migration `0085_exposed_secrets.sql`).

API keys, tokens, private keys and passwords left where others can read them are among the most common ways in. Stackurity already reads repositories and the files deployed applications serve, so it looks for secrets in the same pass.

## Where it looks

| Scan | Files | Exposure | Severity |
| --- | --- | --- | --- |
| Repository: `stackurity scan` in CI, Git, GitHub and GitLab integrations | Every tracked file. Git-ignored files are not in the repository, so they are left out. | `repository` | high for a known key format, medium for a password or generic key |
| Deployed application (agent) | Only files the web server sends as they are: everything that is not a server script (`.php` and the like) in a site whose root has an index file, and in `public/`, `static/`, `www/`, `htdocs/`, `html/`, `web/`, `wwwroot/`, `public_html/`, and in `dist/`, `build/` and `out/` when they hold an `index.html`. That covers front-end bundles, source maps, a `.env`, backups or SQL dumps in a document root. | `public` | critical |

Configuration the application reads on the server (`wp-config.php`, a Laravel `.env` outside `public/`) is where credentials belong and is not reported. Container images are not scanned yet.

Lowered to low: keys in tests, fixtures, examples and documentation, and keys usually meant to be in front-end code (Google API keys, which are restricted by referrer instead). A line with `stackurity:allow` (or `gitleaks:allow`) is skipped.

Skipped: `.git`, `node_modules`, `vendor` and other dependency or cache directories, lockfiles (their integrity hashes look random), binary files, files over 2 MiB; a scan stops after 20,000 files or 96 MiB and is then incomplete.

## Rules

Known formats: AWS access key IDs and secret keys, GitHub and GitLab tokens, Slack tokens and webhooks, Stripe live keys, Google API keys, private keys (PEM and OpenSSH), SendGrid, npm, OpenAI, Anthropic, DigitalOcean, Shopify and Telegram bot tokens. Generic: a password in a database URL, a `PASSWORD`/`SECRET`/`TOKEN`/`API_KEY` line in a `.env`-style file, and a quoted value assigned to a name like `password`, `api_key` or `client_secret` in code. Generic matches must not look like a placeholder (`your-key-here`, `${VAR}`, `changeme`) or an identifier, and must be random enough (Shannon entropy).

## What is stored

Never the value. A finding has the rule, file and line, a masked preview (the vendor prefix and last 4 characters, `ghp_…4f2a`; only a length for passwords and private keys) and a fingerprint:

- a random-looking value (20 characters or more, 4 bits of entropy per character) is fingerprinted by its SHA-256, so the same key in several repositories or servers is recognised as one secret (`places`);
- a guessable value (a short password) is fingerprinted by where it was found (rule, file, its order in the file), so its hash cannot be used to guess it.

## Lifecycle

`exposed_secrets` has one row per asset, collector, fingerprint and file. A complete scan that no longer finds a row resolves it; finding it again reopens the same row. **Ignore** (security on every asset holding it, with a reason) applies to every place of the secret, and later scans keep it ignored until **Reopen**. Rows follow their asset under row-level security, so members with project access see only their projects' secrets.

Removing a secret from the code does not make it safe: it stays in the repository's history and in any copy already downloaded. The fix is to rotate (revoke and replace) it, then remove it.

## Compatibility

Servers list `exposed_secrets` in `GET /meta`'s features; the client leaves `secrets` out of batches for older servers, which refuse unknown fields.
