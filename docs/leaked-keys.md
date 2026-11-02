# Leaked keys

Stackurity looks for keys, tokens and passwords written into files: an API key committed to a repository, a private key kept with an application, a database password in a `.env` file the web server may send to anyone. It runs wherever inventory is collected (the agent's application scans, `stackurity scan`, repositories the server clones) and is on by default.

The value never leaves the machine that found it. A leak is reported by its rule, file and line, the name of the setting it was assigned to, a fingerprint and a masked preview (`sk_live_…4f2a`; nothing for a password). The fingerprint is a slow salted hash (PBKDF2-SHA256, 20,000 rounds), so the same key in two places is recognised as one, and a short password cannot be guessed back from it cheaply.

The fix for a leaked key is always the same: **rotate it** (revoke it and issue a new one), then remove it from the file. Removing it from the file alone does not help: it stays in the repository's history and in every copy already made.

## What is found

| Rule | Finds | Severity on its own |
|---|---|---|
| `private-key` | RSA, EC, DSA, OpenSSH and PGP private keys, in a file or a string | critical |
| `aws-secret-key` | AWS secret access keys assigned to `aws_secret_access_key` | critical |
| `aws-access-key-id` | AWS access key IDs (`AKIA…`, `ASIA…`) | high |
| `github-token` | GitHub personal, OAuth, app and fine-grained tokens | critical |
| `gitlab-token` | GitLab personal access tokens | critical |
| `slack-token` | Slack bot, user and app tokens | critical |
| `slack-webhook` | Slack incoming webhook addresses | medium |
| `stripe-live-key` | Stripe live secret and restricted keys | critical |
| `razorpay-secret` | Razorpay key secrets | critical |
| `openai-key` | OpenAI API keys | critical |
| `anthropic-key` | Anthropic API keys | critical |
| `sendgrid-key` | SendGrid API keys | critical |
| `npm-token` | npm access tokens | critical |
| `google-api-key` | Google API keys (often meant to be public, restricted by referrer) | medium |
| `database-url` | `postgres://`, `mysql://`, `mongodb://`, `redis://` and `amqp://` addresses with a password | high |
| `password-assignment` | A password, secret, token or API key assigned in a configuration file: `.env`, YAML, TOML, INI, `.properties`, `wp-config.php`, `config/*.php` and copies such as `wp-config.php.bak` | high |

Not reported, because their keys are made up far more often than real: example values and placeholders (`your_password_here`, `changeme`, `${DB_PASSWORD}`, `AKIAIOSFODNN7EXAMPLE`), values read from the environment (`getenv(...)`, `required('DB_PASSWORD')`), templates (`.env.example`, `wp-config-sample.php`; a key with its own format is still reported in one), tests (`*_test.go`, `*.spec.ts`, `test_*.py`), and other people's code (`node_modules`, `vendor`, `third_party`, `testdata`, `fixtures`). WordPress's authentication keys and salts are not reported: every site has them, and `DB_PASSWORD` already reports the file. Assignments in ordinary source code are not reported either: `password = '…'` in a `.js` file is far more often a form field than a credential.

At most 20 leaks are reported from one file and 1,000 from one scan; files over 2 MiB are not read. A scan that stopped at a limit, or could not read some files, says so ("partial") rather than looking clean.

## Severity and exposure

Keeping keys in a `.env` or other configuration file on the server, out of the code and the repository, is the right practice, so on a server what matters is who else can read the file. The agent marks each leak with its exposure, and the severity follows from it:

| Where the key is | Exposure | Severity |
|---|---|---|
| A file under a directory the web server serves (a document root or alias in the Apache or nginx configuration) that it sends as it is, not as PHP: `.env`, `config.php.bak`, `.sql`, `.js` | `served` | critical |
| A key with its own format (Stripe, AWS, GitHub, …) written into the application's code | none or `world_readable` | its own (above) |
| Any key or password in a configuration file (`.env`, `wp-config.php`, `config/*.yml`) every account on the host can read | `world_readable` | medium |
| Any key or password in a configuration file only its owner can read | none | low |
| Anything committed to a repository, `.env` included | none | its own (above) |

Only critical and high leaks raise an alert; medium and low ones are listed on the asset. The agent does not read the web server's deny rules: a `.env` under a document root is reported as served even if a rule blocks it, since one configuration change would expose it. Apache's default denial of `.ht*` files (`.htpasswd`) is assumed.

## The agent

The agent scans every application directory it reports (`--app-dir`, `--discover-apps`). An application inside another (phpMyAdmin under a site's document root) is scanned only as itself. Turn the scan off with `stackurity agent --no-leaks` or `STACKURITY_NO_LEAKS=true`. An agent sends leaks only to a server that takes them (Stackurity 0.15 or later).

A complete scan proves what it no longer sees: a key removed from the file is marked gone at the next collection. A partial scan (a limit, unreadable files) adds what it found and keeps the rest open.

## Repositories and CI (stackurity scan)

`stackurity scan DIR` scans the project's files along with its lockfiles. In a Git checkout it reads only the files Git tracks, so a developer's own `.env`, ignored by Git, is not reported. Git runs with `core.fsmonitor` turned off, so a checkout's own configuration (a pull request's) cannot make it run a program. Leaks are printed with their values masked:

```text
leak: critical GitHub token ghp_…2Qex at src/deploy.js:12
```

`stackurity scan --fail-on-leak high` exits with status 3 when a leak of that severity or higher is found, to stop a pipeline. It needs no server, so it also works with `--output`. `stackurity scan --no-leaks` turns the scan off. Repositories the server clones (Settings → Repositories, the GitHub App) are scanned the same way, on the cloned branch.

Only the files as they are now are read, not the repository's history: a key committed and then deleted is not found, though it still needs rotating.

## Keeping a line out

A line that contains `stackurity:allow` is not reported, for a test key a project means to keep:

```python
TEST_KEY = "sk_test_…"  # stackurity:allow
```
