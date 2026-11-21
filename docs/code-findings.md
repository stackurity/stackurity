# Code findings (code scanner imports)

Code-review security scanners read a repository's own source and report problems such as injection, missing authorisation checks or unsafe redirects. Stackurity imports their reports so these findings sit on the repository's asset next to its dependency, server and image findings, with the same notifications, incidents and access rules.

Supported sources:

| Source | Format | What to give Stackurity |
|---|---|---|
| [deepsec](https://github.com/vercel-labs/deepsec) (Apache-2.0), an agent-based code scanner | `deepsec` | The JSON that `deepsec export --format json` writes |
| Any scanner that writes SARIF 2.1.0 (Semgrep, CodeQL and many others) | `sarif` | The SARIF log |

Code findings are part of every edition. They appear under **Fixes → Code findings**, on the **Code findings** tab of each repository or application, through the API ([`GET /code-findings`](api.md#get-code-findings)) and to AI assistants (`list_code_findings`, [AI assistants](ai-assistants.md)).

## Importing a report

The repository must have reported already (through `stackurity scan`, the scan action or a repository integration): an import attaches findings to an existing repository or application and never creates an asset.

```sh
deepsec export --format json --project-id shop --out deepsec.json
stackurity import code-findings deepsec.json --format deepsec --asset https://github.com/acme/shop --model claude-opus-4-1

stackurity import code-findings results.sarif --format sarif --asset 12
```

`stackurity import code-findings FILE` takes:

| Flag | Meaning |
|---|---|
| `--format` | `deepsec` or `sarif` (required) |
| `--asset` | The repository: its asset id, or its URL as `stackurity scan` reports it. Defaults to `STACKURITY_GIT_URL`, and in a CI job with [keyless sign-in](api.md#post-citoken) to the job's own repository |
| `--partial` | The report is filtered (for example deepsec's `--only-true-positive`, `--since` or `--only-slugs`): nothing it leaves out is resolved |
| `--model` | The AI model that produced the report, recorded with each finding. deepsec's export does not include it |
| `--server`, `--token-file`, `--project` | As for the other commands: the server, a token file (or `STACKURITY_TOKEN`), and a project to scope the request to |

The file is checked on your machine first, so a wrong format or a broken file fails before anything is uploaded. The command needs a server that lists the `code_findings` feature (this version or later).

Who can import: a collector token, an engineer or anyone above, and a CI job's token for its own repository only. A token bound to one asset can import only for that asset. The API is [`POST /code-findings/import`](api.md#post-code-findingsimport).

## How findings are kept up to date

- **One finding, however often it is imported.** A finding is identified by its source (`deepsec`, or `sarif:<tool>`), the scanner's rule, the file and its title (deepsec) or the scanner's own fingerprint (SARIF, falling back to the message). Line numbers are not part of it, so a finding whose lines move is updated, not duplicated.
- **Gone when the report no longer has it.** A complete import resolves, as *gone*, the open findings of that source on that asset that the report no longer holds. deepsec's export leaves out findings it has revalidated as fixed or false positives, so they resolve on the next import. A partial import (`--partial`) resolves nothing.
- **The scanner's verdict is kept.** deepsec's revalidation verdict (`true-positive`, `false-positive`, `fixed`, `uncertain`, `accepted-risk`, `duplicate`) and a SARIF suppression (`suppressed`) are stored with the reasoning. A finding whose verdict says there is nothing to do (false positive, fixed, accepted risk, duplicate, suppressed) is stored as resolved by its verdict and never alerts. If a later report opens it again, it opens again.
- **Several scanners side by side.** Each source replaces only its own findings: importing deepsec's report does not resolve what Semgrep found.
- **Dismissing.** Someone with the security role can dismiss a finding (with a note); it stays dismissed whatever later imports say, and can be undone.

## Severity and alerts

| deepsec | SARIF | Stackurity | Category |
|---|---|---|---|
| `CRITICAL` | `security-severity` 9.0 or more | critical | security |
| `HIGH` | `security-severity` 7.0 to 8.9, or level `error` | high | security |
| `MEDIUM` | `security-severity` 4.0 to 6.9, or level `warning` (the default) | medium | security |
| `LOW` | `security-severity` below 4.0, or level `note` | low | security |
| `HIGH_BUG` |  | low | bug |
| `BUG` |  | info | bug |
|  | level `none` | info | |

A SARIF result is a security finding when its rule (or the result) has a `security-severity` property or a `security` tag; otherwise its category is *other*. SARIF results whose `kind` is not a failure (`pass`, `informational`, `notApplicable` and so on), and results whose `baselineState` is `absent`, are not imported.

Open **critical and high security** findings raise one incident per asset (kind *Code finding*): P1 when one is critical, P2 otherwise. It is sent where new issues go (the routes' *New issues* threshold), to the projects that hold the asset, and resolves itself when no such finding is open. Medium and lower findings, bugs and other results are listed and never alert.

## Limits and safety

A report is untrusted input:

- At most 16 MB and 5,000 findings (SARIF: 20 runs). Larger uploads are refused before they are parsed.
- Every text field is cut to a fixed length, control characters and Unicode bidirectional overrides are removed, and the dashboard and notifications show it as plain text, never as HTML or Markdown.
- Nothing in a report is run, fetched or followed: file paths and links are only shown.
- deepsec's export names people (suggested assignee, owning teams, on-call, managers, contributors and committers, with email addresses). Stackurity does not read or store any of them; only the finding's own description, recommendation and revalidation are kept.
- Each import is recorded in the activity log (`code_findings.import`) with the format, sources, counts and model.

## What is not covered

- Stackurity does not run code scanners itself; it imports their reports.
- Findings are not mapped to CVEs or packages and have no fix group or automatic fix: the fix is a change to the code.
- deepsec's other output formats (`md-dir`) and its per-file data directory are not read; use `deepsec export --format json`.
