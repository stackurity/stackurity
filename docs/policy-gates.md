# Policy gates

A policy gate is a rule your organisation writes once, such as "no known exploited vulnerability on an internet-facing asset", that every asset is held to. Instead of each pipeline deciding for itself with `stackurity scan --fail-on high`, the security team keeps the rules in Stackurity, and the Dashboard, CI jobs and deploy pipelines all read the same answer.

This page describes what is available now: rules, where they apply, their modes, exceptions, the dashboard pages, the weekly summary, checking a build or a deploy against them, and the API ([design](design/policy-gates.md)).

## Rules

Each policy is one rule with its settings, plus filters that choose the assets it looks at.

| Rule (`kind`) | Fails when | Settings (`params`) |
|---|---|---|
| `known_exploited` | an open vulnerability on the asset is in the CISA list of known exploited vulnerabilities | none |
| `end_of_life` | a component is past its end of life | `products`: limit it to these [endoflife.date](https://endoflife.date) products (for example `["python", "nodejs"]`); `after`: a date (YYYY-MM-DD), see below |
| `finding_age` | an open vulnerability of `min_severity` or higher has been open longer than `max_days` | `min_severity` (`low`, `medium`, `high`, `critical`), `max_days` (1 or more), `only_fixable` (only count vulnerabilities with a fix) |
| `leaked_key` | a leaked key on the asset is still open | `min_severity` (default `low`), `served_only` (only count keys in files the asset serves to the network) |

Age is counted from when the asset first had the issue, the same clock as fix deadlines. Findings that are snoozed, accepted as a risk or marked as false positives never count, as in `stackurity scan --fail-on`. A leaked key that was dismissed or is gone does not count.

`after` is stored with an `end_of_life` rule so a policy such as "no end-of-life runtime after 31 March 2027" can be written now. For the moment the rule counts components that are already past their end of life; counting those whose end of life falls before the `after` date comes with a later release.

### Filters

| Filter (`filters`) | Keeps |
|---|---|
| `asset_kinds` | assets of these kinds (`host`, `repository`, `image`, `application`, …) |
| `environments` | assets in these environments; `production` stands for the production environments of your [risk policy](risk.md) |
| `exposure` | `any` (default) or `exposed`: only internet-facing assets, as the risk model sees them |
| `tags` | assets with at least one of these tags |

An empty filter keeps every asset.

## Where a policy applies

Policies are scoped like notifications:

- An **organisation** policy applies to every asset.
- A **project** policy applies to the project's assets.
- An **asset** policy applies to that asset.

A project or asset can turn an inherited policy **off** for itself, or **edit** it: the project or asset gets its own copy, which it can change, and the original stops applying there. Turning the policy back **on** removes the copy. An organisation policy turned off for a project still applies to an asset of that project that is also in another project where it is on. Archived projects are left out.

Organisation admins manage the organisation's policies; anyone with the security role can read them. A project's or asset's policies are managed by admins of that project or asset and read by its security members.

## Modes

Each policy is `off`, `warn` or `enforce`. New policies start in `warn`, so turning one on never breaks a build without warning. A policy that is off has no violations. A violation of a policy in `warn` mode is reported by CI and deploy checks but lets them pass; a violation of a policy in `enforce` mode makes them fail.

Enforce mode needs a paid plan. In the Community edition a policy can be set to `enforce`, but checks count its violations as warnings and say so ("not enforced on this plan").

## Violations

Violations are worked out from the current findings and leaked keys each time they are read, so they are never out of date. Each one names the policy and its mode, the asset, the component, a sentence saying why (for example "CVE-2026-1234 in openssl 3.0.2 is known to be exploited") and a link to the finding or to the asset's leaked keys.

Once an hour Stackurity counts each policy's violations into a daily history (violations and assets at the end of the day, and how many were opened and closed that day). A deleted policy keeps its history.

## Exceptions

Sometimes a violation cannot be fixed yet: the vendor has no fixed version, or a firewall rule already blocks the attack. An exception says that a policy does not count against an asset until a date, with the reason, who asked and who approved it.

- **What it covers.** One issue or leaked key on the asset (the default when asked from a violation), or every violation of the policy on the asset, including ones found later. The API can also name one component on the asset by its purl key.
- **Asking.** Anyone who can see the asset can ask: use **Ask for an exception** on a row of **Fixes → Policy violations**, or on a policy in an asset's **Policy gates** card (for the whole asset). Give a reason (accepted risk, mitigated, no fix yet or false positive), say why, and choose the day it ends. The end can be at most the risk policy's limit for exceptions (**Settings → Risk policy**, the same limit as for ignoring issues) from today.
- **Deciding.** A security or admin user of the asset (on the organisation, or through a project or asset grant) approves or declines it on **Approvals → Policy exceptions**. Approving can shorten the end date; left empty, the exception ends on the date asked for. A decline needs a reason, which the person who asked sees. One approver is enough, as for requests to ignore issues; that can be the person who asked.
- **While it is in force.** What it covers is left out of the violations list, the Dashboard, the weekly summary and CI and deploy checks. The Violations page lists the exceptions in force below the table, an asset's card and Settings → Policy gates count them per policy, and a request still waiting is shown on its violation's row so nobody asks twice.
- **When it ends.** On its end date the exception ends by itself and the violation counts again. A security or admin user of the asset can also end it early (**End early** on Approvals, with an optional note).

Every step is recorded in the audit log: `policy_exception.request`, `policy_exception.approve`, `policy_exception.decline` and `policy_exception.end`, with the policy, the asset, what it covers, the notes and the dates. An exception also records the policy's `rule_version` when it was asked.

Paid plans add to this workflow: a second approver (the person who asked cannot approve), approver groups and reminders before an exception ends.

## In the dashboard

- **Settings → Policy gates** lists the organisation's policies: each one's rule in words, its mode, the assets it looks at, where it is turned off ("Off for 2 projects") and how many violations it has, with a link to them. Organisation admins add, edit and delete policies here; anyone with the security role can read them. The form asks for the rule and its settings, the assets it looks at (kinds of asset, environments, internet-facing only, tags) and the mode. A new policy starts in warn mode. On a plan without enforce, the Enforce option carries a Pro badge and notice; it can still be chosen, and checks then report its violations as warnings.
- **A project's page and an asset's page** have a **Policy gates** card, like their Notifications card: the policies they inherit from the organisation (and, for an asset, from its projects), each **On**, **Off for this project** or **Edited for this project**, with buttons to turn one off, turn it on again, or edit it for this project or asset only; and their own policies, which their admins add, edit and delete.
- **Fixes → Policy violations** lists every current violation: the policy and its mode, the asset, the component, why it fails and a link to the issue or the leaked key. Filter it by policy, mode or rule; each filter on shows as a chip. Links from the weekly summary and the project and asset cards open it filtered by policy, asset or project. It needs the security role across the organisation.
- **Approvals → Policy exceptions** lists requests for exceptions waiting for a decision (tick the box to see decided and ended ones too), with Approve, Decline and End early for security and admin users of each asset. See [Exceptions](#exceptions).
- **The Dashboard's Needs your attention** band has a row such as "5 policy violations on 2 assets" while any policy has violations, opening the Violations page. It is shown to the security role and above.

## In the weekly summary

A weekly summary has a **Policy gates** section when any policy has violations on the assets the notification rule covers (its projects, teams and environments, as for the rest of the summary): one line per policy with its mode and how many violations on how many assets, the assets with most under it, each linking to the Violations page. Violations alone do not send a summary: the section rides along with the week's news. Daily summaries leave it out.

## In CI

`stackurity scan` checks the policies itself. After it uploads the scan, it asks the server which policies apply to the repository; if any do, it waits for the server to evaluate the scan (as `--fail-on` does, up to `--wait`) and then asks for the answer. It prints a "Policy gates" block:

```
Policy gates: fail, 2 violations (3 policies checked)
  No known exploited vulnerabilities [enforce]
    CVE-2026-1234 in openssl 3.0.2 is known to be exploited
    https://stackurity.example.com/findings/812
  No old criticals in production [warn]
    CVE-2026-0042 in zlib 1.2.11 (critical) has been open for 30 days; the limit is 14
    https://stackurity.example.com/findings/790
```

- Violations of policies in `warn` mode are printed and the job passes (exit 0).
- A violation of a policy in `enforce` mode fails the job with exit status 3, the same status `--fail-on` uses.
- `--fail-on`, `--fail-on-priority` and `--fail-on-kev` keep working and are applied as well: either can fail the job.
- If no policy applies to the repository, or the server is older than policy gates, nothing is printed and the scan behaves as before, without waiting.
- If `--wait` runs out before the server has evaluated the scan, the job fails with status 4 when a policy is enforced; otherwise it prints a warning and passes.
- If the check itself cannot be made (the server is unreachable, say), the job fails when a policy is enforced and prints a warning otherwise.

`--policy=auto` is the default; `--policy=off` skips the check. A CI job's token from the ID-token exchange can check only its own repository, and any collector token can check the scan it uploaded. In GitHub Actions the [scan action](https://github.com/stackurity/scan-action) has a `policy` input (`auto` or `off`) that it passes on.

```sh
stackurity scan . --git-url "$CI_REPOSITORY_URL"                    # policy gates checked
stackurity scan . --git-url "$CI_REPOSITORY_URL" --policy=off       # not checked
```

Each check is recorded on the server with the commit and the branch or tag (from `GITHUB_REF`, `CI_COMMIT_REF_NAME` and the like).

## At deploy

`stackurity policy check` asks the same question for any asset, for deploy pipelines. Name the asset with one of:

- `--asset 42`: the asset's id;
- `--image ghcr.io/acme/shop@sha256:…` or `--image sha256:…`: a container image, by digest (an image Stackurity has scanned, from a registry or a host);
- `--repo https://github.com/acme/shop`: a repository, by the URL it was scanned with.

`--commit` and `--ref` are recorded with the check. Violations of policies in `warn` mode are printed and the command exits 0; a violation of a policy in `enforce` mode exits with status 3. `--json` prints the server's answer as JSON instead of text, with the same exit status. Unlike `stackurity scan`, the command fails on a server without policy gates, since the pipeline asked for a check.

```sh
stackurity policy check --image "ghcr.io/acme/shop@$DIGEST" --commit "$GIT_SHA" --ref "$RELEASE"
```

The token needs the viewer role (an API token made under **Integrations → API tokens**), or is a collector token bound to the asset. The check answers from what the server knows now: scan the image or repository first if it may have changed.

The answer, from `POST /api/v1/gate-policies/check`:

```json
{
  "check_id": 518,
  "result": "warn",
  "asset_id": 42,
  "asset_name": "ghcr.io/acme/shop:1.4.0",
  "policies_evaluated": 2,
  "policies_enforced": 0,
  "violations": [
    {
      "policy_id": 3,
      "policy_name": "No known exploited vulnerabilities",
      "mode": "enforce",
      "kind": "known_exploited",
      "reason": "CVE-2026-1234 in openssl 3.0.2 is known to be exploited",
      "component": "openssl 3.0.2",
      "key": "CVE-2026-1234",
      "finding_id": 812,
      "link": "https://stackurity.example.com/findings/812",
      "enforce_requires_plan": true
    }
  ]
}
```

`result` is `pass` (no violation), `warn` (violations of policies in warn mode only) or `fail` (a violation of an enforced policy). Approved [exceptions](#exceptions) that have not expired are honoured. Every check, from CI, a deploy or the API, is recorded with who asked, the asset, the commit, branch or image digest, the result and the violations, for audit and evidence.

## History

Every change is recorded in the audit log: `gate_policy.create`, `gate_policy.update`, `gate_policy.mode` (only the mode changed), `gate_policy.delete`, `gate_policy.exclude` and `gate_policy.include` (turned off or on for a project or asset) and `gate_policy.customise` (replaced by an edited copy). Each event has a one-line summary, and changes carry the policy before and after. A policy's `rule_version` goes up whenever its rule, settings or filters change.

## API

| Request | Role | Does |
|---|---|---|
| `GET /api/v1/gate-policies` | security | every policy, with the projects and assets it is turned off for |
| `POST /api/v1/gate-policies` | admin | add an organisation policy |
| `GET /api/v1/gate-policies/{id}` | security | one policy |
| `PUT /api/v1/gate-policies/{id}` | admin | change a policy (a `mode` left out keeps the current one) |
| `DELETE /api/v1/gate-policies/{id}` | admin | delete a policy |
| `GET /api/v1/gate-policies/violations` | security | current violations; filter with `policy_id`, `asset_id`, `project_id` |
| `POST /api/v1/gate-policies/check` | viewer, or a collector token for its own asset | check one asset now and record it ([At deploy](#at-deploy)) |
| `GET /api/v1/gate-policies/exceptions` | viewer (on the assets they can see) | exceptions; filter with `status` (`pending`, `approved`, `declined`, `ended`, `all`), `policy_id`, `asset_id` |
| `POST /api/v1/gate-policies/exceptions` | viewer on the asset | ask for an exception: `policy_id`, `asset_id`, `target_kind` (`finding` with `finding_id` or `leak_id`, `asset`, or `component` with `component_key`), `reason`, `note`, `expires_at` |
| `GET /api/v1/gate-policies/exceptions/{id}` | viewer (on the asset) | one exception |
| `POST /api/v1/gate-policies/exceptions/{id}/decision` | security on the asset | `{"decision": "approve" \| "decline", "note", "expires_at"}` |
| `POST /api/v1/gate-policies/exceptions/{id}/end` | security on the asset | end an approved exception early, with an optional `note` |
| `GET /api/v1/projects/{id}/gate-policies` | security on the project | what the project inherits (and whether it is on, off or edited) and its own policies |
| `POST /api/v1/projects/{id}/gate-policies` | admin on the project | add a project policy |
| `PUT`, `DELETE /api/v1/projects/{id}/gate-policies/{pid}` | admin on the project | change or delete one of the project's policies |
| `PUT /api/v1/projects/{id}/gate-policies/inherited/{pid}` | admin on the project | `{"state": "on" \| "off" \| "edit"}` for an inherited policy |

The same requests exist under `/api/v1/assets/{id}/gate-policies`. The organisation routes need an organisation-wide role; members who only have access to some projects use the project and asset routes.

A policy:

```json
{
  "name": "No old criticals in production",
  "kind": "finding_age",
  "params": {"min_severity": "critical", "max_days": 14, "only_fixable": true},
  "filters": {"environments": ["production"], "exposure": "any"},
  "mode": "warn"
}
```
