# Policy gates

A policy gate is a rule your organisation writes once, such as "no known exploited vulnerability on an internet-facing asset", that every asset is held to. Instead of each pipeline deciding for itself with `stackurity scan --fail-on high`, the security team keeps the rules in Stackurity, and the Dashboard, CI jobs and deploy pipelines all read the same answer.

This page describes what is available now: rules, where they apply, their modes and the API. Checking a build or a deploy against them (`stackurity scan --policy`, `stackurity policy check`), the dashboard pages and exceptions come in later releases ([design](design/policy-gates.md)).

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

Each policy is `off`, `warn` or `enforce`. New policies start in `warn`, so turning one on never breaks a build without warning. A policy that is off has no violations. (`enforce` makes a CI or deploy check fail once those checks are released.)

## Violations

Violations are worked out from the current findings and leaked keys each time they are read, so they are never out of date. Each one names the policy and its mode, the asset, the component, a sentence saying why (for example "CVE-2026-1234 in openssl 3.0.2 is known to be exploited") and a link to the finding or to the asset's leaked keys.

Once an hour Stackurity counts each policy's violations into a daily history (violations and assets at the end of the day, and how many were opened and closed that day). A deleted policy keeps its history.

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
