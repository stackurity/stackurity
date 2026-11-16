# Policy gates

Status: draft for owner sign-off (16 Nov 2026). Owner approved the feature;
the edition split in section 7 is a plan question and needs a decision.

## 1. What it is

Today a pipeline gates itself: `stackurity scan --fail-on high` (and the
`fail-on*` inputs of scan-action) decide per job, in YAML the security team
doesn't own. Policy gates move that decision into Stackurity: an organisation
writes rules once, scopes them like notifications, and every CI job, deploy
pipeline, the Dashboard and the weekly summary read the same answer.

Name: "policy gates" in the UI and API (`/gate-policies`), because "policy" is
already taken twice (risk policy, automatic-fix policies).

## 2. Rules (v1)

Each policy is one rule kind with parameters plus shared asset filters.

| Kind | Fails when | Parameters |
|---|---|---|
| `known_exploited` | an open finding is in CISA KEV | — |
| `end_of_life` | a component is past end of life, or will be by `after` | `after` (date, optional), `products` (optional) |
| `finding_age` | an open finding of `min_severity` or higher is older than `max_days` | `min_severity`, `max_days`, `only_fixable` |
| `leaked_key` | an open leaked key | `min_severity`, `served_only` |

Shared filters: asset kinds (host, repository, image, …), environments
(`production` means the risk policy's production list), internet-facing
(`any` / `exposed`, using the existing effective-exposure rule), tags.
Examples from the brief map directly: "no KEV on internet-facing assets",
"no end-of-life runtime after 2027-03-31", "no critical older than 14 days in
production", "no leaked key in repositories".

Findings that are risk-accepted, snoozed or rejected never count (same rule
as `gate.blocks` today). Age uses the existing clock `COALESCE(due_from, first_seen)`.

Violations are computed on read from the same columns `riskRows` uses; there
is no violations table to drift. A daily rollup (`gate_policy_daily`) keeps
counts per policy for trends and evidence.

## 3. Scope and inheritance

Same model as scoped notifications (migration 0096): a policy is owned by the
org, a project or an asset. Org policies reach everything; a project or asset
can turn an inherited policy off or replace it with its own copy
(`inherits_policy_id` + an exclusion row). Turning an org policy off below
the org is itself audited and shown on the policy ("off for 2 projects").

## 4. Modes

`off` → `warn` → `enforce`, per policy. New policies start in `warn`, so
switching one on never breaks a build silently. The page shows how many
recent checks would have failed before you move to `enforce`.

## 5. Where it is enforced

- **CI.** `stackurity scan` asks `POST /gate-policies/check` after the result
  is ready (CI-token or API-token auth; a CI token may only check its own
  repository, as with ingest). Output lists each violation with policy name,
  reason, component and a link. Warn-mode violations print and exit 0;
  enforce-mode violations exit 3 (the existing gate code). `--policy=auto|off`,
  default `auto` (skipped silently on servers without the feature). Existing
  `--fail-on*` flags keep working and are applied as well. scan-action gets a
  `policy` input and is released as v1.x with the `v1` tag moved.
- **Deploy.** `stackurity policy check --asset|--image <digest>|--repo <url>`
  for deploy pipelines and admission hooks, same endpoint and exit codes,
  plus a JSON output. A Kubernetes admission example lives in docs.
- **Dashboard and weekly summary.** A "Policy violations" tile in the
  attention band and a section in the weekly summary (scoped per route).

Every check is stored (`gate_policy_checks`: who, asset, commit/image, mode,
result, violations) for audit and evidence.

## 6. Exceptions

Request → approve, with reason, approver and expiry, fully audited.
Target = policy + asset (+ optional component or finding key). Expiry is
capped by the risk policy's `exception_max_days`. The flow, roles (`canDecide`)
and audit names follow ignore requests (`policy_exception.request|approve|decline|end`);
an expired exception ends itself and the violation returns.

## 7. Edition split (needs owner decision)

Constraints already on record: `docs/design/open-core.md` lists the CI gate
as free and says detection is never paid; approving ignore requests on
findings is free today.

Proposed:

| Community (free) | Paid (pro, `//go:build ee`, locked teaser) |
|---|---|
| Policies, scopes, inheritance | **Enforce mode** (a policy fails the build) |
| Violations page, Dashboard tile, weekly section | **Deploy gate** (`policy check` for deploy pipelines / admission) |
| CI check in warn mode | **Exception workflow extras**: second approver (requester can't approve), approver groups, expiry reminders |
| Basic exceptions (one approver, as ignore requests today) | Check history beyond the plan's retention; evidence export |

The brief proposed making the whole approval workflow paid; that would make
policy exceptions stricter than finding exceptions, which are free today.
Recommendation: keep a basic exception free and charge for the workflow extras.

## 8. Evidence

Policies (as at period end + change history), daily violation counts,
checks and exceptions are exposed as `store.PolicyEvidence(ctx, from, to)` for
the evidence pack (shape agreed with stackurity-a9).

## 9. Delivery

1. Core: migration `0108_gate_policies` (policies, exclusions, exceptions,
   checks, daily rollup; RLS + same-workspace triggers), store engine, CRUD
   and violations API (routes classified in `projects.go`), tests.
2. Core: check endpoint, CLI `--policy` and `policy check`; scan-action v1.x.
3. Core web: Settings → Policy gates, project/asset cards, Violations page,
   Dashboard tile, weekly section, UI tests.
4. Pro: enforce mode, deploy gate, exception extras; core teasers.
5. Evidence hook with stackurity-a9.

Each step is its own PR with a `changelog.d` fragment; merges go through the
release owner.
