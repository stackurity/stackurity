# Owner rules

Status: implemented (migration `0081_owner_rules.sql`).

Issues (findings) are assigned to a person, a team or both. Before owner rules, every assignment was made by hand, one issue or one fix at a time, and an estate with hundreds of new issues a week had most of them unassigned. Owner rules let an admin say once who owns which part of the estate, and new issues are assigned as they appear.

## One assignee, many ways to set it

The assignee lives on the issue only. Projects, assets, stacks, fixes and incidents do not have assignees of their own: they are ways to set the issues' assignee, by rule (projects, assets, stacks) or in bulk (a fix's and an incident's **Assign**). So there is never a question of which of two assignees is the real one, and every list, filter and "Assigned to me" keeps reading one column.

## Rules

| Column | Meaning |
| --- | --- |
| `project_id` / `asset_id` | Where: one project, one asset, or neither (every asset). Not both. |
| `layer` | Optional part of the stack, a layer of `store.findingLayer` (`os`, `web_server`, `cms`, `runtime`, `data_store`, `libraries`, `declared`, `managed_service`, `platform`, `other`), the same layers the asset Stack tab shows. |
| `component` | Optional package name pattern, whole name, case-insensitive, `*` for any characters; matched against the name and against `namespace/name`. |
| `user_id` / `team_id` | Who: a person who is a member of the organisation, a team, or both. |

### Precedence

The most specific matching rule assigns an issue:

1. part of one asset's stack (asset and a layer or package),
2. one asset,
3. part of one project's stack,
4. one project (any active project the asset is in),
5. part of every stack,
6. the organisation default (no scope, no stack).

At the same level, a package name and a layer beat a package name, which beats a layer; then the older rule (lower id). An asset in two projects with conflicting project rules therefore gets the older project rule; the settings page lists rules in this order, and an asset's or project's page lists the rules that can apply there in the same order.

## What a rule changes

Findings carry `owner_rule_id` (the rule that assigned it), `assignment_manual` (a person assigned or unassigned it) and `owner_checked_at`.

- **New issues.** The dispatcher's upkeep (each minute per organisation, after ignore rules and before prioritising and incidents) runs `AssignByOwnerRules`: open issues with no assignee that no person touched, and that were not checked since the newest rule was written (`updated_at`, `clock_timestamp()`), are matched; a match is assigned with an `assign` event from the system actor `owner rules` whose note names the rule ("Owner rule #3: operating system on every asset"); others are marked checked. Up to 2,000 a pass. With no rules the pass reads nothing else.
- **A person's choice wins.** Any `assign` action (on the issue, in bulk, on a fix or an incident, from Slack) sets `assignment_manual` and clears `owner_rule_id`, unassigning included. Rules never change those issues. The migration marks every issue assigned before it as manual.
- **Changing or deleting rules** checks unassigned issues again on the next pass, but does not move issues a rule already assigned: `POST /owner-rules/apply` with `dry_run: true` previews the moves (grouped by from and to, with sample issues), and `dry_run: false` makes them, each with an event. Issues whose rule no longer matches and that no other rule matches are unassigned. Up to 20,000 issues per apply.
- Nobody is notified of an assignment (as before for assignments by hand).

## Access

Owner rules are organisation settings: listing needs an organisation-wide role, changes need admin, and members with project access only get 403 (routes classified `org`). The table has workspace row-level security only, like `access_grants`. A rule's person must be a member of the organisation and every reference is checked to be in the same workspace. Changes are audited as `owner_rule.create`, `.update`, `.delete` and `.apply`.

## Editions

All editions. Rules assign to people and teams that exist; Community has one team, so routing to several teams stays with Pro's Teams feature.
