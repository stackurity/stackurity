# Projects and permissions

Status: implemented in 0.8 (migration `0032_projects.sql`). Builds on [workspaces.md](workspaces.md).

An organisation (a workspace; the API, CLI and database keep that name) groups its assets into **projects**: a site, a client, a product. People and teams can be given a role on chosen projects, or on one asset, instead of on the whole organisation. An agency's client sees only their project; a new hire added to a team inherits the team's access.

## Model

| Table | What it holds |
| --- | --- |
| `projects` | `id`, `workspace_id`, `name` (unique per workspace), `description`, `archived_at` |
| `project_assets` | `(project_id, asset_id)`. One asset can be in several projects, such as a database server two sites share |
| `access_grants` | A role (`viewer`, `engineer`, `security`, `admin`) for a person (`user_id`) or a team (`team_id`) on a project (`project_id`) or one asset (`asset_id`); exactly one of each pair |
| `workspace_members.role` | Now nullable: NULL is a member with **project access only** |
| `workspace_members.default_project_id` | The project the person chose last in the switcher |
| `routes.project_ids` | A notification route limited to these projects' assets |

Every new table has `workspace_id` defaulting to `stackurity_ws()`, row-level security with the usual `ws` and `sys` policies, and the same-workspace triggers of migration 0025 on every reference, so a grant can never name another workspace's project, asset, team or person.

## Access rules

- An **organisation-wide role** (today's workspace role) sees every asset, in every project and in none.
- A **role on a project** sees that project's assets; a **role on an asset** sees that asset. A **team's** grant applies to everyone in the team, now and later. Grants on an **archived** project give nothing.
- What hangs off a visible asset is visible: findings, fix groups, inventory, coverage, collections, relations (both ends visible), finding events, remediation actions, components (through inventory) with their in-use counts, search hits, reports and exports. An **incident** spanning several projects is visible through any visible finding; its counts, asset and component names, priority, SOS flag and title are recomputed from the visible findings (`store.narrowIncidents`). Collection and coverage problems follow their asset; feed problems hold no tenant data.
- **Audit events** about visible assets, findings and incidents are visible; events about anything else (people, settings, projects) are for organisation-wide roles.
- **Assets in no project** are seen by organisation-wide roles only. Home asks them to file the assets ("N assets are not in a project").
- **Organisation routes** (users, teams, integrations, channels, routes, deliveries, jobs, secrets, enrollments, remediation plans and policies, ingest, project management) refuse members with project access only (403).
- **Roles from grants act per asset.** The principal carries `Role` (organisation-wide, empty with project access only) and `ProjectRole` (the highest grant). A project-scoped route opens with either; a handler that changes something checks the role on each asset it touches (`Server.allowedOn`, SQL `stackurity_grant_role`). An organisation viewer with engineer on Project A can acknowledge A's findings and only view the rest.
- **Tokens** of a member never act above the member's highest role, and are narrowed like their sessions. Collector and host-bound agent tokens have no user: they belong to the workspace and are not limited by projects.
- Changes to grants, team membership and roles apply on the next request: access is read from the database for every request.

## Enforcement: row-level security

Two more connection settings, set by the pool's `PrepareConn` hook from the request context with the existing two (`internal/tenant`, `internal/db`):

| Setting | Set when | Effect |
| --- | --- | --- |
| `stackurity.member` | the caller has project access only | narrow to their projects' assets and asset grants |
| `stackurity.project` | a project is chosen in the switcher (`X-Stackurity-Project` or `project_id`) on a project-scoped route | narrow to that project's assets |

`stackurity_visible_assets()` returns the asset ids a narrowed connection may see (the chosen project's assets, intersected for a member with their active projects' assets and asset grants), or NULL when the connection is not narrowed. The `ws` policy of every asset-bound table becomes

```sql
workspace_id = stackurity_ws()
AND ((SELECT stackurity_narrowed()) IS NOT TRUE
     OR asset_id IN (SELECT unnest(stackurity_visible_assets())))
```

for `assets` (on `id`), `asset_identifiers`, `collections`, `coverage`, `inventory`, `findings`, `fix_groups`, `remediation_actions`; both ends for `asset_relations`; through the parent row for `coverage_history` (collections), `finding_events` (findings), `remediation_plans` (their actions) and `incidents` (findings, or the asset in a collection or coverage key); `asset_ids <@` for `identity_conflicts`; and `stackurity_audit_visible()` for reading `audit_events` (inserting stays workspace-wide). The component catalogue was already visible only through `inventory`, so it follows. The same predicate is the `WITH CHECK`, so a narrowed connection cannot write a row it could not read (for example a relation to another project's asset).

**The fast path.** `(SELECT stackurity_narrowed())` is an InitPlan evaluated once per query; for an organisation-wide caller it is false, the `OR` is decided by its first term, and the hashed SubPlan that lists visible assets is never executed (the plan shows it as "never executed"). For a narrowed caller the list is computed once per query and probed by hash. Inside the functions, `(SELECT stackurity_member())` and `IN (SELECT unnest(stackurity_member_projects()))` are likewise evaluated once rather than per row; the first version called them per row and members' lists took 0.2 to 0.3 seconds.

`projects` and `project_assets` are narrowed for members to their own projects; `access_grants` is workspace-wide because the scope functions read it (the API shows grants to admins only).

## Every route declares its project scope

`internal/api/projects.go` lists each authenticated route as `account`, `global`, `scoped` or `scoped-write`; a route not listed is **organisation only**, and `projectGate` (after routing, on every authenticated route) refuses it to members with project access only. A new route is therefore closed to them until someone classifies it. `TestEveryRouteIsClassified` fails when a route is missing from the test's `projectScopes` table or disagrees with the router, and `TestProjectIsolationSweep` sends every route as every kind of member.

`projectGate` also applies the switcher: on `scoped` and `scoped-write` routes it checks that the chosen project exists, is active and is visible to the caller (404 otherwise) and narrows the context; other routes ignore it, so settings and organisation pages always see the whole workspace.

## Notifications

A route with `project_ids` hears about issues counted per asset for those projects' assets only, about collection and coverage problems of those assets, and about no other problems: urgent alerts, summaries, overdue alerts and "connected" messages never name an asset outside the projects. `ListRoutes` loads each such route's asset set (active projects only). Jira issues describe a whole incident across every asset, so routes to Jira cannot be limited to projects yet (400).

## Grouping suggestions

`GET /project-suggestions` proposes, from `runs_on`, `built_from` and `deployed_as` relations: assets in no project related to a project's assets ("add them to Shop"), and groups of related assets all in no project ("new project: billing-app"). Nothing changes until an admin adds the assets; a dismissed suggestion stays hidden until its set of assets changes.

## Performance

`TestProjectScopePerformance` (`STACKURITY_PERF_FINDINGS=130000 go test ./internal/store -run TestProjectScopePerformance -v`) seeds 130,000 open findings on 2,000 hosts, vacuums and analyses as autovacuum would, and times each caller (median of 7). On the development machine (PostgreSQL 17 in Docker):

| Caller | Findings list (first page and total) | Findings summary | Asset list |
| --- | --- | --- | --- |
| Organisation-wide, 0.6 policies (baseline, same data) | 52 ms | 118 ms | 3 ms |
| Organisation-wide, 0.8 (fast path) | 57 ms | 118 ms | 4 ms |
| Organisation-wide, project of 100 hosts chosen | 68 ms | 96 ms | 16 ms |
| Member of a project of 100 hosts | 73 ms | 102 ms | 10 ms |
| Member of a project of 1,000 hosts | 87 ms | 124 ms | 11 ms |

The fast path adds about 3 ms of planning time per query. The test fails if any of these reaches a second.

## Out of scope for 0.8

- Jira routes limited to projects (an issue would need a per-project view of its incident).
- Project-level filters on incidents by stored priority: list filters (`priority=`, `sos=`) use the incident's stored values; the narrowed values are shown.
- Links in notifications for project routes open the dashboard without choosing the project.
- The CLI has no project option; the API's `project_id` parameter works with any client.
