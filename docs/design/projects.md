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
- **Checks, ignore rules and the approval inbox** (0.7). A check follows its asset. An ignore rule for one asset follows the asset. A rule for **every asset** applies across every project, so only an organisation-wide security or admin role may create one, approve a request for one or end one; a member sees such a rule only through a visible finding it covers, with only those findings counted, and a narrowed connection cannot insert one (the row check fails for a rule that covers nothing yet). A request to ignore issues is visible when every issue in it is; someone with security through a project grant decides the requests about issues all on assets where they hold it, and sees those and their own in the inbox.
- **People and links.** Grants are audited as `access_grant` and asset merges as `asset_merge`, object types narrowed connections never read, because their details name people, teams and projects. Someone who assigns through a project role assigns only to the people and teams of their projects, and their directory lists only those people (also when they are organisation-wide viewers). Tracker (Jira) links describe a whole incident and are hidden from narrowed connections, in the API and by RLS on `incident_issues`. Narrowed incident lists filter and sort on the priority, SOS and escalation of the visible findings, and hide what was announced (`notified_priority`).
- **Asset merges** move access: the kept asset joins the merged assets' projects and takes their asset grants. The resolve answer says so and the merge is audited.
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

for `assets` (on `id`), `asset_identifiers`, `collections`, `coverage`, `inventory`, `findings`, `fix_groups`, `remediation_actions`, `checks`; `finding_exceptions` (one asset, or for every asset through a covered finding) and `ignore_requests` (every issue in it); both ends for `asset_relations`; through the parent row for `coverage_history` (collections), `finding_events` (findings), `remediation_plans` (their actions) and `incidents` (findings, or the asset in a collection or coverage key); `asset_ids <@` for `identity_conflicts`; and `stackurity_audit_visible()` for reading `audit_events` (inserting stays workspace-wide). The component catalogue was already visible only through `inventory`, so it follows. The same predicate is the `WITH CHECK`, so a narrowed connection cannot write a row it could not read (for example a relation to another project's asset).

**The fast path.** `(SELECT stackurity_narrowed())` is an InitPlan evaluated once per query; for an organisation-wide caller it is false, the `OR` is decided by its first term, and the hashed SubPlan that lists visible assets is never executed (the plan shows it as "never executed"). For a narrowed caller the list is computed once per query and probed by hash. Inside the functions, `(SELECT stackurity_member())` and `IN (SELECT unnest(stackurity_member_projects()))` are likewise evaluated once rather than per row; the first version called them per row and members' lists took 0.2 to 0.3 seconds.

`projects` and `project_assets` are narrowed for members to their own projects; `access_grants` is workspace-wide because the scope functions read it (the API shows grants to admins only).

## Every route declares its project scope

`internal/api/projects.go` lists each authenticated route as `account`, `global`, `scoped` or `scoped-write`; a route not listed is **organisation only**, and `projectGate` (after routing, on every authenticated route) refuses it to members with project access only. A new route is therefore closed to them until someone classifies it. `TestEveryRouteIsClassified` fails when a route is missing from the test's `projectScopes` table or disagrees with the router, and `TestProjectIsolationSweep` sends every route as every kind of member.

`projectGate` also applies the switcher: on `scoped` and `scoped-write` routes it checks that the chosen project exists, is active and is visible to the caller (404 otherwise) and narrows the context; other routes ignore it, so settings and organisation pages always see the whole workspace.

## Notifications

A route with `project_ids` opens its links in its project (0.9; `notify.routeProject`). It hears about issues counted per asset for those projects' assets only, about collection and coverage problems of those assets, and about no other problems: urgent alerts, summaries, overdue alerts and "connected" messages never name an asset outside the projects. `ListRoutes` loads each such route's asset set (active projects only). As a second lock, every message for such a route is checked before it is queued: one that links to an asset outside the projects (an asset page, its issues or fixes, a fix of it) is withheld and logged. Such a route is stored with `enabled` false and its switch in `project_enabled`, so a release before 0.8, which ignores `project_ids`, sees it as off rather than sending it every project's alerts (such releases also refuse a database migrated by a newer one). Jira issues describe a whole incident across every asset, so a route to Jira limited to a project keeps its own issues instead (0.10, below).

### Jira routes limited to a project (0.10)

A route to a Jira channel may name one project (two or more: 400, one route per project). It keeps one issue per incident in `route_issues`, keyed by route, project, channel and incident, and labelled `stackurity-incident-<ws>-<incident>-route-<route>-project-<project>`, so it never finds (or is found by) the whole-incident issue of an unscoped route searching for `stackurity-incident-<ws>-<incident>` in the same Jira project. Unscoped Jira routes and `incident_issues` are unchanged.

- **What is read under the project.** Everything the issue says is read with a connection narrowed to the project (`tenant.WithProject`, `stackurity.project`): the incident (`GetIncident`, which recomputes counts, asset and component names, priority, SOS, title and escalation from the visible findings), the risk factors and affected assets (`IncidentBrief`), and the planning queries (`ProjectIssueCandidates`, `IncidentIssues`, `IncidentsSeen`). Row-level security returns only the project's findings and assets, so a filter forgotten in Go cannot add another project's. `ProjectIssueCandidates` refuses a connection that is not narrowed. The owner team is left out (it may come from another project's asset); every link carries `?project=`.
- **What is kept workspace-wide.** `route_issues` rows, like `incident_issues`, are hidden from narrowed connections (RLS) and written with the dispatcher's workspace connection; the store refuses narrowed callers. Deliveries carry only the incident id and `project_id`; the text is built when the issue is created or updated, after the route is read again (a delivery queued before the route moved to another project or channel, or was deleted, is dropped).
- **When.** An incident gets an issue when the project's part has an active finding outside a first-scan backlog that matches the route's filters, and it was announced, or the project's finding appeared or came back, after the route was created. Updates follow the project's part (priority, finding and asset counts); it is resolved, with the resolve transition, when none of the project's findings remain open, and gets an "open again" comment if they return. Routes with `escalation` comment escalations of incidents whose part matches.
- **Who sees the links.** Organisation-wide roles see them on the incident with `project_id`; members with project access see no tracker links, as before.

## Grouping suggestions

`GET /project-suggestions` proposes, from `runs_on`, `built_from` and `deployed_as` relations: assets in no project related to a project's assets ("add them to Shop"), and groups of related assets all in no project ("new project: billing-app"). Nothing changes until an admin adds the assets; a dismissed suggestion stays hidden until its set of assets changes.

## Performance

`TestProjectScopePerformance` (`STACKURITY_PERF_FINDINGS=130000 go test ./internal/store -run TestProjectScopePerformance -v`) seeds 130,000 open findings on 2,000 hosts, vacuums and analyses as autovacuum would, and times each caller (median of 7). On the development machine, on top of 0.7 (PostgreSQL 17 in Docker):

| Caller | Findings list (first page and total) | Findings summary | Asset list |
| --- | --- | --- | --- |
| Organisation-wide, 0.6 policies (baseline, same data) | 51 ms | 116 ms | 3 ms |
| Organisation-wide, 0.8 (fast path) | 58 ms | 132 ms | 4 ms |
| Organisation-wide, project of 100 hosts chosen | 88 ms | 102 ms | 7 ms |
| Member of a project of 100 hosts | 77 ms | 101 ms | 9 ms |
| Member of a project of 1,000 hosts | 76 ms | 119 ms | 10 ms |

The fast path adds about 3 ms of planning time per query. The test fails if any of these reaches a second.

## Out of scope for 0.8

- Jira routes limited to projects (an issue would need a per-project view of its incident). Done in 0.10 for one project per route; see "Jira routes limited to a project".
- Project-level filters on incidents by stored priority: list filters (`priority=`, `sos=`) use the incident's stored values; the narrowed values are shown.
- Links in notifications for project routes open the dashboard without choosing the project. Done in 0.9: every link of a route limited to projects carries `?project=` (its only project, or the first of its projects the item's asset is in).
- The CLI has no project option; the API's `project_id` parameter works with any client. Done in 0.10: every command that uses a token takes `--project` (an id or name; `STACKURITY_PROJECT`). Reads send `X-Stackurity-Project`; `scan`, `agent` and `sbom import` send `project_id`, which `POST /ingest` now honours as `POST /sbom/import` does, for admins and for a collector token made for that project only (never another project, never moving an existing asset); `enroll --project` checks the code's project without changing it. The CLI refuses an upload with `--project` to a server whose `GET /meta` does not list `upload_project`.
