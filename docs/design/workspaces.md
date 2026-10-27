# Workspaces (multi-tenancy)

Status: design, October 2026. Implementation lives on the `workspaces` branch.

Stackurity becomes a platform: one installation serves many organisations, each in its own **workspace**. A self-hosted install starts with one workspace and looks exactly as it does today; Stackurity Cloud runs many. Workspaces are part of the Apache-2.0 core. Sign-up, billing, quotas and regions stay in the private Cloud code.

## Goals

- One workspace can never read or change another workspace's data, even when a query forgets a filter.
- Existing installs upgrade in place: all current data becomes workspace 1, and agents, tokens and integrations keep working.
- Users are global and can belong to several workspaces with a different role in each.
- Public intelligence (OSV, KEV, lifecycle, registry releases) is stored once and shared.

Out of scope here: self-service sign-up, billing, data residency, a silo database per customer. These build on this design. Per-workspace limits on monitored assets are a generic mechanism in the core (`workspaces.asset_limit`, see [asset-limits.md](../asset-limits.md)); a hosted service only sets the limits.

## Model

| Concept | Scope | Notes |
| --- | --- | --- |
| `workspaces` | global | id, name, slug, created_at, disabled_at |
| `workspace_members` | global | (workspace_id, user_id, role); replaces `users.role` |
| `users` | global | gains `instance_admin` (operates the installation); `role` kept for one release, then dropped |
| `sessions` | global | gains `workspace_id`: the workspace the browser is working in |
| `oidc_logins`, `jobs` | global | `jobs` gains a nullable `workspace_id`; handlers run in that workspace |
| Intelligence: `feeds`, `advisories`, `advisory_packages`, `affected_values`, `pending_packages`, `known_exploited`, `lifecycle_*` | global, shared | Public data. No tenant information |
| Component catalogue: `components`, `package_releases`, `evaluation_gaps` | global, filtered | Purls can reveal private package names, so rows are visible only when the current workspace's inventory references them (see RLS) |
| Everything else: assets, identifiers, relations, conflicts, collections, inventory, coverage, findings, finding events, incidents, teams, team members, channels, routes, deliveries, integrations, API tokens, enrollments, remediation policies, plans and actions, fix groups, settings, audit events | workspace | `workspace_id bigint NOT NULL REFERENCES workspaces` |

Roles (`viewer`, `engineer`, `security`, `admin`, `collector`) keep their meaning but now apply within one workspace. Since 0.8 they can also be granted on chosen projects or single assets only, and the workspace scope can be narrowed to them; see [projects.md](projects.md). `instance_admin` is separate: it manages workspaces and installation-wide settings and does not by itself grant access to a workspace's data.

## Isolation: two locks

1. **Scope in the context.** Every request and job carries a scope in its `context.Context`: a workspace id, or *system* for platform work (claiming jobs, looking up tokens and sessions, redeeming enrollment codes, housekeeping, feed sync). Code without a scope sees no tenant rows at all.
2. **PostgreSQL row-level security.** Every workspace table has `ENABLE` and `FORCE ROW LEVEL SECURITY` and two permissive policies:
   ```sql
   CREATE POLICY ws ON t
     USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
   CREATE POLICY sys ON t
     USING (stackurity_system()) WITH CHECK (stackurity_system());
   ```
   `stackurity_ws()` reads the `stackurity.workspace_id` setting and returns NULL when it is unset; `stackurity_system()` is true only when `stackurity.scope = 'system'`. Unset means no rows: the default fails closed.

   `workspace_id` defaults to `stackurity_ws()`, so inserts made in a workspace scope need no code change, and an insert made in system scope without an explicit workspace fails the NOT NULL check instead of landing in the wrong place.

   Catalogue tables use a visibility policy instead: a component row is visible in workspace scope only if `EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = components.id)`, which RLS on `inventory` already limits to the current workspace. Writes to the catalogue (ingest upserts, feed matching) run in system scope.

**Setting the scope on connections.** The pool's `PrepareConn` hook reads the scope from the acquiring context and runs one `set_config` for `stackurity.scope` and `stackurity.workspace_id` (skipped when the connection already carries that scope). Transactions acquire once, so the whole transaction shares the scope. Handlers and store methods do not change their SQL to get isolation.

**Making sure RLS applies.** Superusers and roles with `BYPASSRLS` ignore RLS, and Compose runs PostgreSQL with the app as superuser. Migration 0010 creates a `NOLOGIN` role `stackurity_app` (when the migrating user may create roles), grants it table and sequence privileges, and the pool's `AfterConnect` runs `SET ROLE stackurity_app`. At startup the server checks `rolsuper OR rolbypassrls` for the effective role; if RLS would be bypassed and more than one workspace exists, it refuses to start. Migrations run on a separate connection as the owner.

**Tests.** A cross-workspace suite creates two workspaces with the same fixtures and, for every API route, asserts that workspace B's credentials never return, count, change or delete workspace A's objects, including by guessing ids. A store-level test runs every query helper with no scope and asserts zero tenant rows.

## Requests

- **Bearer tokens** (API, agents, CI, MCP) belong to one workspace. The token lookup runs in system scope; the request then runs in the token's workspace.
- **Browser sessions** carry the active workspace. `GET /api/v1/workspaces` lists the user's memberships; `POST /api/v1/workspaces/{id}/activate` switches (membership required). The principal's role is the membership role in the active workspace.
- **Enrollment** (`/enroll`, unauthenticated) redeems the code in system scope and issues a token bound to the code's workspace.
- **SSO**: a first sign-in joins `STACKURITY_OIDC_WORKSPACE` (default: workspace 1) with the mapped role.
- **Instance admin** endpoints: `GET/POST /api/v1/admin/workspaces`, `PATCH` (rename, disable). Creating a workspace names its first admin by email; an existing user is added, a new one is created with a one-time setup link.
- **Workspace members** (workspace admin): list, add by email, change role, remove. The last admin cannot be removed.

## Jobs and background work

`jobs.workspace_id` is set from the scope when a job is enqueued; the worker claims in system scope and runs the handler in the job's workspace. Periodic tasks that act on tenant data (alert dispatch, digests, remediation ticks, stale assets, due integrations, daily evaluation) run once per active workspace. Feed sync and catalogue matching stay global; the evaluation that turns matches into findings runs per workspace.

## Multi-tenant hardening

Some features are safe when one organisation runs its own server but not when strangers share one. In a workspace other than the one an instance admin is acting in, these rules apply:

| Risk | Rule |
| --- | --- |
| Secret references `env:` and `file:` read the server's own secrets | Allowed only when created by an instance admin. Workspaces store their own secrets as `stored:` values, encrypted with AES-256-GCM under a key from `STACKURITY_SECRET_KEY` (KMS on Cloud) and never returned by the API |
| Server-side requests to internal addresses (Git clones, webhooks, registries, plugin targets) | Resolve the host and refuse loopback, private, link-local, CGNAT and metadata ranges unless an instance admin allows a CIDR. Checked again at connect time to defeat DNS rebinding |
| Plugins using ambient credentials (for example the AWS instance role) | Require explicit credentials outside workspace 1 |
| Plugin executables | Installed only by instance admins; available to workspaces as an allowlist |
| One workspace exhausting shared resources | Per-workspace rate limits on ingest and API, job concurrency caps, and an optional limit on monitored assets ([asset-limits.md](../asset-limits.md)) |
| Audit | Audit events belong to a workspace; platform events (logins, workspace creation) have no workspace and are visible to instance admins |

## Migration of an existing install

Migration 0010, in one transaction:

1. Create `workspaces` and insert workspace 1, named from `STACKURITY_DEFAULT_WORKSPACE_NAME` or "Default" (renamable later).
2. Add `workspace_id` to every workspace table, fill it with 1, set NOT NULL and the default.
3. Rebuild unique constraints with `workspace_id` first: asset identifiers `(workspace_id, scheme, value)`, team, channel, route and policy names, the open-incident key, plan and action keys, `settings (workspace_id, key)`. Update the matching `ON CONFLICT` targets in the store.
4. Create `workspace_members` from `users.role`; mark existing admins `instance_admin`.
5. Create the RLS functions, role, grants and policies.

Tokens, sessions and enrollment codes keep working because they now belong to workspace 1.

## Delivery steps

1. Schema, scope plumbing, RLS, role check, store tests with no scope.
2. Principal and request scoping, token and session flows, jobs and per-workspace periodic tasks.
3. Workspace and member APIs, dashboard switcher and admin pages.
4. Cross-workspace API test suite.
5. Hardening: stored secrets, outbound address guard, plugin rules, rate limits.
6. Upgrade existing single-organisation installs in place: their data becomes workspace 1.
