# Open core: what is free, what is paid, and where the code lives

Status: October 2026.

## Split

| Free (Community, Apache-2.0) | Pro | Enterprise |
| --- | --- | --- |
| Inventory: hosts, applications, repositories, images, SBOMs, AWS | Automatic fixing: policies, approvals, canary rollouts, verification, rollback, Renovate pull requests | Everything in Pro |
| Intelligence: OSV, KEV, end of life, releases | Several teams, routing alerts by team, escalation | Enterprise stack packs (SAP, Oracle, network firmware, ...) |
| Priorities, incidents, alerts, one team, Action plan | Evidence report | |
| CI gate, MCP, workspaces, official stack packs | Single sign-on | |

Detection is never paid for: a free install that hides vulnerabilities would leave its users unsafe.

## Mechanism

- `internal/license` verifies an Ed25519-signed licence offline (no phone-home) and decides the edition: active, 30 days of grace after expiry, then Community.
- Each workspace has a plan; a workspace gets the lower of its plan and the licence. A hosted platform sets plans per organisation; a self-hosted install leaves them "as licensed".
- Paid features are checked in the API (`402 plan_required`), in background work (remediation engine, escalation) and in the dashboard. Agents simply receive no changes without the plan.
- The licence issuer's private key stays with the issuer; `tools/license` issues keys.

## Where the code lives

The paid implementations live in the private repository `stackurity/stackurity-pro`, laid out like this one. The licensed edition is the core plus those files:

- Every file there starts with `//go:build ee` and sits at the path of the core package it joins (for example `internal/rollout/rollout.go`, `internal/api/handlers_remediation.go`).
- `tools/eeoverlay` writes a Go build overlay that adds them; it refuses a file that would replace a core file. `make build-ee`, `make test-ee` and `make image-ee` (with `PRO=path/to/stackurity-pro`) use it, and the Dockerfile takes `--build-context pro=... --build-arg EDITION=ee`.
- The core holds the extension points and their Community versions in `*_community.go` files (`//go:build !ee`): API routes for paid features answer `402 plan_required`, agents receive no changes, escalation does nothing, and the server sets nothing up.
- Database migrations, the data model, the Action plan, host-bound tokens and the agent stay in the core, so both editions share one schema.

| Image | Built from | Contains |
| --- | --- | --- |
| `stackurity` | this repository | Community |
| `stackurity-ee` | this repository + `stackurity-pro` | all features, switched on by a licence and each workspace's plan |

**Before this repository is made public**, its git history must not include the paid code it held until October 2026: publish a fresh history (or filter those paths out) rather than the private history.
