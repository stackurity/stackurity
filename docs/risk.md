# How priorities are decided

Every open finding gets a priority from P1 (most urgent) to P4, an SOS flag for the few that should page someone, and acknowledgement and fix deadlines. This page describes how, what happens when evidence is missing, the scenarios the scoring is tested against and the guarantees it keeps. The code is `internal/risk`; the weights live in the risk policy (**Settings → Risk policy**, `GET/PUT /api/v1/risk-policy`).

## Inputs

| Input | Where it comes from |
|---|---|
| CVSS score | The advisory's CVSS base score (v3.x or v4.0, whichever is higher). A score of 0 counts as none. |
| Severity | The advisory's severity, used only when there is no CVSS score. SUSE publishes none, so SUSE findings have `unknown`. While an inventory version is unconfirmed the severity is withheld (`unknown`), but a CVSS score is still used. |
| Known exploited | The advisory, or any of its aliases, is in the CISA KEV catalogue. |
| Internet exposure | In order: the **Internet exposed** value set on the asset, else the collector's observation (a Kubernetes workload's `exposure`), else for an image the current workloads deployed as it: exposed if any is, internal only if every one is internal, otherwise unknown. |
| Environment | The asset's environment. It counts as production when it matches one of the policy's production environment names (case-insensitive). Empty or blank means unknown. |
| Criticality | The asset's criticality: `critical`, `high`, `medium`, `low` or `unknown` (the default). |
| Fix available | The finding has a fixed version obtainable without a subscription. A fix that needs Ubuntu Pro does not count. |
| Overdue | The fix deadline has passed and the finding is still `new`, `acknowledged` or `in_progress`. |
| Scope | `dev` for a development-only dependency. |
| Kernel not running | The package belongs to an installed kernel that is not the one running. |
| Verification | `confirmed`, `needs_validation` (the installed version came from a low-confidence source) or `stale` (the asset has stopped reporting). |

## Score

The score starts from a base and adds points. Each contribution is stored with the finding as a factor (`priority_factors`) with its points and the evidence behind it, and shown under **Why this priority**.

| Factor | Default points | When |
|---|---|---|
| CVSS base score | the score | a CVSS score is known |
| Severity | critical 9.5, high 7.5, medium 5, low 2.5, none 0.5, unknown 5 | no CVSS score; an unrecognised or missing severity uses `unknown` |
| End of life | 6 | end-of-life findings, instead of the two above |
| Known exploited | +3 | in CISA KEV |
| Internet exposed | +1.5 | exposure is known to be external; the detail names the source (set on the asset, reported by the collector, or a workload running the image) |
| Exposure unknown | +0.5 | exposure is not recorded, or the collector could not decide it |
| Production | +1 | the environment is a production environment |
| Environment unknown | +0.5 | the asset has no environment |
| Asset criticality | critical +1.5, high +1, medium 0, low -1, unknown 0 | |
| Fix available | +0.5 | an upgrade resolves it now (it is more actionable) |
| Overdue | +1 | past its fix deadline |
| Development dependency | -2 | dev-only scope |
| Kernel not running | -10 | installed kernel that is not booted |
| Evidence confidence | score × 0.7 (`needs_validation`) or × 0.8 (`stale`) | applied last, only to a positive score |

The score is rounded to one decimal and mapped to a priority: P1 at 12 or more, P2 at 8.5, P3 at 6, otherwise P4.

**SOS** fires when the finding is `confirmed`, is not on an idle kernel, and matches an SOS rule. The defaults are "Known exploited in production" and "Critical, exposed production asset" (severity critical). A rule that requires an exposed asset also matches unknown exposure, and one that requires production also matches an asset with no environment. A rule may not rely on severity alone.

**Deadlines** run from first detection: P1 acknowledge in 4 hours and fix in 3 days, P2 24 hours and 14 days, P3 72 hours and 45 days, P4 168 hours and 90 days. They move only when the priority changes.

## Missing evidence

Missing evidence is never scored like the benign value, and is always named in the explanation. It is not always scored like the worst value; these are the deliberate differences:

| Missing | Scored as | Why not the worst value |
|---|---|---|
| Exposure (unknown, or Kubernetes Services or Ingresses unreadable) | +0.5, between internal (0) and exposed (+1.5). SOS treats it as exposed. | Scoring every unrecorded asset as exposed would push most findings up a priority. SOS, which pages, is where a wrong "internal" would hurt most, so there it counts as exposed. |
| Environment (empty) | +0.5, between non-production (0) and production (+1). SOS treats it as production. | Same reasoning as exposure. Set environments to remove the uncertainty: a confirmed KEV finding on an asset with no environment is SOS. |
| Criticality (`unknown`, or empty) | The policy's `unknown` weight, 0 by default, like `medium` and above `low`. | Criticality is a business judgement most assets never get; treating every asset as critical would make the factor meaningless. Raise the `unknown` weight to be more cautious. |
| Severity (none published, as for SUSE, or unrecognised) | The policy's `unknown` base, 5 by default (medium). It never meets an SOS rule's `min_severity`. | Treating every SUSE finding as critical would flood P1 and SOS. KEV, exposure and environment still apply, and KEV in production is SOS whatever the severity. |
| Fix (no fixed version known, or only with Ubuntu Pro) | No fix bonus. | "Fix available" is an actionability bonus, not a risk factor: a finding that can be fixed now ranks slightly higher. |
| Confidence (`needs_validation`, `stale`) | The score is scaled down (× 0.7, × 0.8) and the finding cannot be SOS. | Low-confidence and stale evidence may describe software that is not, or no longer, installed. The finding stays visible with its own factor; it is never dropped. |

CISA's "known ransomware campaign use" flag is stored with the KEV catalogue but is not a separate input: such an entry scores exactly as any KEV entry.

## Scenarios

`internal/risk/scenarios_test.go` pins what the default policy decides for these findings, together with the complete explanation (every factor, its points and the evidence it names). All are confirmed, runtime and with criticality `unknown` unless stated.

| Scenario | Score | Priority | SOS rule |
|---|---|---|---|
| KEV, CVSS 9.8, internet exposed, production, critical asset, fix available | 17.3 | P1 | Known exploited in production |
| Same CVE on an internal development box (criticality low) | 12.3 | P1 | |
| KEV, CVSS 7.5, exposed production, fix available | 13.5 | P1 | Known exploited in production |
| Same CVE on an internal development box (criticality low) | 10.0 | P2 | |
| KEV, CVSS 7.5, internal production, no fix | 11.5 | P2 | Known exploited in production |
| Ransomware-flagged KEV, CVSS 8.1, exposed production | 13.6 | P1 | Known exploited in production |
| KEV on an installed kernel that is not running, exposed production | 4.8 | P4 | |
| CVSS 9.8, exposed production, high criticality, fix available | 13.8 | P1 | Critical, exposed production asset |
| CVSS 9.8, exposed staging | 11.3 | P2 | |
| CVSS 8.8, exposed production, no fix | 11.3 | P2 | |
| CVSS 8.8, exposed production, fix available | 11.8 | P2 | |
| CVSS 8.8, exposed production, fix only with Ubuntu Pro | 11.3 | P2 | |
| CVSS 5.3, internal production | 6.3 | P3 | |
| CVSS 3.1, exposed production | 5.6 | P4 | |
| Severity critical, no CVSS score, exposed production | 12.0 | P1 | Critical, exposed production asset |
| Unknown severity (SUSE), exposed production | 7.5 | P3 | |
| Unknown severity (SUSE), KEV, exposed production | 10.5 | P2 | Known exploited in production |
| Unrecognised severity label, exposed production | 7.5 | P3 | |
| CVSS 9.1, production, Kubernetes exposure undecidable | 10.6 | P2 | Critical, exposed production asset |
| Same, known internal | 10.1 | P2 | |
| CVSS 7.5, production image exposed through a workload | 10.0 | P2 | |
| CVSS 7.5, production workload exposed by its Service | 10.0 | P2 | |
| KEV, CVSS 7.5, no environment, exposure not recorded | 11.5 | P2 | Known exploited in production |
| Same, labelled staging and internal | 10.5 | P2 | |
| CVSS 6.5, blank environment, internal | 7.0 | P3 | |
| CVSS 7.5, exposed production, criticality empty | 10.0 | P2 | |
| CVSS 7.5, exposed production, criticality low | 9.0 | P2 | |
| CVSS 7.5, environment "PROD", internal | 8.5 | P2 | |
| KEV, CVSS 7.5, exposed production, version unconfirmed | 9.1 | P2 | |
| CVSS 9.8, exposed production, version unconfirmed | 8.6 | P2 | |
| KEV, CVSS 7.5, exposed production, asset stale | 10.4 | P2 | |
| CVSS 7.8 on an idle kernel, production, asset stale | -1.2 | P4 | |
| CVSS 9.8 in a dev-only dependency, internal production | 8.8 | P2 | |
| End-of-life runtime, exposed production | 8.5 | P2 | |
| End-of-life runtime, internal staging | 6.0 | P3 | |
| CVSS 6.1, internal staging, overdue | 7.1 | P3 | |

Two outcomes worth knowing: a KEV finding with a critical CVSS score stays P1 even on an internal development box (it is five points lower than in exposed production and is not SOS), and a KEV finding in production is SOS whether or not the asset is exposed.

## Invariants

Property tests check these over thousands of generated findings, and the first and third over generated policies too:

1. **Monotonicity.** Adding a risk-raising fact never lowers the score or the priority, and under the default rules never removes SOS. Risk-raising facts: becoming known exploited; internal to unknown to exposed; non-production to no environment to production; criticality low to medium to high to critical; becoming overdue; a fix becoming available; a dev dependency becoming runtime; the kernel being booted; evidence becoming confirmed; a higher severity or CVSS score.
2. **Missing evidence** never scores below the benign value, and where it scores below the worst value it does so exactly as the table above says.
3. **Explanations** add up to the score, contain no zero-point factor, and list exactly the factors whose conditions hold, no more and no fewer.
4. **Reproducibility.** The same policy and input always give the same result, also after the policy is stored and read back, and any change to the policy changes its version.

The policy editor enforces what these need: it rejects negative points for known exploitation, exposure, production or overdue, unknown exposure or environment weighted above the known value, positive points for dev dependencies or idle kernels, and severity or criticality weights out of order.

## Reproducibility and audit

- A policy's **version** (`sha256:` and 16 hex digits) is a hash of its full content: weights, thresholds, deadlines, production environments and SOS rules. **Settings → Risk policy** and `GET /risk-policy` show it.
- Each finding records the version that produced its priority, score, factors and SOS flag (`priority_policy_version`). `GET /findings/{id}/explain` returns it as `policy_version`, with `current_policy_version` and `policy_changed`. Open findings are re-prioritised every minute, so after a policy change they move to the new version within minutes.
- Every change is written to the audit log (`risk_policy.update`, **Settings → Audit log**) in the same transaction as the change, with who made it, the full policy before and after, both versions and the fields that changed. Any version a finding cites can be rebuilt from the log (or is the default policy of that release) and, with the same evidence, gives the same priority.
- `PUT /risk-policy` replaces the whole policy; a field left out takes its default, as it does when a stored policy is read after an upgrade adds a field. Upgrading can therefore change the version without anyone editing the policy; the new version is what is applied.
