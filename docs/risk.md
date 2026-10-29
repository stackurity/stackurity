# How priorities are decided

Every open finding gets a priority from P1 (most urgent) to P4, an SOS flag for the few that should page someone, and acknowledgement and fix deadlines. This page describes how, what happens when evidence is missing, the scenarios the scoring is tested against and the guarantees it keeps. The code is `internal/risk`; the weights live in the risk policy (**Settings → Risk policy**, `GET/PUT /api/v1/risk-policy`).

## Inputs

| Input | Where it comes from |
|---|---|
| CVSS score | The advisory's CVSS base score (v3.x or v4.0, whichever is higher). A score of 0 counts as none. |
| Severity | The advisory's severity, used only when there is no CVSS score. SUSE publishes none, so SUSE findings have `unknown`. While an inventory version is unconfirmed the severity is withheld (`unknown`), but a CVSS score is still used. |
| Known exploited | The advisory, or any of its aliases, is in the CISA KEV catalogue. |
| Predicted exploitation (EPSS) | FIRST's EPSS for the finding's CVE (its `key`): the probability that the CVE is exploited in the wild in the next 30 days, from the daily `epss:first` feed. See [below](#predicted-exploitation-epss). |
| Internet exposure | In order: the **Internet exposed** value set on the asset, else the collector's observation (a Kubernetes workload's `exposure`), else for an image the current workloads deployed as it: exposed if any is, internal only if every one is internal, otherwise unknown. |
| Environment | The asset's environment. It counts as production when it matches one of the policy's production environment names (case-insensitive). Empty or blank means unknown. |
| Criticality | The asset's criticality: `critical`, `high`, `medium`, `low` or `unknown` (the default). |
| Fix available | The finding has a fixed version obtainable without a subscription. A fix published only in Ubuntu Pro or SUSE LTSS (paid) does not count. |
| Overdue | The fix deadline has passed and the finding is still `new`, `acknowledged` or `in_progress`. |
| Scope | `dev` for a development-only dependency. |
| Kernel not running | The finding is on an installed kernel version that is not the one running. Kernel findings are one per CVE per installed kernel version, and none on headers ([compatibility.md](compatibility.md#kernels)), so a CVE in the running kernel is scored once. |
| Verification | `confirmed`, `needs_validation` (the installed version came from a low-confidence source) or `stale` (the asset has stopped reporting); `rejected` findings are false positives a person ignored. The definitions are in [verification.md, "Evidence states"](verification.md#evidence-states). **A second-check disagreement never lowers priority**: it does not change verification, the score, SOS or alerts; it is shown for a person to review ([verification.md, "Second check"](verification.md#second-check)). |

**VEX statements never change a priority.** An imported `affected`, `fixed` or `under_investigation` statement is shown on the finding and nothing else. A `not_affected` statement hides a finding only once a security or admin user approved it (or a source an admin trusts applied it), as an ignore rule with the reason `false_positive` or `mitigated`, pinned to the component version and image it was about; an ignored finding leaves prioritisation like any other. See [vex.md](vex.md#the-trust-model).

## Score

The score starts from a base and adds points. Each contribution is stored with the finding as a factor (`priority_factors`) with its points and the evidence behind it, and shown under **Why this priority**.

| Factor | Default points | When |
|---|---|---|
| CVSS base score | the score | a CVSS score is known |
| Severity | critical 9.5, high 7.5, medium 5, low 2.5, none 0.5, unknown 5 | no CVSS score; an unrecognised or missing severity uses `unknown` |
| End of life | 6 | end-of-life findings, instead of the two above |
| Known exploited | +3 | in CISA KEV |
| Exploit prediction (EPSS) | +1.5 | EPSS at or above the policy's threshold (10%), kept down to 80% of it; not for a CVE in CISA KEV |
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

## Predicted exploitation (EPSS)

FIRST's [Exploit Prediction Scoring System](https://www.first.org/epss/) gives every published CVE a daily probability of exploitation activity in the next 30 days, and its percentile among all CVEs. Stackurity downloads the whole file once a day (feed `epss:first`, [network.md](network.md#intelligence-feeds)) and stores the score, percentile, model version and score date for each CVE. A finding's EPSS is that of its `key`, which is the lowest CVE among the advisory's identifiers; findings without a CVE (a GHSA or distribution advisory with none) have no EPSS.

The policy has two settings: `epss`, the points (1.5 by default), and `epss_threshold`, the probability from which they apply (0.1, that is 10%, by default; about the top 5% of CVEs). EPSS works as a threshold rather than a sliding weight, so the priority changes only when a CVE crosses it, never because its score moved from 31% to 33%:

- **The factor is all or nothing.** At or above the threshold the finding gets the full points, below it none. Its detail names the threshold, not the day's score ("FIRST EPSS of 10% or more..."), so the stored factors of a finding stay the same from day to day and its row is not rewritten.
- **Hysteresis.** A finding that has the factor keeps it until its EPSS falls below 80% of the threshold (8% by default); one that does not have it gets it only at the threshold. A score that moves between 9% and 11% for a week changes the priority once, not every day. Whether a finding already has the factor is read from its stored `priority_factors`, so a restart or a new server changes nothing.
- **Not on top of KEV.** A CVE in CISA KEV gets the known-exploited points and no EPSS points: KEV is evidence of exploitation, EPSS a prediction of it. The policy editor rejects `epss` above `known_exploited`, so a CVE that joins KEV never loses points.
- **Read fresh.** Priorities are recomputed every minute from the stored scores, so a new EPSS file changes priorities within minutes without re-evaluating any inventory. EPSS changes priority, the score and deadlines like any other factor; it never opens or closes a finding, and on its own it never makes a finding SOS.

The current score, percentile and date are shown with every finding (the **EPSS** column on **All issues**, and the filter **Exploit prediction (EPSS)**), whether or not they count. **Why this priority** on the finding page, `GET /findings/{id}/explain` (`risk.epss`) and the AI assistants' `explain_finding` tool say in one sentence what EPSS predicts for the CVE and why it counts or not: above the threshold, kept after crossing it, below it, replaced by KEV, or not scored yet.

To leave EPSS out of priorities, set `epss` to 0. Disabling the `epss:first` feed only stops refreshing the stored scores, which then keep counting, like KEV's. A stale EPSS feed (no success for 72 hours) is a warning on Platform health and a P3 feed incident, not a vulnerability feed's critical problem: findings are still matched, only their predictions are old.

When a policy saved before EPSS existed is read, `epss` takes its default, but never more than the policy's own `known_exploited`. The first prioritisation after the upgrade records the new policy version on every open finding, once. Like every prioritisation, it writes in chunks of 1,000 findings, each its own short transaction, so even a pass that rewrites every finding holds row locks on at most 1,000 of them at a time, for well under a second, and evaluations, workflow actions and the API do not wait for the whole pass. A pass interrupted part way keeps the chunks it wrote; the next one, a minute later, finishes the rest.

## Missing evidence

Missing evidence is never scored like the benign value, except for the two extras that are not risk facts about the asset (an available fix, and EPSS), and is always named in the explanation. It is not always scored like the worst value; these are the deliberate differences:

| Missing | Scored as | Why not the worst value |
|---|---|---|
| Exposure (unknown, or Kubernetes Services or Ingresses unreadable) | +0.5, between internal (0) and exposed (+1.5). SOS treats it as exposed. | Scoring every unrecorded asset as exposed would push most findings up a priority. SOS, which pages, is where a wrong "internal" would hurt most, so there it counts as exposed. |
| Environment (empty) | +0.5, between non-production (0) and production (+1). SOS treats it as production. | Same reasoning as exposure. Set environments to remove the uncertainty: a confirmed KEV finding on an asset with no environment is SOS. |
| Criticality (`unknown`, or empty) | The policy's `unknown` weight, 0 by default, like `medium` and above `low`. | Criticality is a business judgement most assets never get; treating every asset as critical would make the factor meaningless. Raise the `unknown` weight to be more cautious. |
| Severity (none published, as for SUSE, or unrecognised) | The policy's `unknown` base, 5 by default (medium). It never meets an SOS rule's `min_severity`. | Treating every SUSE finding as critical would flood P1 and SOS. KEV, exposure and environment still apply, and KEV in production is SOS whatever the severity. |
| Fix (no fixed version known, or only in a paid channel: Ubuntu Pro, SUSE LTSS) | No fix bonus. | "Fix available" is an actionability bonus, not a risk factor: a finding that can be fixed now ranks slightly higher. |
| EPSS (no CVE, or a CVE FIRST has not scored yet) | No EPSS points, as below the threshold. | EPSS is a prediction added on top of severity and KEV, like "fix available" an extra rather than a base: most advisories without a CVE are distribution or ecosystem records whose CVE is the key of another finding, and a new CVE is usually scored within days. The explanation says that there is no score. |
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
| CVSS 6.5, internal production, EPSS 42% | 9.0 | P2 | |
| Same, EPSS 3% | 7.5 | P3 | |
| Same, EPSS fell to 9% after crossing 10% | 9.0 | P2 | |
| Same, EPSS 9% that never crossed 10% | 7.5 | P3 | |
| KEV, CVSS 7.5, exposed production, fix available, EPSS 97% | 13.5 | P1 | Known exploited in production |

Two outcomes worth knowing: a KEV finding with a critical CVSS score stays P1 even on an internal development box (it is five points lower than in exposed production and is not SOS), and a KEV finding in production is SOS whether or not the asset is exposed.

## Invariants

Property tests check these over thousands of generated findings, and the first and third over generated policies too:

1. **Monotonicity.** Adding a risk-raising fact never lowers the score or the priority, and under the default rules never removes SOS. Risk-raising facts: becoming known exploited; an EPSS score being published or rising, or the finding having had the EPSS factor before; internal to unknown to exposed; non-production to no environment to production; criticality low to medium to high to critical; becoming overdue; a fix becoming available; a dev dependency becoming runtime; the kernel being booted; evidence becoming confirmed; a higher severity or CVSS score.
2. **Missing evidence** never scores below the benign value, and where it scores below the worst value it does so exactly as the table above says.
3. **Explanations** add up to the score, contain no zero-point factor, and list exactly the factors whose conditions hold, no more and no fewer.
4. **Reproducibility.** The same policy and input always give the same result, also after the policy is stored and read back, and any change to the policy changes its version.

The policy editor enforces what these need: it rejects negative points for known exploitation, EPSS, exposure, production or overdue, EPSS points above the known-exploited points, an EPSS threshold outside (0, 1], unknown exposure or environment weighted above the known value, positive points for dev dependencies or idle kernels, and severity or criticality weights out of order.

## Reproducibility and audit

- A policy's **version** (`sha256:` and 16 hex digits) is a hash of its full content: weights, thresholds, deadlines, production environments and SOS rules. **Settings → Risk policy** and `GET /risk-policy` show it.
- Each finding records the version that produced its priority, score, factors and SOS flag (`priority_policy_version`). `GET /findings/{id}/explain` returns it as `policy_version`, with `current_policy_version` and `policy_changed`. Open findings are re-prioritised every minute, so after a policy change they move to the new version within minutes.
- Every change is written to the audit log (`risk_policy.update`, **Activity → Audit log**) in the same transaction as the change, with who made it, the full policy before and after, both versions and the fields that changed. Any version a finding cites can be rebuilt from the log (or is the default policy of that release) and, with the same evidence, gives the same priority.
- `PUT /risk-policy` replaces the whole policy; a field left out takes its default, as it does when a stored policy is read after an upgrade adds a field. Upgrading can therefore change the version without anyone editing the policy; the new version is what is applied.
- **Preview before saving.** `POST /risk-policy/preview` (admins) takes a proposed policy, validates it exactly as `PUT` does, and scores the workspace's open findings under the policy in force and under the proposed one, in memory and inside a read-only transaction, so nothing is written. It returns the open findings per priority and the SOS count before and after, how many findings change priority (raised and lowered) or SOS, and up to 50 of the changed findings with their asset, priority and score before and after, and the factors whose points differ. Both sides use the same evidence, so the difference is the policy change alone; `stored_differs` counts findings whose stored priority is already out of date because their evidence changed. **Settings → Risk policy** requires a preview of the exact changes before **Save**, and shows who last changed the policy and when, from the audit log (`last_change` in `GET /risk-policy`).
