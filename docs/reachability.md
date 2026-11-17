# Reachability

Most findings are in packages that are installed but never used: a library a dependency pulled in that no code of yours imports, or an operating-system package that no running program executes or loads. Reachability says, for each finding, whether its package is reached, and shows the evidence.

| Status | Meaning | Evidence comes from |
|---|---|---|
| Reachable | First-party code imports the package, or a running process executes it or has it loaded | The collector that read the source or the processes |
| Not imported | An application or repository package that no first-party source file imports | Repository scans and `stackurity scan` read the source files (Go, npm, Python, PHP) |
| Not running | A host package that no running process executes or has loaded | The agent reads the running processes; it needs read access to other users' processes, which is opt-in when the server is added |
| Not assessed (`unknown`) | No evidence either way | The default for every package, and what any collector that did not check reports |

**Not assessed counts as reachable.** Nothing is ever shown as unreachable without evidence a person can check: each status other than unknown carries the collector's evidence lines ("no import of `lodash` in 214 source files under `src/`", "no running process has `libssl.so.3` loaded"). A collection that does not assess a package sets it back to unknown, so an old claim never outlives the check that made it. The server stores a claim that a package is not reached only when its own records say the source can make it: not running only for a host, from that host's own agent (a token bound to the host, or the token the agent got when it enrolled, which is tied to the first host it reports), and not imported only for a repository, from the server's own repository scan or a token that is not an agent's. The batch must also come from the collector that makes the claim (`linux-agent` for dpkg and apk packages; `lockfile-scanner` for npm, Go, Composer and Python packages) with a coverage entry that says the reading was whole. Any other claim is stored as unknown.

Reachability is a statement about the asset as it was last collected: a package that is not running now may be started later, and code that does not import a package today may import it after the next deploy. That is why it lowers a priority by at most one level and never hides a finding.

## What it does to a priority

| Edition | Effect |
|---|---|
| Community | The status and evidence are shown on the finding, in the explanation (`explain_finding`, `why.reachability`) and in the API. Priorities do not change. |
| Pro and Enterprise | A finding that is not imported or not running is one priority level lower (P1 to P2, P2 to P3, P3 to P4; P4 stays P4), recorded as the factor `Not reached` with the evidence. It is **never lowered when the finding is known exploited (CISA KEV) and its asset is internet-facing or its exposure is unknown**: the factor `Not reached, priority kept` says so. The reachability filters and views are also part of these plans. |

Lowering a priority never ends SOS: the SOS rules look at known exploitation, severity, exposure and environment ([risk.md, "Score"](risk.md#score)), and an unreachable package on an exposed production server still raises one when they match. The step runs after the score is mapped to a priority, and its name is part of the risk policy version stored with each priority ([risk.md, "Reproducibility and audit"](risk.md#reproducibility-and-audit)).
