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

## Repositories and `stackurity scan`: not imported

When the server scans a repository, or `stackurity scan` scans a directory, it reads the first-party source files after the lockfiles, as data (nothing is run or built), with the scan's limits: 50,000 source files, 1 MiB of each and 256 MiB in all, the walk's own limits, and the same skipped directories (`node_modules`, `vendor`, `.git`, ignored files, nested checkouts). The coverage entry `reachability` says how many files of each language were read. When a limit was reached its reason starts with `partial:` and names the limit, and the scan reports nothing as not imported. Its status is always `checked`: what reachability could read says nothing about whether the package list is whole, so it never counts as a coverage gap, an alert or a reason to hide a trust badge.

| Ecosystem | Reachable when | Not imported when | Otherwise not assessed |
|---|---|---|---|
| Go | A non-test `.go` file imports a package of the module | No `.go` file imports it, or only `_test.go` files do (so it is not in the built program) | No Go files; a file that does not parse |
| npm | An `import`, `export … from`, `require()` or `import()` names the package (`lodash/fp` counts as `lodash`) | No file imports it and nothing names it as a string | No JavaScript or TypeScript files; any `require()` or `import()` with a computed argument; the package is named as a string in source or configuration (`client: 'pg'`, a plugin list, a `package.json` script), since it may be loaded by name |
| PHP (Composer) | A name in its autoload namespace (from `composer.lock`) appears in PHP or configuration files (`use Monolog\Logger`, a class name in YAML) | No PHP or configuration file names anything in its namespaces | The package autoloads files on every request, is a Composer plugin or Symfony bundle, registers itself with Laravel, has only a class map, or autoloads from the root namespace |
| Python | An `import` or `from` names the package (dashes as underscores) | Never: a distribution's import name can differ from its name (PyYAML is `yaml`), so a missing import proves nothing | Every package that is not reachable |

Each claim carries its evidence: the file that imports the package, or what was searched ("no import or require of left-pad in 214 JavaScript/TypeScript files, and not named in scripts or configuration"). A development dependency says so, and a transitive one says that it may still run through a package that imports it: not imported means first-party code does not import it, not that nothing does.

Servers before reachability refuse the field, so `stackurity scan` sends it only to servers whose `GET /meta` lists `reachability`.

## What it does to a priority

| Edition | Effect |
|---|---|
| Community | The status and evidence are shown on the finding, in the explanation (`explain_finding`, `why.reachability`) and in the API. Priorities do not change. |
| Pro and Enterprise | A finding that is not imported or not running is one priority level lower (P1 to P2, P2 to P3, P3 to P4; P4 stays P4), recorded as the factor `Not reached` with the evidence. It is **never lowered when the finding is known exploited (CISA KEV) and its asset is internet-facing or its exposure is unknown**: the factor `Not reached, priority kept` says so. The reachability filters and views are also part of these plans. |

Lowering a priority never ends SOS: the SOS rules look at known exploitation, severity, exposure and environment ([risk.md, "Score"](risk.md#score)), and an unreachable package on an exposed production server still raises one when they match. The step runs after the score is mapped to a priority, and its name is part of the risk policy version stored with each priority ([risk.md, "Reproducibility and audit"](risk.md#reproducibility-and-audit)).
