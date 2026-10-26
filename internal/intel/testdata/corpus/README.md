# Matching corpus

Real advisory records, frozen per ecosystem, with installed versions and the
verdict each must get. `TestCorpus` (`internal/intel/corpus_test.go`) runs
every directory through the real pipeline: the records are served from a fake
upstream exactly as the source publishes them (an OSV `all.zip`, or Amazon
Linux repositories with `updateinfo.xml.gz`), synced by the `Syncer`, and
each case is ingested as its own asset and evaluated by the `Evaluator`.

Run it with a test database:

    STACKURITY_TEST_DATABASE_URL=postgres://... go test ./internal/intel -run TestCorpus

## Files

Each directory holds the records (`<ID>.json`, ":" in an id written as "_")
and `cases.json`:

| Field | Meaning |
|---|---|
| `feed` | The feed the records are synced through (`osv:<Ecosystem>` or `alas:Amazon Linux`) |
| `purl`, `version`, `evidence` | What a collector reports. `version` is given only when it differs from the purl's |
| `affected` | Every advisory group that must match (the lowest CVE among the record's id, aliases and upstream ids, else the id) and the fixed version to recommend, `""` when there is none. Any other match fails the case, so `{}` means "not affected" |
| `subscription` | The paid channel a group's only fix needs (Ubuntu Pro, SUSE LTSS) |
| `coverage`, `reason` | `evaluated` by default; `not_evaluated` or `unsupported` with words the reason must contain, for cases the system cannot evaluate |
| `note` | What the case shows |

Every directory covers, where the source has them: versions below, at and
above a fix; distribution backports (`+deb12u3`, `ubuntu0.22.04.4`,
`el9_4`, `150400.4.57.1`, `amzn2023.0.3`); epochs; pre-releases;
`last_affected` ranges; several ranges and several events in one range;
explicitly listed versions; withdrawn records; records covering several
ecosystems or releases; an unparseable version; and a release, product or
distribution the source has no data for.

## Sources

Records were downloaded on 2026-10-25 from the OSV bucket
(`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/<ID>.json`)
and trimmed: only the `affected` entries the cases use are kept (other
packages, releases and ecosystems removed), `ranges` of type GIT are dropped,
and `details`, `references` and `database_specific` (other than
`severity`) are removed. Ids, aliases, upstream ids, `withdrawn`, ranges and
version lists are unchanged.

| Directory | Cases | Records |
|---|---|---|
| `alma/` | 5 | [ALSA-2024:2447](https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/ALSA-2024%3A2447.json), [ALSA-2024:6783](https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/ALSA-2024%3A6783.json), [ALSA-2024:7848](https://osv-vulnerabilities.storage.googleapis.com/AlmaLinux/ALSA-2024%3A7848.json) |
| `alpine/` | 9 | [ALPINE-CVE-2023-5678](https://osv-vulnerabilities.storage.googleapis.com/Alpine/ALPINE-CVE-2023-5678.json), [ALPINE-CVE-2024-0727](https://osv-vulnerabilities.storage.googleapis.com/Alpine/ALPINE-CVE-2024-0727.json), [ALPINE-CVE-2024-5535](https://osv-vulnerabilities.storage.googleapis.com/Alpine/ALPINE-CVE-2024-5535.json) |
| `crates/` | 8 | [GHSA-22w3-693w-x895](https://osv-vulnerabilities.storage.googleapis.com/crates.io/GHSA-22w3-693w-x895.json), [GHSA-5wjr-9356-4wc8](https://osv-vulnerabilities.storage.googleapis.com/crates.io/GHSA-5wjr-9356-4wc8.json), [GHSA-gw89-822v-8v8g](https://osv-vulnerabilities.storage.googleapis.com/crates.io/GHSA-gw89-822v-8v8g.json), [RUSTSEC-2021-0124](https://osv-vulnerabilities.storage.googleapis.com/crates.io/RUSTSEC-2021-0124.json), [RUSTSEC-2023-0005](https://osv-vulnerabilities.storage.googleapis.com/crates.io/RUSTSEC-2023-0005.json) |
| `debian/` | 14 | [CVE-2010-0928](https://osv-vulnerabilities.storage.googleapis.com/Debian/CVE-2010-0928.json), [DEBIAN-CVE-2024-0727](https://osv-vulnerabilities.storage.googleapis.com/Debian/DEBIAN-CVE-2024-0727.json), [DEBIAN-CVE-2024-6387](https://osv-vulnerabilities.storage.googleapis.com/Debian/DEBIAN-CVE-2024-6387.json), [DSA-5586-1](https://osv-vulnerabilities.storage.googleapis.com/Debian/DSA-5586-1.json), [DSA-5724-1](https://osv-vulnerabilities.storage.googleapis.com/Debian/DSA-5724-1.json) |
| `go/` | 10 | [GO-2021-0157](https://osv-vulnerabilities.storage.googleapis.com/Go/GO-2021-0157.json), [GO-2022-0197](https://osv-vulnerabilities.storage.googleapis.com/Go/GO-2022-0197.json), [GO-2024-2687](https://osv-vulnerabilities.storage.googleapis.com/Go/GO-2024-2687.json) |
| `maven/` | 9 | [GHSA-7rjr-3q55-vv33](https://osv-vulnerabilities.storage.googleapis.com/Maven/GHSA-7rjr-3q55-vv33.json), [GHSA-jfh8-c2jp-5v3q](https://osv-vulnerabilities.storage.googleapis.com/Maven/GHSA-jfh8-c2jp-5v3q.json), [GHSA-wrr7-33fx-rcvj](https://osv-vulnerabilities.storage.googleapis.com/Maven/GHSA-wrr7-33fx-rcvj.json) |
| `npm/` | 23 | [GHSA-2p57-rm9w-gvfp](https://osv-vulnerabilities.storage.googleapis.com/npm/GHSA-2p57-rm9w-gvfp.json), [GHSA-35jh-r3h4-6jhm](https://osv-vulnerabilities.storage.googleapis.com/npm/GHSA-35jh-r3h4-6jhm.json), [GHSA-5844-q3fc-56rh](https://osv-vulnerabilities.storage.googleapis.com/Pub/GHSA-5844-q3fc-56rh.json), [GHSA-5f7q-jpqc-wp7h](https://osv-vulnerabilities.storage.googleapis.com/npm/GHSA-5f7q-jpqc-wp7h.json), [GHSA-78xj-cgh5-2h22](https://osv-vulnerabilities.storage.googleapis.com/npm/GHSA-78xj-cgh5-2h22.json), [GHSA-c2qf-rxjj-qqgw](https://osv-vulnerabilities.storage.googleapis.com/npm/GHSA-c2qf-rxjj-qqgw.json), [GHSA-pj86-cfqh-vqx6](https://osv-vulnerabilities.storage.googleapis.com/npm/GHSA-pj86-cfqh-vqx6.json) |
| `nuget/` | 9 | [GHSA-2865-hh9g-w894](https://osv-vulnerabilities.storage.googleapis.com/NuGet/GHSA-2865-hh9g-w894.json), [GHSA-2m65-m22p-9wjw](https://osv-vulnerabilities.storage.googleapis.com/NuGet/GHSA-2m65-m22p-9wjw.json), [GHSA-494h-xx7x-5frh](https://osv-vulnerabilities.storage.googleapis.com/NuGet/GHSA-494h-xx7x-5frh.json), [GHSA-5crp-9r3c-p9vr](https://osv-vulnerabilities.storage.googleapis.com/NuGet/GHSA-5crp-9r3c-p9vr.json) |
| `opensuse/` | 5 | [SUSE-SU-2024:0815-1](https://osv-vulnerabilities.storage.googleapis.com/openSUSE/SUSE-SU-2024%3A0815-1.json), [SUSE-SU-2024:2066-1](https://osv-vulnerabilities.storage.googleapis.com/openSUSE/SUSE-SU-2024%3A2066-1.json), [SUSE-SU-2024:2635-1](https://osv-vulnerabilities.storage.googleapis.com/openSUSE/SUSE-SU-2024%3A2635-1.json) |
| `packagist/` | 9 | [DRUPAL-CONTRIB-2020-011](https://osv-vulnerabilities.storage.googleapis.com/Packagist/DRUPAL-CONTRIB-2020-011.json), [GHSA-25mq-v84q-4j7r](https://osv-vulnerabilities.storage.googleapis.com/Packagist/GHSA-25mq-v84q-4j7r.json), [GHSA-364w-9g92-3grq](https://osv-vulnerabilities.storage.googleapis.com/Packagist/GHSA-364w-9g92-3grq.json), [GHSA-f2wf-25xc-69c9](https://osv-vulnerabilities.storage.googleapis.com/Packagist/GHSA-f2wf-25xc-69c9.json), [GHSA-m6ch-gg5f-wxx3](https://osv-vulnerabilities.storage.googleapis.com/Packagist/GHSA-m6ch-gg5f-wxx3.json), [GHSA-mjrx-74jh-7xgw](https://osv-vulnerabilities.storage.googleapis.com/Packagist/GHSA-mjrx-74jh-7xgw.json), [GHSA-w248-ffj2-4v5q](https://osv-vulnerabilities.storage.googleapis.com/Packagist/GHSA-w248-ffj2-4v5q.json) |
| `pub/` | 9 | [GHSA-3hpf-ff72-j67p](https://osv-vulnerabilities.storage.googleapis.com/Pub/GHSA-3hpf-ff72-j67p.json), [GHSA-4rgh-jx4f-qfcq](https://osv-vulnerabilities.storage.googleapis.com/Pub/GHSA-4rgh-jx4f-qfcq.json), [GHSA-fmj7-7gfw-64pg](https://osv-vulnerabilities.storage.googleapis.com/Pub/GHSA-fmj7-7gfw-64pg.json), [GHSA-jwpw-q68h-r678](https://osv-vulnerabilities.storage.googleapis.com/Pub/GHSA-jwpw-q68h-r678.json) |
| `pypi/` | 17 | [GHSA-56pw-mpj4-fxww](https://osv-vulnerabilities.storage.googleapis.com/PyPI/GHSA-56pw-mpj4-fxww.json), [GHSA-5844-q3fc-56rh](https://osv-vulnerabilities.storage.googleapis.com/Pub/GHSA-5844-q3fc-56rh.json), [GHSA-58pv-8j8x-9vj2](https://osv-vulnerabilities.storage.googleapis.com/PyPI/GHSA-58pv-8j8x-9vj2.json), [GHSA-6565-fg86-6jcx](https://osv-vulnerabilities.storage.googleapis.com/PyPI/GHSA-6565-fg86-6jcx.json), [GHSA-h95j-h2rv-qrg4](https://osv-vulnerabilities.storage.googleapis.com/PyPI/GHSA-h95j-h2rv-qrg4.json), [GHSA-q7q2-qf2q-rw3w](https://osv-vulnerabilities.storage.googleapis.com/PyPI/GHSA-q7q2-qf2q-rw3w.json), [GHSA-vm8q-m57g-pff3](https://osv-vulnerabilities.storage.googleapis.com/PyPI/GHSA-vm8q-m57g-pff3.json), [PYSEC-2024-47](https://osv-vulnerabilities.storage.googleapis.com/PyPI/PYSEC-2024-47.json) |
| `redhat/` | 12 | [RHSA-2024:0310](https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/RHSA-2024%3A0310.json), [RHSA-2024:0500](https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/RHSA-2024%3A0500.json), [RHSA-2024:2394](https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/RHSA-2024%3A2394.json), [RHSA-2024:2447](https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/RHSA-2024%3A2447.json), [RHSA-2024:6783](https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/RHSA-2024%3A6783.json), [RHSA-2026:1472](https://osv-vulnerabilities.storage.googleapis.com/Red%20Hat/RHSA-2026%3A1472.json) |
| `rocky/` | 8 | [RLSA-2024:6783](https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/RLSA-2024%3A6783.json), [RLSA-2024:7848](https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/RLSA-2024%3A7848.json), [RLSA-2024:9333](https://osv-vulnerabilities.storage.googleapis.com/Rocky%20Linux/RLSA-2024%3A9333.json) |
| `rubygems/` | 11 | [GHSA-5jhf-fpp7-v2pv](https://osv-vulnerabilities.storage.googleapis.com/RubyGems/GHSA-5jhf-fpp7-v2pv.json), [GHSA-7mqq-6cf9-v2qp](https://osv-vulnerabilities.storage.googleapis.com/RubyGems/GHSA-7mqq-6cf9-v2qp.json), [GHSA-8vqr-qjwx-82mw](https://osv-vulnerabilities.storage.googleapis.com/RubyGems/GHSA-8vqr-qjwx-82mw.json), [GHSA-9chr-4fjh-5rgw](https://osv-vulnerabilities.storage.googleapis.com/RubyGems/GHSA-9chr-4fjh-5rgw.json), [GHSA-xc9x-jj77-9p9j](https://osv-vulnerabilities.storage.googleapis.com/RubyGems/GHSA-xc9x-jj77-9p9j.json) |
| `suse/` | 7 | [SUSE-SU-2024:2020-1](https://osv-vulnerabilities.storage.googleapis.com/SUSE/SUSE-SU-2024%3A2020-1.json), [SUSE-SU-2024:2088-1](https://osv-vulnerabilities.storage.googleapis.com/SUSE/SUSE-SU-2024%3A2088-1.json), [SUSE-SU-2024:3105-1](https://osv-vulnerabilities.storage.googleapis.com/SUSE/SUSE-SU-2024%3A3105-1.json) |
| `ubuntu/` | 17 | [UBUNTU-CVE-2023-3446](https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/UBUNTU-CVE-2023-3446.json), [UBUNTU-CVE-2024-0727](https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/UBUNTU-CVE-2024-0727.json), [UBUNTU-CVE-2024-36971](https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/UBUNTU-CVE-2024-36971.json), [UBUNTU-CVE-2024-9143](https://osv-vulnerabilities.storage.googleapis.com/Ubuntu/UBUNTU-CVE-2024-9143.json) |
| `amazon/` | 9 | Amazon Linux `updateinfo.xml` from `cdn.amazonlinux.com`, read through each repository's `mirror.list` and `repodata/repomd.xml`: `al2023-core.xml` (AL2023 core: ALAS2023-2026-2136, ALAS2023-2026-3204, ALAS2023-2026-3267), `al2-core.xml` (AL2 core: ALAS2-2026-3992, ALAS2-2026-4036) and `al2-extras-kernel-5.10.xml` (AL2 extras topic kernel-5.10: ALAS2KERNEL-5.10-2026-135). The `<update>` elements are verbatim except that descriptions are cut to their first line and i686, aarch64 and debuginfo packages are removed |

`UBUNTU-CVE-2024-36971` and `RHSA-2024:2394` (downloaded 2026-10-26) are kernel advisories, kept
with only their Ubuntu 20.04 `linux` entry and their RHEL 9 `kernel`,
`kernel-core`, `kernel-modules`, `kernel-devel` and `kernel-tools` entries;
the cases show that packages with no running code (headers, `kernel-devel`)
get no findings although the advisory covers their source or names them.

`GHSA-5844-q3fc-56rh` is a GitHub advisory covering eleven ecosystems; it is
kept in `npm/` and `pypi/` with its npm, PyPI and Packagist entries.

## Adding a case

Add a line to `cases.json`; add a record if none covers it. Work out the
expected verdict from the record, not from what the matcher returns. If the
matcher disagrees and the record is right, that is a matching bug: fix it in
its own commit and keep the case.

Reports from users come through the [wrong finding](../../../../.github/ISSUE_TEMPLATE/wrong-finding.yml) and [missed vulnerability](../../../../.github/ISSUE_TEMPLATE/missed-vulnerability.yml) issue forms; each confirmed one gets a case here, referencing the issue in its `note`.
