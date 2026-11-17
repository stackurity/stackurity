### Added

- **Verified closure: every closed finding says whether a check saw the fix.** Resolved findings show **Verified fixed**, **Verified removed**, **Disappeared (not verified)** or **Closed, not a fix**, in the findings list and on the finding. A fixed finding lists its proof: the version before and after, the check (agent report, repository or image scan…) that saw it and when, and the remediation plan if one fixed it. `GET /api/v1/findings/{id}/closure` returns the proof as one record. See [Why a finding closed](docs/api.md#verified-closure).

### Changed

- **Findings no longer count as fixed when Stackurity only lost sight of them.** When a repository is no longer granted to the GitHub App or leaves the connected GitLab group, or an image is deleted from its registry, its findings now close as `disappeared` instead of `removed`. They are not counted as remediation in the outcomes and evidence reports, so fixed totals and SLA rates can drop slightly where that happened.

### Upgrading

- Migration `0108_verified_closure` adds `collections.absence_unverified` and reclassifies past findings closed that way from `removed` to `disappeared` (their history events too).
