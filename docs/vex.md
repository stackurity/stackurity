# VEX

VEX (Vulnerability Exploitability eXchange) documents say whether a product is affected by a vulnerability. A vendor can tell you that a CVE in a library inside their image cannot be exploited; you can tell your customers the same about your software. Stackurity imports VEX, shows it on findings and, with a person's approval, ignores the findings a `not_affected` statement covers. It exports its own decisions as VEX.

VEX is part of Community. Importing needs the `engineer` role or higher; approving needs an organisation-wide `security` or `admin` role; trusting a source to apply on its own is for admins.

## Formats

| Format | Read | Written |
|---|---|---|
| OpenVEX v0.2.0 (and the older v0.0.1 shape, with string products and vulnerabilities) | Yes | v0.2.0 |
| CycloneDX VEX (1.4 to 1.6): `vulnerabilities[]` with an `analysis`, standalone or embedded in a CycloneDX BOM | Yes | 1.6 |
| Either one as the predicate of a signed in-toto attestation: a DSSE envelope, or a Sigstore bundle (`cosign attest` and `cosign attest-blob` output) | Yes; the signature is checked against a source's key | No |
| CSAF VEX | No | No |

Statuses are OpenVEX's: `not_affected` (with a justification or an impact statement), `affected`, `fixed` and `under_investigation`. CycloneDX analysis states map to them: `not_affected` and `false_positive` to `not_affected`, `exploitable` to `affected`, `in_triage` to `under_investigation`, `resolved` and `resolved_with_pedigree` to `fixed`. CycloneDX justifications map to the nearest OpenVEX one (`code_not_present` to `vulnerable_code_not_present`, `code_not_reachable` to `vulnerable_code_not_in_execute_path`, `requires_*` to `vulnerable_code_cannot_be_controlled_by_adversary` or, for `requires_dependency`, `component_not_present`, `protected_*` to `inline_mitigations_already_exist`); the original state and justification are kept. A CycloneDX vulnerability without an analysis says nothing and is skipped.

A vulnerability is matched by its id and aliases. A GHSA, OSV or distribution id finds the CVE the finding is keyed by through the stored advisories, so `GHSA-p6mc-m468-83gw` matches the finding for CVE-2020-8203.

## Importing

```sh
stackurity vex import vendor.openvex.json
stackurity vex import api.intoto.json --source 3          # a signed attestation from source 3
stackurity vex import product-abc.vex.cdx.json --asset 12  # about asset 12
```

Or **Settings → VEX → Import a VEX document**, or `POST /api/v1/vex/import` ([api.md](api.md#vex)). An SBOM uploaded with `stackurity sbom import` or `POST /sbom/import` that has VEX embedded has it imported for the asset the upload created, for approval like any other import (a collector token's SBOM keeps its VEX out: use an engineer's token).

The answer says how many statements matched, how many did not and why, how many wait for approval, and how many applied on their own. Every import is kept under **Settings → VEX** with the file name, its SHA-256, the source, the signature and each statement's outcome, and is recorded in the activity log (`vex.import`).

### Matching

Each product a statement names is matched to component versions on your assets:

| The product is | It matches |
|---|---|
| An image by digest (`pkg:oci/name@sha256:…`, `registry/name@sha256:…`, or a `sha-256` hash) | The image assets with that digest (from the image scanner, Kubernetes, or a reference pinned by digest). Its subcomponents are the packages in it; with none, every component of the image with a finding for the vulnerability |
| An application by package URL, or a CycloneDX BOM by serial number (also as a BOM-Link) | The asset an SBOM with that package URL or serial number was imported as, with its subcomponents (by package URL, CPE or bom-ref) |
| A package by package URL, with a version | That package at that version on every asset in scope |
| A package by CPE 2.3 or 2.2, with a version | The package of that name at that version, when exactly one package fits |
| A CycloneDX document's own subject with no identifier of its own (CISA's use cases) | Only the asset the import is scoped to (`--asset`) |

Package URLs compare by type, namespace and name (PyPI names normalised), and versions exactly (a leading `v` is ignored). A `distro` or `arch` qualifier on both sides must agree.

**When matching is ambiguous, the statement is not applied**; it is listed as unmatched with the reason:

- a package URL without a version, outside an image pinned by digest (it would cover every version);
- a package without a version in an image that has two versions of it;
- a CPE without a version, or one that fits two different packages (the vendor is rarely in a package URL);
- an image named by tag, not digest (tags move);
- a product that holds components but is none of your assets, unless the import is scoped to one asset;
- version ranges (CycloneDX `range`), and a version list that contradicts the analysis;
- a statement matching more than 5,000 component versions (too broad: import it for one asset or project).

`--asset` or `--project` (`asset_id`, `project_id`) limits matching to that asset or project's assets.

## The trust model

A VEX document can hide real findings, so **an imported `not_affected` statement never suppresses anything by itself**:

1. Each matched `not_affected` statement becomes a request under **Approvals**, marked VEX, with the source, file, justification, impact statement, how many component versions and assets it matches, and the products it could not match. Its issues stay open meanwhile; the finding shows the statement as waiting for approval.
2. An organisation-wide `security` or `admin` user approves or declines it, one by one or a whole document at once (**Settings → VEX**, or `POST /vex/documents/{id}/decision`). Members with security only through a project grant cannot decide VEX requests and do not see them.
3. An approved statement becomes ignore rules: one per matched component version on each asset, with the reason `false_positive` (justifications `component_not_present`, `vulnerable_code_not_present`, or CycloneDX `false_positive`) or `mitigated` (the others), the VEX source and justification as the note, and no expiry. The activity log records the file (name and SHA-256), the statement, the requester and the approver (`ignore_request.approve` with `vex_statement_id`, `vex_document_id`, `source`, `vulnerability`, `justification`, `filename`, `sha256`, `signature`).

**Trusted sources.** An admin can let a source's statements apply without a person (**Settings → VEX → Sources**, `POST /vex/sources`). The document's own `author` is never trusted, since anyone can write any name into a document; a source may apply on its own only while it is pinned to something a document cannot claim:

- a **public key** (PEM, as `cosign generate-key-pair` writes `cosign.pub`; ECDSA P-256 or P-384, Ed25519, or RSA of 2,048 bits or more): uploads for the source must then be a signed attestation that verifies with it, and plain documents or bad signatures are refused (400); and/or
- an **API token**: only uploads made with that token apply on their own; anyone else's upload for the source waits for approval.

Every pin the source has must hold. Auto-applied statements are recorded in the activity log as approvals by `VEX source <name> (auto-apply)` with `auto_apply: true`. Changing a source is audited (`vex_source.create`, `vex_source.update`, `vex_source.delete`).

**Signatures.** Key-based signatures on DSSE envelopes and Sigstore bundles are verified. Keyless signatures (a Fulcio certificate with a Rekor entry, cosign's default) are not: such a document is shown as signed but unverified and can only be approved by a person. The verification is behind one interface (`vex.Verifier`), where keyless verification can be added.

### When a statement stops applying

A rule made from a VEX statement is pinned to the component version it matched, and to the image digest when the statement named the image by digest:

- after an upgrade, the new version's finding is not covered, and the rule ends by itself (`ended_reason: no_longer_matches`) within a minute;
- when an image asset's digest changes (a new build under the same tag), the rule ends and its issues return to `new` with a `reopen` event;
- a newer `affected` or `under_investigation` statement about the same component version (from any source) ends the rules of older `not_affected` statements (`ended_reason: vex_superseded`), and approving an older `not_affected` statement after it applies nothing. Which statement is newer is decided by the statement's timestamp, else the document's; a timestamp in the future counts as the time of import, so a document cannot make itself newer than later ones.

Rules made from VEX can also be ended by hand under **Approvals → Ignore rules**, like any rule.

## On findings

A finding shows the latest statement about its component version and vulnerability: a **VEX** badge on the finding page and in lists, with the status, justification, impact or action statement and the source. `affected` and `fixed` are informational, `under_investigation` is a note, and a `not_affected` statement shows whether it waits for approval or applies. A declined statement is not shown. In the API, findings carry `vex` (null when none); the AI assistants' `list_findings` and `get_finding` return it too.

## Exporting

```sh
stackurity vex export --asset 12 -o asset-12.openvex.json
stackurity vex export --project shop --format cyclonedx -o shop.vex.cdx.json
```

Or **Export VEX** on an asset's page and under **Settings → VEX**, or `GET /api/v1/vex/export` (any role that can see the assets; members with project access get their projects' assets). The document lists the decisions about open issues:

- issues ignored as a **false positive** (`not_affected`, `vulnerable_code_not_present`; CycloneDX `false_positive`) or **mitigated** (`not_affected`, `inline_mitigations_already_exist`; CycloneDX `not_affected`, `protected_by_mitigating_control`), with the rule's note and mitigation as the impact statement, or with the statement's own justification and impact statement when an approved VEX statement made the rule;
- the latest imported `affected`, `fixed` and `under_investigation` statements about other open issues.

Accepted risks and issues ignored because no fix exists are not exported: they say nothing about exploitability. Each statement names the component version (its package URL), inside its image (a `pkg:oci` package URL with the digest) or its application (the package URL its SBOM gave it) when the asset has one. Exporting the same decisions twice gives the same document id. An exported document imports back: scope a document of package-only statements to the same asset or project.

Notes and mitigations are written into the document as you wrote them; read it before you send it to anyone.

## Limits

| | |
|---|---|
| Document size | 16 MiB (an SBOM with VEX embedded: the SBOM limit, 64 MiB) |
| Statements per document | 20,000 |
| Products per statement, subcomponents per product | 1,000 each; 200,000 in a document |
| Component versions one statement may match | 5,000 |
| Matches in one document | 100,000 |
| Text kept (impact and action statements, notes) | 4,000 bytes each |

Matching runs inside the importing workspace under row-level security: a document naming another workspace's images or packages matches nothing there, even with that workspace's asset ids.
