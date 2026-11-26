# Using Stackurity in a SOC 2 or ISO 27001 audit

Stackurity gives you **evidence** for the vulnerability-management controls of SOC 2, ISO 27001, PCI DSS and the EU Cyber Resilience Act. It does not make you compliant and it cannot certify you. Only an independent auditor issues a SOC 2 report, and only an accredited certification body issues an ISO 27001 certificate. Both look at your whole security programme; Stackurity covers one part of it.

This page explains which controls Stackurity gives evidence for, what it does not cover, how to give the evidence to your auditor, and what you can and cannot say about it on your website.

## Which controls Stackurity gives evidence for

The [audit evidence pack](api.md#audit-evidence-pack) maps what Stackurity records to these controls. For each control the pack says what in it is evidence and, where it applies, what Stackurity does not show. Control titles here paraphrase the frameworks; they are not their text.

| Framework | Control | What Stackurity shows | What it does not show | Plan |
|---|---|---|---|---|
| SOC 2 | CC7.1: detecting new vulnerabilities and changes that introduce them | Every monitored asset's installed software checked against vulnerability and end-of-life data on its own schedule, how many expected reports arrived and the longest gap, what was found and is open, leaked keys found in its files, and when each vulnerability source was last refreshed | Anything outside the software Stackurity reads on monitored assets | Team and up |
| SOC 2 | CC8.1: changes are authorised, tested, approved and implemented | Each security fix tracked from finding to closure against its deadline, exceptions with reason, approver and expiry, verified closures and policy changes where those features are on | The rest of your change-management process | Team and up |
| ISO 27001:2022 | A.8.8: management of technical vulnerabilities | Vulnerabilities found on every monitored asset, prioritised, and fixed within your policy's deadlines or excepted with approval | | Team and up |
| ISO 27001:2022 | A.8.9: configuration management | The installed software and versions of every asset each time it reports, SBOMs, and policy rules for what may run | Configuration settings other than installed software | Team and up |
| ISO 27001:2022 | A.5.17: authentication information | Keys, tokens and passwords found written in files on monitored assets, and when each was found, rotated and gone (never the values) | How authentication information is issued, stored or rotated elsewhere | Team and up |
| PCI DSS 4.0 | 6.3.1, 6.3.3, 11.3 | Vulnerabilities from public sources ranked by risk, time to patch against your deadlines, and regular checks of installed software | Stackurity is not a network vulnerability scanner or an Approved Scanning Vendor: it does not replace the ASV scans of 11.3.2 or the internal scans of 11.3.1 | Compliance add-on |
| EU Cyber Resilience Act | Annex I part II (1) to (4) | An SBOM of each asset, time to fix, regular checks, and VEX statements | Penetration tests and code review | Compliance add-on |

When the pack says checks ran "every hour", it is because it has the recorded hourly re-checks to prove it for the period.

## What Stackurity does not cover

A SOC 2 or ISO 27001 audit also looks at much that Stackurity does not touch, for example:

- your security policies, risk assessment and the scope of your management system;
- people: background checks, security training, joiners and leavers;
- access control: who has access to what, access reviews, single sign-on and two-factor authentication;
- vendor and supplier risk;
- incident response, backups, business continuity and disaster recovery;
- physical security;
- penetration tests and network scans.

A compliance platform such as Vanta or Drata tracks these, and your auditor tests them.

## Giving the evidence to your auditor

- **Download the audit evidence pack.** Open **Governance › Reports and audit**, find **Audit evidence pack**, choose the audit period and the frameworks your auditor asked about, and download the PDF, or the ZIP with a CSV of every table and a SHA-256 manifest. A SOC 2 Type II audit covers a period, usually 3 to 12 months: choose the same dates as the audit. A pack covers at most a year. Every download is in the audit log. See [Audit evidence pack](api.md#audit-evidence-pack) for what is in it.
- **Or send it to your compliance platform.** With the Compliance add-on, Stackurity sends the same evidence to Vanta or Drata on a schedule, so those controls there stay current. See [Compliance evidence connectors](evidence-connectors.md).
- **Your auditor may ask about Stackurity itself.** Stackurity becomes one of your vendors, so your auditor may ask how it is run and secured. Contact us for what you need. On a self-hosted server it runs in your own infrastructure, under your own controls.

Start the evidence early: a pack can only show what Stackurity recorded, so an asset added the week before the audit shows one week of monitoring.

## Checking a pack's signature

The ZIP's `manifest.json` lists every file in the pack with its SHA-256. On Stackurity Cloud it is also signed: `manifest.json.sig` is an Ed25519 signature over the exact bytes of `manifest.json`, and names the key that made it (`key_id`, which `manifest.json` repeats as `signing_key_id`). Together they show the pack came from Stackurity and that no file was changed, added or removed after it was made. Your auditor can check it without an account:

```sh
stackurity evidence verify stackurity-evidence-workspace-2026-07-01-2026-09-30.zip
```

It prints `ok`, the key and the date, and exits 0; it exits non-zero and says why when a file was changed, the pack is unsigned, or the key is unknown or revoked. `stackurity evidence verify --keys FILE` checks against a saved copy of the key set instead of fetching it (offline). Without the CLI: check each file's SHA-256 against `manifest.json`, then the signature with any Ed25519 library, using the `public_key` (base64, 32 bytes) of the `key_id` in the key set.

- **The key set** is published at `https://stackurity.ai/.well-known/stackurity-evidence-keys.json`, an address that does not change. It lists every key ever used, with `status` (`active`, `retired` or `revoked`), `not_before` and, once retired, `not_after`. A key is never removed, so a pack signed before a key was rotated still verifies: a retired key verifies the packs dated (`generated_at`) inside its period. Only a revoked (compromised) key stops verifying anything.
- **An unsigned pack** says so in `manifest.json` (`"signed": false`), in `pack.json` (`signature.signed`) and in the PDF. Its files still match the manifest, but nothing proves who made it. The PDF and JSON downloads are not signed on their own; the ZIP's signed manifest lists the PDF's SHA-256.
- **On your own server** packs are signed when `STACKURITY_EVIDENCE_SIGNING_KEY_FILE` names an Ed25519 private key (PKCS#8 PEM, as `openssl genpkey -algorithm ed25519 -out evidence.key` makes; readable only by the server). `stackurity evidence pubkey evidence.key` prints its key set entry (`--not-before` sets the date it starts signing, default now). Publish your own key set (`{"keys": [ ... ]}`) where your auditors can fetch it, and give them `--keys` with its address. To rotate: add the new key's entry, switch the server to the new key, then mark the old entry `retired` with `not_after` set to the switch time; never delete it. Keep an offline copy of each private key.


## What you can say on your website

| You can say | You cannot say |
|---|---|
| "Monitored by Stackurity", with the [trust badge](trust-badge.md) | "SOC 2 compliant", "SOC 2 certified" or "ISO 27001 certified" because Stackurity scans your systems |
| "Our infrastructure is continuously monitored for vulnerabilities by Stackurity" | "Secured by Stackurity" or "Stackurity certified" |
| "SOC 2 Type II" or "ISO 27001 certified", **only** if you hold that report or certificate yourself, shown as a separate statement | "SOC 2 / ISO 27001 via Stackurity", or anything that suggests Stackurity gave you a report or certificate |

Saying you hold a certification or attestation you do not hold is misleading advertising, and the AICPA and certification bodies limit who may use their logos. If you have a SOC 2 report or ISO 27001 certificate, it is yours, from your auditor; Stackurity's badge sits next to it and says only that Stackurity monitors your systems.
