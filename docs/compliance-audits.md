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

## What you can say on your website

| You can say | You cannot say |
|---|---|
| "Monitored by Stackurity", with the [trust badge](trust-badge.md) | "SOC 2 compliant", "SOC 2 certified" or "ISO 27001 certified" because Stackurity scans your systems |
| "Our infrastructure is continuously monitored for vulnerabilities by Stackurity" | "Secured by Stackurity" or "Stackurity certified" |
| "SOC 2 Type II" or "ISO 27001 certified", **only** if you hold that report or certificate yourself, shown as a separate statement | "SOC 2 / ISO 27001 via Stackurity", or anything that suggests Stackurity gave you a report or certificate |

Saying you hold a certification or attestation you do not hold is misleading advertising, and the AICPA and certification bodies limit who may use their logos. If you have a SOC 2 report or ISO 27001 certificate, it is yours, from your auditor; Stackurity's badge sits next to it and says only that Stackurity monitors your systems.
