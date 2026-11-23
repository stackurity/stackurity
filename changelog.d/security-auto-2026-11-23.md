### Security

- **SAML sign-in library updated.** `github.com/crewjam/saml` 0.5.1 → 0.5.2 (licensed edition's SAML sign-in), which reads `NameID` only from the SAML assertion namespace and rejects assertions without a Subject, Conditions or bearer confirmation: [GO-2026-6909](https://osv.dev/vulnerability/GO-2026-6909). Stackurity already refused foreign-namespace `NameID`s itself. `github.com/beevik/etree` 1.7.0 → 1.8.1 comes with it.
