### Added

- **Trust badge, part 1: the rule and its history (Stackurity Cloud only, off).** The rule that decides whether a "Monitored by Stackurity" badge is active, and an append-only history of every decision with the evidence to rebuild it. Every evaluation now records which refresh of each vulnerability source it read. Which refresh each evaluation read is recorded on every server (`inventory_evaluations`); the badges, their decisions and anything public exist only on the Stackurity Cloud build with `STACKURITY_TRUST_BADGE=on`. The badge launches after legal sign-off. See [Trust badge](docs/trust-badge.md).

### Upgrading

- Migration `0103_trust_badge` adds the tables `inventory_evaluations`, `trust_badges`, `trust_badge_status` and `trust_badge_purges`, the purge function and a NOLOGIN role `stackurity_purge` (where the migrating user may create roles).
