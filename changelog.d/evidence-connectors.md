### Added

- **Send compliance evidence to Vanta and Drata** (licensed build, Compliance add-on). Under **Integrations → Compliance evidence** an admin connects Vanta (OAuth, once the operator has set `STACKURITY_VANTA_CLIENT_ID` and `STACKURITY_VANTA_CLIENT_SECRET`) or Drata (an API key). On a schedule (every 6 or 12 hours, daily or weekly) Stackurity replaces the monitored assets and open vulnerabilities there and attaches the evidence pack, with each vulnerability's SLA status. Each sync is recorded with its counts and any error; **Sync now**, Pause and Disconnect are on the card. Without the add-on the card shows what it does and how to get it. See [Compliance evidence connectors](docs/evidence-connectors.md).

### Upgrading

- Migration `0109_evidence_connections` adds the tables `evidence_connections`, `evidence_oauth_states` and `evidence_sync_runs`. Additive; nothing is rewritten.
