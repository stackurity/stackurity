### Added

- **MCP: `plan_options` and `evidence_pack` tools.** `plan_options` lists the organisation's paid features, those its plan lacks with what each does, and the plan or add-on that includes each; it is meant for when someone asks about their plan. `evidence_pack` says which frameworks the plan covers and gives the link that downloads the compliance evidence pack (it builds nothing itself). `integrations_status` also shows the Vanta and Drata evidence connectors. See [AI assistants](docs/ai-assistants.md).
- **`GET /api/v1/plan/options`**: the organisation's paid features and how to get the missing ones. See [API](docs/api.md#get-planoptions).

### Changed

- **`402 plan_required` says what includes the feature.** The error keeps its code and a fixed message, and adds `feature`, `feature_name`, `hosted`, `included_in`, `plan`, `addon`, `trial_available` and `plans_url` ([API conventions](docs/api.md#conventions)). On Stackurity Cloud the prices come from the plan configuration, in the organisation's currency. MCP tools turn it into one line: the smallest plan with its price, or the Compliance add-on's price on a plan (never a trial for the add-on); ChatGPT connections get the plan's name and the plans page only. Answers that worked never carry an offer.

### Fixed

- **The Compliance add-on's refusal no longer says it is part of Stackurity Pro**, and Enterprise-only features (phishing-resistant sign-in, enterprise stack packs) say Enterprise. Reachability and verified closure are named instead of showing their internal ids.
