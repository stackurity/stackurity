### Fixed

- **Evidence pack and plan options work from AI assistants and Ask Stackurity.** The `evidence_pack` and `plan_options` tools in Claude, ChatGPT and other connected assistants answered "an assistant cannot change account settings", because they read the plan's features from an account route that assistants were not allowed to read. Assistants and Ask Stackurity may now read the plan's features (read-only); every other account setting stays closed to them.
