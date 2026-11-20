### Added

- **Attack tools: ARTEX.** Risky settings has a new category, **Attack tools**, for attacker tools found on your assets. The first one is ARTEX, the AI-driven attack framework the FBI warned about on 13 November 2026. It covers renamed forks such as ScopeWeaver. The agent finds it on servers as a Go executable built from it (the build record is read; nothing is run) or a copy of its source. It finds it in container images by image name or by the image's Go executables, and in repositories by `go.mod`, `Dockerfile` and Compose files. The prebuilt images `tomicdd/artex` and `congdonglinux/artex`, reported to carry a backdoor, have a rule of their own. Every match is high and raises a Risky setting incident. See [Risky settings](docs/config-checks.md#attack-tools).

### Upgrading

- Migration `0117_config_attack_tools` widens the `config_findings` category check to allow `attack_tool`. Additive. Agents send attack tool findings only to servers that list `config_attack_tools` in `GET /meta`, so older servers keep taking their batches.
