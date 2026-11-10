### Added

- **`pkg/engine`: the scan engine as a public Go package.** Lockfile parsing, the host and container collectors, leaked-key detection, OSV range matching and endoflife.date lifecycle resolution can now be imported from outside this module, with no server or database. The standalone scanner (`stackurity/scan`) uses it, so a parser or matching fix lands in both. The API may change before 1.0.
- **Hugging Face access tokens are reported as leaked keys** (`hf_…`, critical), next to the Anthropic, OpenAI and Google keys already found.

### Changed

- The endoflife.date product resolver moved from `internal/intel` to `internal/lifecycle` so it runs without the store; results are unchanged.
