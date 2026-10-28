# Swift pack fixtures

Real files from public repositories, unchanged, downloaded on 2026-10-28 from
`raw.githubusercontent.com` at the commits below.

| Fixture | Source | What it shows |
|---|---|---|
| `penny-bot-v1/Package.resolved` | [vapor/penny-bot](https://github.com/vapor/penny-bot) `API/Package.resolved` at `7e3f2ee576bb9de26730be2657155189b37cc94d` (2022-03) | Format 1 (`object.pins`, `repositoryURL`); a package pinned to a branch (`swift-aws-lambda-runtime`, no version); `swift-nio` 2.38.0, affected by GHSA-rj37-6j9x-74q6 |
| `swiftlint-v2/Package.resolved` | [realm/SwiftLint](https://github.com/realm/SwiftLint) `Package.resolved` at `ac44fe23b67b017c26927b016553a05fb21f3f21` (2022-12) | Format 2; mixed-case repository names (`jpsim/SourceKitten`); a revision pin |
| `penny-bot-v3/Package.resolved` | [vapor/penny-bot](https://github.com/vapor/penny-bot) `Package.resolved` at `e1481d187e703649e2116d36c3cb022357946916` (2026-10) | Format 3 (`originHash`); pre-release versions (`1.0.0-rc.3`); a branch pin |
| `tuist-registry-v3/Package.resolved` | [tuist/tuist](https://github.com/tuist/tuist) `Package.resolved` at `ba2b1151ebe4606255f776d1dc029c9c30f3fe3c` | Format 3 with `registry` pins (`identity` = `scope.name`, empty `location`, `originalLocation` naming the mirrored repository) |
| `chriseidhofnl-local-v2/Package.resolved` | [chriseidhof/chriseidhofnl](https://github.com/chriseidhof/chriseidhofnl) `Package.resolved` at `75951fb77f1ab99b71c386cbd7edcec486cf2ae5` | Format 2 with `localSourceControl` pins (the author's own packages on disk) and branch pins |
| `signal-ios/Podfile.lock` | [signalapp/Signal-iOS](https://github.com/signalapp/Signal-iOS) `Podfile.lock` at `9b5fd0f750ad6fc0d663b716bb140ea79d5de0d0` | Pods from git repositories (`EXTERNAL SOURCES` with `:git:`, `:tag:`, `:submodules:`), subspecs, an exact requirement (`= 1.38.1`) |
| `mattermost-mobile/Podfile.lock` | [mattermost/mattermost-mobile](https://github.com/mattermost/mattermost-mobile) `ios/Podfile.lock` at `c772c6ad1e75357c0cd943015b461e987810856d` | A React Native app: over a hundred development pods from `node_modules` (`:path:`), pods from local podspecs (`:podspec:`), quoted entries, trunk pods |
