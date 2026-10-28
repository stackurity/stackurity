# Hex pack fixtures

Real files from public repositories, unchanged, downloaded on 2026-10-28 from
`raw.githubusercontent.com`.

| Fixture | Source | What it shows |
|---|---|---|
| `phoenix-1.0.0/mix.lock` | [phoenixframework/phoenix](https://github.com/phoenixframework/phoenix) `mix.lock` at tag `v1.0.0` (2015) | The Mix 1.0 format: `{:hex, :name, "version"}` only; a git dependency |
| `phoenix-1.2.1/mix.lock` | [phoenixframework/phoenix](https://github.com/phoenixframework/phoenix) `mix.lock` at tag `v1.2.1` (2016) | Six-element tuples without a repository; `plug` 1.1.6, affected by CVE-2017-1000052, CVE-2017-1000053 and CVE-2018-1000883 |
| `plausible/mix.lock` | [plausible/analytics](https://github.com/plausible/analytics) `mix.lock` at `be3bc8ac721cc6a9721316ff3c8d23addce0ab8a` (2026) | The current eight-element format with `"hexpm"`; eleven git dependencies (with `branch:`, `ref:` and `sparse:` options); packages renamed in `mix.exs` (`"chatterbox": {:hex, :ts_chatterbox, ...}`, `"hpack": {:hex, :hpack_erl, ...}`) |
| `private-org/mix.lock` | [kamilkowalski/public_project](https://github.com/kamilkowalski/public_project) `mix.lock` at `5be388305222c952c031b87d87428bffc9ef3794` | A package from a private Hex organisation (`"hexpm:renovate_test"`) |
