### Added

- **Risky settings: Shirudo micropatches that stopped working.** On servers that use [Shirudo](https://docs.shirudo.dev) to block an exploit until the patch is installed, the agent reports a micropatch that is archived but not loaded in the running kernel (`shirudo-upatch-not-loaded`), and Shirudo enforcement that is not attached (`shirudo-enforcement-off`). Files are only listed. The check needs the agent to run as root, and reports "not read" otherwise. See [Risky settings](docs/config-checks.md#shirudo-micropatches).
