### Fixed

- **Upgrading the agent keeps release-layout applications' history.** From 0.20.24 the agent reports an application deployed in a release layout (Capistrano, Deployer, Envoyer, Ghost-CLI) by its own folder. Its first such report made a new asset: the old one was marked removed, its issues resolved as removed and came back as new issues on the new asset, and its projects stayed behind. The report now goes to the existing asset, which keeps its issues, history, projects, snoozes and assignments and takes the folder's name. An application that keeps its old release's path as well is no longer marked removed for it.

### Upgrading

- Migration `0122_release_layout_assets` repairs hosts whose agents upgraded to 0.20.24 first: each new folder-named asset hands its identity, name and projects to the asset it replaced and is deleted. On the next agent report the old asset's issues reopen as the same issues.
