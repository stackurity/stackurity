### Fixed

- **A deploy no longer creates a new application.** An application deployed in a release layout (releases/ or versions/ plus a `current` link, as Capistrano, Deployer, Envoyer and Ghost-CLI deploy) was tracked by its current release's folder, so every deploy added a new asset and marked the previous one removed. A web server that also serves the `releases/` folder made a second application, named "releases", that counted every old release. The agent now reports the application by its own folder (for example `commmerce-ui on <host>` for `/var/www/commmerce-ui`), scanning only the current release. The release scanned is still shown as the application directory.

### Upgrading

- After the agent updates, each such application appears once under its own folder's name, and the release-named asset it replaces is marked removed. Its snoozes and assignments do not carry over.
