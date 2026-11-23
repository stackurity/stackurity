### Fixed

- **No more "No such project" errors after the chosen project goes away.** When the project chosen in the switcher was archived, or belonged to another organisation after switching in another tab, every page showed `404 not_found` until a reload. The dashboard now drops back to all projects, reloads the switcher's list and loads the page. The API marks this 404 with an `X-Stackurity-Project-Unknown` header ([API](docs/api.md), #540).
