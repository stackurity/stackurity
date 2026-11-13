### Fixed

- **Zabbix and Icinga builds from their own repositories are recognised again.** The snapd fix above narrowed the rule to MySQL's version form, so versions such as `1:7.0.5-1+ubuntu24.04` were checked against Ubuntu's advisories, which do not cover them. They are flagged as vendor builds again; snapd (`2.77.1+ubuntu24.04`, no packaging revision) stays the distribution's build.
- **The Renovate command on a plan quotes the repository.** Only a plain `owner/repository` path is put into the copy-and-paste command, in single quotes.
