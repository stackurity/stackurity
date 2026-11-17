### Added

- **Running or not running, on hosts:** the Linux agent reads which installed dpkg and apk packages its host's running processes use (each process's program, the file names in its memory map and its listening sockets, under `/proc`) and marks them reachable with that evidence, remembered for 7 days across restarts. Not running is claimed only for a service that is off: its systemd service or init script is not enabled, its programs are neither scripts, links, setuid/setgid nor given file capabilities, and none ran in 7 days of readings that covered every process at least every 13 hours. Command-line tools, libraries, helpers, scripts and anything started on a schedule or on demand stay not assessed. See [docs/reachability.md](docs/reachability.md#hosts-running-or-not-running).
- **Process access, opt-in:** **Add server** has a **See which packages are running** option, and `agent.sh` takes `STACKURITY_PROCESSES=1`. It gives the agent's service `CAP_SYS_PTRACE` (equivalent to root on the host, as the installer and the dashboard say) and a state directory, `/var/lib/stackurity-agent`. Without it the agent never marks a package not running. A host's page shows whether it is on (attribute `process_access`) and the command that turns it on.

### Changed

- Reachability coverage entries (`reachability`, `reachability/processes`) are always `checked`, with any limit in the reason, so they never count as a coverage gap. The agent sends reachability only to servers whose `GET /meta` lists it.
