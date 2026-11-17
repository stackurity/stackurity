### Added

- **Running or not running, on hosts:** the Linux agent reads which installed dpkg and apk packages its host's running processes use (each process's program, the file names in its memory map and its listening sockets, under `/proc`) and marks them reachable with that evidence. When it can read every process, a package whose only code is programs, none of them running, is marked not running; libraries, helpers, scripts and anything started on a schedule or on demand stay not assessed. A package seen running stays reachable for 7 days. See [docs/reachability.md](docs/reachability.md#hosts-running-or-not-running).
- **Process access, opt-in:** **Add server** has a **See which packages are running** option, and `agent.sh` takes `STACKURITY_PROCESSES=1`. It gives the agent's service `CAP_SYS_PTRACE` (equivalent to root on the host, as the installer and the dashboard say), with the `ptrace` and `process_vm` system calls blocked. Without it the agent never marks a package not running. A host's page shows whether it is on (attribute `process_access`) and the command that turns it on.

### Changed

- Reachability coverage entries (`reachability`, `reachability/processes`) are always `checked`, with any limit in the reason, so they never count as a coverage gap. The agent sends reachability only to servers whose `GET /meta` lists it.
