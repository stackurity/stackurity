### Changed

- **Process access reads Debian's crontabs:** with `STACKURITY_PROCESSES=1` the agent's service also gets `CAP_DAC_READ_SEARCH`, so it can read `/var/spool/cron/crontabs` (closed to other users on Debian and Ubuntu). Before, those hosts never had a package marked not running, because an unread crontab might start it. Like `CAP_SYS_PTRACE`, it is equivalent to root on the host, and process access stays opt-in. Hosts that already have process access get it when the installer runs again or the agent is upgraded.
