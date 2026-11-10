### Fixed

- **A feed's first sync no longer leaves packages unchecked.** The re-evaluation a feed sync queues could start in the few milliseconds before the sync recorded its success, see the feed as never synced and skip it, so a new server's Ubuntu or Debian hosts showed almost no findings (and "feed has not completed a sync" under Coverage) until the feed next changed. The re-evaluation now starts 30 seconds after the sync.
