### Fixed

- **The Assets list's search finds assets by their identifiers too.** Searching the Assets list now also matches machine ids, hostnames, image references and digests, repository addresses and the other identifiers the search box matches, so "See all" from search lists the same assets.
- **Messages point at where pages are now.** `stackurity doctor` sends you to Admin → Licence, the agent uninstallers and the Helm notes to Integrations → API tokens, and Platform health to Settings → Jobs.

### Changed

- **An asset's open-findings count on the Stack tab is amber, not red.** Red stays for known exploited and overdue findings, shown in the layers table.
