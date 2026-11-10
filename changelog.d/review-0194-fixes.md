### Fixed

- **Outcomes, the evidence report and the dashboard use one SLA.** Outcomes measured each fix against the current policy's days from first detection, while the evidence report and the dashboard used each issue's fix-by date, so the same 246 fixes read 82.1% in one and 100% in the other. All three now use the fix-by date people saw (it follows patch windows, carried-over deadlines and priority changes), out of the fixes that had one, and say how many had none instead of dropping them silently. `GET /outcomes` adds `resolved_no_deadline` per priority and counts open overdue issues by their fix-by date; the evidence report adds `resolved.with_deadline`.
- **A finding's upgrade recommendation no longer implies that a major upgrade is needed when a smaller one fixes the issue.** The recommendation covers every open issue on the package. When the issue on screen alone is fixed in a version in the installed major line (Next.js 13.5.9, say, while all 36 open issues need 15.5.28), the card now shows that version as "fixes this issue", names the other figure "minimum for all 36 open issues", and explains why it recommends the major upgrade (the other issues, and an end-of-life line) instead of saying the fix is only in a new major version.
- **Issue and incident titles no longer say an open issue "was fixed".** Distribution advisories titled from the vendor's side ("A security issue was fixed in nginx.") now read "Security issue in nginx (fix available)". Existing findings take the new title at their next evaluation.
- **Coverage percentages round to the nearest** (29 of 31 is 94%), still never showing 100% unless every component was checked.
- **Fixes says why its views can add up to more than All fixes**: a fix needed in several places is in the view of each place.
- **Wide tables show their sideways-scroll cue above the table**, so a long table (Jobs) shows it without scrolling to its end, and the automatic-fix policy table keeps readable column widths instead of wrapping every few words.
- **Outcomes says when no end-of-life components were resolved** instead of showing a one-row comparison.

### Added

- **Owner rules show how every open issue got its owner**: by a rule, by a person, or not at all, so the rules' counts can be read against the open total. `GET /owner-rules` returns this as `coverage` when not filtered to an asset or project.
