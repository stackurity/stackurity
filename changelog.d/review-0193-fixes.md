### Fixed

- **The dashboard's deadline figure adds up and is never rounded to 100%.** It now reads "1,132 of 1,134 (99.8%) within deadline" instead of "100% of open issues within deadline" when two are overdue. Open issues that are snoozed or accepted have no deadline, so they are left out of that figure; the dashboard now says how many, so its counts match the open-issue total. `GET /api/v1/dashboard/trend` returns them as `sla.excepted`. Outcomes and the evidence report use the same rounding.
- **The evidence report shows its dates as "8 Oct 2026"**, the same in every locale, next to the date pickers (which follow the browser's locale, so 08/10/2026 could read as August or October).
- **Tables never cut off their buttons.** A table's last column of row buttons (Reset password, Revoke, Remove and so on) stays pinned to the right edge while the rest scrolls, and a table with columns out of view shows a shadow on that edge and says it scrolls sideways.
- **The page for instance administrators explains itself.** Someone without that role who opens an instance page (such as `/updates`) is told who it is for, gets a link to the changelog and a way back to Home.

### Security

- **One-time install codes and collector tokens are masked on screen until you press Show code.** The install command on Add a server, the fleet and cloud-init commands and the onboarding collector token show only the code's first characters, so a screen share or screenshot does not reveal a usable code. Copy still copies the full command.
